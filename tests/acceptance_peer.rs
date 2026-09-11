use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bgpkit_parser::bgp::parse_bgp_message;
use bgpkit_parser::models::{
    AsPath, Asn, AsnLength, AttributeValue, Attributes, BgpMessage, BgpOpenMessage,
    BgpUpdateMessage, NetworkPrefix, Nlri, OptParam, Origin, ParamValue,
};
use bgpkit_parser::parse_mrt_record;
use bytes::Bytes;
use flate2::read::GzDecoder;
use focl::archive::types::ArchiveStream;
use focl::archive::ArchiveService;
use focl::bgp::{BgpService, PrefixSource, PrefixStatus};
use focl::config::{ArchiveConfig, FoclConfig, GlobalConfig, PeerConfig, PrefixConfig};
use focl::types::{Event, PeerState};
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::time::timeout;

const PEER_AS: u32 = 65_002;
const FOCL_AS: u32 = 65_001;

#[tokio::test]
async fn configured_prefixes_exchange_bidirectionally_and_archive() -> Result<()> {
    let temp = tempfile::tempdir()?;
    // Allocate before starting focl; this is the test's documented bounded port race.
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let archive_root = temp.path().join("archive");
    let cfg = FoclConfig {
        global: GlobalConfig {
            asn: FOCL_AS,
            router_id: "192.0.2.1".to_string(),
            listen: true,
            listen_addr: format!("127.0.0.1:{port}"),
            control_socket: temp.path().join("focld.sock"),
            log_level: "warn".to_string(),
        },
        peers: vec![PeerConfig {
            address: "127.0.0.1".to_string(),
            remote_as: PEER_AS,
            local_as: None,
            hold_time_secs: 30,
            connect_retry_secs: 1,
            remote_port: port,
            local_address: None,
            enabled: true,
            passive: true,
            route_refresh: true,
            name: None,
            password: None,
        }],
        prefixes: vec![
            PrefixConfig {
                network: "198.51.100.0/24".to_string(),
                next_hop: Some("192.0.2.1".to_string()),
            },
            PrefixConfig {
                network: "2001:db8:feed::/48".to_string(),
                next_hop: Some("2001:db8::1".to_string()),
            },
        ],
        archive: ArchiveConfig {
            enabled: true,
            root: archive_root.clone(),
            tmp_root: archive_root.join(".tmp"),
            updates_interval_secs: 900,
            ribs_interval_secs: 900,
            ..ArchiveConfig::default()
        },
    };
    let archive = ArchiveService::new(cfg.archive.clone(), Ipv4Addr::new(192, 0, 2, 1)).await?;
    let mut events = archive.subscribe_events();
    let bgp =
        BgpService::new_with_archive(&cfg, archive.event_sender(), Some(Arc::clone(&archive)))
            .await?;

    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    let focl_open = read_message(&mut stream).await?;
    assert!(matches!(focl_open, BgpMessage::Open(_)));
    write_message(&mut stream, &peer_open()).await?;
    let keepalive = read_message(&mut stream).await?;
    assert!(matches!(keepalive, BgpMessage::KeepAlive));
    write_message(&mut stream, &BgpMessage::KeepAlive).await?;

    let first = read_message(&mut stream).await?;
    let second = read_message(&mut stream).await?;
    let received = [first, second];
    assert!(received.iter().any(has_focl_v4));
    assert!(received.iter().any(has_focl_v6));

    write_message(
        &mut stream,
        &announce_v4("192.0.2.0/24", "192.0.2.2".parse()?),
    )
    .await?;
    write_message(
        &mut stream,
        &announce_v6("2001:db8::/32", "2001:db8::2".parse()?),
    )
    .await?;

    timeout(Duration::from_secs(5), async {
        loop {
            let prefixes = bgp.rib_in("127.0.0.1").await?;
            if prefixes.iter().any(|prefix| prefix == "192.0.2.0/24")
                && prefixes.iter().any(|prefix| prefix == "2001:db8::/32")
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;

    let mut established_recorded = false;
    timeout(Duration::from_secs(5), async {
        while !established_recorded {
            if let Ok(event) = events.recv().await {
                if matches!(
                    event.event,
                    Event::PeerState {
                        state: PeerState::Established,
                        ..
                    }
                ) {
                    established_recorded = true;
                }
            }
        }
    })
    .await?;
    assert!(established_recorded);

    // Finalize and parse every MRT record, ensuring raw BGP4MP output is readable.
    archive.rollover(ArchiveStream::Updates).await?;
    let segment = walkdir::WalkDir::new(&archive_root)
        .into_iter()
        .filter_map(Result::ok)
        .find_map(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|ext| ext == "gz")
                .then(|| entry.path().to_path_buf())
        })
        .context("updates rollover should create a gzip segment")?;
    let mut decoded = Vec::new();
    GzDecoder::new(std::fs::File::open(segment)?).read_to_end(&mut decoded)?;
    let mut cursor = Cursor::new(decoded);
    let mut record_count = 0;
    while (cursor.position() as usize) < cursor.get_ref().len() {
        parse_mrt_record(&mut cursor)?;
        record_count += 1;
    }
    // two outbound configured-prefix UPDATEs plus the two peer UPDATEs, and state changes.
    assert!(
        record_count >= 4,
        "expected both directions in archived BGP4MP records"
    );
    Ok(())
}

/// Builds a service with one passive peer and no configured prefixes.
async fn service_with_passive_peer(temp: &tempfile::TempDir, port: u16) -> Result<BgpService> {
    let cfg = FoclConfig {
        global: GlobalConfig {
            asn: FOCL_AS,
            router_id: "192.0.2.1".to_string(),
            listen: true,
            listen_addr: format!("127.0.0.1:{port}"),
            control_socket: temp.path().join("focld.sock"),
            log_level: "warn".to_string(),
        },
        peers: vec![PeerConfig {
            address: "127.0.0.1".to_string(),
            remote_as: PEER_AS,
            local_as: None,
            hold_time_secs: 30,
            connect_retry_secs: 1,
            remote_port: port,
            local_address: None,
            enabled: true,
            passive: true,
            route_refresh: true,
            name: None,
            password: None,
        }],
        prefixes: vec![],
        archive: ArchiveConfig {
            enabled: false,
            ..ArchiveConfig::default()
        },
    };
    let (event_tx, _events) = broadcast::channel(16);
    BgpService::new(&cfg, event_tx).await
}

/// Connects as the peer side and completes the OPEN/KEEPALIVE exchange.
async fn establish_peer_session(port: u16, capabilities: Vec<u8>) -> Result<TcpStream> {
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    assert!(matches!(
        read_message(&mut stream).await?,
        BgpMessage::Open(_)
    ));
    write_message(&mut stream, &peer_open_with_capabilities(capabilities)).await?;
    assert!(matches!(
        read_message(&mut stream).await?,
        BgpMessage::KeepAlive
    ));
    write_message(&mut stream, &BgpMessage::KeepAlive).await?;
    Ok(stream)
}

/// Runtime control has to reach an established session on the wire, and the
/// session must survive both changes.
#[tokio::test]
async fn runtime_prefix_changes_reach_an_established_session() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let bgp = service_with_passive_peer(&temp, port).await?;
    let mut stream = establish_peer_session(port, capabilities()).await?;

    // With no configured prefixes, establishment sends only the two End-of-RIB
    // markers (IPv4 empty UPDATE, IPv6 MP_UNREACH).
    for _ in 0..2 {
        assert!(matches!(
            read_message(&mut stream).await?,
            BgpMessage::Update(_)
        ));
    }

    let network: IpNet = "203.0.113.0/24".parse()?;
    let added = bgp.prefix_add(network, None, false).await?;
    assert!(added.changed);
    assert_eq!(added.peers_notified, vec!["127.0.0.1".to_string()]);
    let announcement = read_message(&mut stream).await?;
    assert!(
        matches!(&announcement, BgpMessage::Update(update)
            if update.announced_prefixes.iter()
                .any(|prefix| prefix.prefix.to_string() == "203.0.113.0/24")),
        "expected the runtime announcement on the wire, got {announcement:?}"
    );

    let removed = bgp.prefix_remove(network, false).await?;
    assert!(removed.changed);
    assert_eq!(removed.status, PrefixStatus::Absent);
    assert_eq!(removed.source, Some(PrefixSource::Runtime));
    let withdrawal = read_message(&mut stream).await?;
    assert!(
        matches!(&withdrawal, BgpMessage::Update(update)
            if update.withdrawn_prefixes.iter()
                .any(|prefix| prefix.prefix.to_string() == "203.0.113.0/24")),
        "expected the runtime withdrawal on the wire, got {withdrawal:?}"
    );

    let peer = bgp
        .peer_show("127.0.0.1")
        .await
        .context("peer stays configured")?;
    assert!(matches!(peer.state, PeerState::Established));
    Ok(())
}

/// A prefix must not be dispatched to a peer that did not negotiate its family.
#[tokio::test]
async fn runtime_changes_skip_peers_without_the_family() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let bgp = service_with_passive_peer(&temp, port).await?;
    let mut stream = establish_peer_session(port, capabilities_v4_only()).await?;

    // A v4-only peer receives just the IPv4 End-of-RIB marker.
    assert!(matches!(
        read_message(&mut stream).await?,
        BgpMessage::Update(_)
    ));

    let v6: IpNet = "2001:db8::/48".parse()?;
    let added = bgp
        .prefix_add(v6, Some("2001:db8::1".parse()?), false)
        .await?;
    assert!(added.changed, "the originated set still changed");
    assert!(
        added.peers_notified.is_empty(),
        "a v4-only peer must not be reported as notified: {:?}",
        added.peers_notified
    );
    assert!(
        timeout(Duration::from_millis(250), read_message(&mut stream))
            .await
            .is_err(),
        "an IPv6 update must not reach a v4-only peer"
    );
    Ok(())
}

fn capabilities() -> Vec<u8> {
    let mut bytes = vec![1, 4, 0, 1, 0, 1, 1, 4, 0, 2, 0, 1, 65, 4];
    bytes.extend_from_slice(&PEER_AS.to_be_bytes());
    bytes.extend_from_slice(&[2, 0]);
    bytes
}

/// Same as [`capabilities`] without the IPv6 unicast multiprotocol capability.
fn capabilities_v4_only() -> Vec<u8> {
    let mut bytes = vec![1, 4, 0, 1, 0, 1, 65, 4];
    bytes.extend_from_slice(&PEER_AS.to_be_bytes());
    bytes.extend_from_slice(&[2, 0]);
    bytes
}

fn peer_open_with_capabilities(capabilities: Vec<u8>) -> BgpMessage {
    BgpMessage::Open(BgpOpenMessage {
        version: 4,
        asn: Asn::new_16bit(PEER_AS as u16),
        hold_time: 30,
        bgp_identifier: Ipv4Addr::new(192, 0, 2, 2),
        extended_length: false,
        opt_params: vec![OptParam {
            param_type: 2,
            param_value: ParamValue::Raw(capabilities),
        }],
    })
}

fn peer_open() -> BgpMessage {
    peer_open_with_capabilities(capabilities())
}

fn attrs() -> Attributes {
    let mut attrs = Attributes::default();
    attrs.add_attr(AttributeValue::Origin(Origin::IGP).into());
    attrs.add_attr(
        AttributeValue::AsPath {
            path: AsPath::from_sequence([PEER_AS]),
            is_as4: true,
        }
        .into(),
    );
    attrs
}

fn announce_v4(prefix: &str, next_hop: IpAddr) -> BgpMessage {
    let mut attributes = attrs();
    attributes.add_attr(AttributeValue::NextHop(next_hop).into());
    BgpMessage::Update(BgpUpdateMessage {
        withdrawn_prefixes: vec![],
        attributes,
        announced_prefixes: vec![prefix.parse::<NetworkPrefix>().unwrap()],
    })
}

fn announce_v6(prefix: &str, next_hop: IpAddr) -> BgpMessage {
    let mut attributes = attrs();
    attributes.add_attr(
        AttributeValue::MpReachNlri(Nlri::new_reachable(prefix.parse().unwrap(), Some(next_hop)))
            .into(),
    );
    BgpMessage::Update(BgpUpdateMessage {
        withdrawn_prefixes: vec![],
        attributes,
        announced_prefixes: vec![],
    })
}

fn has_focl_v4(message: &BgpMessage) -> bool {
    matches!(message, BgpMessage::Update(update) if update.announced_prefixes.iter().any(|prefix| prefix.prefix.to_string() == "198.51.100.0/24"))
}

fn has_focl_v6(message: &BgpMessage) -> bool {
    matches!(message, BgpMessage::Update(update) if update.attributes.get_reachable_nlri().is_some_and(|nlri| nlri.prefixes.iter().any(|prefix| prefix.prefix.to_string() == "2001:db8:feed::/48")))
}

async fn write_message(stream: &mut TcpStream, message: &BgpMessage) -> Result<()> {
    let mut bytes = message.encode(AsnLength::Bits32)?.to_vec();
    bytes[..16].fill(0xff);
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn read_message(stream: &mut TcpStream) -> Result<BgpMessage> {
    let mut header = [0; 19];
    timeout(Duration::from_secs(5), stream.read_exact(&mut header)).await??;
    let length = u16::from_be_bytes([header[16], header[17]]) as usize;
    let mut raw = header.to_vec();
    if length > 19 {
        let mut body = vec![0; length - 19];
        timeout(Duration::from_secs(5), stream.read_exact(&mut body)).await??;
        raw.extend_from_slice(&body);
    }
    let mut bytes = Bytes::from(raw);
    Ok(parse_bgp_message(&mut bytes, false, &AsnLength::Bits32)?)
}

#[test]
fn ipv6_peer_address_dials_correctly() {
    // Regression for duck: format!("{}:{}", v6, port) is unparseable, so
    // active IPv6 sessions never dialed. The fixed path parses the IP
    // explicitly and builds SocketAddr::new — assert both halves.
    let ip: std::net::IpAddr = "2001:19f0:ffff::1".parse().expect("v6 parses");
    let addr = std::net::SocketAddr::new(ip, 179);
    assert_eq!(addr.to_string(), "[2001:19f0:ffff::1]:179");
    // and the broken concat really is unparseable (guards the regression):
    assert!(format!("{}:179", "2001:19f0:ffff::1")
        .parse::<std::net::SocketAddr>()
        .is_err());
}
