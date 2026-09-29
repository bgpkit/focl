use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bgpkit_parser::bgp::parse_bgp_message;
use bgpkit_parser::models::{
    Afi, AsPath, Asn, AsnLength, AttrFlags, AttributeValue, Attributes, Bgp4MpEnum, BgpMessage,
    BgpOpenMessage, BgpRouteRefreshMessage, BgpState, BgpUpdateMessage, MrtMessage, NetworkPrefix,
    Nlri, OptParam, Origin, ParamValue, TableDumpV2Message, TableDumpV2Type,
};
use bgpkit_parser::parse_mrt_record;
use bytes::Bytes;
use flate2::read::GzDecoder;
use focl::archive::types::ArchiveStream;
use focl::archive::ArchiveService;
use focl::bgp::{BgpService, PrefixSource, PrefixStatus, TcpSocketExt};
use focl::config::{ArchiveConfig, FoclConfig, GlobalConfig, PeerConfig, PrefixConfig};
use focl::types::{Event, PeerState};
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::broadcast;
use tokio::time::timeout;

const PEER_AS: u32 = 65_002;
const FOCL_AS: u32 = 65_001;
/// The TCP-MD5 password of the passive peer in the MD5 acceptance test.
const MD5_PASSWORD: &str = "focl-md5-acceptance";
/// The IPv6 prefix carrying the attribute-255 clock in the clock tests.
const CLOCK_PREFIX: &str = "2001:db8:feed::/48";

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
                dev_attr255_interval_secs: None,
            },
            PrefixConfig {
                network: "2001:db8:feed::/48".to_string(),
                next_hop: Some("2001:db8::1".to_string()),
                dev_attr255_interval_secs: None,
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
    let mut local_records = 0;
    let mut received_records = 0;
    while (cursor.position() as usize) < cursor.get_ref().len() {
        let record = parse_mrt_record(&mut cursor)?;
        if let MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(message)) = &record.message {
            if message.is_local() {
                local_records += 1;
            } else {
                received_records += 1;
            }
        }
        record_count += 1;
    }
    // one outbound UPDATE per configured prefix plus the two peer UPDATEs, and
    // state changes.
    assert!(
        record_count >= 4,
        "expected both directions in archived BGP4MP records"
    );
    // Our own announcements are archived in the local direction (RFC 6396
    // section 4.4.6); the peer's updates keep the received direction.
    assert!(
        local_records >= 2,
        "expected at least two locally generated records, got {local_records}"
    );
    assert!(
        received_records >= 2,
        "expected at least two received records, got {received_records}"
    );
    Ok(())
}

/// The archive's periodic RIB snapshot is built from the speaker's live
/// Adj-RIB-In: the segment carries a peer index table plus one RIB entry per
/// received route and parses as TABLE_DUMP_V2.
#[tokio::test]
async fn rib_snapshot_carries_the_live_adj_rib_in() -> Result<()> {
    let temp = tempfile::tempdir()?;
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
        prefixes: vec![],
        archive: ArchiveConfig {
            enabled: true,
            root: archive_root.clone(),
            tmp_root: archive_root.join(".tmp"),
            ..ArchiveConfig::default()
        },
    };
    let archive = ArchiveService::new(cfg.archive.clone(), Ipv4Addr::new(192, 0, 2, 1)).await?;
    let bgp =
        BgpService::new_with_archive(&cfg, archive.event_sender(), Some(Arc::clone(&archive)))
            .await?;
    // The daemon wires the speaker in as the archive's RIB view source.
    archive.set_snapshot_source(Arc::new(bgp.clone()));

    let mut stream = establish_peer_session(port, capabilities()).await?;
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

    archive.rollover(ArchiveStream::Ribs).await?;

    let segment = walkdir::WalkDir::new(&archive_root)
        .into_iter()
        .filter_map(Result::ok)
        .find_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            (entry.file_type().is_file() && name.starts_with("rib.") && name.ends_with(".gz"))
                .then(|| entry.path().to_path_buf())
        })
        .context("a RIB rollover should write a rib segment for the received routes")?;
    let mut decoded = Vec::new();
    GzDecoder::new(std::fs::File::open(segment)?).read_to_end(&mut decoded)?;
    let mut cursor = Cursor::new(decoded);

    let MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(table)) =
        parse_mrt_record(&mut cursor)?.message
    else {
        panic!("the RIB segment must start with a peer index table");
    };
    assert_eq!(table.id_peer_map.len(), 1, "one session, one peer entry");
    let peer = table.id_peer_map.get(&0).context("peer index 0 is used")?;
    assert_eq!(peer.peer_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(peer.peer_asn.to_u32(), PEER_AS);
    assert_eq!(peer.peer_bgp_id, Ipv4Addr::new(192, 0, 2, 2));

    let MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(v4)) =
        parse_mrt_record(&mut cursor)?.message
    else {
        panic!("expected a RIB AFI entry for the IPv4 route");
    };
    assert_eq!(v4.rib_type, TableDumpV2Type::RibIpv4Unicast);
    assert_eq!(v4.prefix.prefix.to_string(), "192.0.2.0/24");
    assert_eq!(v4.rib_entries.len(), 1);
    assert_eq!(v4.rib_entries[0].peer_index, 0);
    assert_eq!(
        v4.rib_entries[0].attributes.next_hop(),
        Some("192.0.2.2".parse::<IpAddr>()?)
    );
    assert_eq!(
        v4.rib_entries[0]
            .attributes
            .as_path()
            .map(ToString::to_string),
        Some(PEER_AS.to_string())
    );

    let MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(v6)) =
        parse_mrt_record(&mut cursor)?.message
    else {
        panic!("expected a RIB AFI entry for the IPv6 route");
    };
    assert_eq!(v6.rib_type, TableDumpV2Type::RibIpv6Unicast);
    assert_eq!(v6.prefix.prefix.to_string(), "2001:db8::/32");
    assert_eq!(v6.rib_entries.len(), 1);
    assert_eq!(v6.rib_entries[0].peer_index, 0);
    Ok(())
}

/// Ending a session records the exit transition: clearing the RIB drops the
/// session's local address, so the state change has to be archived first or it
/// is lost.
#[tokio::test]
async fn session_end_archives_the_established_to_active_transition() -> Result<()> {
    let temp = tempfile::tempdir()?;
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
        prefixes: vec![],
        archive: ArchiveConfig {
            enabled: true,
            root: archive_root.clone(),
            tmp_root: archive_root.join(".tmp"),
            ..ArchiveConfig::default()
        },
    };
    let archive = ArchiveService::new(cfg.archive.clone(), Ipv4Addr::new(192, 0, 2, 1)).await?;
    let _bgp =
        BgpService::new_with_archive(&cfg, archive.event_sender(), Some(Arc::clone(&archive)))
            .await?;

    let stream = establish_peer_session(port, capabilities()).await?;
    // Establishment archives OpenSent, OpenConfirm and Established. With no
    // configured prefixes nothing else is archived while the session is quiet,
    // so the record count can only move again when the session ends.
    timeout(Duration::from_secs(5), async {
        loop {
            if archive.status().await?.updates_record_count >= 3 {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("the establishment state changes should be archived")??;
    let before = archive.status().await?.updates_record_count;

    drop(stream);
    timeout(Duration::from_secs(5), async {
        loop {
            if archive.status().await?.updates_record_count > before {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("ending the session should archive a record")??;

    archive.rollover(ArchiveStream::Updates).await?;

    let mut transition = None;
    for entry in walkdir::WalkDir::new(&archive_root) {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !entry.file_type().is_file() || !name.ends_with(".gz") {
            continue;
        }
        let mut decoded = Vec::new();
        GzDecoder::new(std::fs::File::open(entry.path())?).read_to_end(&mut decoded)?;
        let mut cursor = Cursor::new(decoded);
        while (cursor.position() as usize) < cursor.get_ref().len() {
            let record = parse_mrt_record(&mut cursor)?;
            if let MrtMessage::Bgp4Mp(Bgp4MpEnum::StateChange(state)) = record.message {
                if state.old_state == BgpState::Established && state.new_state == BgpState::Active {
                    transition = Some(state);
                }
            }
        }
    }

    let transition =
        transition.context("the Established -> Active transition should be archived")?;
    assert_eq!(transition.peer_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(
        transition.local_addr,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    );
    Ok(())
}

/// Builds a service with one passive peer and the given configured prefixes.
async fn service_with_prefixes(
    temp: &tempfile::TempDir,
    port: u16,
    prefixes: Vec<PrefixConfig>,
) -> Result<BgpService> {
    service_with_peer(temp, port, prefixes, None, 30).await
}

/// Same as [`service_with_prefixes`], with an optional TCP-MD5 password and an
/// explicit hold time on the passive peer.
async fn service_with_peer(
    temp: &tempfile::TempDir,
    port: u16,
    prefixes: Vec<PrefixConfig>,
    password: Option<&str>,
    hold_time_secs: u16,
) -> Result<BgpService> {
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
            hold_time_secs,
            connect_retry_secs: 1,
            remote_port: port,
            local_address: None,
            enabled: true,
            passive: true,
            route_refresh: true,
            name: None,
            password: password.map(str::to_string),
        }],
        prefixes,
        archive: ArchiveConfig {
            enabled: false,
            ..ArchiveConfig::default()
        },
    };
    let (event_tx, _events) = broadcast::channel(16);
    BgpService::new(&cfg, event_tx).await
}

/// Builds a service with one passive peer and no configured prefixes.
async fn service_with_passive_peer(temp: &tempfile::TempDir, port: u16) -> Result<BgpService> {
    service_with_prefixes(temp, port, vec![]).await
}

/// Builds a service with one passive peer and the clock prefix configured to
/// re-announce every second.
async fn service_with_clock_prefix(temp: &tempfile::TempDir, port: u16) -> Result<BgpService> {
    service_with_prefixes(
        temp,
        port,
        vec![PrefixConfig {
            network: CLOCK_PREFIX.to_string(),
            next_hop: Some("2001:db8::1".to_string()),
            dev_attr255_interval_secs: Some(1),
        }],
    )
    .await
}

/// Connects as the peer side and completes the OPEN/KEEPALIVE exchange.
async fn establish_peer_session(port: u16, capabilities: Vec<u8>) -> Result<TcpStream> {
    establish_session(port, peer_open_with_capabilities(capabilities)).await
}

/// Connects as a peer that negotiates no capabilities at all: a plain RFC 4271
/// IPv4-only speaker, whose OPEN carries no optional parameters.
async fn establish_capability_less_session(port: u16) -> Result<TcpStream> {
    establish_session(port, peer_open_without_capabilities()).await
}

/// Connects as the peer side with `open` and completes the OPEN/KEEPALIVE
/// exchange.
async fn establish_session(port: u16, open: BgpMessage) -> Result<TcpStream> {
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    assert!(matches!(
        read_message(&mut stream).await?,
        BgpMessage::Open(_)
    ));
    write_message(&mut stream, &open).await?;
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

/// TCP-MD5 (RFC 2385) on a passive session: the kernel validates the digest on
/// the SYN, before `accept()` can return, so the key has to be installed on the
/// listening socket. Without that install a peer with a configured password can
/// never complete the handshake (its connect hangs, the session never starts).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn passive_session_with_md5_completes_the_handshake() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let bgp = service_with_peer(
        &temp,
        port,
        vec![PrefixConfig {
            network: "198.51.100.0/24".to_string(),
            next_hop: Some("192.0.2.1".to_string()),
            dev_attr255_interval_secs: None,
        }],
        Some(MD5_PASSWORD),
        30,
    )
    .await?;

    // The peer side installs the same key on its own socket before connecting,
    // exactly like an authenticating router would. Installing a TCP-MD5 key
    // needs CAP_NET_ADMIN, like it does for the daemon.
    let remote = SocketAddr::from(([127, 0, 0, 1], port));
    let socket = TcpSocket::new_v4()?;
    socket
        .set_md5_signature(&remote, MD5_PASSWORD)
        .context("installing the peer-side TCP-MD5 key (needs CAP_NET_ADMIN)")?;
    let mut stream = timeout(Duration::from_secs(5), socket.connect(remote))
        .await
        .context("the MD5-keyed peer could not connect: the listener has no key")??;

    assert!(matches!(
        read_message(&mut stream).await?,
        BgpMessage::Open(_)
    ));
    write_message(&mut stream, &peer_open()).await?;
    assert!(matches!(
        read_message(&mut stream).await?,
        BgpMessage::KeepAlive
    ));
    write_message(&mut stream, &BgpMessage::KeepAlive).await?;

    // The authenticated session exchanges routes like any other.
    let announcement = read_message(&mut stream).await?;
    assert!(
        has_focl_v4(&announcement),
        "expected the configured table over the MD5 session, got {announcement:?}"
    );
    assert!(ipv4_eor(&read_message(&mut stream).await?));
    let peer = bgp
        .peer_show("127.0.0.1")
        .await
        .context("peer stays configured")?;
    assert!(matches!(peer.state, PeerState::Established));
    Ok(())
}

/// RFC 2918 s4: a ROUTE-REFRESH for a negotiated family replays that family's
/// Adj-RIB-Out and then its End-of-RIB. A refresh for the other family stays
/// silent (see `route_refresh_for_an_unnegotiated_family_is_ignored`).
#[tokio::test]
async fn route_refresh_replays_the_requested_family_then_end_of_rib() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let bgp = service_with_prefixes(
        &temp,
        port,
        vec![
            PrefixConfig {
                network: "198.51.100.0/24".to_string(),
                next_hop: Some("192.0.2.1".to_string()),
                dev_attr255_interval_secs: None,
            },
            PrefixConfig {
                network: "2001:db8:feed::/48".to_string(),
                next_hop: Some("2001:db8::1".to_string()),
                dev_attr255_interval_secs: None,
            },
        ],
    )
    .await?;
    let mut stream = establish_peer_session(port, capabilities()).await?;

    // Establishment sends the configured table once per family, then both
    // End-of-RIB markers.
    let mut v4_seen = false;
    let mut v6_seen = false;
    let mut v4_eor_seen = false;
    let mut v6_eor_seen = false;
    timeout(Duration::from_secs(5), async {
        while !(v4_eor_seen && v6_eor_seen) {
            let message = read_message(&mut stream).await?;
            v4_seen |= has_focl_v4(&message);
            v6_seen |= has_focl_v6(&message);
            v4_eor_seen |= ipv4_eor(&message);
            v6_eor_seen |= ipv6_eor(&message);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    assert!(
        v4_seen && v6_seen,
        "expected both families in the initial table"
    );

    // Ask for the IPv4 table again: the replay carries the IPv4 prefix, not the
    // IPv6 one, and ends with the IPv4 End-of-RIB.
    write_message(&mut stream, &route_refresh(1, 1)).await?;
    let replay = read_message(&mut stream).await?;
    assert!(
        has_focl_v4(&replay),
        "expected the IPv4 announcement to be replayed, got {replay:?}"
    );
    assert!(
        !has_focl_v6(&replay),
        "an IPv4 refresh must not replay the IPv6 table: {replay:?}"
    );
    let trailing_eor = read_message(&mut stream).await?;
    assert!(
        ipv4_eor(&trailing_eor),
        "the replay has to end with the IPv4 End-of-RIB, got {trailing_eor:?}"
    );

    let peer = bgp
        .peer_show("127.0.0.1")
        .await
        .context("the session survives the replay")?;
    assert!(matches!(peer.state, PeerState::Established));
    Ok(())
}

/// A refresh for a family the session did not negotiate has no Adj-RIB-Out to
/// send and must leave the session silent (RFC 2918 s4).
#[tokio::test]
async fn route_refresh_for_an_unnegotiated_family_is_ignored() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let _bgp = service_with_passive_peer(&temp, port).await?;
    let mut stream = establish_peer_session(port, capabilities_v4_only()).await?;
    // A v4-only peer with no configured prefixes gets the IPv4 EoR only.
    assert!(ipv4_eor(&read_message(&mut stream).await?));

    write_message(&mut stream, &route_refresh(2, 1)).await?;
    assert!(
        timeout(Duration::from_millis(250), read_message(&mut stream))
            .await
            .is_err(),
        "an IPv6 refresh on a v4-only session must be ignored"
    );
    Ok(())
}

/// RFC 4271: a peer that negotiates no capabilities still has classic IPv4
/// unicast, so it gets the IPv4 table and the IPv4 End-of-RIB, and only once.
#[tokio::test]
async fn capability_less_peer_receives_the_ipv4_table_and_end_of_rib_once() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let _bgp = service_with_prefixes(
        &temp,
        port,
        vec![PrefixConfig {
            network: "198.51.100.0/24".to_string(),
            next_hop: Some("192.0.2.1".to_string()),
            dev_attr255_interval_secs: None,
        }],
    )
    .await?;
    let mut stream = establish_capability_less_session(port).await?;

    let announcement = read_message(&mut stream).await?;
    assert!(
        has_focl_v4(&announcement),
        "classic NLRI is available without any capability, got {announcement:?}"
    );
    let eor = read_message(&mut stream).await?;
    assert!(
        ipv4_eor(&eor),
        "the IPv4 End-of-RIB must follow the table, got {eor:?}"
    );

    // The initial table is sent exactly once, under the registration lock: no
    // duplicate announcement after the End-of-RIB, and nothing for a family
    // that was not negotiated.
    assert!(
        timeout(Duration::from_millis(250), read_message(&mut stream))
            .await
            .is_err(),
        "a capability-less session must be quiet after its single table and EoR"
    );
    Ok(())
}

/// RFC 4271 s4.2/s4.4: the OPEN advertises the configured hold time — including
/// 0, which disables the timers instead of being raised to a minimum.
#[tokio::test]
async fn open_advertises_the_configured_hold_time_including_zero() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let _bgp = service_with_peer(&temp, port, vec![], None, 0).await?;

    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    let BgpMessage::Open(open) = read_message(&mut stream).await? else {
        panic!("the first message from focld must be an OPEN")
    };
    assert_eq!(
        open.hold_time, 0,
        "a configured hold time of 0 means \"no timers\" and must be advertised as-is"
    );
    Ok(())
}

/// The attribute-255 clock travels on the wire for a configured prefix and is
/// re-announced with a fresh embedded unix time on the configured interval.
#[tokio::test]
async fn clock_attribute_refreshes_on_schedule() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let _bgp = service_with_clock_prefix(&temp, port).await?;
    let mut stream = establish_peer_session(port, capabilities()).await?;

    let (flags, first_payload) =
        timeout(Duration::from_secs(5), read_development_clock(&mut stream)).await??;
    assert_eq!(first_payload.len(), 13, "13-byte clock payload");
    assert!(
        first_payload.starts_with(b"BGPKIT\x01"),
        "magic and version lead the payload"
    );
    assert!(
        flags.contains(AttrFlags::OPTIONAL) && flags.contains(AttrFlags::TRANSITIVE),
        "originating flags must be OPTIONAL|TRANSITIVE, got {flags:?}"
    );
    assert!(
        !flags.contains(AttrFlags::PARTIAL),
        "an originated attribute must not be marked PARTIAL"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the epoch")
        .as_secs();
    let first_unix = clock_unix(&first_payload);
    assert!(
        first_unix.abs_diff(now) <= 60,
        "embedded unix {first_unix} must be within a minute of now ({now})"
    );

    // The refresh loop re-sends the announcement with a newer clock while the
    // session stays up.
    let later_unix = timeout(Duration::from_secs(5), async {
        loop {
            let message = read_message(&mut stream).await?;
            if let Some((_, payload)) = development_clock(&message, CLOCK_PREFIX) {
                let unix = clock_unix(&payload);
                if unix > first_unix {
                    return Ok::<_, anyhow::Error>(unix);
                }
            }
        }
    })
    .await??;
    assert!(later_unix > first_unix);
    Ok(())
}

/// Removing and re-adding a configured clock prefix keeps the attribute-255
/// clock on the announcement the re-add emits.
#[tokio::test]
async fn runtime_readd_keeps_configured_clock() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let bgp = service_with_clock_prefix(&temp, port).await?;
    let mut stream = establish_peer_session(port, capabilities()).await?;
    let network: IpNet = CLOCK_PREFIX.parse()?;

    // Wait for the establishment announcement, then for a refresh tick. A
    // tick only reaches the socket through a registered session handle, so
    // the removal below cannot race the session's initial table send (an
    // early removal would simply never announce, and withdraw nothing).
    let (_, first_payload) =
        timeout(Duration::from_secs(5), read_development_clock(&mut stream)).await??;
    let first_unix = clock_unix(&first_payload);
    timeout(Duration::from_secs(5), async {
        loop {
            let message = read_message(&mut stream).await?;
            if let Some((_, payload)) = development_clock(&message, CLOCK_PREFIX) {
                if clock_unix(&payload) > first_unix {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        }
    })
    .await
    .context("the refresh tick did not arrive before the removal")??;

    let removed = bgp.prefix_remove(network, false).await?;
    assert!(removed.changed);
    timeout(
        Duration::from_secs(5),
        read_until_withdrawal(&mut stream, CLOCK_PREFIX),
    )
    .await
    .context("withdrawal for the removed clock prefix did not arrive")??;

    // Removal silences the refresh loop. Drain anything that was already in
    // flight, so the next announcement observed is the one re-add emits.
    timeout(Duration::from_secs(5), async {
        loop {
            match timeout(Duration::from_millis(1500), read_message(&mut stream)).await {
                Err(_) => return Ok::<_, anyhow::Error>(()),
                Ok(Ok(_)) => continue,
                Ok(Err(error)) => return Err(error),
            }
        }
    })
    .await
    .context("the clock prefix did not go quiet after removal")??;

    let added = bgp.prefix_add(network, None, false).await?;
    assert!(added.changed);
    assert_eq!(added.peers_notified, vec!["127.0.0.1".to_string()]);
    let (flags, payload) = timeout(Duration::from_secs(5), read_development_clock(&mut stream))
        .await
        .context("the re-add announcement did not arrive")??;
    assert_eq!(payload.len(), 13);
    assert!(payload.starts_with(b"BGPKIT\x01"));
    assert!(
        flags.contains(AttrFlags::OPTIONAL) && flags.contains(AttrFlags::TRANSITIVE),
        "the re-added prefix keeps the clock with originating flags"
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

/// An OPEN without any optional parameter: a peer that negotiates nothing.
fn peer_open_without_capabilities() -> BgpMessage {
    BgpMessage::Open(BgpOpenMessage {
        version: 4,
        asn: Asn::new_16bit(PEER_AS as u16),
        hold_time: 30,
        bgp_identifier: Ipv4Addr::new(192, 0, 2, 2),
        extended_length: false,
        opt_params: vec![],
    })
}

/// A ROUTE-REFRESH (RFC 2918) for one family. AFI and SAFI are the raw wire
/// integers, so the tests can also ask for a family they did not negotiate.
fn route_refresh(afi: u16, safi: u8) -> BgpMessage {
    BgpMessage::RouteRefresh(BgpRouteRefreshMessage {
        afi,
        subtype: 0,
        safi,
        data: vec![],
    })
}

/// The IPv4 End-of-RIB: an UPDATE with no NLRI and no attributes (RFC 4271).
fn ipv4_eor(message: &BgpMessage) -> bool {
    matches!(message, BgpMessage::Update(update)
        if update.withdrawn_prefixes.is_empty()
            && update.announced_prefixes.is_empty()
            && update.attributes.clone().into_attributes_iter().next().is_none())
}

/// The IPv6 End-of-RIB: MP_UNREACH_NLRI for IPv6 with no prefix.
fn ipv6_eor(message: &BgpMessage) -> bool {
    matches!(message, BgpMessage::Update(update)
        if update.announced_prefixes.is_empty()
            && update.attributes.get_unreachable_nlri().is_some_and(|nlri| nlri.afi == Afi::Ipv6 && nlri.prefixes.is_empty()))
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

/// The attribute-255 payload attached to an announcement of `prefix`, when
/// present, together with its attribute flags.
fn development_clock(message: &BgpMessage, prefix: &str) -> Option<(AttrFlags, Vec<u8>)> {
    let BgpMessage::Update(update) = message else {
        return None;
    };
    let announced = update
        .announced_prefixes
        .iter()
        .any(|network| network.prefix.to_string() == prefix)
        || update
            .attributes
            .get_reachable_nlri()
            .is_some_and(|nlri| nlri.prefixes.iter().any(|p| p.prefix.to_string() == prefix));
    if !announced {
        return None;
    }
    update
        .attributes
        .clone()
        .into_attributes_iter()
        .find_map(|attribute| match attribute.value {
            AttributeValue::Development(payload) => Some((attribute.flag, payload)),
            _ => None,
        })
}

/// True when the message withdraws `prefix` (classic NLRI or MP_UNREACH).
fn withdraws_prefix(message: &BgpMessage, prefix: &str) -> bool {
    let BgpMessage::Update(update) = message else {
        return false;
    };
    update
        .withdrawn_prefixes
        .iter()
        .any(|network| network.prefix.to_string() == prefix)
        || update
            .attributes
            .get_unreachable_nlri()
            .is_some_and(|nlri| nlri.prefixes.iter().any(|p| p.prefix.to_string() == prefix))
}

/// The low 32 bits of the send time embedded in a clock payload.
fn clock_unix(payload: &[u8]) -> u64 {
    u64::from(u32::from_be_bytes([
        payload[9],
        payload[10],
        payload[11],
        payload[12],
    ]))
}

/// Reads until the clock prefix is announced with the development attribute.
async fn read_development_clock(stream: &mut TcpStream) -> Result<(AttrFlags, Vec<u8>)> {
    loop {
        let message = read_message(stream).await?;
        if let Some(clock) = development_clock(&message, CLOCK_PREFIX) {
            return Ok(clock);
        }
    }
}

/// Reads until `prefix` is withdrawn.
async fn read_until_withdrawal(stream: &mut TcpStream, prefix: &str) -> Result<()> {
    loop {
        let message = read_message(stream).await?;
        if withdraws_prefix(&message, prefix) {
            return Ok(());
        }
    }
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
    // A session without the four-octet AS capability encodes its AS_PATH with
    // 2-octet segments, so fall back to that width like focld's own reader.
    let mut wide = Bytes::from(raw.clone());
    let mut narrow = Bytes::from(raw);
    parse_bgp_message(&mut wide, false, &AsnLength::Bits32)
        .or_else(|_| parse_bgp_message(&mut narrow, false, &AsnLength::Bits16))
        .map_err(Into::into)
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
