//! The exporting side of BMP: a dialer, a bounded queue, and a liveness timer.
//!
//! The station never dials focl, so this task owns the connection and every failure mode that
//! comes with it. Three decisions are worth stating, because the obvious alternative loses data
//! without saying so:
//!
//! - **The queue never blocks a BGP session.** Session loops hand frames over with `try_send`; a
//!   full queue marks the connection as lagging and drops it. A station that cannot keep up
//!   therefore sees a session end and a fresh one begin, which its archive records as a gap, while
//!   a blocking send would stall a peer's session and hide the problem in the daemon instead.
//! - **A reconnect re-announces the peers it can still see.** The exporter remembers the Peer Up
//!   frame of every live peer, so a new connection starts with Initiation plus those Peer Ups and
//!   resumes from the next frame. focl does not keep a peer's raw initial table, so the outage
//!   window is a hole the station must be able to see rather than one this code can paper over.
//! - **Statistics Reports are the heartbeat.** One goes out per live peer on the configured timer
//!   even when nothing else happens: BMP has no keepalive, and without it a quiet daemon and a
//!   dead socket look identical to the station.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::debug;

use crate::bmp::wire::{self, PeerHeader};

/// How many frames may be waiting for the station before the exporter gives up on the connection.
/// A full BGP table arrives as a burst of roughly a million PDUs, so the default is sized to absorb
/// one table without turning a slow station into a broken session.
pub const DEFAULT_QUEUE: usize = 65_536;

/// How often a Statistics Report is sent per live peer when nothing else is.
pub const DEFAULT_STATS_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct BmpExportSettings {
    pub station: String,
    pub sys_name: String,
    pub sys_descr: String,
    pub stats_interval_secs: u64,
    /// Peer names to export. Empty means every peer that comes up.
    pub peers: Vec<String>,
    pub queue: usize,
}

impl BmpExportSettings {
    fn exports(&self, key: &str) -> bool {
        self.peers.is_empty() || self.peers.iter().any(|name| name == key)
    }
}

/// What a monitored peer looks like to the station, kept so a reconnect can re-announce it.
#[derive(Debug, Clone)]
struct LivePeer {
    peer: PeerHeader,
    local_ip: IpAddr,
    local_port: u16,
    remote_port: u16,
    sent_open: Vec<u8>,
    received_open: Vec<u8>,
}

#[derive(Debug)]
enum Item {
    Up {
        key: String,
        live: LivePeer,
    },
    Frame {
        key: String,
        pdu: Vec<u8>,
        at_micros: i64,
    },
    Down {
        key: String,
        peer: PeerHeader,
        reason: u8,
        at_micros: i64,
    },
}

/// The handle session loops hold. Every method is non-blocking: the queue is the only shared
/// state, and a failure is reported by dropping the connection, never by stalling a session.
#[derive(Clone)]
pub struct ExportHandle {
    tx: mpsc::Sender<Item>,
    live: std::sync::Arc<std::sync::Mutex<HashMap<String, LivePeer>>>,
    settings: std::sync::Arc<BmpExportSettings>,
    lagging: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for ExportHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportHandle")
            .field("station", &self.settings.station)
            .finish_non_exhaustive()
    }
}

impl ExportHandle {
    /// Whether this peer is meant to be exported at all.
    pub fn exports(&self, key: &str) -> bool {
        self.settings.exports(key)
    }

    /// Announces a peer that just reached Established.
    #[allow(clippy::too_many_arguments)]
    pub fn peer_up(
        &self,
        key: &str,
        peer: PeerHeader,
        local_ip: IpAddr,
        local_port: u16,
        remote_port: u16,
        sent_open: Vec<u8>,
        received_open: Vec<u8>,
    ) {
        if !self.exports(key) {
            return;
        }
        let live = LivePeer {
            peer,
            local_ip,
            local_port,
            remote_port,
            sent_open,
            received_open,
        };
        // The map is what a reconnect replays from, so it is updated even if the queue is full.
        self.with_live(|map| {
            map.insert(key.to_string(), live.clone());
        });
        self.offer(Item::Up {
            key: key.to_string(),
            live,
        });
    }

    /// Forwards one inbound UPDATE exactly as it arrived.
    pub fn frame(&self, key: &str, pdu: &[u8], at_micros: i64) {
        if !self.exports(key) {
            return;
        }
        self.offer(Item::Frame {
            key: key.to_string(),
            pdu: pdu.to_vec(),
            at_micros,
        });
    }

    /// Closes a peer that is no longer established. The header travels with the item: the peer is
    /// removed from the live map here, and a station that received a Peer Down with another peer's
    /// identity would corrupt the archive rather than just lose a frame.
    pub fn peer_down(&self, key: &str, reason: u8, at_micros: i64) {
        if !self.exports(key) {
            return;
        }
        let peer = self
            .with_live(|map| map.remove(key).map(|live| live.peer))
            .flatten();
        let Some(peer) = peer else {
            return;
        };
        self.offer(Item::Down {
            key: key.to_string(),
            peer,
            reason,
            at_micros,
        });
    }

    /// Number of peers the exporter currently believes it should be describing.
    pub fn live_peers(&self) -> usize {
        self.with_live(|map| map.len()).unwrap_or_default()
    }

    fn with_live<T>(&self, f: impl FnOnce(&mut HashMap<String, LivePeer>) -> T) -> Option<T> {
        let mut guard = self.live.lock().ok()?;
        Some(f(&mut guard))
    }

    fn offer(&self, item: Item) {
        if self.tx.try_send(item).is_err() {
            // Either the task is gone or it cannot keep up. Both end the connection: a dropped
            // frame would silently corrupt the station's table, so the honest outcome is a session
            // break the archive can record.
            self.lagging
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

pub struct BmpExporter;

impl BmpExporter {
    /// Spawns the exporting task and returns the handle session loops use.
    pub fn spawn(settings: BmpExportSettings) -> Result<ExportHandle> {
        let station: SocketAddr = settings
            .station
            .parse()
            .with_context(|| format!("bmp station {:?} is not host:port", settings.station))?;
        let (tx, rx) = mpsc::channel(settings.queue.max(1));
        let live: std::sync::Arc<std::sync::Mutex<HashMap<String, LivePeer>>> =
            std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let lagging = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let settings = std::sync::Arc::new(settings);
        let handle = ExportHandle {
            tx,
            live: live.clone(),
            settings: settings.clone(),
            lagging: lagging.clone(),
        };
        tokio::spawn(async move { run(station, settings, live, lagging, rx).await });
        Ok(handle)
    }
}

async fn run(
    station: SocketAddr,
    settings: std::sync::Arc<BmpExportSettings>,
    live: std::sync::Arc<std::sync::Mutex<HashMap<String, LivePeer>>>,
    lagging: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mut rx: mpsc::Receiver<Item>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match TcpStream::connect(station).await {
            Ok(mut stream) => {
                backoff = Duration::from_secs(1);
                debug!(%station, "bmp: connected");
                if let Err(error) = pump(&mut stream, &settings, &live, &lagging, &mut rx).await {
                    debug!(%station, %error, "bmp: session ended");
                }
            }
            Err(error) => {
                debug!(%station, %error, "bmp: connect failed");
            }
        }
        // Anything still queued describes a connection the station has already closed; replaying it
        // into the next one would file those frames under the wrong session.
        while rx.try_recv().is_ok() {}
        if rx.is_closed() {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn pump(
    stream: &mut TcpStream,
    settings: &BmpExportSettings,
    live: &std::sync::Mutex<HashMap<String, LivePeer>>,
    lagging: &std::sync::atomic::AtomicBool,
    rx: &mut mpsc::Receiver<Item>,
) -> Result<()> {
    // Peers announced on this connection, with the header each one needs.
    let mut announced: HashMap<String, PeerHeader> = HashMap::new();
    write_frame(
        stream,
        &wire::initiation(&settings.sys_name, &settings.sys_descr),
    )
    .await?;

    // Peers that were already up when this connection started are announced first: their frames
    // are already in flight on the queue and a station cannot apply a frame to an unknown peer.
    let snapshot: Vec<(String, LivePeer)> = {
        let guard = live
            .lock()
            .map_err(|_| anyhow::anyhow!("bmp live-peer map poisoned"))?;
        let mut entries: Vec<(String, LivePeer)> = guard
            .iter()
            .map(|(key, peer)| (key.clone(), peer.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    };
    for (key, peer) in snapshot {
        announce(stream, &peer).await?;
        announced.insert(key, peer.peer);
    }

    let stats_interval = Duration::from_secs(settings.stats_interval_secs.max(1));
    loop {
        if lagging.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(anyhow::anyhow!(
                "bmp queue overflowed; dropping the session so the station records the gap"
            ));
        }
        match tokio::time::timeout(stats_interval, rx.recv()).await {
            Ok(Some(Item::Up { key, live })) => {
                if announced.contains_key(&key) {
                    continue;
                }
                announce(stream, &live).await?;
                announced.insert(key, live.peer);
            }
            Ok(Some(Item::Down {
                key,
                peer,
                reason,
                at_micros,
            })) => {
                if announced.remove(&key).is_none() {
                    continue;
                }
                write_frame(stream, &wire::peer_down(&peer, reason, at_micros)).await?;
            }
            Ok(Some(Item::Frame {
                key,
                pdu,
                at_micros,
            })) => {
                let Some(header) = announced.get(&key) else {
                    continue;
                };
                write_frame(stream, &wire::route_monitoring(header, &pdu, at_micros)).await?;
            }
            Ok(None) => return Ok(()),
            Err(_) => {
                // Nothing to send this interval, so say we are alive.
                let at = wire::now_micros();
                let headers: Vec<PeerHeader> = {
                    let mut ordered: Vec<(String, PeerHeader)> = announced
                        .iter()
                        .map(|(key, peer)| (key.clone(), peer.clone()))
                        .collect();
                    ordered.sort_by(|a, b| a.0.cmp(&b.0));
                    ordered.into_iter().map(|(_, peer)| peer).collect()
                };
                for header in headers {
                    write_frame(stream, &wire::statistics_report(&header, at)).await?;
                }
            }
        }
    }
}

async fn announce(stream: &mut TcpStream, peer: &LivePeer) -> Result<()> {
    let at = wire::now_micros();
    let frame = wire::peer_up(
        &peer.peer,
        peer.local_ip,
        peer.local_port,
        peer.remote_port,
        &peer.sent_open,
        &peer.received_open,
        at,
    );
    write_frame(stream, &frame).await
}

async fn write_frame(stream: &mut TcpStream, frame: &[u8]) -> Result<()> {
    stream.write_all(frame).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use bgpkit_parser::bmp::messages::BmpMessageBody;
    use bgpkit_parser::parse_bmp_msg;
    use bytes::Bytes;
    use tokio::io::AsyncReadExt;

    fn settings(station: &str) -> BmpExportSettings {
        BmpExportSettings {
            station: station.to_string(),
            sys_name: "focl-test".to_string(),
            sys_descr: "focl test".to_string(),
            stats_interval_secs: 60,
            peers: vec![],
            queue: 64,
        }
    }

    fn open_pdu(asn: u32) -> Vec<u8> {
        use bgpkit_parser::models::{AsnLength, BgpMessage, BgpOpenMessage};
        BgpMessage::Open(BgpOpenMessage {
            version: 4,
            asn: asn.into(),
            hold_time: 90,
            bgp_identifier: "192.0.2.1".parse().unwrap(),
            extended_length: false,
            opt_params: vec![],
        })
        .encode(AsnLength::Bits32)
        .unwrap()
        .to_vec()
    }

    fn header() -> PeerHeader {
        PeerHeader {
            peer_ip: "192.0.2.7".parse().unwrap(),
            peer_asn: 64500,
            peer_bgp_id: "192.0.2.7".parse().unwrap(),
            asn_16bit: false,
        }
    }

    /// Reads frames off the accepted socket until `wanted` have arrived.
    async fn read_frames(stream: &mut TcpStream, wanted: usize) -> Vec<Vec<u8>> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 8192];
        let mut frames = Vec::new();
        while frames.len() < wanted {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            loop {
                if buffer.len() < 6 {
                    break;
                }
                let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
                if buffer.len() < len {
                    break;
                }
                frames.push(buffer.drain(..len).collect::<Vec<u8>>());
            }
        }
        frames
    }

    fn parse(frame: &[u8]) -> bgpkit_parser::bmp::messages::BmpMessage {
        let mut bytes = Bytes::copy_from_slice(frame);
        parse_bmp_msg(&mut bytes).unwrap()
    }

    #[tokio::test]
    async fn a_connection_opens_with_initiation_then_the_peers_frames() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let station = listener.local_addr().unwrap();
        let handle = BmpExporter::spawn(settings(&station.to_string())).unwrap();

        let (mut stream, _) = listener.accept().await.unwrap();
        let initiation = read_frames(&mut stream, 1).await;
        assert_eq!(initiation[0][5], wire::MSG_INITIATION);
        assert!(matches!(
            parse(&initiation[0]).message_body,
            BmpMessageBody::InitiationMessage(_)
        ));

        handle.peer_up(
            "198.51.100.1",
            header(),
            "192.0.2.1".parse().unwrap(),
            179,
            51234,
            open_pdu(65001),
            open_pdu(64500),
        );
        let mut pdu = open_pdu(64500);
        handle.frame("198.51.100.1", &pdu, 1_700_000_000_000_000);
        pdu[18] = 4;
        handle.frame("198.51.100.1", &pdu, 1_700_000_000_000_000);

        let frames = read_frames(&mut stream, 3).await;
        assert_eq!(frames.len(), 3);
        assert!(matches!(
            parse(&frames[0]).message_body,
            BmpMessageBody::PeerUpNotification(_)
        ));
        let first = parse(&frames[1]);
        assert!(matches!(
            first.message_body,
            BmpMessageBody::RouteMonitoring(_)
        ));
        drop(handle);
    }

    #[tokio::test]
    async fn a_peer_closed_after_announcement_gets_a_peer_down() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let station = listener.local_addr().unwrap();
        let handle = BmpExporter::spawn(settings(&station.to_string())).unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_frames(&mut stream, 1).await;

        handle.peer_up(
            "198.51.100.1",
            header(),
            "192.0.2.1".parse().unwrap(),
            179,
            51234,
            open_pdu(65001),
            open_pdu(64500),
        );
        handle.peer_down(
            "198.51.100.1",
            wire::PEER_DOWN_REMOTE_NO_DATA,
            1_700_000_000_000_000,
        );
        let frames = read_frames(&mut stream, 2).await;
        assert!(matches!(
            parse(&frames[1]).message_body,
            BmpMessageBody::PeerDownNotification(_)
        ));
        drop(handle);
    }

    #[tokio::test]
    async fn a_peer_name_outside_the_allow_list_is_not_announced() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let station = listener.local_addr().unwrap();
        let mut cfg = settings(&station.to_string());
        cfg.peers = vec!["198.51.100.1".to_string()];
        let handle = BmpExporter::spawn(cfg).unwrap();
        assert!(handle.exports("198.51.100.1"));
        assert!(!handle.exports("198.51.100.2"));
        handle.peer_up(
            "198.51.100.2",
            header(),
            "192.0.2.1".parse().unwrap(),
            179,
            51234,
            open_pdu(65001),
            open_pdu(64500),
        );
        assert_eq!(handle.live_peers(), 0);
        drop(handle);
    }

    #[test]
    fn a_station_that_is_not_host_port_is_refused_before_the_daemon_runs() {
        assert!(BmpExporter::spawn(settings("not-a-socket")).is_err());
    }
}
