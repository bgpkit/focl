use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bgpkit_parser::models::{
    AsPath, AsnLength, AttributeValue, Attributes, BgpMessage, BgpOpenMessage, BgpUpdateMessage,
    NetworkPrefix, Origin,
};
use bgpkit_parser::bgp::parse_bgp_message;
use bytes::Bytes;
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

use crate::config::{FoclConfig, PeerConfig};
use crate::types::{Event, EventEnvelope, PeerState};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub name: Option<String>,
    pub remote_as: u32,
    pub local_as: u32,
    pub remote_port: u16,
    pub passive: bool,
    pub state: PeerState,
    pub last_error: Option<String>,
    pub advertised_prefixes: usize,
    pub established_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RibSummary {
    pub peers_total: usize,
    pub peers_established: usize,
    pub advertised_prefixes_total: usize,
}

#[derive(Debug)]
struct PeerRuntime {
    info: PeerInfo,
    cfg: PeerConfig,
    task: JoinHandle<()>,
}

#[derive(Clone)]
pub struct BgpService {
    inner: Arc<BgpServiceInner>,
}

struct BgpServiceInner {
    global_asn: u32,
    router_id: Ipv4Addr,
    prefixes: Vec<Ipv4Net>,
    peers: RwLock<HashMap<String, PeerRuntime>>,
    event_tx: broadcast::Sender<EventEnvelope>,
}

impl BgpService {
    pub async fn new(cfg: &FoclConfig, event_tx: broadcast::Sender<EventEnvelope>) -> Result<Self> {
        let router_id = cfg
            .global
            .router_id
            .parse::<Ipv4Addr>()
            .context("global.router_id must be IPv4")?;

        let prefixes = cfg
            .prefixes
            .iter()
            .map(|p| Ipv4Net::from_str(&p.network))
            .collect::<Result<Vec<_>, _>>()
            .context("invalid prefix in config")?;

        let inner = Arc::new(BgpServiceInner {
            global_asn: cfg.global.asn,
            router_id,
            prefixes,
            peers: RwLock::new(HashMap::new()),
            event_tx,
        });

        let service = Self { inner };
        service.start_peers(&cfg.peers).await;
        Ok(service)
    }

    async fn start_peers(&self, peers: &[PeerConfig]) {
        for peer in peers {
            if !peer.enabled {
                continue;
            }
            let runtime = self.spawn_peer_task(peer.clone());
            self.inner
                .peers
                .write()
                .await
                .insert(peer.address.clone(), runtime);
        }
    }

    fn spawn_peer_task(&self, peer_cfg: PeerConfig) -> PeerRuntime {
        let local_as = peer_cfg.local_as.unwrap_or(self.inner.global_asn);
        let info = PeerInfo {
            address: peer_cfg.address.clone(),
            name: peer_cfg.name.clone(),
            remote_as: peer_cfg.remote_as,
            local_as,
            remote_port: peer_cfg.remote_port,
            passive: peer_cfg.passive,
            state: PeerState::Idle,
            last_error: None,
            advertised_prefixes: 0,
            established_at: None,
        };

        let service = self.clone();
        let address = peer_cfg.address.clone();
        let peer_for_task = peer_cfg.clone();
        let task = tokio::spawn(async move {
            service.peer_loop(peer_for_task).await;
            let mut peers = service.inner.peers.write().await;
            if let Some(runtime) = peers.get_mut(&address) {
                runtime.info.state = PeerState::Idle;
            }
        });

        PeerRuntime {
            info,
            cfg: peer_cfg,
            task,
        }
    }

    async fn peer_loop(&self, peer: PeerConfig) {
        loop {
            self.set_peer_state(&peer.address, PeerState::Connect, None, None)
                .await;

            let result = if peer.passive {
                self.run_passive_session(&peer).await
            } else {
                self.run_active_session(&peer).await
            };

            match result {
                Ok(()) => {
                    self.set_peer_state(&peer.address, PeerState::Active, None, None)
                        .await;
                }
                Err(err) => {
                    self.set_peer_state(
                        &peer.address,
                        PeerState::Active,
                        Some(err.to_string()),
                        None,
                    )
                    .await;
                }
            }

            sleep(Duration::from_secs(peer.connect_retry_secs as u64)).await;
        }
    }

    async fn run_active_session(&self, peer: &PeerConfig) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", peer.address, peer.remote_port)
            .parse()
            .with_context(|| {
                format!("invalid peer socket {}:{}", peer.address, peer.remote_port)
            })?;

        let mut stream = connect_with_optional_bind(peer, addr).await?;
        self.run_session(peer, &mut stream).await
    }

    async fn run_passive_session(&self, peer: &PeerConfig) -> Result<()> {
        let listen_addr = peer
            .local_address
            .clone()
            .unwrap_or_else(|| format!("0.0.0.0:{}", peer.remote_port));
        let listen: SocketAddr = normalize_socket_addr(&listen_addr, peer.remote_port)
            .with_context(|| format!("invalid passive local_address {}", listen_addr))?;

        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("failed binding passive listener {listen}"))?;

        let (mut stream, _) = listener.accept().await?;
        self.run_session(peer, &mut stream).await
    }

    async fn run_session(&self, peer: &PeerConfig, stream: &mut TcpStream) -> Result<()> {
        self.set_peer_state(&peer.address, PeerState::OpenSent, None, None)
            .await;

        let local_as = peer.local_as.unwrap_or(self.inner.global_asn);
        let hold_time = peer.hold_time_secs.max(3);

        let open = BgpMessage::Open(BgpOpenMessage {
            version: 4,
            asn: local_as.into(),
            hold_time,
            sender_ip: self.inner.router_id,
            extended_length: false,
            opt_params: vec![],
        });
        write_bgp_message(stream, &open).await?;

        let incoming = read_bgp_message(stream).await?;
        if !matches!(incoming, BgpMessage::Open(_)) {
            return Err(anyhow!("expected OPEN from peer"));
        }

        write_bgp_message(stream, &BgpMessage::KeepAlive).await?;
        let incoming = read_bgp_message(stream).await?;
        if !matches!(incoming, BgpMessage::KeepAlive) {
            return Err(anyhow!("expected KEEPALIVE from peer after OPEN"));
        }

        self.set_peer_state(
            &peer.address,
            PeerState::Established,
            None,
            Some(chrono::Utc::now().timestamp()),
        )
        .await;

        self.send_prefix_announcements(peer, stream).await?;

        let negotiated_hold = Duration::from_secs(hold_time as u64);
        let keepalive_interval = Duration::from_secs((hold_time as u64 / 3).max(1));
        let mut next_keepalive = Instant::now() + keepalive_interval;
        let mut hold_deadline = Instant::now() + negotiated_hold;

        loop {
            let now = Instant::now();
            if now >= next_keepalive {
                write_bgp_message(stream, &BgpMessage::KeepAlive).await?;
                next_keepalive = now + keepalive_interval;
            }

            if now >= hold_deadline {
                return Err(anyhow!("hold timer expired"));
            }

            let timeout_dur = std::cmp::min(
                next_keepalive.saturating_duration_since(now),
                Duration::from_secs(1),
            );
            match timeout(timeout_dur, read_bgp_message(stream)).await {
                Ok(Ok(msg)) => match msg {
                    BgpMessage::KeepAlive | BgpMessage::Update(_) | BgpMessage::Open(_) => {
                        hold_deadline = Instant::now() + negotiated_hold;
                    }
                    BgpMessage::Notification(_) => {
                        return Err(anyhow!("received NOTIFICATION from peer"));
                    }
                },
                Ok(Err(err)) => return Err(err),
                Err(_) => {}
            }
        }
    }

    async fn send_prefix_announcements(
        &self,
        peer: &PeerConfig,
        stream: &mut TcpStream,
    ) -> Result<()> {
        let local_as = peer.local_as.unwrap_or(self.inner.global_asn);
        let next_hop = self.inner.router_id;

        for prefix in &self.inner.prefixes {
            let update = build_ipv4_announce_update(*prefix, next_hop, local_as);
            write_bgp_message(stream, &update).await?;
        }

        let count = self.inner.prefixes.len();
        let mut peers = self.inner.peers.write().await;
        if let Some(runtime) = peers.get_mut(&peer.address) {
            runtime.info.advertised_prefixes = count;
        }

        Ok(())
    }

    async fn set_peer_state(
        &self,
        address: &str,
        state: PeerState,
        last_error: Option<String>,
        established_at: Option<i64>,
    ) {
        let mut peers = self.inner.peers.write().await;
        if let Some(runtime) = peers.get_mut(address) {
            runtime.info.state = state;
            if let Some(err) = last_error {
                runtime.info.last_error = Some(err);
            } else if matches!(state, PeerState::Established) {
                runtime.info.last_error = None;
            }
            if let Some(ts) = established_at {
                runtime.info.established_at = Some(ts);
            }
            let _ = self
                .inner
                .event_tx
                .send(EventEnvelope::new(Event::PeerState {
                    peer: address.to_string(),
                    state,
                }));
        }
    }

    pub async fn peer_list(&self) -> Vec<PeerInfo> {
        self.inner
            .peers
            .read()
            .await
            .values()
            .map(|r| r.info.clone())
            .collect()
    }

    pub async fn peer_show(&self, peer: &str) -> Option<PeerInfo> {
        self.inner
            .peers
            .read()
            .await
            .get(peer)
            .map(|r| r.info.clone())
    }

    pub async fn peer_reset(&self, peer: &str) -> Result<()> {
        let old = {
            let mut peers = self.inner.peers.write().await;
            peers.remove(peer)
        };

        let Some(old_runtime) = old else {
            return Err(anyhow!("peer {} not found", peer));
        };

        old_runtime.task.abort();

        let runtime = self.spawn_peer_task(old_runtime.cfg);
        self.inner
            .peers
            .write()
            .await
            .insert(peer.to_string(), runtime);
        Ok(())
    }

    pub async fn rib_summary(&self) -> RibSummary {
        let peers = self.inner.peers.read().await;
        let established = peers
            .values()
            .filter(|p| matches!(p.info.state, PeerState::Established))
            .count();

        RibSummary {
            peers_total: peers.len(),
            peers_established: established,
            advertised_prefixes_total: peers.values().map(|p| p.info.advertised_prefixes).sum(),
        }
    }

    pub async fn rib_out(&self, peer: &str) -> Result<Vec<String>> {
        let peers = self.inner.peers.read().await;
        if !peers.contains_key(peer) {
            return Err(anyhow!("peer {} not found", peer));
        }
        Ok(self.inner.prefixes.iter().map(|p| p.to_string()).collect())
    }

    pub async fn rib_in(&self, peer: &str) -> Result<Vec<String>> {
        let peers = self.inner.peers.read().await;
        if !peers.contains_key(peer) {
            return Err(anyhow!("peer {} not found", peer));
        }
        Ok(vec![])
    }
}

async fn connect_with_optional_bind(peer: &PeerConfig, remote: SocketAddr) -> Result<TcpStream> {
    let local_bind = match peer.local_address.as_deref() {
        None => None,
        Some(raw) => Some(normalize_socket_addr(raw, 0).context("invalid peer local_address")?),
    };

    match (remote, local_bind) {
        (SocketAddr::V4(remote_v4), Some(SocketAddr::V4(local_v4))) => {
            let socket = TcpSocket::new_v4()?;
            socket.bind(SocketAddr::V4(local_v4))?;
            socket
                .connect(SocketAddr::V4(remote_v4))
                .await
                .map_err(Into::into)
        }
        (_, Some(local)) => {
            let socket = if local.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.bind(local)?;
            socket.connect(remote).await.map_err(Into::into)
        }
        (_, None) => TcpStream::connect(remote).await.map_err(Into::into),
    }
}

fn normalize_socket_addr(raw: &str, default_port: u16) -> Result<SocketAddr> {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Ok(sa);
    }

    let ip: IpAddr = raw
        .parse()
        .with_context(|| format!("invalid ip/address {raw}"))?;
    Ok(SocketAddr::new(ip, default_port))
}

async fn write_bgp_message(stream: &mut TcpStream, msg: &BgpMessage) -> Result<()> {
    let mut bytes = msg.encode(AsnLength::Bits32).to_vec();
    if bytes.len() < 19 {
        return Err(anyhow!("encoded BGP message too short"));
    }

    bytes[0..16].fill(0xff);

    stream.write_all(&bytes).await?;
    Ok(())
}

async fn read_bgp_message(stream: &mut TcpStream) -> Result<BgpMessage> {
    let mut header = [0u8; 19];
    stream.read_exact(&mut header).await?;

    if header[0..16] != [0xff; 16] {
        return Err(anyhow!("invalid BGP marker"));
    }

    let length = u16::from_be_bytes([header[16], header[17]]) as usize;
    if !(19..=4096).contains(&length) {
        return Err(anyhow!("invalid BGP message length {}", length));
    }

    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&header);

    let payload_len = length - 19;
    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await?;
        bytes.extend_from_slice(&payload);
    }

    let bytes32 = bytes.clone();
    let mut raw32 = Bytes::from(bytes32);
    let parsed = parse_bgp_message(&mut raw32, false, &AsnLength::Bits32)
        .or_else(|_| {
            let mut raw16 = Bytes::from(bytes);
            parse_bgp_message(&mut raw16, false, &AsnLength::Bits16)
        })
        .map_err(|e| anyhow!("failed parsing BGP message using bgpkit-parser: {e}"))?;

    Ok(parsed)
}

fn build_ipv4_announce_update(prefix: Ipv4Net, next_hop: Ipv4Addr, local_as: u32) -> BgpMessage {
    let mut attrs = Attributes::default();
    attrs.add_attr(AttributeValue::Origin(Origin::IGP).into());
    attrs.add_attr(
        AttributeValue::AsPath {
            path: AsPath::from_sequence([local_as]),
            is_as4: false,
        }
        .into(),
    );
    attrs.add_attr(AttributeValue::NextHop(IpAddr::V4(next_hop)).into());

    let announced = NetworkPrefix::new(IpNet::V4(prefix), None);
    BgpMessage::Update(BgpUpdateMessage {
        withdrawn_prefixes: vec![],
        attributes: attrs,
        announced_prefixes: vec![announced],
    })
}
