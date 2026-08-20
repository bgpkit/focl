use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bgpkit_parser::bgp::parse_bgp_message;
use bgpkit_parser::models::{
    Afi, AsPath, Asn, AsnLength, AttributeValue, Attributes, BgpMessage, BgpOpenMessage,
    BgpUpdateMessage, NetworkPrefix, Nlri, OptParam, Origin, ParamValue, Safi,
};
use bytes::Bytes;
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

use crate::archive::types::{PeerStateRecordInput, UpdateRecordInput};
use crate::archive::ArchiveService;
use crate::config::{FoclConfig, PeerConfig};
use crate::types::{Event, EventEnvelope, PeerState};

mod auth;
use auth::{TcpSocketExt, TcpStreamExt};

const AS_TRANS: u16 = 23_456;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub name: Option<String>,
    pub remote_as: u32,
    pub local_as: u32,
    pub remote_port: u16,
    pub passive: bool,
    pub auth_enabled: bool,
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
    task: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct PrefixEntry {
    network: IpNet,
    next_hop: Option<IpAddr>,
}

/// A deliberately owned, uninterned v1 Adj-RIB-In value. Attribute interning is
/// deferred until the collector's memory profile is measured under real feeds.
#[derive(Debug, Clone)]
struct AdjRibValue {
    next_hop: Option<IpAddr>,
    as_path: Option<String>,
    last_seen: i64,
}

#[derive(Debug, Clone, Default)]
struct NegotiatedCapabilities {
    families: HashSet<(Afi, Safi)>,
    asn4: bool,
    route_refresh: bool,
    graceful_restart: bool,
}

impl NegotiatedCapabilities {
    fn supports(&self, afi: Afi, safi: Safi) -> bool {
        // IPv4 unicast is available to an RFC 4271 peer even if it sent no
        // RFC 4760 MP capability. IPv6 always requires explicit MP-BGP.
        (afi == Afi::Ipv4 && safi == Safi::Unicast) || self.families.contains(&(afi, safi))
    }
}

struct BgpServiceInner {
    global_asn: u32,
    router_id: Ipv4Addr,
    prefixes: Vec<PrefixEntry>,
    peers: RwLock<HashMap<String, PeerRuntime>>,
    rib_in: RwLock<HashMap<String, IpnetTrie<AdjRibValue>>>,
    session_local_ips: RwLock<HashMap<String, IpAddr>>,
    event_tx: broadcast::Sender<EventEnvelope>,
    archive: Option<Arc<ArchiveService>>,
}

#[derive(Debug)]
struct ReceivedMessage {
    message: BgpMessage,
    raw: Vec<u8>,
}

#[derive(Clone)]
pub struct BgpService {
    inner: Arc<BgpServiceInner>,
}

impl BgpService {
    pub async fn new(cfg: &FoclConfig, event_tx: broadcast::Sender<EventEnvelope>) -> Result<Self> {
        Self::new_with_archive(cfg, event_tx, None).await
    }

    /// Builds the speaker with an archive sink. Keeping `new` preserves the
    /// control/library contract while daemon and collector callers opt in.
    pub async fn new_with_archive(
        cfg: &FoclConfig,
        event_tx: broadcast::Sender<EventEnvelope>,
        archive: Option<Arc<ArchiveService>>,
    ) -> Result<Self> {
        let router_id = cfg
            .global
            .router_id
            .parse::<Ipv4Addr>()
            .context("global.router_id must be IPv4")?;
        let prefixes = cfg
            .prefixes
            .iter()
            .map(|p| {
                let network = IpNet::from_str(&p.network)
                    .with_context(|| format!("invalid prefix network: {}", p.network))?;
                let next_hop = p
                    .next_hop
                    .as_ref()
                    .map(|nh| nh.parse::<IpAddr>())
                    .transpose()
                    .with_context(|| format!("invalid next-hop address: {:?}", p.next_hop))?;
                Ok::<_, anyhow::Error>(PrefixEntry { network, next_hop })
            })
            .collect::<Result<Vec<_>, _>>()
            .context("invalid prefix in config")?;
        let inner = Arc::new(BgpServiceInner {
            global_asn: cfg.global.asn,
            router_id,
            prefixes,
            peers: RwLock::new(HashMap::new()),
            rib_in: RwLock::new(HashMap::new()),
            session_local_ips: RwLock::new(HashMap::new()),
            event_tx,
            archive,
        });
        let service = Self { inner };
        service.start_peers(&cfg.peers).await;
        if cfg.global.listen {
            service.start_listener(&cfg.global.listen_addr).await?;
        }
        Ok(service)
    }

    async fn start_peers(&self, peers: &[PeerConfig]) {
        for peer in peers.iter().filter(|peer| peer.enabled) {
            let runtime = self.make_runtime(peer.clone());
            self.inner
                .rib_in
                .write()
                .await
                .insert(peer.address.clone(), IpnetTrie::new());
            self.inner
                .peers
                .write()
                .await
                .insert(peer.address.clone(), runtime);
        }
    }

    fn make_runtime(&self, peer_cfg: PeerConfig) -> PeerRuntime {
        let local_as = peer_cfg.local_as.unwrap_or(self.inner.global_asn);
        let info = PeerInfo {
            address: peer_cfg.address.clone(),
            name: peer_cfg.name.clone(),
            remote_as: peer_cfg.remote_as,
            local_as,
            remote_port: peer_cfg.remote_port,
            passive: peer_cfg.passive,
            auth_enabled: peer_cfg.password.is_some(),
            state: PeerState::Idle,
            last_error: None,
            advertised_prefixes: 0,
            established_at: None,
        };
        let task = (!peer_cfg.passive).then(|| self.spawn_active_loop(peer_cfg.clone()));
        PeerRuntime {
            info,
            cfg: peer_cfg,
            task,
        }
    }

    fn spawn_active_loop(&self, peer_cfg: PeerConfig) -> JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move { service.peer_loop(peer_cfg).await })
    }

    async fn start_listener(&self, listen_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .with_context(|| format!("failed binding global BGP listener {listen_addr}"))?;
        let service = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, remote)) => service.accept_inbound(stream, remote).await,
                    Err(error) => tracing::warn!(error=%error, "global BGP listener accept failed"),
                }
            }
        });
        Ok(())
    }

    async fn accept_inbound(&self, mut stream: TcpStream, remote: SocketAddr) {
        let peer = {
            let peers = self.inner.peers.read().await;
            peers
                .values()
                .find(|runtime| {
                    runtime.cfg.enabled
                        && runtime
                            .cfg
                            .address
                            .parse::<IpAddr>()
                            .is_ok_and(|address| address == remote.ip())
                })
                .map(|runtime| runtime.cfg.clone())
        };
        let Some(peer) = peer else {
            tracing::warn!(remote=%remote, "dropping inbound BGP connection from unconfigured peer");
            return;
        };
        if let Some(password) = &peer.password {
            if let Err(error) = stream.set_md5_signature(&remote, password) {
                tracing::warn!(peer=%peer.address, error=%error, "failed to set TCP-MD5 on inbound BGP connection");
                return;
            }
        }

        // RFC collision handling deliberately favours the accepted connection.
        // Cancel the active loop before it can mutate the session state further.
        let old_task = {
            let mut peers = self.inner.peers.write().await;
            peers
                .get_mut(&peer.address)
                .and_then(|runtime| runtime.task.take())
        };
        if let Some(task) = old_task {
            task.abort();
        }

        let service = self.clone();
        let key = peer.address.clone();
        let task = tokio::spawn(async move {
            let result = service.run_session(&peer, &mut stream).await;
            service.clear_rib(&peer.address).await;
            match result {
                Ok(()) => {
                    service
                        .set_peer_state(&peer.address, PeerState::Active, None, None)
                        .await
                }
                Err(error) => {
                    service
                        .set_peer_state(
                            &peer.address,
                            PeerState::Active,
                            Some(error.to_string()),
                            None,
                        )
                        .await
                }
            }
            if !peer.passive {
                sleep(Duration::from_secs(peer.connect_retry_secs as u64)).await;
                service.peer_loop(peer).await;
            }
        });
        let mut peers = self.inner.peers.write().await;
        if let Some(runtime) = peers.get_mut(&key) {
            runtime.task = Some(task);
        }
    }

    async fn peer_loop(&self, peer: PeerConfig) {
        loop {
            self.set_peer_state(&peer.address, PeerState::Connect, None, None)
                .await;
            let result = self.run_active_session(&peer).await;
            self.clear_rib(&peer.address).await;
            match result {
                Ok(()) => {
                    self.set_peer_state(&peer.address, PeerState::Active, None, None)
                        .await
                }
                Err(error) => {
                    self.set_peer_state(
                        &peer.address,
                        PeerState::Active,
                        Some(error.to_string()),
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

    async fn run_session(&self, peer: &PeerConfig, stream: &mut TcpStream) -> Result<()> {
        let local_ip = stream.local_addr()?.ip();
        self.inner
            .session_local_ips
            .write()
            .await
            .insert(peer.address.clone(), local_ip);
        self.set_peer_state(&peer.address, PeerState::OpenSent, None, None)
            .await;

        let local_as = peer.local_as.unwrap_or(self.inner.global_asn);
        let hold_time = peer.hold_time_secs.max(3);
        let open = local_open(
            self.inner.router_id,
            local_as,
            hold_time,
            peer.route_refresh,
        );
        write_bgp_message(stream, &open, AsnLength::Bits32).await?;

        let incoming = read_bgp_message(stream).await?;
        let BgpMessage::Open(remote_open) = incoming.message else {
            return Err(anyhow!("expected OPEN from peer"));
        };
        let negotiated = negotiate_capabilities(&incoming.raw, peer.route_refresh);
        validate_remote_as(&remote_open, &incoming.raw, peer.remote_as, negotiated.asn4)?;

        self.set_peer_state(&peer.address, PeerState::OpenConfirm, None, None)
            .await;
        write_bgp_message(stream, &BgpMessage::KeepAlive, AsnLength::Bits32).await?;
        let incoming = read_bgp_message(stream).await?;
        if !matches!(incoming.message, BgpMessage::KeepAlive) {
            return Err(anyhow!("expected KEEPALIVE from peer after OPEN"));
        }

        self.set_peer_state(
            &peer.address,
            PeerState::Established,
            None,
            Some(chrono::Utc::now().timestamp()),
        )
        .await;
        self.send_prefix_announcements(peer, stream, &negotiated)
            .await?;

        let negotiated_hold = Duration::from_secs(hold_time as u64);
        let keepalive_interval = Duration::from_secs((hold_time as u64 / 3).max(1));
        let mut next_keepalive = Instant::now() + keepalive_interval;
        let mut hold_deadline = Instant::now() + negotiated_hold;
        loop {
            let now = Instant::now();
            if now >= next_keepalive {
                write_bgp_message(stream, &BgpMessage::KeepAlive, AsnLength::Bits32).await?;
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
                Ok(Ok(incoming)) => match incoming.message {
                    BgpMessage::Update(update) => {
                        self.ingest_received_update(
                            peer,
                            local_as,
                            local_ip,
                            update,
                            incoming.raw,
                            &negotiated,
                        )
                        .await?;
                        hold_deadline = Instant::now() + negotiated_hold;
                    }
                    BgpMessage::KeepAlive | BgpMessage::Open(_) | BgpMessage::RouteRefresh(_) => {
                        hold_deadline = Instant::now() + negotiated_hold;
                    }
                    BgpMessage::Notification(_) => {
                        return Err(anyhow!("received NOTIFICATION from peer"))
                    }
                },
                Ok(Err(error)) => return Err(error),
                Err(_) => {}
            }
        }
    }

    async fn ingest_received_update(
        &self,
        peer: &PeerConfig,
        local_as: u32,
        local_ip: IpAddr,
        update: BgpUpdateMessage,
        raw: Vec<u8>,
        negotiated: &NegotiatedCapabilities,
    ) -> Result<()> {
        self.apply_update_to_rib(&peer.address, &update, negotiated)
            .await;
        if let Some(archive) = &self.inner.archive {
            archive
                .ingest_update(UpdateRecordInput {
                    timestamp: chrono::Utc::now().timestamp(),
                    peer_ip: peer.address.parse().context("invalid configured peer IP")?,
                    peer_asn: peer.remote_as,
                    local_ip,
                    local_asn: local_as,
                    interface_index: 0,
                    bgp_message: raw,
                })
                .await?;
        }
        Ok(())
    }

    async fn apply_update_to_rib(
        &self,
        peer: &str,
        update: &BgpUpdateMessage,
        negotiated: &NegotiatedCapabilities,
    ) {
        let next_hop = update.attributes.next_hop();
        let as_path = update.attributes.as_path().map(ToString::to_string);
        let now = chrono::Utc::now().timestamp();
        let mut ribs = self.inner.rib_in.write().await;
        let rib = ribs.entry(peer.to_string()).or_insert_with(IpnetTrie::new);
        for prefix in &update.withdrawn_prefixes {
            if negotiated.supports(afi_for(prefix.prefix), Safi::Unicast) {
                rib.remove(prefix.prefix);
            }
        }
        for prefix in &update.announced_prefixes {
            if negotiated.supports(afi_for(prefix.prefix), Safi::Unicast) {
                rib.insert(
                    prefix.prefix,
                    AdjRibValue {
                        next_hop,
                        as_path: as_path.clone(),
                        last_seen: now,
                    },
                );
            }
        }
        if let Some(nlri) = update.attributes.get_unreachable_nlri() {
            if negotiated.supports(nlri.afi, nlri.safi) {
                for prefix in nlri {
                    rib.remove(*prefix);
                }
            }
        }
        if let Some(nlri) = update.attributes.get_reachable_nlri() {
            if negotiated.supports(nlri.afi, nlri.safi) {
                let mp_next_hop = nlri.next_hop.map(|next_hop| next_hop.addr());
                for prefix in nlri {
                    rib.insert(
                        *prefix,
                        AdjRibValue {
                            next_hop: mp_next_hop,
                            as_path: as_path.clone(),
                            last_seen: now,
                        },
                    );
                }
            }
        }
    }

    async fn send_prefix_announcements(
        &self,
        peer: &PeerConfig,
        stream: &mut TcpStream,
        negotiated: &NegotiatedCapabilities,
    ) -> Result<()> {
        let local_as = peer.local_as.unwrap_or(self.inner.global_asn);
        let local_ip = stream.local_addr()?.ip();
        for update in build_announce_updates(
            &self.inner.prefixes,
            self.inner.router_id,
            local_ip,
            local_as,
            negotiated,
        ) {
            let raw = write_bgp_message(stream, &update, AsnLength::Bits32).await?;
            // Keep the collector's configured-prefix baseline alongside the
            // received feed; it lets a self-contained lab archive replay both
            // sides of this peering session.
            if let Some(archive) = &self.inner.archive {
                archive
                    .ingest_update(UpdateRecordInput {
                        timestamp: chrono::Utc::now().timestamp(),
                        peer_ip: peer.address.parse().context("invalid configured peer IP")?,
                        peer_asn: peer.remote_as,
                        local_ip,
                        local_asn: local_as,
                        interface_index: 0,
                        bgp_message: raw,
                    })
                    .await?;
            }
        }
        let mut peers = self.inner.peers.write().await;
        if let Some(runtime) = peers.get_mut(&peer.address) {
            runtime.info.advertised_prefixes = self.inner.prefixes.len();
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
        let old_state = {
            let mut peers = self.inner.peers.write().await;
            let Some(runtime) = peers.get_mut(address) else {
                return;
            };
            let old_state = runtime.info.state;
            runtime.info.state = state;
            if let Some(error) = last_error {
                runtime.info.last_error = Some(error);
            } else if matches!(state, PeerState::Established) {
                runtime.info.last_error = None;
            }
            if let Some(timestamp) = established_at {
                runtime.info.established_at = Some(timestamp);
            }
            old_state
        };
        let _ = self
            .inner
            .event_tx
            .send(EventEnvelope::new(Event::PeerState {
                peer: address.to_string(),
                state,
            }));
        self.archive_peer_state(address, old_state, state).await;
    }

    async fn archive_peer_state(&self, address: &str, old_state: PeerState, new_state: PeerState) {
        let Some(archive) = &self.inner.archive else {
            return;
        };
        let (peer_asn, local_asn) = {
            let peers = self.inner.peers.read().await;
            let Some(runtime) = peers.get(address) else {
                return;
            };
            (runtime.info.remote_as, runtime.info.local_as)
        };
        let Some(local_ip) = self
            .inner
            .session_local_ips
            .read()
            .await
            .get(address)
            .copied()
        else {
            return;
        };
        let Ok(peer_ip) = address.parse::<IpAddr>() else {
            return;
        };
        if let Err(error) = archive
            .ingest_peer_state(PeerStateRecordInput {
                timestamp: chrono::Utc::now().timestamp(),
                peer_ip,
                peer_asn,
                local_ip,
                local_asn,
                interface_index: 0,
                old_state: peer_state_code(old_state),
                new_state: peer_state_code(new_state),
            })
            .await
        {
            tracing::warn!(peer=%address, error=%error, "failed archiving BGP peer state");
        }
    }

    async fn clear_rib(&self, peer: &str) {
        self.inner
            .rib_in
            .write()
            .await
            .insert(peer.to_string(), IpnetTrie::new());
        self.inner.session_local_ips.write().await.remove(peer);
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
        let (cfg, old_task) = {
            let mut peers = self.inner.peers.write().await;
            let runtime = peers
                .get_mut(peer)
                .ok_or_else(|| anyhow!("peer {peer} not found"))?;
            (runtime.cfg.clone(), runtime.task.take())
        };
        if let Some(task) = old_task {
            task.abort();
        }
        self.clear_rib(peer).await;
        let new_task = (!cfg.passive).then(|| self.spawn_active_loop(cfg));
        if let Some(runtime) = self.inner.peers.write().await.get_mut(peer) {
            runtime.task = new_task;
            runtime.info.state = PeerState::Idle;
        }
        Ok(())
    }

    pub async fn rib_summary(&self) -> RibSummary {
        let peers = self.inner.peers.read().await;
        RibSummary {
            peers_total: peers.len(),
            peers_established: peers
                .values()
                .filter(|peer| matches!(peer.info.state, PeerState::Established))
                .count(),
            advertised_prefixes_total: peers
                .values()
                .map(|peer| peer.info.advertised_prefixes)
                .sum(),
        }
    }

    pub async fn rib_out(&self, peer: &str) -> Result<Vec<String>> {
        if !self.inner.peers.read().await.contains_key(peer) {
            return Err(anyhow!("peer {peer} not found"));
        }
        Ok(self
            .inner
            .prefixes
            .iter()
            .map(|prefix| prefix.network.to_string())
            .collect())
    }

    pub async fn rib_in(&self, peer: &str) -> Result<Vec<String>> {
        if !self.inner.peers.read().await.contains_key(peer) {
            return Err(anyhow!("peer {peer} not found"));
        }
        let ribs = self.inner.rib_in.read().await;
        let mut prefixes = ribs
            .get(peer)
            .into_iter()
            .flat_map(|rib| {
                rib.iter().map(|(prefix, value)| {
                    let _ = (&value.next_hop, &value.as_path, value.last_seen);
                    prefix.to_string()
                })
            })
            .collect::<Vec<_>>();
        prefixes.sort();
        Ok(prefixes)
    }
}

fn local_open(
    router_id: Ipv4Addr,
    local_as: u32,
    hold_time: u16,
    route_refresh: bool,
) -> BgpMessage {
    BgpMessage::Open(BgpOpenMessage {
        version: 4,
        asn: Asn::new_16bit(if local_as > u16::MAX as u32 {
            AS_TRANS
        } else {
            local_as as u16
        }),
        hold_time,
        bgp_identifier: router_id,
        extended_length: false,
        opt_params: vec![OptParam {
            param_type: 2,
            param_value: ParamValue::Raw(capability_bytes(local_as, route_refresh)),
        }],
    })
}

fn capability_bytes(local_as: u32, route_refresh: bool) -> Vec<u8> {
    let mut bytes = vec![1, 4, 0, 1, 0, 1, 1, 4, 0, 2, 0, 1, 65, 4];
    bytes.extend_from_slice(&local_as.to_be_bytes());
    if route_refresh {
        bytes.extend_from_slice(&[2, 0]);
    }
    bytes
}

fn peer_capabilities(raw: &[u8]) -> Vec<(u8, Vec<u8>)> {
    if raw.len() < 29 || raw[18] != 1 {
        return vec![];
    }
    let end = (29 + raw[28] as usize).min(raw.len());
    let mut index = 29;
    let mut result = Vec::new();
    while index + 2 <= end {
        let param_type = raw[index];
        let length = raw[index + 1] as usize;
        index += 2;
        if index + length > end {
            break;
        }
        if param_type == 2 {
            let mut cap_index = index;
            while cap_index + 2 <= index + length {
                let cap_type = raw[cap_index];
                let cap_len = raw[cap_index + 1] as usize;
                cap_index += 2;
                if cap_index + cap_len > index + length {
                    break;
                }
                result.push((cap_type, raw[cap_index..cap_index + cap_len].to_vec()));
                cap_index += cap_len;
            }
        }
        index += length;
    }
    result
}

fn negotiate_capabilities(raw: &[u8], route_refresh_configured: bool) -> NegotiatedCapabilities {
    let mut negotiated = NegotiatedCapabilities::default();
    for (cap_type, value) in peer_capabilities(raw) {
        match (cap_type, value.as_slice()) {
            (1, [0, 1, _, 1]) => {
                negotiated.families.insert((Afi::Ipv4, Safi::Unicast));
            }
            (1, [0, 2, _, 1]) => {
                negotiated.families.insert((Afi::Ipv6, Safi::Unicast));
            }
            (65, [_, _, _, _]) => negotiated.asn4 = true,
            (2, []) => negotiated.route_refresh = route_refresh_configured,
            (64, _) => negotiated.graceful_restart = true,
            _ => {}
        }
    }
    negotiated
}

fn validate_remote_as(open: &BgpOpenMessage, raw: &[u8], expected: u32, asn4: bool) -> Result<()> {
    let advertised_asn4 = peer_capabilities(raw).into_iter().find_map(|(ty, value)| {
        (ty == 65 && value.len() == 4).then(|| u32::from_be_bytes(value.try_into().unwrap()))
    });
    let wire_asn: u32 = open.asn.into();
    let actual = if wire_asn == AS_TRANS as u32 && asn4 {
        advertised_asn4.unwrap_or(wire_asn)
    } else {
        wire_asn
    };
    if actual != expected {
        return Err(anyhow!(
            "peer ASN mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn build_announce_updates(
    prefixes: &[PrefixEntry],
    router_id: Ipv4Addr,
    local_ip: IpAddr,
    local_as: u32,
    negotiated: &NegotiatedCapabilities,
) -> Vec<BgpMessage> {
    let mut result = Vec::new();
    for prefix in prefixes
        .iter()
        .filter(|prefix| matches!(prefix.network, IpNet::V4(_)))
    {
        let mut attrs = base_announce_attributes(local_as, negotiated.asn4);
        let next_hop = prefix.next_hop.unwrap_or(IpAddr::V4(router_id));
        attrs.add_attr(AttributeValue::NextHop(next_hop).into());
        result.push(BgpMessage::Update(BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![NetworkPrefix::new(prefix.network, None)],
        }));
    }
    for prefix in prefixes
        .iter()
        .filter(|prefix| matches!(prefix.network, IpNet::V6(_)))
    {
        if !negotiated.supports(Afi::Ipv6, Safi::Unicast) {
            continue;
        }
        let mut attrs = base_announce_attributes(local_as, negotiated.asn4);
        // MP_REACH requires an IPv6 next hop. A configured non-v6 next hop is
        // ignored rather than serializing a malformed NEXT_HOP attribute.
        let next_hop = prefix
            .next_hop
            .filter(IpAddr::is_ipv6)
            .or_else(|| local_ip.is_ipv6().then_some(local_ip));
        let Some(next_hop) = next_hop else {
            tracing::warn!("not announcing IPv6 prefixes: no IPv6 configured/session next hop");
            continue;
        };
        let nlri = Nlri::new_reachable(NetworkPrefix::new(prefix.network, None), Some(next_hop));
        attrs.add_attr(AttributeValue::MpReachNlri(nlri).into());
        result.push(BgpMessage::Update(BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        }));
    }
    result
}

fn base_announce_attributes(local_as: u32, asn4: bool) -> Attributes {
    let mut attrs = Attributes::default();
    attrs.add_attr(AttributeValue::Origin(Origin::IGP).into());
    attrs.add_attr(
        AttributeValue::AsPath {
            path: AsPath::from_sequence([local_as]),
            is_as4: asn4,
        }
        .into(),
    );
    attrs
}

fn afi_for(prefix: IpNet) -> Afi {
    match prefix {
        IpNet::V4(_) => Afi::Ipv4,
        IpNet::V6(_) => Afi::Ipv6,
    }
}

fn peer_state_code(state: PeerState) -> u16 {
    match state {
        PeerState::Idle => 1,
        PeerState::Connect => 2,
        PeerState::Active => 3,
        PeerState::OpenSent => 4,
        PeerState::OpenConfirm => 5,
        PeerState::Established => 6,
    }
}

async fn connect_with_optional_bind(peer: &PeerConfig, remote: SocketAddr) -> Result<TcpStream> {
    let local_bind = peer
        .local_address
        .as_deref()
        .map(|raw| normalize_socket_addr(raw, 0))
        .transpose()
        .context("invalid peer local_address")?;
    match (remote, local_bind) {
        (SocketAddr::V4(remote_v4), Some(SocketAddr::V4(local_v4))) => {
            let socket = TcpSocket::new_v4()?;
            socket.bind(SocketAddr::V4(local_v4))?;
            if let Some(password) = &peer.password {
                socket.set_md5_signature(&remote, password)?;
            }
            Ok(socket.connect(SocketAddr::V4(remote_v4)).await?)
        }
        (_, Some(local)) => {
            let socket = if local.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.bind(local)?;
            if let Some(password) = &peer.password {
                socket.set_md5_signature(&remote, password)?;
            }
            Ok(socket.connect(remote).await?)
        }
        (_, None) => {
            let stream = TcpStream::connect(remote).await?;
            if let Some(password) = &peer.password {
                stream.set_md5_signature(&remote, password)?;
            }
            Ok(stream)
        }
    }
}

fn normalize_socket_addr(raw: &str, default_port: u16) -> Result<SocketAddr> {
    if let Ok(socket) = raw.parse::<SocketAddr>() {
        return Ok(socket);
    }
    let address = raw
        .parse::<IpAddr>()
        .with_context(|| format!("invalid ip/address {raw}"))?;
    Ok(SocketAddr::new(address, default_port))
}

async fn write_bgp_message(
    stream: &mut TcpStream,
    message: &BgpMessage,
    asn_len: AsnLength,
) -> Result<Vec<u8>> {
    let mut bytes = message
        .encode(asn_len)
        .map_err(|error| anyhow!("failed encoding BGP message: {error}"))?
        .to_vec();
    if bytes.len() < 19 {
        return Err(anyhow!("encoded BGP message too short"));
    }
    bytes[0..16].fill(0xff);
    stream.write_all(&bytes).await?;
    Ok(bytes)
}

async fn read_bgp_message(stream: &mut TcpStream) -> Result<ReceivedMessage> {
    let mut header = [0u8; 19];
    stream.read_exact(&mut header).await?;
    if header[0..16] != [0xff; 16] {
        return Err(anyhow!("invalid BGP marker"));
    }
    let length = u16::from_be_bytes([header[16], header[17]]) as usize;
    if !(19..=4096).contains(&length) {
        return Err(anyhow!("invalid BGP message length {length}"));
    }
    let mut raw = Vec::with_capacity(length);
    raw.extend_from_slice(&header);
    if length > 19 {
        let mut payload = vec![0; length - 19];
        stream.read_exact(&mut payload).await?;
        raw.extend_from_slice(&payload);
    }
    let mut raw32 = Bytes::from(raw.clone());
    let message = parse_bgp_message(&mut raw32, false, &AsnLength::Bits32)
        .or_else(|_| {
            let mut raw16 = Bytes::from(raw.clone());
            parse_bgp_message(&mut raw16, false, &AsnLength::Bits16)
        })
        .map_err(|error| anyhow!("failed parsing BGP message using bgpkit-parser: {error}"))?;
    Ok(ReceivedMessage { message, raw })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_open_advertises_dual_stack_as4_and_optional_route_refresh() {
        let BgpMessage::Open(open) = local_open(Ipv4Addr::new(192, 0, 2, 1), 65_536, 90, true)
        else {
            panic!()
        };
        assert_eq!(open.asn, Asn::new_16bit(AS_TRANS));
        let raw = BgpMessage::Open(open.clone())
            .encode(AsnLength::Bits32)
            .unwrap();
        let negotiated = negotiate_capabilities(&raw, true);
        assert!(negotiated.supports(Afi::Ipv4, Safi::Unicast));
        assert!(negotiated.supports(Afi::Ipv6, Safi::Unicast));
        assert!(negotiated.asn4);
        assert!(negotiated.route_refresh);
    }

    #[test]
    fn v6_announcements_use_mp_reach_not_classic_nlri() {
        let prefixes = vec![PrefixEntry {
            network: "2001:db8::/32".parse().unwrap(),
            next_hop: Some("2001:db8::1".parse().unwrap()),
        }];
        let mut negotiated = NegotiatedCapabilities::default();
        negotiated.families.insert((Afi::Ipv6, Safi::Unicast));
        let updates = build_announce_updates(
            &prefixes,
            Ipv4Addr::new(192, 0, 2, 1),
            "2001:db8::2".parse().unwrap(),
            65_001,
            &negotiated,
        );
        let BgpMessage::Update(update) = &updates[0] else {
            panic!()
        };
        assert!(update.announced_prefixes.is_empty());
        assert_eq!(
            update.attributes.get_reachable_nlri().unwrap().prefixes[0]
                .prefix
                .to_string(),
            "2001:db8::/32"
        );
    }
}
