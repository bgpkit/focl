use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
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

/// Where an originated prefix comes from: the config baseline or a runtime
/// `focl prefix add`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefixSource {
    Config,
    Runtime,
}

/// Announced state of a prefix in the effective originated set. `Absent` only
/// appears in mutation results, where the prefix is no longer part of the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefixStatus {
    Announced,
    Suppressed,
    Absent,
}

/// One row of `focl prefix list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixView {
    pub network: String,
    pub family: String,
    pub next_hop: Option<String>,
    pub status: PrefixStatus,
    pub source: PrefixSource,
}

/// Outcome of `focl prefix add` / `focl prefix remove`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixMutation {
    pub action: String,
    pub network: String,
    pub family: String,
    pub status: PrefixStatus,
    /// Provenance of the network at the time of the mutation. `None` when the
    /// state never knew it (for example removing a prefix that was neither
    /// configured nor added).
    pub source: Option<PrefixSource>,
    /// False when the effective originated set was already in the requested state.
    pub changed: bool,
    pub dry_run: bool,
    /// Established sessions the update was dispatched to (empty on a no-op;
    /// sessions filter by negotiated address family).
    pub peers_notified: Vec<String>,
}

/// Outcome of a `reload` for the originated prefix set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixReload {
    pub announced: Vec<String>,
    pub withdrawn: Vec<String>,
    pub overrides_reset: usize,
    pub peers_notified: Vec<String>,
}

/// An established session that accepts runtime route changes. The negotiated
/// families travel with the sender so dispatch and dry-run targets report only
/// peers that can actually carry the update.
#[derive(Debug, Clone)]
struct SessionHandle {
    tx: mpsc::Sender<SessionOp>,
    supports_v4: bool,
    supports_v6: bool,
}

impl SessionHandle {
    fn supports(&self, network: &IpNet) -> bool {
        match network {
            IpNet::V4(_) => self.supports_v4,
            IpNet::V6(_) => self.supports_v6,
        }
    }
}

/// An outbound route change pushed into one established session.
#[derive(Debug, Clone)]
enum SessionOp {
    Announce(PrefixEntry),
    Withdraw { network: IpNet },
}

/// Runtime overrides layered over the configured prefix list.
///
/// The config file stays the baseline; `added` and `suppressed` win until a
/// `reload` resets them. Runtime state is deliberately in-memory and never
/// written back to the config file, matching GoBGP's in-memory RIB and
/// OpenBGPD's dynamically added networks.
#[derive(Debug, Clone, Default)]
struct PrefixState {
    config: Vec<PrefixEntry>,
    added: BTreeMap<IpNet, PrefixEntry>,
    suppressed: BTreeSet<IpNet>,
}

impl PrefixState {
    fn new(config: Vec<PrefixEntry>) -> Self {
        Self {
            config,
            added: BTreeMap::new(),
            suppressed: BTreeSet::new(),
        }
    }

    fn override_count(&self) -> usize {
        self.added.len() + self.suppressed.len()
    }

    /// The set that is actually announced: (config + added) - suppressed.
    /// A runtime entry shadows the configured one for the same network, so an
    /// explicit `prefix add --next-hop` keeps working for configured prefixes.
    fn effective(&self) -> Vec<PrefixEntry> {
        let mut entries: Vec<PrefixEntry> = self
            .added
            .iter()
            .filter(|(network, _)| !self.suppressed.contains(*network))
            .map(|(_, entry)| entry.clone())
            .collect();
        for entry in &self.config {
            if self.suppressed.contains(&entry.network) || self.added.contains_key(&entry.network) {
                continue;
            }
            entries.push(entry.clone());
        }
        entries
    }

    fn is_known(&self, network: &IpNet) -> bool {
        self.added.contains_key(network) || self.config.iter().any(|e| e.network == *network)
    }

    fn is_announced(&self, network: &IpNet) -> bool {
        self.is_known(network) && !self.suppressed.contains(network)
    }

    fn status_of(&self, network: &IpNet) -> PrefixStatus {
        if self.is_announced(network) {
            PrefixStatus::Announced
        } else if self.is_known(network) {
            PrefixStatus::Suppressed
        } else {
            PrefixStatus::Absent
        }
    }

    /// Where a network's entry comes from, when the state knows it at all:
    /// an unknown network (never configured, or a runtime entry already
    /// dropped) has no provenance to report.
    fn source_of(&self, network: &IpNet) -> Option<PrefixSource> {
        if self.added.contains_key(network) {
            Some(PrefixSource::Runtime)
        } else if self.config.iter().any(|entry| entry.network == *network) {
            Some(PrefixSource::Config)
        } else {
            None
        }
    }

    /// Configured next hop for the prefix's family, if any. Runtime additions
    /// are deliberately excluded: inheriting from them would make the default
    /// depend on the order of earlier commands.
    fn default_next_hop(&self, network: &IpNet) -> Option<IpAddr> {
        let wants_v4 = matches!(network, IpNet::V4(_));
        self.config
            .iter()
            .filter_map(|entry| entry.next_hop)
            .find(|address| address.is_ipv4() == wants_v4)
    }

    fn view(&self) -> Vec<PrefixView> {
        let mut rows: Vec<PrefixView> = self
            .config
            .iter()
            .map(|entry| self.view_of(entry, PrefixSource::Config))
            .collect();
        for (network, entry) in &self.added {
            if self.config.iter().any(|e| e.network == *network) {
                continue;
            }
            rows.push(self.view_of(entry, PrefixSource::Runtime));
        }
        rows
    }

    fn view_of(&self, entry: &PrefixEntry, source: PrefixSource) -> PrefixView {
        PrefixView {
            network: entry.network.to_string(),
            family: family_name(&entry.network),
            next_hop: entry.next_hop.map(|address| address.to_string()),
            status: if self.suppressed.contains(&entry.network) {
                PrefixStatus::Suppressed
            } else {
                PrefixStatus::Announced
            },
            source,
        }
    }

    /// Records a runtime addition or override. Returns whether the effective
    /// originated set changed, which includes a next-hop change: peers keep the
    /// old next hop until the prefix is announced again.
    fn add(&mut self, entry: PrefixEntry) -> bool {
        let network = entry.network;
        let was_announced = self.is_announced(&network);
        let previous = self.added.get(&network).or_else(|| {
            self.config
                .iter()
                .find(|configured| configured.network == network)
        });
        let next_hop_changed = previous.map(|previous| previous.next_hop) != Some(entry.next_hop);
        let configured = self.config.iter().any(|e| e.network == network);
        // A runtime entry wins over the config baseline for the same network.
        let store = !configured || next_hop_changed || self.added.contains_key(&network);
        self.suppressed.remove(&network);
        if store {
            self.added.insert(network, entry);
        }
        !was_announced || next_hop_changed
    }

    /// Withdraws a prefix: a runtime-only entry is dropped, a configured one is
    /// suppressed. Returns whether the effective originated set changed.
    fn remove(&mut self, network: &IpNet) -> bool {
        let was_announced = self.is_announced(network);
        if self.added.remove(network).is_some() {
            return was_announced;
        }
        if self.config.iter().any(|e| e.network == *network) {
            self.suppressed.insert(*network);
        }
        was_announced
    }

    /// Replaces the config baseline and drops every runtime override, returning
    /// the prefixes to announce and to withdraw.
    fn reset_overrides(&mut self, config: Vec<PrefixEntry>) -> (Vec<PrefixEntry>, Vec<IpNet>) {
        let before = self.effective();
        self.config = config;
        self.added.clear();
        self.suppressed.clear();
        let after = self.effective();
        let announce = after
            .iter()
            .filter(|entry| !before.iter().any(|old| old.network == entry.network))
            .cloned()
            .collect();
        let withdraw = before
            .iter()
            .filter(|entry| !after.iter().any(|new| new.network == entry.network))
            .map(|entry| entry.network)
            .collect();
        (announce, withdraw)
    }
}

fn family_name(network: &IpNet) -> String {
    match network {
        IpNet::V4(_) => "v4",
        IpNet::V6(_) => "v6",
    }
    .to_string()
}

/// Parses the configured `[[prefixes]]` list into the baseline entry set.
fn parse_prefix_entries(cfg: &FoclConfig) -> Result<Vec<PrefixEntry>> {
    cfg.prefixes
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
        .context("invalid prefix in config")
}

fn ensure_next_hop_family(network: &IpNet, next_hop: IpAddr) -> Result<()> {
    let matches_family = matches!(
        (network, next_hop),
        (IpNet::V4(_), IpAddr::V4(_)) | (IpNet::V6(_), IpAddr::V6(_))
    );
    if matches_family {
        return Ok(());
    }
    Err(anyhow!(
        "next hop {next_hop} does not match the prefix family of {network}"
    ))
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
        self.families.contains(&(afi, safi))
    }

    /// True when the peer sent an OPEN with no capabilities at all (plain
    /// RFC 4271 IPv4-only speaker). IPv4 unicast is then still available.
    fn plain_ipv4(&self) -> bool {
        self.families.is_empty()
    }
}

struct BgpServiceInner {
    global_asn: u32,
    router_id: Ipv4Addr,
    /// Effective originated prefixes: config baseline plus runtime overrides.
    prefix_state: RwLock<PrefixState>,
    /// Serializes each runtime prefix mutation with its session dispatch, so
    /// concurrent control clients cannot enqueue a withdrawal before the
    /// announcement it reverses.
    prefix_ops: Mutex<()>,
    /// Established sessions that accept runtime route changes, keyed by peer address.
    session_ops: RwLock<HashMap<String, SessionHandle>>,
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
        let prefixes = parse_prefix_entries(cfg)?;
        let inner = Arc::new(BgpServiceInner {
            global_asn: cfg.global.asn,
            router_id,
            prefix_state: RwLock::new(PrefixState::new(prefixes)),
            prefix_ops: Mutex::new(()),
            session_ops: RwLock::new(HashMap::new()),
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

    async fn accept_inbound(&self, stream: TcpStream, remote: SocketAddr) {
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
            let result = service.run_session(&peer, stream).await;
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
        let ip: IpAddr = peer
            .address
            .parse()
            .with_context(|| format!("invalid peer address {}", peer.address))?;
        let addr = SocketAddr::new(ip, peer.remote_port);
        let stream = connect_with_optional_bind(peer, addr).await?;
        self.run_session(peer, stream).await
    }

    async fn run_session(&self, peer: &PeerConfig, stream: TcpStream) -> Result<()> {
        let local_ip = stream.local_addr()?.ip();
        self.inner
            .session_local_ips
            .write()
            .await
            .insert(peer.address.clone(), local_ip);
        let result = self.run_session_inner(peer, stream, local_ip).await;
        self.inner.session_ops.write().await.remove(&peer.address);
        result
    }

    async fn run_session_inner(
        &self,
        peer: &PeerConfig,
        stream: TcpStream,
        local_ip: IpAddr,
    ) -> Result<()> {
        let (reader, mut writer) = stream.into_split();
        // One task owns framing, so a runtime operation can never cancel a
        // partially consumed read: `read_exact` is not cancel-safe, and the
        // session loop below selects between control operations and messages.
        // The task ends when the socket closes or the receiver is dropped.
        let (msg_tx, mut msg_rx) = mpsc::channel::<Result<ReceivedMessage>>(32);
        tokio::spawn(async move {
            let mut reader = reader;
            loop {
                match read_bgp_message(&mut reader).await {
                    Ok(message) => {
                        if msg_tx.send(Ok(message)).await.is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = msg_tx.send(Err(error)).await;
                        return;
                    }
                }
            }
        });
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
        write_bgp_message(&mut writer, &open, AsnLength::Bits32).await?;

        let incoming = next_bgp_message(&mut msg_rx).await?;
        let BgpMessage::Open(remote_open) = incoming.message else {
            return Err(anyhow!("expected OPEN from peer"));
        };
        let negotiated = negotiate_capabilities(&incoming.raw, peer.route_refresh);
        validate_remote_as(&remote_open, &incoming.raw, peer.remote_as, negotiated.asn4)?;

        self.set_peer_state(&peer.address, PeerState::OpenConfirm, None, None)
            .await;
        write_bgp_message(&mut writer, &BgpMessage::KeepAlive, AsnLength::Bits32).await?;
        let incoming = next_bgp_message(&mut msg_rx).await?;
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
        self.send_prefix_announcements(peer, &mut writer, &negotiated, local_ip)
            .await?;
        // RFC 4271 End-of-RIB: an empty UPDATE per family marks the initial
        // table transfer complete. Vultr's route servers treat a session
        // missing EoR as still converging; send both families' markers.
        for eor_family in [Afi::Ipv4, Afi::Ipv6] {
            if negotiated.supports(eor_family, Safi::Unicast) {
                let eor = if eor_family == Afi::Ipv4 {
                    BgpMessage::Update(BgpUpdateMessage::default())
                } else {
                    let mut attrs = Attributes::default();
                    attrs.add_attr(
                        AttributeValue::MpUnreachNlri(Nlri {
                            afi: Afi::Ipv6,
                            safi: Safi::Unicast,
                            next_hop: None,
                            prefixes: vec![],
                            labeled_prefixes: None,
                            link_state_nlris: None,
                            flowspec_nlris: None,
                        })
                        .into(),
                    );
                    BgpMessage::Update(BgpUpdateMessage {
                        withdrawn_prefixes: vec![],
                        attributes: attrs,
                        announced_prefixes: vec![],
                    })
                };
                let asn_len = if negotiated.asn4 {
                    AsnLength::Bits32
                } else {
                    AsnLength::Bits16
                };
                write_bgp_message(&mut writer, &eor, asn_len).await?;
            }
        }

        // Register and send the initial table under the mutation lock: a
        // concurrent add/remove that lands between the snapshot and the
        // registration would otherwise never reach this session, leaving it
        // advertising a stale set until the next mutation.
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<SessionOp>(64);
        {
            let _guard = self.inner.prefix_ops.lock().await;
            let handle = SessionHandle {
                tx: ctrl_tx,
                supports_v4: negotiated.plain_ipv4()
                    || negotiated.supports(Afi::Ipv4, Safi::Unicast),
                supports_v6: negotiated.supports(Afi::Ipv6, Safi::Unicast),
            };
            self.inner
                .session_ops
                .write()
                .await
                .insert(peer.address.clone(), handle);
            self.send_prefix_announcements(peer, &mut writer, &negotiated, local_ip)
                .await?;
        }

        let negotiated_hold = Duration::from_secs(hold_time as u64);
        let keepalive_interval = Duration::from_secs((hold_time as u64 / 3).max(1));
        let mut next_keepalive = Instant::now() + keepalive_interval;
        let mut hold_deadline = Instant::now() + negotiated_hold;
        loop {
            let now = Instant::now();
            if now >= next_keepalive {
                write_bgp_message(&mut writer, &BgpMessage::KeepAlive, AsnLength::Bits32).await?;
                next_keepalive = now + keepalive_interval;
            }
            if now >= hold_deadline {
                return Err(anyhow!("hold timer expired"));
            }
            let timeout_dur = std::cmp::min(
                next_keepalive.saturating_duration_since(now),
                Duration::from_secs(1),
            );
            // Runtime announce/withdraw commands are applied between reads; the
            // read future is cancel-safe against this branch because both
            // borrow separate halves of the socket.
            tokio::select! {
                biased;
                op = ctrl_rx.recv() => {
                    if let Some(op) = op {
                        self.apply_session_op(peer, &mut writer, &negotiated, local_ip, op)
                            .await?;
                    }
                }
                incoming = timeout(timeout_dur, msg_rx.recv()) => {
                    match incoming {
                        Ok(Some(Ok(message))) => match message.message {
                            BgpMessage::Update(update) => {
                                self.ingest_received_update(
                                    peer,
                                    local_as,
                                    local_ip,
                                    update,
                                    message.raw,
                                    &negotiated,
                                )
                                .await?;
                                hold_deadline = Instant::now() + negotiated_hold;
                            }
                            BgpMessage::KeepAlive
                            | BgpMessage::Open(_)
                            | BgpMessage::RouteRefresh(_) => {
                                hold_deadline = Instant::now() + negotiated_hold;
                            }
                            BgpMessage::Notification(_) => {
                                return Err(anyhow!("received NOTIFICATION from peer"))
                            }
                        },
                        Ok(Some(Err(error))) => return Err(error),
                        Ok(None) => return Err(anyhow!("peer reader stopped")),
                        // Tick: keepalive and hold timers are handled above.
                        Err(_) => {}
                    }
                }
            }
        }
    }

    /// Applies one runtime route change to this session: build, write, archive,
    /// then refresh the advertised-prefix count for the peer.
    async fn apply_session_op<W: AsyncWrite + Unpin>(
        &self,
        peer: &PeerConfig,
        writer: &mut W,
        negotiated: &NegotiatedCapabilities,
        local_ip: IpAddr,
        op: SessionOp,
    ) -> Result<()> {
        let local_as = peer.local_as.unwrap_or(self.inner.global_asn);
        let updates = match &op {
            SessionOp::Announce(entry) => build_announce_updates(
                std::slice::from_ref(entry),
                self.inner.router_id,
                local_ip,
                local_as,
                negotiated,
            ),
            SessionOp::Withdraw { network } => {
                build_withdraw_updates(std::slice::from_ref(network), negotiated)
            }
        };
        self.emit_updates(peer, writer, negotiated, local_ip, local_as, updates)
            .await?;
        self.refresh_advertised_count(peer, local_ip, local_as, negotiated)
            .await;
        Ok(())
    }

    /// Recomputes how many announcements this session currently carries.
    async fn refresh_advertised_count(
        &self,
        peer: &PeerConfig,
        local_ip: IpAddr,
        local_as: u32,
        negotiated: &NegotiatedCapabilities,
    ) {
        let prefixes = self.inner.prefix_state.read().await.effective();
        let advertised = build_announce_updates(
            &prefixes,
            self.inner.router_id,
            local_ip,
            local_as,
            negotiated,
        )
        .len();
        let mut peers = self.inner.peers.write().await;
        if let Some(runtime) = peers.get_mut(&peer.address) {
            runtime.info.advertised_prefixes = advertised;
        }
    }

    /// Writes updates to one session and mirrors them into the archive. The
    /// archive is receive-only for a collector, so our own announcements are
    /// recorded here to keep a self-contained lab archive complete.
    async fn emit_updates<W: AsyncWrite + Unpin>(
        &self,
        peer: &PeerConfig,
        writer: &mut W,
        negotiated: &NegotiatedCapabilities,
        local_ip: IpAddr,
        local_as: u32,
        updates: Vec<BgpMessage>,
    ) -> Result<()> {
        let asn_len = if negotiated.asn4 {
            AsnLength::Bits32
        } else {
            AsnLength::Bits16
        };
        for update in updates {
            let raw = write_bgp_message(writer, &update, asn_len).await?;
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
        Ok(())
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
        // Plain IPv4 NLRI is only valid on a session that carries IPv4
        // (negotiated v4 MP capability or a capability-less RFC 4271 peer).
        let classic_ipv4_ok =
            negotiated.plain_ipv4() || negotiated.supports(Afi::Ipv4, Safi::Unicast);
        for prefix in &update.withdrawn_prefixes {
            if classic_ipv4_ok {
                rib.remove(prefix.prefix);
            }
        }
        for prefix in &update.announced_prefixes {
            if classic_ipv4_ok {
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

    async fn send_prefix_announcements<W: AsyncWrite + Unpin>(
        &self,
        peer: &PeerConfig,
        writer: &mut W,
        negotiated: &NegotiatedCapabilities,
        local_ip: IpAddr,
    ) -> Result<()> {
        let local_as = peer.local_as.unwrap_or(self.inner.global_asn);
        let prefixes = self.inner.prefix_state.read().await.effective();
        let updates = build_announce_updates(
            &prefixes,
            self.inner.router_id,
            local_ip,
            local_as,
            negotiated,
        );
        let advertised = updates.len();
        self.emit_updates(peer, writer, negotiated, local_ip, local_as, updates)
            .await?;
        let mut peers = self.inner.peers.write().await;
        if let Some(runtime) = peers.get_mut(&peer.address) {
            runtime.info.advertised_prefixes = advertised;
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

    /// Effective originated prefix set with provenance and status.
    pub async fn prefix_view(&self) -> Vec<PrefixView> {
        self.inner.prefix_state.read().await.view()
    }

    /// Announces (or re-announces) a prefix at runtime and pushes the update to
    /// every established session.
    pub async fn prefix_add(
        &self,
        network: IpNet,
        next_hop: Option<IpAddr>,
        dry_run: bool,
    ) -> Result<PrefixMutation> {
        // Serialize the mutation with its dispatch: two concurrent control
        // clients must not be able to enqueue changes out of order.
        let _guard = self.inner.prefix_ops.lock().await;
        if let Some(next_hop) = next_hop {
            ensure_next_hop_family(&network, next_hop)?;
        }
        let entry = {
            let state = self.inner.prefix_state.read().await;
            PrefixEntry {
                network,
                next_hop: next_hop.or_else(|| state.default_next_hop(&network)),
            }
        };
        // A dry run reports what would happen without touching the state.
        let changed = if dry_run {
            !self.inner.prefix_state.read().await.is_announced(&network)
        } else {
            self.inner.prefix_state.write().await.add(entry.clone())
        };
        let peers_notified = if !changed {
            Vec::new()
        } else if dry_run {
            self.session_targets(&network).await
        } else {
            self.dispatch_session_op(SessionOp::Announce(entry)).await
        };
        let state = self.inner.prefix_state.read().await;
        Ok(PrefixMutation {
            action: "announce".to_string(),
            network: network.to_string(),
            family: family_name(&network),
            status: state.status_of(&network),
            source: state.source_of(&network),
            changed,
            dry_run,
            peers_notified,
        })
    }

    /// Withdraws a prefix at runtime: a configured prefix is suppressed, a
    /// runtime-only one is dropped.
    pub async fn prefix_remove(&self, network: IpNet, dry_run: bool) -> Result<PrefixMutation> {
        // Provenance has to be read before the entry is dropped.
        let previous_source = self.inner.prefix_state.read().await.source_of(&network);
        let _guard = self.inner.prefix_ops.lock().await;
        let changed = if dry_run {
            self.inner.prefix_state.read().await.is_announced(&network)
        } else {
            self.inner.prefix_state.write().await.remove(&network)
        };
        let peers_notified = if !changed {
            Vec::new()
        } else if dry_run {
            self.session_targets(&network).await
        } else {
            self.dispatch_session_op(SessionOp::Withdraw { network })
                .await
        };
        let state = self.inner.prefix_state.read().await;
        Ok(PrefixMutation {
            action: "withdraw".to_string(),
            network: network.to_string(),
            family: family_name(&network),
            status: state.status_of(&network),
            source: state.source_of(&network).or(previous_source),
            changed,
            dry_run,
            peers_notified,
        })
    }

    /// Re-reads the configured prefix list, applies the delta, and clears every
    /// runtime override. Peer sessions and other config sections are untouched.
    pub async fn reload_prefixes(&self, cfg: &FoclConfig) -> Result<PrefixReload> {
        let _guard = self.inner.prefix_ops.lock().await;
        let entries = parse_prefix_entries(cfg)?;
        let (announce, withdraw, overrides_reset) = {
            let mut state = self.inner.prefix_state.write().await;
            let overrides_reset = state.override_count();
            let (announce, withdraw) = state.reset_overrides(entries);
            (announce, withdraw, overrides_reset)
        };
        let mut peers_notified = Vec::new();
        for entry in announce.iter() {
            peers_notified.extend(
                self.dispatch_session_op(SessionOp::Announce(entry.clone()))
                    .await,
            );
        }
        for network in withdraw.iter() {
            peers_notified.extend(
                self.dispatch_session_op(SessionOp::Withdraw { network: *network })
                    .await,
            );
        }
        peers_notified.sort();
        peers_notified.dedup();
        Ok(PrefixReload {
            announced: announce
                .iter()
                .map(|entry| entry.network.to_string())
                .collect(),
            withdrawn: withdraw.iter().map(|network| network.to_string()).collect(),
            overrides_reset,
            peers_notified,
        })
    }

    /// Dispatches one route change to every established session that carries
    /// the prefix's address family, returning the peers that accepted it.
    async fn dispatch_session_op(&self, op: SessionOp) -> Vec<String> {
        let network = match &op {
            SessionOp::Announce(entry) => entry.network,
            SessionOp::Withdraw { network } => *network,
        };
        let handles: Vec<(String, SessionHandle)> = self
            .inner
            .session_ops
            .read()
            .await
            .iter()
            .filter(|(_, handle)| handle.supports(&network))
            .map(|(peer, handle)| (peer.clone(), handle.clone()))
            .collect();
        let mut notified = Vec::new();
        for (peer, handle) in handles {
            if handle.tx.send(op.clone()).await.is_ok() {
                notified.push(peer);
            }
        }
        notified.sort();
        notified
    }

    /// Established sessions that could carry the prefix's family, without
    /// dispatching anything (`--dry-run`).
    async fn session_targets(&self, network: &IpNet) -> Vec<String> {
        let mut targets: Vec<String> = self
            .inner
            .session_ops
            .read()
            .await
            .iter()
            .filter(|(_, handle)| handle.supports(network))
            .map(|(peer, _)| peer.clone())
            .collect();
        targets.sort();
        targets
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
            .prefix_state
            .read()
            .await
            .effective()
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
    let plain_ipv4 = negotiated.plain_ipv4();
    for prefix in prefixes
        .iter()
        .filter(|prefix| matches!(prefix.network, IpNet::V4(_)))
    {
        if plain_ipv4 || negotiated.supports(Afi::Ipv4, Safi::Unicast) {
            let mut attrs = base_announce_attributes(local_as);
            let next_hop = prefix.next_hop.unwrap_or(IpAddr::V4(router_id));
            attrs.add_attr(AttributeValue::NextHop(next_hop).into());
            result.push(BgpMessage::Update(BgpUpdateMessage {
                withdrawn_prefixes: vec![],
                attributes: attrs,
                announced_prefixes: vec![NetworkPrefix::new(prefix.network, None)],
            }));
        }
    }
    for prefix in prefixes
        .iter()
        .filter(|prefix| matches!(prefix.network, IpNet::V6(_)))
    {
        if !negotiated.supports(Afi::Ipv6, Safi::Unicast) {
            continue;
        }
        let mut attrs = base_announce_attributes(local_as);
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

/// Builds the withdrawal updates for one family set. IPv4 withdrawals use the
/// classic withdrawn-NLRI field; IPv6 withdrawals use MP_UNREACH.
fn build_withdraw_updates(
    networks: &[IpNet],
    negotiated: &NegotiatedCapabilities,
) -> Vec<BgpMessage> {
    let mut result = Vec::new();
    let classic_ipv4_ok = negotiated.plain_ipv4() || negotiated.supports(Afi::Ipv4, Safi::Unicast);
    let v4: Vec<NetworkPrefix> = networks
        .iter()
        .filter(|network| matches!(network, IpNet::V4(_)))
        .map(|network| NetworkPrefix::new(*network, None))
        .collect();
    if classic_ipv4_ok && !v4.is_empty() {
        result.push(BgpMessage::Update(BgpUpdateMessage {
            withdrawn_prefixes: v4,
            attributes: Attributes::default(),
            announced_prefixes: vec![],
        }));
    }
    if negotiated.supports(Afi::Ipv6, Safi::Unicast) {
        let v6: Vec<NetworkPrefix> = networks
            .iter()
            .filter(|network| matches!(network, IpNet::V6(_)))
            .map(|network| NetworkPrefix::new(*network, None))
            .collect();
        if !v6.is_empty() {
            let mut attrs = Attributes::default();
            attrs.add_attr(
                AttributeValue::MpUnreachNlri(Nlri {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                    next_hop: None,
                    prefixes: v6,
                    labeled_prefixes: None,
                    link_state_nlris: None,
                    flowspec_nlris: None,
                })
                .into(),
            );
            result.push(BgpMessage::Update(BgpUpdateMessage {
                withdrawn_prefixes: vec![],
                attributes: attrs,
                announced_prefixes: vec![],
            }));
        }
    }
    result
}

fn base_announce_attributes(local_as: u32) -> Attributes {
    let mut attrs = Attributes::default();
    attrs.add_attr(AttributeValue::Origin(Origin::IGP).into());
    attrs.add_attr(
        AttributeValue::AsPath {
            path: AsPath::from_sequence([local_as]),
            // `is_as4: true` selects AS4_PATH (attribute type 17), which is
            // only for the RFC 6793 migration fallback. On a session that
            // negotiated 4-octet AS, the correct wire form is AS_PATH (type 2)
            // with 4-octet segments: keep this false and let the session
            // AsnLength (Bits32 when AS4, Bits16 otherwise) drive the width.
            is_as4: false,
        }
        .into(),
    );
    attrs
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

async fn write_bgp_message<W: AsyncWrite + Unpin>(
    stream: &mut W,
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

/// Awaits the next framed message from a session's reader task.
async fn next_bgp_message(
    rx: &mut mpsc::Receiver<Result<ReceivedMessage>>,
) -> Result<ReceivedMessage> {
    match rx.recv().await {
        Some(Ok(message)) => Ok(message),
        Some(Err(error)) => Err(error),
        None => Err(anyhow!("peer reader stopped")),
    }
}

async fn read_bgp_message<R: AsyncRead + Unpin>(stream: &mut R) -> Result<ReceivedMessage> {
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
    fn announce_updates_use_type2_as_path_with_negotiated_width() {
        fn as_path_attr(msg: &BgpMessage, asn_len: AsnLength) -> (u8, Vec<u8>) {
            let BgpMessage::Update(u) = msg else {
                panic!("not an UPDATE")
            };
            let mut buf = bytes::BytesMut::new();
            u.attributes.encode_to(asn_len, &mut buf).unwrap();
            let mut p = 0;
            while p < buf.len() {
                let flags = buf[p];
                let code = buf[p + 1];
                let (l, hdr) = if flags & 0x10 != 0 {
                    (u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize, 4)
                } else {
                    (buf[p + 2] as usize, 3)
                };
                if code == 2 || code == 17 {
                    return (code, buf[p + hdr..p + hdr + l].to_vec());
                }
                p += hdr + l;
            }
            panic!("no AS_PATH attribute found");
        }

        let prefixes = vec![PrefixEntry {
            network: "192.0.2.0/24".parse().unwrap(),
            next_hop: None,
        }];

        let negotiated = NegotiatedCapabilities {
            families: HashSet::from([(Afi::Ipv4, Safi::Unicast)]),
            asn4: true,
            ..Default::default()
        };
        let updates = build_announce_updates(
            &prefixes,
            "192.0.2.1".parse().unwrap(),
            IpAddr::V4("192.0.2.1".parse().unwrap()),
            400644,
            &negotiated,
        );
        // RFC 6793: AS4-capable session carries AS_PATH (type 2) with
        // 4-octet segments, one AS_SEQUENCE {400644} = 0x00061D04.
        let (code, val) = as_path_attr(&updates[0], AsnLength::Bits32);
        assert_eq!(
            (code, val.as_slice()),
            (2u8, &[2u8, 1, 0x00, 0x06, 0x1D, 0x04][..])
        );

        // Plain 16-bit peer (e.g. local AS 65010): type 2 with 2-octet segments.
        let plain = NegotiatedCapabilities {
            families: HashSet::from([(Afi::Ipv4, Safi::Unicast)]),
            asn4: false,
            ..Default::default()
        };
        let updates = build_announce_updates(
            &prefixes,
            "192.0.2.1".parse().unwrap(),
            IpAddr::V4("192.0.2.1".parse().unwrap()),
            65010,
            &plain,
        );
        let (code, val) = as_path_attr(&updates[0], AsnLength::Bits16);
        assert_eq!((code, val.as_slice()), (2u8, &[2u8, 1, 0xFD, 0xF2][..]));
    }

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
    fn prefix_state_layers_runtime_overrides_over_config() {
        let config = vec![
            PrefixEntry {
                network: "192.0.2.0/24".parse().unwrap(),
                next_hop: Some("192.0.2.1".parse().unwrap()),
            },
            PrefixEntry {
                network: "2001:db8::/48".parse().unwrap(),
                next_hop: None,
            },
        ];
        let v6: IpNet = "2001:db8::/48".parse().unwrap();
        let mut state = PrefixState::new(config);

        // Suppressing a configured prefix withdraws it from the effective set.
        assert!(state.remove(&v6));
        assert_eq!(state.effective().len(), 1);
        assert_eq!(state.status_of(&v6), PrefixStatus::Suppressed);
        assert_eq!(state.source_of(&v6), Some(PrefixSource::Config));
        // Removing it again changes nothing.
        assert!(!state.remove(&v6));

        // Re-adding restores the config entry without duplicating it.
        assert!(state.add(PrefixEntry {
            network: v6,
            next_hop: None,
        }));
        assert_eq!(state.effective().len(), 2);
        assert_eq!(state.override_count(), 0);

        // A runtime-only entry is added and dropped without residue.
        let runtime_only: IpNet = "198.51.100.0/24".parse().unwrap();
        assert!(state.add(PrefixEntry {
            network: runtime_only,
            next_hop: None,
        }));
        assert_eq!(state.source_of(&runtime_only), Some(PrefixSource::Runtime));
        assert_eq!(state.status_of(&runtime_only), PrefixStatus::Announced);
        assert!(state.remove(&runtime_only));
        assert_eq!(state.status_of(&runtime_only), PrefixStatus::Absent);
        assert_eq!(state.override_count(), 0);
    }

    #[test]
    fn reload_resets_overrides_and_reports_the_delta() {
        let suppressed: IpNet = "192.0.2.0/24".parse().unwrap();
        let runtime_only: IpNet = "198.51.100.0/24".parse().unwrap();
        let mut state = PrefixState::new(vec![PrefixEntry {
            network: suppressed,
            next_hop: None,
        }]);
        assert!(state.remove(&suppressed));
        assert!(state.add(PrefixEntry {
            network: runtime_only,
            next_hop: None,
        }));

        let added: IpNet = "203.0.113.0/24".parse().unwrap();
        let (announce, withdraw) = state.reset_overrides(vec![PrefixEntry {
            network: added,
            next_hop: None,
        }]);

        assert_eq!(
            announce
                .iter()
                .map(|entry| entry.network.to_string())
                .collect::<Vec<_>>(),
            vec!["203.0.113.0/24"]
        );
        // The suppressed config prefix was not announced before the reload, so
        // only the runtime addition needs withdrawing.
        assert_eq!(
            withdraw
                .iter()
                .map(|network| network.to_string())
                .collect::<Vec<_>>(),
            vec!["198.51.100.0/24"]
        );
        assert_eq!(state.override_count(), 0);
    }

    #[test]
    fn reload_re_announces_a_suppressed_prefix() {
        let entry = PrefixEntry {
            network: "2620:aa:a000::/48".parse().unwrap(),
            next_hop: None,
        };
        let mut state = PrefixState::new(vec![entry.clone()]);
        assert!(state.remove(&entry.network));
        assert!(state.effective().is_empty());

        // An unchanged config re-announces what the operator suppressed.
        let (announce, withdraw) = state.reset_overrides(vec![entry.clone()]);
        assert_eq!(announce.len(), 1);
        assert!(withdraw.is_empty());
        assert_eq!(state.status_of(&entry.network), PrefixStatus::Announced);
    }

    #[test]
    fn withdraw_updates_use_withdrawn_nlri_for_v4_and_mp_unreach_for_v6() {
        let networks: Vec<IpNet> = vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/48".parse().unwrap(),
        ];
        let negotiated = NegotiatedCapabilities {
            families: HashSet::from([(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]),
            ..Default::default()
        };
        let updates = build_withdraw_updates(&networks, &negotiated);
        assert_eq!(updates.len(), 2);

        let BgpMessage::Update(v4) = &updates[0] else {
            panic!("not an UPDATE")
        };
        assert_eq!(v4.withdrawn_prefixes.len(), 1);
        assert_eq!(v4.withdrawn_prefixes[0].prefix.to_string(), "192.0.2.0/24");
        assert!(v4.announced_prefixes.is_empty());

        let BgpMessage::Update(v6) = &updates[1] else {
            panic!("not an UPDATE")
        };
        assert!(v6.withdrawn_prefixes.is_empty());
        let unreach = v6
            .attributes
            .get_unreachable_nlri()
            .expect("MP_UNREACH present");
        assert_eq!(unreach.afi, Afi::Ipv6);
        assert_eq!(unreach.prefixes.len(), 1);
        assert_eq!(unreach.prefixes[0].prefix.to_string(), "2001:db8::/48");
    }

    #[test]
    fn withdraw_and_announce_respect_negotiated_families() {
        let v6: IpNet = "2001:db8::/48".parse().unwrap();
        let v4_only = NegotiatedCapabilities {
            families: HashSet::from([(Afi::Ipv4, Safi::Unicast)]),
            ..Default::default()
        };
        assert!(build_withdraw_updates(&[v6], &v4_only).is_empty());
        assert!(build_announce_updates(
            &[PrefixEntry {
                network: v6,
                next_hop: None,
            }],
            Ipv4Addr::new(192, 0, 2, 1),
            "192.0.2.2".parse().unwrap(),
            65_001,
            &v4_only,
        )
        .is_empty());
    }

    #[test]
    fn next_hop_family_mismatch_is_rejected() {
        let v6: IpNet = "2001:db8::/48".parse().unwrap();
        assert!(ensure_next_hop_family(&v6, "192.0.2.1".parse().unwrap()).is_err());
        assert!(ensure_next_hop_family(&v6, "2001:db8::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn next_hop_change_is_a_change() {
        let network: IpNet = "198.51.100.0/24".parse().unwrap();
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.9".parse().unwrap();
        let mut state = PrefixState::new(vec![]);

        assert!(state.add(PrefixEntry {
            network,
            next_hop: Some(first),
        }));
        // Same next hop again: nothing to announce.
        assert!(!state.add(PrefixEntry {
            network,
            next_hop: Some(first),
        }));
        // A different next hop must re-announce, and the effective entry follows.
        assert!(state.add(PrefixEntry {
            network,
            next_hop: Some(second),
        }));
        let effective = state.effective();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].next_hop, Some(second));
    }

    #[test]
    fn runtime_override_shadows_the_configured_next_hop() {
        let network: IpNet = "192.0.2.0/24".parse().unwrap();
        let configured: IpAddr = "10.0.0.1".parse().unwrap();
        let override_hop: IpAddr = "10.0.0.9".parse().unwrap();
        let mut state = PrefixState::new(vec![PrefixEntry {
            network,
            next_hop: Some(configured),
        }]);

        assert!(!state.add(PrefixEntry {
            network,
            next_hop: Some(configured),
        }));
        assert!(state.add(PrefixEntry {
            network,
            next_hop: Some(override_hop),
        }));
        let effective = state.effective();
        assert_eq!(
            effective.len(),
            1,
            "the config entry must not be duplicated"
        );
        assert_eq!(effective[0].next_hop, Some(override_hop));
    }

    #[test]
    fn default_next_hop_comes_from_the_config_only() {
        let v4: IpNet = "192.0.2.0/24".parse().unwrap();
        let v6: IpNet = "2001:db8::/48".parse().unwrap();
        let mut state = PrefixState::new(vec![PrefixEntry {
            network: v4,
            next_hop: Some("10.0.0.1".parse().unwrap()),
        }]);

        assert_eq!(
            state.default_next_hop(&v4),
            Some("10.0.0.1".parse().unwrap())
        );
        // No configured v6 next hop: a runtime addition must not become the
        // default for later commands.
        assert_eq!(state.default_next_hop(&v6), None);
        state.add(PrefixEntry {
            network: v6,
            next_hop: Some("2001:db8::1".parse().unwrap()),
        });
        assert_eq!(state.default_next_hop(&v6), None);
    }

    fn test_service_config() -> FoclConfig {
        toml::from_str(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen = false
control_socket = "/tmp/focl-test-only.sock"

[archive]
enabled = false
"#,
        )
        .expect("test config parses")
    }

    #[tokio::test]
    async fn dry_run_reports_without_changing_state() {
        let cfg = test_service_config();
        let (event_tx, _) = broadcast::channel::<EventEnvelope>(4);
        let service = BgpService::new(&cfg, event_tx).await.unwrap();
        let network: IpNet = "192.0.2.0/24".parse().unwrap();

        let dry_add = service.prefix_add(network, None, true).await.unwrap();
        assert!(dry_add.changed && dry_add.dry_run);
        assert!(
            service.prefix_view().await.is_empty(),
            "a dry run must not originate the prefix"
        );

        let applied = service.prefix_add(network, None, false).await.unwrap();
        assert!(applied.changed && !applied.dry_run);
        assert_eq!(service.prefix_view().await.len(), 1);

        let dry_remove = service.prefix_remove(network, true).await.unwrap();
        assert!(dry_remove.changed && dry_remove.dry_run);
        assert_eq!(
            service.prefix_view().await.len(),
            1,
            "a dry run must not withdraw the prefix"
        );

        let removed = service.prefix_remove(network, false).await.unwrap();
        assert!(removed.changed);
        assert!(service.prefix_view().await.is_empty());
    }

    #[tokio::test]
    async fn prefix_add_rejects_a_mismatched_next_hop() {
        let cfg = test_service_config();
        let (event_tx, _) = broadcast::channel::<EventEnvelope>(4);
        let service = BgpService::new(&cfg, event_tx).await.unwrap();
        let network: IpNet = "2001:db8::/48".parse().unwrap();
        let error = service
            .prefix_add(network, Some("192.0.2.1".parse().unwrap()), false)
            .await
            .expect_err("IPv4 next hop on an IPv6 prefix must be rejected");
        assert!(error
            .to_string()
            .contains("does not match the prefix family"));
        assert!(service.prefix_view().await.is_empty());
    }
}
