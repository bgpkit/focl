use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bgpkit_parser::bgp::parse_bgp_message;
use bgpkit_parser::models::{
    Afi, AsPath, Asn, AsnLength, AttrFlags, AttrType, Attribute, AttributeValue, Attributes,
    BgpMessage, BgpOpenMessage, BgpRouteRefreshMessage, BgpUpdateMessage, NetworkPrefix, Nlri,
    OptParam, Origin, ParamValue, Safi,
};
use bytes::Bytes;
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

use crate::archive::types::{
    PeerStateRecordInput, RibSnapshotInput, SnapshotPeer, SnapshotRoute, UpdateRecordInput,
};
use crate::archive::{ArchiveService, RibSnapshotSource, SnapshotInputFuture};
use crate::bmp::wire::{self as bmp_wire, PeerHeader};
use crate::bmp::ExportHandle;
use crate::config::{FoclConfig, PeerConfig, TcpAoKeyConfig};
use crate::types::{Event, EventEnvelope, PeerAuthMode, PeerState};

mod auth;
/// TCP-MD5 (RFC 2385) and TCP-AO (RFC 5925) socket helpers. Re-exported so
/// library users and the socket-level tests can authenticate a session against
/// `focld` the same way the daemon does.
pub use auth::{tcp_ao_probe, tcp_ao_supported, TcpAoStatus, TcpSocketExt, TcpStreamExt};

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
    #[serde(default)]
    pub auth_mode: PeerAuthMode,
    pub state: PeerState,
    pub last_error: Option<String>,
    /// Set when a key for this peer could not be installed on the listening
    /// socket. Unlike `last_error` it is not a session outcome, so a later
    /// connection error or a session that established with the keys that did
    /// install never clears it.
    #[serde(default)]
    pub listener_key_error: Option<String>,
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
    /// The peer's BGP identifier, learned from its OPEN. A TABLE_DUMP_V2
    /// snapshot Peer entry carries it; it is unspecified until a session has
    /// presented an OPEN.
    remote_bgp_id: Option<Ipv4Addr>,
}

#[derive(Debug, Clone)]
struct PrefixEntry {
    network: IpNet,
    next_hop: Option<IpAddr>,
    /// Attribute-255 clock refresh interval in seconds, when this prefix
    /// carries the development attribute clock.
    dev_attr255_interval_secs: Option<u32>,
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
    /// RFC 2918 route refresh was negotiated on both sides for this family, so a request will be
    /// answered rather than ignored.
    refresh_v4: bool,
    refresh_v6: bool,
}

impl SessionHandle {
    /// Families this session can be asked to resend its table for.
    fn refreshable_families(&self) -> Vec<Afi> {
        let mut families = Vec::with_capacity(2);
        if self.supports_v4 && self.refresh_v4 {
            families.push(Afi::Ipv4);
        }
        if self.supports_v6 && self.refresh_v6 {
            families.push(Afi::Ipv6);
        }
        families
    }
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
    Withdraw {
        network: IpNet,
    },
    /// Ask the peer to resend its Adj-RIB-In for one family (RFC 2918). focl sends no routes of
    /// its own for this: the peer answers with the table it holds now, which a station that
    /// attached after the session came up needs in order to have a baseline at all.
    RequestRefresh {
        afi: Afi,
    },
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

    /// Configured attribute-255 clock interval for the network, if any. Like
    /// `default_next_hop`, only the config baseline is consulted, so a runtime
    /// add for a configured network keeps the configured clock.
    fn configured_attr255_interval(&self, network: &IpNet) -> Option<u32> {
        self.config
            .iter()
            .find(|entry| entry.network == *network)
            .and_then(|entry| entry.dev_attr255_interval_secs)
    }

    fn view(&self) -> Vec<PrefixView> {
        let mut rows: Vec<PrefixView> = self
            .config
            .iter()
            .map(|entry| {
                // A runtime entry shadows the configured one for the same
                // network, so the row has to describe the entry that is
                // actually announced, not the config baseline behind it.
                match self.added.get(&entry.network) {
                    Some(runtime) => self.view_of(runtime, PrefixSource::Runtime),
                    None => self.view_of(entry, PrefixSource::Config),
                }
            })
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
        // Dropping a runtime override alone leaves a configured network
        // announced through the config baseline, so a configured network has to
        // be suppressed as well; otherwise peers get a withdrawal while the
        // state still calls the network announced.
        self.added.remove(network);
        if self.config.iter().any(|e| e.network == *network) {
            self.suppressed.insert(*network);
        }
        was_announced
    }

    /// Replaces the config baseline and drops every runtime override, returning
    /// the prefixes to announce and to withdraw.
    ///
    /// The delta compares whole entries, not just networks: a changed configured
    /// next hop or a changed/cleared attribute-255 interval updates the internal
    /// state but leaves established peers with the old attributes on the wire, so
    /// it counts as an announcement. A changed interval only takes effect after
    /// a restart, because the refresh task set is sampled at startup.
    fn reset_overrides(&mut self, config: Vec<PrefixEntry>) -> (Vec<PrefixEntry>, Vec<IpNet>) {
        let before = self.effective();
        self.config = config;
        self.added.clear();
        self.suppressed.clear();
        let after = self.effective();
        let announce = after
            .iter()
            .filter(|entry| {
                !before.iter().any(|old| {
                    old.network == entry.network
                        && old.next_hop == entry.next_hop
                        && old.dev_attr255_interval_secs == entry.dev_attr255_interval_secs
                })
            })
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
            if let Some(next_hop) = next_hop {
                // Same check as the runtime path: classic NEXT_HOP only carries
                // the prefix's own family, so a mismatched configured next hop
                // would encode a 16-octet v6 NEXT_HOP on a v4 announcement (the
                // inverse is dropped later), never reaching the wire as intended.
                ensure_next_hop_family(&network, next_hop).with_context(|| {
                    format!(
                        "invalid prefix entry {} with next hop {next_hop}",
                        p.network
                    )
                })?;
            }
            Ok::<_, anyhow::Error>(PrefixEntry {
                network,
                next_hop,
                dev_attr255_interval_secs: p.dev_attr255_interval_secs,
            })
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
    /// The received AS path, kept parsed rather than formatted: a RIB snapshot
    /// rebuilds the route's AS_PATH attribute from it.
    as_path: Option<AsPath>,
    /// The received ORIGIN, when the peer sent one.
    origin: Option<Origin>,
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

    /// Whether the session carries the family for announcements and for
    /// End-of-RIB: a capability-less peer still has classic IPv4 (RFC 4271),
    /// so every IPv4 decision has to accept [`Self::plain_ipv4`] as well.
    fn carries(&self, afi: Afi, safi: Safi) -> bool {
        self.supports(afi, safi) || (afi == Afi::Ipv4 && safi == Safi::Unicast && self.plain_ipv4())
    }

    /// AS number width on this session's wire (RFC 6793).
    fn asn_length(&self) -> AsnLength {
        if self.asn4 {
            AsnLength::Bits32
        } else {
            AsnLength::Bits16
        }
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
    /// One entry per `[[bmp.stations]]`: every session forwards what the peer sent it (Adj-RIB-In)
    /// to the inbound stations and what it sent the peer (Adj-RIB-Out) to the others.
    bmp: Vec<ExportHandle>,
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
        Self::new_with_sinks(cfg, event_tx, archive, Vec::new()).await
    }

    /// Builds the speaker with every optional sink attached.
    ///
    /// The BMP handle is a sink like the archive: sessions hand frames to it and never wait for it,
    /// so a station that is down costs frames from that station's view, not session progress.
    pub async fn new_with_sinks(
        cfg: &FoclConfig,
        event_tx: broadcast::Sender<EventEnvelope>,
        archive: Option<Arc<ArchiveService>>,
        bmp: Vec<ExportHandle>,
    ) -> Result<Self> {
        // `FoclConfig::load` validates, but a config built in code arrives
        // unchecked, and `peer_auth` relies on a peer naming one mechanism.
        cfg.validate().context("invalid configuration")?;
        // Only a peer that authenticates with TCP-AO depends on the kernel
        // option: a host that cannot answer the probe must not refuse a
        // configuration that never asks for it.
        if let Some(supported) = probe_kernel_tcp_ao(&cfg.peers, auth::tcp_ao_probe)? {
            require_tcp_ao_support(&cfg.peers, supported)?;
        }
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
            bmp,
        });
        let service = Self { inner };
        service.start_peers(&cfg.peers).await;
        if cfg.global.listen {
            service
                .start_listener(&cfg.global.listen_addr, &cfg.peers)
                .await?;
        }
        service.start_clock_refresh().await;
        Ok(service)
    }

    async fn start_peers(&self, peers: &[PeerConfig]) {
        for peer in peers.iter().filter(|peer| peer.enabled) {
            self.inner
                .rib_in
                .write()
                .await
                .insert(peer.address.clone(), IpnetTrie::new());
        }
        // Register every peer before spawning its loop: an active peer reports
        // its first state as soon as the task runs, and a write that arrives
        // before the peer is in the map is dropped. The map stays locked across
        // the spawn, so that first write waits for the registration.
        let mut runtime_peers = self.inner.peers.write().await;
        for peer in peers.iter().filter(|peer| peer.enabled) {
            runtime_peers.insert(peer.address.clone(), self.make_runtime(peer.clone()));
            if !peer.passive {
                let task = self.spawn_active_loop(peer.clone());
                if let Some(runtime) = runtime_peers.get_mut(&peer.address) {
                    runtime.task = Some(task);
                }
            }
        }
    }

    fn make_runtime(&self, peer_cfg: PeerConfig) -> PeerRuntime {
        let local_as = peer_cfg.local_as.unwrap_or(self.inner.global_asn);
        let auth = peer_auth(&peer_cfg);
        let info = PeerInfo {
            address: peer_cfg.address.clone(),
            name: peer_cfg.name.clone(),
            remote_as: peer_cfg.remote_as,
            local_as,
            remote_port: peer_cfg.remote_port,
            passive: peer_cfg.passive,
            auth_enabled: auth.is_some(),
            auth_mode: match auth {
                None => PeerAuthMode::None,
                Some(PeerAuth::Md5(_)) => PeerAuthMode::Md5,
                Some(PeerAuth::TcpAo(_)) => PeerAuthMode::TcpAo,
            },
            state: PeerState::Idle,
            last_error: None,
            listener_key_error: None,
            advertised_prefixes: 0,
            established_at: None,
        };
        PeerRuntime {
            info,
            cfg: peer_cfg,
            task: None,
            remote_bgp_id: None,
        }
    }

    fn spawn_active_loop(&self, peer_cfg: PeerConfig) -> JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move { service.peer_loop(peer_cfg).await })
    }

    async fn start_listener(&self, listen_addr: &str, peers: &[PeerConfig]) -> Result<()> {
        let socket = bind_listener_socket(listen_addr)
            .await
            .with_context(|| format!("failed binding global BGP listener {listen_addr}"))?;
        // RFC 2385 and RFC 5925: the kernel validates the MD5 digest or the
        // TCP-AO MAC when the SYN arrives, so a passive peer's key has to live
        // on the listening socket. It goes on before `listen()`: a SYN that
        // beat its key would be accepted unsigned, and for TCP-MD5 nothing
        // can tell afterwards. A peer whose key did not make it is refused
        // in `accept_inbound`.
        let local_addr = socket.local_addr()?;
        let v6_only = local_addr.is_ipv6() && listener_v6_only(socket.as_raw_fd());
        let (unkeyed, failures) = install_listener_auth_keys(
            local_addr,
            socket.as_raw_fd(),
            &listener_auth_keys(peers),
            v6_only,
        );
        // Record a key that never reached the socket, and a passive peer that
        // can never connect, where `focl peer show` reads it instead of
        // leaving it to the startup log.
        for (address, error) in failures {
            self.set_peer_listener_key_error(&address, error.clone())
                .await;
            self.set_peer_state(&address, PeerState::Idle, Some(error), None)
                .await;
        }
        for peer in unreachable_passive_peers(local_addr, peers, v6_only) {
            tracing::warn!(peer=%peer.address, listener=%local_addr, "passive peer can never connect: the BGP listener does not take connections of its address family");
            let error = format!(
                "listener {local_addr} does not take connections of this peer's address family"
            );
            self.set_peer_state(&peer.address, PeerState::Idle, Some(error), None)
                .await;
        }
        let listener = socket
            .listen(LISTEN_BACKLOG)
            .with_context(|| format!("failed listening on global BGP listener {listen_addr}"))?;
        let service = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, remote)) => service.accept_inbound(stream, remote, &unkeyed).await,
                    Err(error) => tracing::warn!(error=%error, "global BGP listener accept failed"),
                }
            }
        });
        Ok(())
    }

    /// Re-announces every configured attribute-255 clock prefix on its own
    /// interval. The effective set is re-read on each tick, so a runtime
    /// suppression is respected without touching the task; intervals
    /// introduced by a later `reload` are only scheduled after a restart.
    async fn start_clock_refresh(&self) {
        let intervals: BTreeSet<u32> = self
            .inner
            .prefix_state
            .read()
            .await
            .effective()
            .iter()
            .filter_map(|entry| entry.dev_attr255_interval_secs)
            .collect();
        for interval in intervals {
            let service = self.clone();
            tokio::spawn(async move {
                let mut ticker = clock_ticker(interval);
                // The establishment announcement already covers t0.
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let entries: Vec<PrefixEntry> = service
                        .inner
                        .prefix_state
                        .read()
                        .await
                        .effective()
                        .into_iter()
                        .filter(|entry| entry.dev_attr255_interval_secs == Some(interval))
                        .collect();
                    for entry in entries {
                        let _ = service
                            .dispatch_session_op(SessionOp::Announce(entry))
                            .await;
                    }
                }
            });
        }
    }

    /// Runs a session on an accepted connection. `unkeyed` holds the peers
    /// whose authentication key the listener could not take.
    async fn accept_inbound(
        &self,
        stream: TcpStream,
        remote: SocketAddr,
        unkeyed: &HashSet<IpAddr>,
    ) {
        // A dual-stack listener reports IPv4 peers v4-mapped.
        let remote_ip = remote.ip().to_canonical();
        let peer = {
            let peers = self.inner.peers.read().await;
            peers
                .values()
                .find(|runtime| {
                    runtime.cfg.enabled && peer_address_matches(&runtime.cfg.address, remote_ip)
                })
                .map(|runtime| runtime.cfg.clone())
        };
        let Some(peer) = peer else {
            tracing::warn!(remote=%remote, "dropping inbound BGP connection from unconfigured peer");
            return;
        };
        // Before the collision handling below: a connection that fails here
        // must not tear down an authenticated session the peer already has.
        if let Err(error) = authenticate_inbound(&stream, &peer, !unkeyed.contains(&remote_ip)) {
            tracing::warn!(peer=%peer.address, error=%error, "dropping inbound BGP connection that failed authentication");
            return;
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
            // Record the exit transition before clearing the RIB: `clear_rib`
            // drops the session's local address, and a state change without it
            // cannot be archived.
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
            service.clear_rib(&peer.address).await;
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
        tracing::debug!(peer = %peer.address, "active peer loop started");
        loop {
            self.set_peer_state(&peer.address, PeerState::Connect, None, None)
                .await;
            let result = self.run_active_session(&peer).await;
            // Same ordering as the passive path: archive the exit transition
            // while the session's local address is still known.
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
            self.clear_rib(&peer.address).await;
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
        let local_ip = stream.local_addr()?.ip().to_canonical();
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
        // A BMP Peer Up describes the two socket endpoints of the session, and only the socket
        // knows them: capture both before the split.
        let local_endpoint = stream.local_addr()?;
        let remote_endpoint = stream.peer_addr()?;
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
        // RFC 4271 s4.2: the OPEN carries the configured hold time as-is; 0 is
        // a deliberate "timers disabled" setting and must not be raised to a
        // minimum here.
        let open = local_open(
            self.inner.router_id,
            local_as,
            peer.hold_time_secs,
            peer.route_refresh,
        );
        // Kept for the station: a Peer Up carries our own OPEN PDU verbatim, and re-encoding it
        // later would describe a different session than the one that came up.
        let sent_open = write_bgp_message(&mut writer, &open, AsnLength::Bits32).await?;

        let incoming = next_bgp_message(&mut msg_rx).await?;
        let BgpMessage::Open(remote_open) = incoming.message else {
            return Err(anyhow!("expected OPEN from peer"));
        };
        let negotiated = negotiate_capabilities(&incoming.raw, peer.route_refresh);
        validate_remote_as(&remote_open, &incoming.raw, peer.remote_as, negotiated.asn4)?;
        // RFC 4271 s4.4/s6.1: the hold time that governs this session is 0 when
        // either side advertised 0, otherwise the smaller of the two.
        let hold_time = negotiate_hold_time(peer.hold_time_secs, remote_open.hold_time);
        if let Some(runtime) = self.inner.peers.write().await.get_mut(&peer.address) {
            runtime.remote_bgp_id = Some(remote_open.bgp_identifier);
        }

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
        // The station learns a peer from this frame, and everything after it is attributed to it.
        // Both OPENs travel verbatim: a station reads the peer's address families, BGP identifier
        // and add-path negotiation out of them.
        if !self.inner.bmp.is_empty() {
            let header = PeerHeader {
                peer_ip: remote_endpoint.ip(),
                peer_asn: peer.remote_as,
                peer_bgp_id: remote_open.bgp_identifier,
                asn_16bit: matches!(negotiated.asn_length(), AsnLength::Bits16),
            };
            // Peer Up describes the session, not a direction (RFC 8671 §6.3): every station that
            // carries either direction of this peer needs it before any frame arrives.
            let received_open = incoming.raw;
            for bmp in &self.inner.bmp {
                bmp.peer_up(
                    &peer.address,
                    header.clone(),
                    local_endpoint.ip(),
                    local_endpoint.port(),
                    remote_endpoint.port(),
                    sent_open.clone(),
                    received_open.clone(),
                );
            }
        }
        // Register this session and send its initial table in one critical
        // section under the mutation lock: a concurrent add/remove landing
        // between the snapshot and the registration would otherwise never
        // reach this session (stale set until the next mutation), and
        // registering before the snapshot would deliver the same change twice.
        // The End-of-RIB markers follow that single send, so the initial table
        // reaches the peer exactly once.
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<SessionOp>(64);
        {
            let _guard = self.inner.prefix_ops.lock().await;
            let handle = SessionHandle {
                tx: ctrl_tx,
                supports_v4: negotiated.carries(Afi::Ipv4, Safi::Unicast),
                supports_v6: negotiated.supports(Afi::Ipv6, Safi::Unicast),
                refresh_v4: negotiated.route_refresh,
                refresh_v6: negotiated.route_refresh,
            };
            self.inner
                .session_ops
                .write()
                .await
                .insert(peer.address.clone(), handle);
            self.send_prefix_announcements(peer, &mut writer, &negotiated, local_ip)
                .await?;
            // RFC 4271 End-of-RIB: an empty UPDATE per family marks the initial
            // table transfer complete. A capability-less RFC 4271 peer still
            // gets the IPv4 marker, and a route server missing one treats the
            // session as still converging.
            for eor_family in [Afi::Ipv4, Afi::Ipv6] {
                if negotiated.carries(eor_family, Safi::Unicast) {
                    self.write_own_update(
                        peer,
                        &mut writer,
                        &end_of_rib(eor_family),
                        negotiated.asn_length(),
                    )
                    .await?;
                }
            }
        }

        // RFC 4271 s4.4: a negotiated hold time of 0 disables both the
        // keepalive and the hold timer, so they are only armed when non-zero.
        let keepalive_interval =
            (hold_time != 0).then(|| Duration::from_secs((u64::from(hold_time) / 3).max(1)));
        let mut next_keepalive = keepalive_interval.map(|interval| Instant::now() + interval);
        let mut hold_deadline = reset_hold_deadline(hold_time);
        loop {
            let now = Instant::now();
            if next_keepalive.is_some_and(|deadline| now >= deadline) {
                write_bgp_message(&mut writer, &BgpMessage::KeepAlive, AsnLength::Bits32).await?;
                next_keepalive = keepalive_interval.map(|interval| now + interval);
            }
            if hold_deadline.is_some_and(|deadline| now >= deadline) {
                return Err(anyhow!("hold timer expired"));
            }
            let timeout_dur = std::cmp::min(
                next_keepalive.map_or(Duration::from_secs(1), |next| {
                    next.saturating_duration_since(now)
                }),
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
                                // Forwarded before parsing effects anything: the station receives
                                // the PDU as it arrived, which is the only way an attribute this
                                // build does not model survives the export.
                                if !self.inner.bmp.is_empty() {
                                    let at = bmp_wire::now_micros();
                                    for bmp in &self.inner.bmp {
                                        bmp.frame(&peer.address, &message.raw, at);
                                    }
                                }
                                self.ingest_received_update(
                                    peer,
                                    local_as,
                                    local_ip,
                                    update,
                                    message.raw,
                                    &negotiated,
                                )
                                .await?;
                                hold_deadline = reset_hold_deadline(hold_time);
                            }
                            BgpMessage::RouteRefresh(refresh) => {
                                hold_deadline = reset_hold_deadline(hold_time);
                                self.replay_route_refresh(
                                    peer,
                                    &mut writer,
                                    &negotiated,
                                    local_ip,
                                    &refresh,
                                )
                                .await?;
                            }
                            BgpMessage::KeepAlive | BgpMessage::Open(_) => {
                                hold_deadline = reset_hold_deadline(hold_time);
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
            // A route refresh is not an announcement: it asks the peer for its table, so it carries
            // no update to mirror into the archive or to a station, and it does not change how many
            // prefixes this session advertises.
            SessionOp::RequestRefresh { afi } => {
                let refresh = BgpMessage::RouteRefresh(BgpRouteRefreshMessage {
                    afi: (*afi).into(),
                    subtype: 0,
                    safi: Safi::Unicast.into(),
                    data: Vec::new(),
                });
                write_bgp_message(writer, &refresh, negotiated.asn_length()).await?;
                return Ok(());
            }
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

    /// RFC 2918 s4: answer a ROUTE-REFRESH by re-sending this session's
    /// Adj-RIB-Out for the requested family, followed by that family's
    /// End-of-RIB. A refresh for a family the session does not carry is
    /// ignored; the caller resets the hold timer either way.
    async fn replay_route_refresh<W: AsyncWrite + Unpin>(
        &self,
        peer: &PeerConfig,
        writer: &mut W,
        negotiated: &NegotiatedCapabilities,
        local_ip: IpAddr,
        refresh: &BgpRouteRefreshMessage,
    ) -> Result<()> {
        let (Some(afi), Some(safi)) = (refresh.afi(), refresh.safi()) else {
            return Ok(());
        };
        // Subtype 1/2 (BoRR/EoRR, RFC 7313) are not implemented, and answering
        // them as a normal refresh would send a table the peer did not ask for.
        if refresh.subtype != 0 || !negotiated.carries(afi, safi) {
            return Ok(());
        }
        let local_as = peer.local_as.unwrap_or(self.inner.global_asn);
        // The mutation lock is deliberately not taken here. A control client
        // holds it across its dispatch, and a dispatch blocked on this
        // session's full queue can only be unblocked by this loop draining it,
        // so a lock wait here deadlocks the session against its own producer.
        // Ordering comes from this loop instead: the state read below is one
        // atomic view, a mutation applied before it is inside the replay, and a
        // later one is written after it.
        let prefixes: Vec<PrefixEntry> = self
            .inner
            .prefix_state
            .read()
            .await
            .effective()
            .into_iter()
            .filter(|entry| afi_of(&entry.network) == afi)
            .collect();
        let updates = build_announce_updates(
            &prefixes,
            self.inner.router_id,
            local_ip,
            local_as,
            negotiated,
        );
        self.emit_updates(peer, writer, negotiated, local_ip, local_as, updates)
            .await?;
        self.write_own_update(peer, writer, &end_of_rib(afi), negotiated.asn_length())
            .await?;
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

    /// Writes one of our own UPDATE and mirrors it to the Adj-RIB-Out stations.
    ///
    /// Every path that changes what a session announces goes through here, because a station told
    /// about some of our announcements and not others cannot tell which of its rows are missing,
    /// and the frame it receives is the PDU that went out, O-flagged so it is filed as outbound.
    async fn write_own_update<W: AsyncWrite + Unpin>(
        &self,
        peer: &PeerConfig,
        writer: &mut W,
        message: &BgpMessage,
        asn_len: AsnLength,
    ) -> Result<Vec<u8>> {
        let raw = write_bgp_message(writer, message, asn_len).await?;
        if !self.inner.bmp.is_empty() {
            let at = bmp_wire::now_micros();
            for bmp in &self.inner.bmp {
                bmp.frame_out(&peer.address, &raw, at);
            }
        }
        Ok(raw)
    }

    /// Writes updates to one session and mirrors them into the archive. The
    /// archive is receive-only for a collector, so our own announcements are
    /// recorded here to keep a self-contained lab archive complete; they are
    /// archived in the local direction (RFC 6396 section 4.4.6), so a consumer
    /// can still tell them apart from updates received from the peer.
    async fn emit_updates<W: AsyncWrite + Unpin>(
        &self,
        peer: &PeerConfig,
        writer: &mut W,
        negotiated: &NegotiatedCapabilities,
        local_ip: IpAddr,
        local_as: u32,
        updates: Vec<BgpMessage>,
    ) -> Result<()> {
        let asn_len = negotiated.asn_length();
        for update in updates {
            let raw = self
                .write_own_update(peer, writer, &update, asn_len)
                .await?;
            if let Some(archive) = &self.inner.archive {
                archive
                    .ingest_local_update(UpdateRecordInput {
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
        // RFC 6793 §4.2.3 merged path: AS_PATH plus AS4_PATH on migration sessions.
        let as_path = update.attributes.effective_as_path();
        // Absent ORIGIN stays absent: the snapshot must not invent a value for
        // an attribute the peer never sent.
        let origin = update
            .attributes
            .has_attr(AttrType::ORIGIN)
            .then(|| update.attributes.origin());
        let now = chrono::Utc::now().timestamp();
        let mut ribs = self.inner.rib_in.write().await;
        let rib = ribs.entry(peer.to_string()).or_insert_with(IpnetTrie::new);
        // Plain IPv4 NLRI is only valid on a session that carries IPv4
        // (negotiated v4 MP capability or a capability-less RFC 4271 peer).
        let classic_ipv4_ok = negotiated.carries(Afi::Ipv4, Safi::Unicast);
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
                        origin,
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
                            origin,
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

    async fn set_peer_listener_key_error(&self, address: &str, error: String) {
        if let Some(runtime) = self.inner.peers.write().await.get_mut(address) {
            runtime.info.listener_key_error = Some(error);
        }
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
                tracing::warn!(
                    address,
                    ?state,
                    "state change for a peer that is not running"
                );
                return;
            };
            let old_state = runtime.info.state;
            tracing::debug!(address, ?old_state, ?state, "peer state");
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
        self.export_peer_close(address, old_state, state);
    }

    /// Closes a monitored peer the moment it stops being Established.
    ///
    /// Skipping this is the failure a station cannot detect: it keeps reporting the peer's last
    /// known table, which then looks like a quiet network rather than a lost session. Reason 4 is
    /// RFC 7854's "remote system closed without a notification", which is what an unexpected
    /// transport end looks like from here.
    fn export_peer_close(&self, address: &str, old_state: PeerState, new_state: PeerState) {
        if !matches!(old_state, PeerState::Established)
            || matches!(new_state, PeerState::Established)
        {
            return;
        }
        let at = bmp_wire::now_micros();
        for bmp in &self.inner.bmp {
            bmp.peer_down(address, bmp_wire::PEER_DOWN_REMOTE_NO_DATA, at);
        }
    }

    /// Asks one established peer to resend its Adj-RIB-In (RFC 2918), for every family it can.
    ///
    /// Returns whether a request reached the session. Peers that never negotiated route refresh,
    /// and sessions that are not established, are not asked: an unanswered request would look like
    /// a table that is on its way and never arrives.
    pub async fn redump_peer(&self, address: &str) -> bool {
        let families = {
            let sessions = self.inner.session_ops.read().await;
            sessions
                .get(address)
                .map(SessionHandle::refreshable_families)
                .unwrap_or_default()
        };
        if families.is_empty() {
            return false;
        }
        let mut asked = false;
        for afi in families {
            let tx = {
                let sessions = self.inner.session_ops.read().await;
                sessions.get(address).map(|handle| handle.tx.clone())
            };
            let Some(tx) = tx else {
                continue;
            };
            if tx.send(SessionOp::RequestRefresh { afi }).await.is_ok() {
                asked = true;
            }
        }
        asked
    }

    /// Asks every established peer that can answer to resend its table. Ignores the station
    /// cooldown: callers that react to a reconnect use [`Self::spawn_station_redump_task`].
    pub async fn redump_all_peers(&self) -> usize {
        let addresses: Vec<String> = {
            let sessions = self.inner.session_ops.read().await;
            sessions.keys().cloned().collect()
        };
        let mut asked = 0;
        for address in addresses {
            if self.redump_peer(&address).await {
                asked += 1;
            }
        }
        asked
    }

    /// Turns a station's reconnect into a table request, at most once per peer per cooldown.
    ///
    /// A station that attached after a session came up has no baseline for that peer: the table it
    /// would have recorded arrived before it was listening. Keeping a copy of every PDU since
    /// session start in case that happens would duplicate the archive inside the daemon, so the
    /// daemon asks the peer for its current table instead, which is what an operator would do by
    /// hand. The cooldown is the safety property: a flapping station must not be able to make this
    /// daemon pull a full table from every peer on each reconnect.
    pub fn spawn_station_redump_task(
        &self,
        mut signals: mpsc::Receiver<()>,
        cooldown: Duration,
    ) -> JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut last: HashMap<String, Instant> = HashMap::new();
            while signals.recv().await.is_some() {
                let now = Instant::now();
                let addresses: Vec<String> = {
                    let sessions = service.inner.session_ops.read().await;
                    sessions.keys().cloned().collect()
                };
                for address in addresses {
                    if last
                        .get(&address)
                        .is_some_and(|asked_at| now.duration_since(*asked_at) < cooldown)
                    {
                        continue;
                    }
                    if service.redump_peer(&address).await {
                        last.insert(address, now);
                    }
                }
            }
        })
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
                dev_attr255_interval_secs: state.configured_attr255_interval(&network),
            }
        };
        // A dry run reports what would happen without touching the state: run
        // the same `add` on a snapshot clone and discard it, so a dry run and
        // the real mutation agree (including a next-hop change).
        let changed = if dry_run {
            let mut snapshot = self.inner.prefix_state.read().await.clone();
            snapshot.add(entry.clone())
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
        let _guard = self.inner.prefix_ops.lock().await;
        // Provenance has to be read before the entry is dropped, and under the
        // mutation lock: a concurrent add/remove/reload can change (or drop) it
        // in between, and the reported source would not describe the entry the
        // withdrawal applies to.
        let previous_source = self.inner.prefix_state.read().await.source_of(&network);
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
            // A refresh names a family, not a prefix, and is sent to one session by address rather
            // than dispatched to every session that carries a network.
            SessionOp::RequestRefresh { .. } => return Vec::new(),
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

    /// Builds the archive's RIB view: every peer that currently holds a
    /// session, with its Adj-RIB-In entries. The trie the session loop already
    /// maintains is the source; an Adj-RIB-In value keeps no attribute blob
    /// (interning is deferred), so a route's TABLE_DUMP_V2 attributes are
    /// rebuilt from ORIGIN, the stored AS path and, for IPv4 prefixes, the
    /// next hop.
    pub async fn rib_snapshot_input(&self) -> Result<RibSnapshotInput> {
        let local_ips = self.inner.session_local_ips.read().await;
        let peers = self.inner.peers.read().await;
        let ribs = self.inner.rib_in.read().await;

        // A stable order keeps the peer index table reproducible.
        let mut addresses = local_ips.keys().cloned().collect::<Vec<_>>();
        addresses.sort();

        let mut snapshot_peers = Vec::with_capacity(addresses.len());
        let mut routes = Vec::new();
        for address in addresses {
            let Some(runtime) = peers.get(&address) else {
                continue;
            };
            let Ok(peer_ip) = address.parse::<IpAddr>() else {
                continue;
            };
            let peer_index = u16::try_from(snapshot_peers.len())
                .context("snapshot peer count exceeds the TABLE_DUMP_V2 limit")?;
            snapshot_peers.push(SnapshotPeer {
                peer_bgp_id: runtime.remote_bgp_id.unwrap_or(Ipv4Addr::UNSPECIFIED),
                peer_ip,
                peer_asn: runtime.info.remote_as,
            });
            let Some(rib) = ribs.get(&address) else {
                continue;
            };
            for (prefix, value) in rib.iter() {
                routes.push(SnapshotRoute {
                    prefix,
                    peer_index,
                    originated_time: value.last_seen as u32,
                    path_id: None,
                    path_attributes: snapshot_path_attributes(value, prefix)?,
                });
            }
        }

        Ok(RibSnapshotInput {
            timestamp: chrono::Utc::now().timestamp(),
            collector_bgp_id: Ipv4Addr::UNSPECIFIED,
            view_name: "main".to_string(),
            peers: snapshot_peers,
            routes,
        })
    }
}

impl RibSnapshotSource for BgpService {
    fn snapshot_input(&self) -> SnapshotInputFuture<'_> {
        Box::pin(self.rib_snapshot_input())
    }
}

/// Rebuilds the path attributes a TABLE_DUMP_V2 RIB entry carries from one
/// Adj-RIB-In value: the received ORIGIN and AS path (attribute type 2 with
/// four-octet segments), plus NEXT_HOP for an IPv4 prefix. A table dump has no
/// NLRI inside the attribute blob, so no MP_REACH is emitted for IPv6, and an
/// attribute the peer never sent is left out rather than invented.
fn snapshot_path_attributes(value: &AdjRibValue, prefix: IpNet) -> Result<Vec<u8>> {
    let mut attributes = Attributes::default();
    if let Some(origin) = value.origin {
        attributes.add_attr(AttributeValue::Origin(origin).into());
    }
    if let Some(as_path) = &value.as_path {
        attributes.add_attr(AttributeValue::AsPath(as_path.clone()).into());
    }
    if let (Some(next_hop @ IpAddr::V4(_)), IpNet::V4(_)) = (value.next_hop, prefix) {
        attributes.add_attr(AttributeValue::NextHop(next_hop).into());
    }
    let encoded = attributes
        .encode(AsnLength::Bits32)
        .map_err(|error| anyhow!("failed encoding snapshot path attributes: {error}"))?;
    Ok(encoded.to_vec())
}

/// RFC 4271 s4.2/s6.1 hold-time negotiation: a hold time of 0 on either side
/// disables the timers, otherwise the smaller advertised value is the
/// negotiated one.
fn negotiate_hold_time(local: u16, remote: u16) -> u16 {
    if local == 0 || remote == 0 {
        0
    } else {
        local.min(remote)
    }
}

/// Restarts the hold timer after a received message. `None` when the negotiated
/// hold time is 0, which disables the timer (RFC 4271 s4.4).
fn reset_hold_deadline(hold_time: u16) -> Option<Instant> {
    (hold_time != 0).then(|| Instant::now() + Duration::from_secs(u64::from(hold_time)))
}

/// RFC 4271 End-of-RIB: an empty UPDATE marks one family's initial or refreshed
/// table as complete. IPv4 uses the classic empty UPDATE, IPv6 the MP_UNREACH
/// form with no NLRI.
fn end_of_rib(family: Afi) -> BgpMessage {
    if family == Afi::Ipv4 {
        return BgpMessage::Update(BgpUpdateMessage::default());
    }
    let mut attrs = Attributes::default();
    attrs.add_attr(
        AttributeValue::MpUnreachNlri(Nlri {
            afi: family,
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
}

/// Address family of an originated prefix.
fn afi_of(network: &IpNet) -> Afi {
    match network {
        IpNet::V4(_) => Afi::Ipv4,
        IpNet::V6(_) => Afi::Ipv6,
    }
}

/// The refresh ticker for one attribute-255 interval. Missed ticks are skipped
/// rather than burst: after a stall the same clock round would otherwise be
/// dispatched once per missed tick, which can fill a session queue without
/// recovering any measurement.
fn clock_ticker(interval_secs: u32) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval(Duration::from_secs(u64::from(interval_secs)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker
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
    let now = unix_now();
    let mut result = Vec::new();
    for prefix in prefixes
        .iter()
        .filter(|prefix| matches!(prefix.network, IpNet::V4(_)))
    {
        if negotiated.carries(Afi::Ipv4, Safi::Unicast) {
            let mut attrs = base_announce_attributes(local_as, negotiated);
            let next_hop = prefix.next_hop.unwrap_or(IpAddr::V4(router_id));
            attrs.add_attr(AttributeValue::NextHop(next_hop).into());
            attach_dev_attr255(&mut attrs, prefix, now);
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
        let mut attrs = base_announce_attributes(local_as, negotiated);
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
        attach_dev_attr255(&mut attrs, prefix, now);
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
    let classic_ipv4_ok = negotiated.carries(Afi::Ipv4, Safi::Unicast);
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

fn base_announce_attributes(local_as: u32, negotiated: &NegotiatedCapabilities) -> Attributes {
    let mut attrs = Attributes::default();
    attrs.add_attr(AttributeValue::Origin(Origin::IGP).into());
    // `As4Path` is attribute type 17 and always encodes 4-octet segments. On a
    // session that negotiated 4-octet AS support the correct wire form is
    // AS_PATH (type 2) with 4-octet segments, so the session AsnLength drives
    // the width. A session without that capability cannot carry a 4-octet ASN
    // in AS_PATH (RFC 6793 s4.2), so an unrepresentable local ASN goes into
    // AS4_PATH while AS_TRANS takes its place in AS_PATH; a 2-octet local ASN
    // needs neither and keeps a plain AS_PATH.
    let (as_path, real_asn) = if !negotiated.asn4 && local_as > u32::from(u16::MAX) {
        (u32::from(AS_TRANS), Some(local_as))
    } else {
        (local_as, None)
    };
    attrs.add_attr(AttributeValue::AsPath(AsPath::from_sequence([as_path])).into());
    if let Some(real_asn) = real_asn {
        attrs.add_attr(AttributeValue::As4Path(AsPath::from_sequence([real_asn])).into());
    }
    attrs
}

/// Attribute-255 development clock: magic bytes, format version, refresh
/// round, and the low 32 bits of the unix time.
const DEV_ATTR255_MAGIC: &[u8] = b"BGPKIT";
const DEV_ATTR255_VERSION: u8 = 1;

fn dev_attr255_clock_payload(unix_secs: u64, interval_secs: u32) -> Vec<u8> {
    let interval = u64::from(interval_secs).max(1);
    let round = ((unix_secs / interval) % 65_536) as u16;
    let mut payload = Vec::with_capacity(13);
    payload.extend_from_slice(DEV_ATTR255_MAGIC);
    payload.push(DEV_ATTR255_VERSION);
    payload.extend_from_slice(&round.to_be_bytes());
    payload.extend_from_slice(&(unix_secs as u32).to_be_bytes());
    payload
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Attaches the attribute-255 clock when the prefix carries one. The flag is
/// OPTIONAL|TRANSITIVE: `Development`'s `.into()` default would also set the
/// PARTIAL bit (0xe0), which an originating speaker must not send.
fn attach_dev_attr255(attrs: &mut Attributes, prefix: &PrefixEntry, now: u64) {
    let Some(interval) = prefix.dev_attr255_interval_secs else {
        return;
    };
    attrs.add_attr(Attribute {
        value: AttributeValue::Development(dev_attr255_clock_payload(now, interval)),
        flag: AttrFlags::OPTIONAL | AttrFlags::TRANSITIVE,
    });
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
    let socket = if local_bind.map_or(remote.is_ipv4(), |local| local.is_ipv4()) {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(local) = local_bind {
        socket.bind(local)?;
    }
    // RFC 2385 and RFC 5925: the SYN is the first segment the peer verifies,
    // so the key has to be on the socket before `connect()`.
    match peer_auth(peer) {
        Some(PeerAuth::Md5(password)) => socket.set_md5_signature(&remote, password)?,
        Some(PeerAuth::TcpAo(keys)) => socket.set_tcp_ao_keys(&remote, keys)?,
        None => {}
    }
    Ok(socket.connect(remote).await?)
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

/// How a peer authenticates its TCP connection: a view of the secrets in its
/// `PeerConfig`, which stays their only copy. The two are mutually exclusive:
/// `BgpService` validates its config before it reads a peer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PeerAuth<'a> {
    /// TCP-MD5 (RFC 2385) password.
    Md5(&'a str),
    /// TCP-AO (RFC 5925) master key tuples.
    TcpAo(&'a [TcpAoKeyConfig]),
}

impl std::fmt::Debug for PeerAuth<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAuth::Md5(_) => f.write_str("PeerAuth::Md5(<redacted>)"),
            // `TcpAoKeyConfig` leaves its secret out and shows the KeyIDs.
            PeerAuth::TcpAo(keys) => f.debug_tuple("PeerAuth::TcpAo").field(keys).finish(),
        }
    }
}

fn peer_auth(peer: &PeerConfig) -> Option<PeerAuth<'_>> {
    if !peer.tcp_ao_keys.is_empty() {
        return Some(PeerAuth::TcpAo(&peer.tcp_ao_keys));
    }
    peer.password.as_deref().map(PeerAuth::Md5)
}

/// Probes the kernel only when an enabled peer uses TCP-AO, and returns `None`
/// when nothing needs the answer. A probe that fails is an error, never "the
/// kernel has no TCP-AO".
fn probe_kernel_tcp_ao(
    peers: &[PeerConfig],
    probe: impl FnOnce() -> std::io::Result<bool>,
) -> Result<Option<bool>> {
    if !peers
        .iter()
        .any(|peer| peer.enabled && !peer.tcp_ao_keys.is_empty())
    {
        return Ok(None);
    }
    Ok(Some(probe().context(
        "could not tell whether the kernel implements TCP-AO",
    )?))
}

/// Fails when an enabled peer has TCP-AO keys and the kernel has no TCP-AO
/// (`supported`). Such a peer can never get a session, which would otherwise
/// only show as a failing connect on every retry or a listener key the kernel
/// refused. A disabled peer may keep its keys.
fn require_tcp_ao_support(peers: &[PeerConfig], supported: bool) -> Result<()> {
    let needing: Vec<&str> = peers
        .iter()
        .filter(|peer| peer.enabled && !peer.tcp_ao_keys.is_empty())
        .map(|peer| peer.address.as_str())
        .collect();
    if supported || needing.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "tcp_ao_keys are set for {} but this kernel has no TCP-AO (it takes Linux 6.7+ built with CONFIG_TCP_AO); remove the keys or set enabled = false on those peers",
        needing.join(", ")
    ))
}

/// The peer's configured address, with an IPv4 peer spelled v4-mapped
/// (`::ffff:192.0.2.1`) as that IPv4 address: the form an accepted
/// connection's remote address is compared in. `None` if the address is not a
/// literal IP.
fn peer_ip(peer: &PeerConfig) -> Option<IpAddr> {
    let address = peer.address.parse::<IpAddr>().ok()?;
    Some(address.to_canonical())
}

/// Pending inbound connections the BGP listener queues; the kernel caps it at
/// `net.core.somaxconn`.
const LISTEN_BACKLOG: u32 = 1024;

/// Binds the socket of the BGP listener the way `TcpListener::bind` does, but
/// leaves it for the caller to `listen()` on: the authentication keys have to
/// be on the socket before it takes its first SYN.
async fn bind_listener_socket(listen_addr: &str) -> std::io::Result<TcpSocket> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host(listen_addr).await?.collect();
    bind_first_listener(addresses, bind_listener_one)
}

/// Binds the first address that accepts a socket, like `TcpListener::bind`:
/// socket creation, `SO_REUSEADDR` and `bind` all belong to one attempt, so a
/// family this host cannot create a socket for falls through to the next
/// resolved address instead of aborting startup.
fn bind_first_listener(
    addresses: Vec<SocketAddr>,
    mut bind: impl FnMut(SocketAddr) -> std::io::Result<TcpSocket>,
) -> std::io::Result<TcpSocket> {
    let mut last_error = None;
    for address in addresses {
        match bind(address) {
            Ok(socket) => return Ok(socket),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "could not resolve to any address",
        )
    }))
}

fn bind_listener_one(address: SocketAddr) -> std::io::Result<TcpSocket> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    Ok(socket)
}

/// Per-peer keys for the listening socket: every enabled peer that
/// authenticates, with the configured address kept for diagnostics. Config
/// validation has already rejected a peer address that is not a literal IP.
fn listener_auth_keys(peers: &[PeerConfig]) -> Vec<(String, IpAddr, PeerAuth<'_>)> {
    peers
        .iter()
        .filter(|peer| peer.enabled)
        .filter_map(|peer| {
            let address = peer_ip(peer)?;
            let auth = peer_auth(peer)?;
            Some((peer.address.clone(), address, auth))
        })
        .collect()
}

/// The address a listener bound to `listener` keys `peer` under, or `None`
/// if such a listener can never accept that peer. An IPv6 socket takes IPv4
/// connections on the wildcard address or a v4-mapped one, and sees those
/// peers v4-mapped. The port is not part of the kernel's lookup for either
/// option (the source port of an inbound connection is ephemeral), so the BGP
/// port is used.
fn listener_key_addr(listener: SocketAddr, peer: IpAddr, v6_only: bool) -> Option<SocketAddr> {
    let address = match (listener.ip(), peer) {
        (IpAddr::V4(_), IpAddr::V4(_)) => peer,
        (IpAddr::V4(_), IpAddr::V6(_)) => return None,
        (IpAddr::V6(local), IpAddr::V4(v4)) => {
            if v6_only || (!local.is_unspecified() && local.to_ipv4_mapped().is_none()) {
                return None;
            }
            IpAddr::V6(v4.to_ipv6_mapped())
        }
        (IpAddr::V6(local), IpAddr::V6(_)) => {
            if local.to_ipv4_mapped().is_some() {
                return None;
            }
            peer
        }
    };
    Some(SocketAddr::new(address, 179))
}

/// The enabled passive peers a listener bound to `listener` can never accept,
/// because it does not take connections of their address family. Only they
/// depend on the listener: an active peer dials out.
fn unreachable_passive_peers(
    listener: SocketAddr,
    peers: &[PeerConfig],
    v6_only: bool,
) -> Vec<&PeerConfig> {
    peers
        .iter()
        .filter(|peer| peer.enabled && peer.passive)
        .filter(|peer| {
            peer_ip(peer)
                .is_some_and(|address| listener_key_addr(listener, address, v6_only).is_none())
        })
        .collect()
}

/// Reads `IPV6_V6ONLY` from the bound listening socket. A `[::]` listener takes
/// IPv4 connections as v4-mapped only while this is off (`net.ipv6.bindv6only`).
fn listener_v6_only(fd: i32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `value` and `len` outlive the call and match the option.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &mut value as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if result != 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "could not read IPV6_V6ONLY; assuming the listener takes IPv4 as v4-mapped"
            );
            return false;
        }
        value != 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        // The kernel's authentication options bail out on non-Linux builds, so
        // this only affects the unreachable-passive-peer report.
        let _ = fd;
        false
    }
}

/// Installs `keys` on the socket of the BGP listener. A TCP-AO key goes on
/// without `ao_required`, which would also lock out every other peer, and
/// without current/rnext, which a listener does not have: the kernel already
/// drops an unsigned SYN from an address that has a key. A key the kernel
/// refuses is logged rather than fatal: the listener still serves the other
/// peers. Every key of a peer is attempted, so one refused key does not
/// discard the keys that follow it.
///
/// Returns the peers the listener holds no key for, which the caller has to
/// refuse because the kernel now accepts their unsigned SYN, and one
/// `(peer, error)` entry per peer with a key the kernel refused.
fn install_listener_auth_keys(
    listener: SocketAddr,
    fd: i32,
    keys: &[(String, IpAddr, PeerAuth<'_>)],
    v6_only: bool,
) -> (HashSet<IpAddr>, Vec<(String, String)>) {
    let mut unkeyed = HashSet::new();
    let mut failures = Vec::new();
    for (configured, address, peer_auth) in keys {
        let Some(remote) = listener_key_addr(listener, *address, v6_only) else {
            // No connection of this peer's address family reaches the
            // listener, so there is nothing to key; `start_listener` reports
            // the passive peers this leaves stranded. Should one arrive
            // anyway, it is refused like any other unkeyed peer.
            unkeyed.insert(*address);
            continue;
        };
        match *peer_auth {
            PeerAuth::Md5(password) => {
                if let Err(error) = auth::set_tcp_md5_signature(fd, &remote, password) {
                    tracing::error!(peer=%address, error=%error, "failed to install authentication key on the BGP listener; refusing inbound connections from this peer");
                    unkeyed.insert(*address);
                    failures.push((configured.clone(), error.to_string()));
                }
            }
            PeerAuth::TcpAo(ao_keys) => {
                let mut errors = Vec::new();
                for key in ao_keys {
                    if let Err(error) = auth::add_tcp_ao_key(fd, &remote, key, false) {
                        tracing::error!(peer=%address, send_id=key.send_id, error=%error, "failed to install TCP-AO key on the BGP listener");
                        errors.push(format!("send_id {}: {error}", key.send_id));
                    }
                }
                // With any key in place the kernel drops an unsigned SYN, and
                // `authenticate_inbound` checks the accepted connection.
                if errors.len() == ao_keys.len() {
                    unkeyed.insert(*address);
                }
                if !errors.is_empty() {
                    failures.push((configured.clone(), errors.join("; ")));
                }
            }
        }
    }
    (unkeyed, failures)
}

/// Whether a configured peer address names `remote`. Both sides are
/// canonicalized: a dual-stack listener reports IPv4 peers v4-mapped, and a
/// peer may be configured as an IPv4-mapped literal.
fn peer_address_matches(configured: &str, remote: IpAddr) -> bool {
    configured
        .parse::<IpAddr>()
        .is_ok_and(|address| address.to_canonical() == remote.to_canonical())
}

/// Asserts that an accepted connection carries `peer`'s authentication.
/// `listener_keyed` is whether the listening socket took the peer's key.
///
/// For TCP-MD5 that key is the whole guarantee: it makes the kernel drop an
/// unsigned or wrongly signed SYN and hand the key on to the accepted socket,
/// but nothing can be asked about the connection afterwards. `TCP_MD5SIG`
/// cannot be read back, and setting it again succeeds on a connection that
/// was never signed. For TCP-AO the accepted socket can be asked, and the
/// docs leave verifying its keys to userspace.
fn authenticate_inbound(stream: &TcpStream, peer: &PeerConfig, listener_keyed: bool) -> Result<()> {
    let Some(peer_auth) = peer_auth(peer) else {
        return Ok(());
    };
    if !listener_keyed {
        return Err(anyhow!(
            "the listener does not hold the peer's key, so nothing verified the connection"
        ));
    }
    match peer_auth {
        PeerAuth::TcpAo(keys) => {
            let Some(status) = stream.tcp_ao_status()? else {
                return Err(anyhow!("connection is not TCP-AO protected"));
            };
            if let Some(key) = overridden_current_key(keys, &status) {
                tracing::warn!(
                    peer=%peer.address,
                    configured_send_id=key.send_id,
                    send_id=status.current_key,
                    recv_id=status.rnext_key,
                    "TCP-AO `current` is ignored on a connection the peer opens: its SYN picked the keys"
                );
            }
            Ok(())
        }
        PeerAuth::Md5(_) => Ok(()),
    }
}

/// The key the config marks `current`, if an accepted connection with
/// `status` uses another one. Linux gives an accepted connection the keys its
/// SYN names (the peer's RNextKeyID is the key that signs, its KeyID the one
/// asked of it), and a listener cannot hold a current key to override that.
fn overridden_current_key<'a>(
    keys: &'a [TcpAoKeyConfig],
    status: &TcpAoStatus,
) -> Option<&'a TcpAoKeyConfig> {
    keys.iter()
        .find(|key| key.current)
        .filter(|key| key.send_id != status.current_key || key.recv_id != status.rnext_key)
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
        /// Every AS_PATH (2) and AS4_PATH (17) attribute on the encoded
        /// message, in wire order.
        fn as_path_attrs(msg: &BgpMessage, asn_len: AsnLength) -> Vec<(u8, Vec<u8>)> {
            let BgpMessage::Update(u) = msg else {
                panic!("not an UPDATE")
            };
            let mut buf = bytes::BytesMut::new();
            u.attributes.encode_to(asn_len, &mut buf).unwrap();
            let mut attrs = Vec::new();
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
                    attrs.push((code, buf[p + hdr..p + hdr + l].to_vec()));
                }
                p += hdr + l;
            }
            assert!(!attrs.is_empty(), "no AS_PATH attribute found");
            attrs
        }

        let prefixes = vec![PrefixEntry {
            network: "192.0.2.0/24".parse().unwrap(),
            next_hop: None,
            dev_attr255_interval_secs: None,
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
        assert_eq!(
            as_path_attrs(&updates[0], AsnLength::Bits32),
            vec![(2u8, vec![2u8, 1, 0x00, 0x06, 0x1D, 0x04])]
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
        assert_eq!(
            as_path_attrs(&updates[0], AsnLength::Bits16),
            vec![(2u8, vec![2u8, 1, 0xFD, 0xF2])]
        );

        // RFC 6793 s4.2: a session without AS4 support cannot carry a 4-octet
        // ASN in AS_PATH, so AS_TRANS (23456) goes there and the real ASN goes
        // into AS4_PATH. The old encoding truncated 400644 to its low 16 bits
        // (0x1D04 = AS 7428) on the wire.
        let updates = build_announce_updates(
            &prefixes,
            "192.0.2.1".parse().unwrap(),
            IpAddr::V4("192.0.2.1".parse().unwrap()),
            400_644,
            &plain,
        );
        assert_eq!(
            as_path_attrs(&updates[0], AsnLength::Bits16),
            vec![
                (2u8, vec![2u8, 1, 0x5B, 0xA0]),
                (17u8, vec![2u8, 1, 0x00, 0x06, 0x1D, 0x04]),
            ]
        );

        // The pair round-trips through bgpkit-parser exactly as it goes out:
        // AS_PATH is AS_TRANS and AS4_PATH carries the real local ASN.
        let mut raw = updates[0].encode(AsnLength::Bits16).unwrap();
        let parsed = parse_bgp_message(&mut raw, false, &AsnLength::Bits16).unwrap();
        let BgpMessage::Update(parsed) = parsed else {
            panic!("not an UPDATE")
        };
        let paths: Vec<(bool, String)> = parsed
            .attributes
            .into_attributes_iter()
            .filter_map(|attribute| match attribute.value {
                AttributeValue::AsPath(path) => Some((false, path.to_string())),
                AttributeValue::As4Path(path) => Some((true, path.to_string())),
                _ => None,
            })
            .collect();
        assert_eq!(
            paths,
            vec![
                (false, AS_TRANS.to_string()),
                (true, 400_644u32.to_string()),
            ]
        );
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
    fn listener_auth_keys_cover_exactly_the_enabled_peers_that_authenticate() {
        let ao_keys = vec![TcpAoKeyConfig {
            send_id: 1,
            recv_id: 2,
            algorithm: crate::config::TcpAoAlgorithm::HmacSha1_96,
            secret: "ao-secret".to_string(),
            current: false,
        }];
        let mut ao_peer = md5_peer("192.0.2.4", true, None);
        ao_peer.tcp_ao_keys = ao_keys.clone();
        let mut disabled_ao_peer = md5_peer("192.0.2.5", false, None);
        disabled_ao_peer.tcp_ao_keys = ao_keys.clone();
        let peers = vec![
            md5_peer("192.0.2.1", true, Some("first")),
            md5_peer("192.0.2.2", false, Some("disabled-peer")),
            md5_peer("192.0.2.3", true, None),
            md5_peer("2001:db8::1", true, Some("v6-peer")),
            md5_peer("not-an-address", true, Some("unusable")),
            ao_peer,
            disabled_ao_peer,
            md5_peer("::ffff:192.0.2.6", true, Some("v4-mapped")),
        ];
        assert_eq!(
            listener_auth_keys(&peers),
            vec![
                (
                    "192.0.2.1".to_string(),
                    "192.0.2.1".parse::<IpAddr>().unwrap(),
                    PeerAuth::Md5("first")
                ),
                (
                    "2001:db8::1".to_string(),
                    "2001:db8::1".parse::<IpAddr>().unwrap(),
                    PeerAuth::Md5("v6-peer")
                ),
                (
                    "192.0.2.4".to_string(),
                    "192.0.2.4".parse::<IpAddr>().unwrap(),
                    PeerAuth::TcpAo(&ao_keys)
                ),
                // An IPv4 peer spelled v4-mapped is keyed as the IPv4 peer it is.
                (
                    "::ffff:192.0.2.6".to_string(),
                    "192.0.2.6".parse::<IpAddr>().unwrap(),
                    PeerAuth::Md5("v4-mapped")
                ),
            ]
        );
        assert!(listener_auth_keys(&[]).is_empty());
    }

    /// `listener_v6_only` reads the socket, so the test sets the option
    /// explicitly: a host with `net.ipv6.bindv6only=1` must not change the
    /// expected answer.
    #[cfg(target_os = "linux")]
    #[test]
    fn v6_only_is_read_from_the_bound_socket() {
        fn set_v6_only(socket: &TcpSocket, value: libc::c_int) {
            // SAFETY: the option value outlives the call and matches IPV6_V6ONLY.
            let rc = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &value as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            assert_eq!(
                rc,
                0,
                "set IPV6_V6ONLY={value}: {}",
                std::io::Error::last_os_error()
            );
        }

        let dual = TcpSocket::new_v6().unwrap();
        set_v6_only(&dual, 0);
        dual.bind("[::]:0".parse().unwrap()).unwrap();
        assert!(!listener_v6_only(dual.as_raw_fd()));

        let only = TcpSocket::new_v6().unwrap();
        set_v6_only(&only, 1);
        only.bind("[::]:0".parse().unwrap()).unwrap();
        assert!(listener_v6_only(only.as_raw_fd()));
    }

    /// An active peer reports its first state as soon as its loop runs. If the
    /// loop is spawned before the peer is registered, that write is dropped and
    /// the peer never reports `Connect`, which is what `start_peers` used to do.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_active_peer_reports_its_first_state() {
        let mut cfg = test_service_config();
        cfg.peers = (1..=40)
            .map(|i| PeerConfig {
                address: format!("127.0.1.{i}"),
                remote_as: 65_002,
                local_as: None,
                hold_time_secs: 90,
                connect_retry_secs: 30,
                remote_port: 1,
                local_address: None,
                enabled: true,
                passive: false,
                route_refresh: false,
                name: None,
                password: None,
                tcp_ao_keys: vec![],
            })
            .collect();
        let (event_tx, mut event_rx) = broadcast::channel(4096);
        let service = BgpService::new(&cfg, event_tx).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut connects: HashSet<String> = HashSet::new();
        while let Ok(envelope) = event_rx.try_recv() {
            if let Event::PeerState {
                peer,
                state: PeerState::Connect,
            } = envelope.event
            {
                connects.insert(peer);
            }
        }
        for i in 1..=40 {
            let address = format!("127.0.1.{i}");
            assert!(
                connects.contains(&address),
                "{address} never reported its first state"
            );
        }
        drop(service);
    }

    #[test]
    fn the_tcp_ao_probe_runs_only_for_an_enabled_tcp_ao_peer() {
        let ao_peer = |address: &str, enabled: bool| PeerConfig {
            tcp_ao_keys: vec![TcpAoKeyConfig {
                send_id: 1,
                recv_id: 2,
                algorithm: crate::config::TcpAoAlgorithm::HmacSha1_96,
                secret: "ao-secret".to_string(),
                current: false,
            }],
            ..md5_peer(address, enabled, None)
        };

        let mut called = false;
        assert_eq!(
            probe_kernel_tcp_ao(&[md5_peer("192.0.2.1", true, Some("md5"))], || {
                called = true;
                Ok(true)
            })
            .unwrap(),
            None
        );
        assert!(!called, "a config without TCP-AO peers must not probe");

        let mut called = false;
        assert_eq!(
            probe_kernel_tcp_ao(&[ao_peer("192.0.2.2", false)], || {
                called = true;
                Ok(true)
            })
            .unwrap(),
            None
        );
        assert!(!called, "a disabled TCP-AO peer must not probe");

        let mut called = false;
        assert_eq!(
            probe_kernel_tcp_ao(&[ao_peer("192.0.2.3", true)], || {
                called = true;
                Ok(true)
            })
            .unwrap(),
            Some(true)
        );
        assert!(called);

        let error = probe_kernel_tcp_ao(&[ao_peer("192.0.2.4", true)], || {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("could not tell whether the kernel implements TCP-AO"),
            "{error:#}"
        );
    }

    #[test]
    fn listener_binding_falls_through_to_the_next_address() {
        let addresses = vec![
            "192.0.2.1:179".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        ];
        let socket = bind_first_listener(addresses, |address| {
            if address.ip().to_string() == "192.0.2.1" {
                return Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable));
            }
            bind_listener_one(address)
        })
        .expect("the second address binds");
        assert_eq!(socket.local_addr().unwrap().ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn listener_binding_reports_the_last_error() {
        let addresses = vec![
            "192.0.2.1:179".parse().unwrap(),
            "192.0.2.2:179".parse().unwrap(),
        ];
        let error = bind_first_listener(addresses, |address| {
            let kind = if address.ip().to_string() == "192.0.2.1" {
                std::io::ErrorKind::AddrNotAvailable
            } else {
                std::io::ErrorKind::PermissionDenied
            };
            Err(std::io::Error::from(kind))
        })
        .expect_err("no address binds");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn peer_address_matching_canonicalizes_both_sides() {
        // A dual-stack listener reports IPv4 peers v4-mapped.
        assert!(peer_address_matches(
            "192.0.2.1",
            "::ffff:192.0.2.1".parse().unwrap()
        ));
        // A peer configured as an IPv4-mapped literal matches the plain form.
        assert!(peer_address_matches(
            "::ffff:192.0.2.1",
            "192.0.2.1".parse().unwrap()
        ));
        assert!(peer_address_matches(
            "2001:db8::1",
            "2001:db8::1".parse().unwrap()
        ));
        assert!(!peer_address_matches(
            "2001:db8::1",
            "192.0.2.1".parse().unwrap()
        ));
        assert!(!peer_address_matches(
            "router.example",
            "192.0.2.1".parse().unwrap()
        ));
    }

    #[test]
    fn debug_for_peer_auth_redacts_credentials() {
        let rendered = format!(
            "{:?} {:?}",
            PeerAuth::Md5("md5-secret"),
            PeerAuth::TcpAo(&[TcpAoKeyConfig {
                send_id: 1,
                recv_id: 2,
                algorithm: crate::config::TcpAoAlgorithm::HmacSha1_96,
                secret: "ao-secret".to_string(),
                current: false,
            }])
        );
        assert!(!rendered.contains("md5-secret"), "{rendered}");
        assert!(!rendered.contains("ao-secret"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("send_id: 1, recv_id: 2"), "{rendered}");
    }

    #[test]
    fn listener_key_install_reports_the_peers_it_could_not_key() {
        let peers = [
            md5_peer("192.0.2.1", true, Some("first")),
            md5_peer("2001:db8::1", true, Some("second")),
        ];
        let keys = listener_auth_keys(&peers);
        let listener: SocketAddr = "[::]:179".parse().unwrap();
        // No socket behind the descriptor: every install fails.
        let (unkeyed, failures) = install_listener_auth_keys(listener, -1, &keys, false);
        assert_eq!(
            unkeyed,
            HashSet::from([
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
            ])
        );
        let failed: Vec<&str> = failures.iter().map(|(peer, _)| peer.as_str()).collect();
        assert_eq!(failed, ["192.0.2.1", "2001:db8::1"]);

        #[cfg(target_os = "linux")]
        {
            let socket = TcpSocket::new_v6().unwrap();
            socket.bind("[::]:0".parse().unwrap()).unwrap();
            let bound = socket.local_addr().unwrap();
            let (unkeyed, failures) =
                install_listener_auth_keys(bound, socket.as_raw_fd(), &keys, false);
            assert!(
                unkeyed.is_empty() && failures.is_empty(),
                "a socket that is bound but not listening yet takes the keys"
            );

            // An IPv4 listener has no key for an IPv6 peer, whose connections
            // cannot reach it.
            let socket = TcpSocket::new_v4().unwrap();
            socket.bind("0.0.0.0:0".parse().unwrap()).unwrap();
            let bound = socket.local_addr().unwrap();
            let (unkeyed, failures) =
                install_listener_auth_keys(bound, socket.as_raw_fd(), &keys, false);
            assert_eq!(
                unkeyed,
                HashSet::from(["2001:db8::1".parse::<IpAddr>().unwrap()])
            );
            // Not a refused key: `start_listener` reports a stranded passive
            // peer, and an active one is not affected.
            assert!(failures.is_empty(), "{failures:?}");
        }
    }

    /// The kernel accepts an unsigned SYN from a peer whose TCP-MD5 key is
    /// not on the listener, and nothing about the accepted connection says so
    /// (see `md5_key_installs_on_a_connection_that_was_never_signed`). Such a
    /// peer must not get a session.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn inbound_from_a_peer_the_listener_could_not_key_is_refused() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut cfg = test_service_config();
        cfg.peers
            .push(md5_peer("127.0.0.1", true, Some("md5-password")));
        let (event_tx, _) = broadcast::channel::<EventEnvelope>(4);
        let service = BgpService::new(&cfg, event_tx).await.unwrap();
        // A password over the kernel's 80 bytes cannot be installed, which
        // stands in for any key the listener does not take.
        let unkeyable = md5_peer("127.0.0.1", true, Some(&"x".repeat(81)));
        service
            .start_listener(&format!("127.0.0.1:{port}"), &[unkeyable])
            .await
            .unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("the kernel accepts the unsigned SYN");
        let mut buf = [0u8; 19];
        let read = timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("focl kept a connection open that nothing verified");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "an unverified connection got a session: {read:?}"
        );
        let peer = service.peer_show("127.0.0.1").await.unwrap();
        assert!(matches!(peer.state, PeerState::Idle), "{:?}", peer.state);
        let recorded = peer
            .listener_key_error
            .clone()
            .expect("the key the listener refused is reported");
        assert!(recorded.contains("password too long"), "{recorded}");

        // A session that comes up later must not erase the listener's failure:
        // the peer still runs without the key that could not be installed.
        service
            .set_peer_state("127.0.0.1", PeerState::Established, None, Some(0))
            .await;
        let peer = service.peer_show("127.0.0.1").await.unwrap();
        assert_eq!(peer.listener_key_error, Some(recorded));
    }

    #[test]
    fn current_key_override_is_only_reported_for_an_explicit_current() {
        let key = |send_id, recv_id, current| TcpAoKeyConfig {
            send_id,
            recv_id,
            algorithm: crate::config::TcpAoAlgorithm::HmacSha1_96,
            secret: "ao-secret".to_string(),
            current,
        };
        let status = |current_key, rnext_key| TcpAoStatus {
            current_key,
            rnext_key,
            pkt_good: 0,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
        };
        let keys = [key(1, 2, false), key(3, 4, true)];
        // The peer's SYN named the first key, the config asks for the second.
        assert_eq!(overridden_current_key(&keys, &status(1, 2)), Some(&keys[1]));
        assert_eq!(overridden_current_key(&keys, &status(3, 2)), Some(&keys[1]));
        assert_eq!(overridden_current_key(&keys, &status(3, 4)), None);
        // Without an explicit `current` no key was asked for.
        let unmarked = [key(1, 2, false), key(3, 4, false)];
        assert_eq!(overridden_current_key(&unmarked, &status(3, 4)), None);
    }

    #[test]
    fn listener_keys_follow_the_listener_address_family() {
        let v4_listener: SocketAddr = "0.0.0.0:179".parse().unwrap();
        let v6_listener: SocketAddr = "[::]:179".parse().unwrap();
        let v4_peer: IpAddr = "192.0.2.1".parse().unwrap();
        let v6_peer: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            listener_key_addr(v4_listener, v4_peer, false),
            Some(SocketAddr::new(v4_peer, 179))
        );
        assert_eq!(listener_key_addr(v4_listener, v6_peer, false), None);
        assert_eq!(
            listener_key_addr(v6_listener, v4_peer, false),
            Some("[::ffff:192.0.2.1]:179".parse().unwrap())
        );
        assert_eq!(
            listener_key_addr(v6_listener, v6_peer, false),
            Some(SocketAddr::new(v6_peer, 179))
        );

        // `net.ipv6.bindv6only=1`: a `[::]` listener takes no IPv4 connections,
        // so an IPv4 peer cannot be keyed and cannot reach it either.
        assert_eq!(listener_key_addr(v6_listener, v4_peer, true), None);
        assert_eq!(
            listener_key_addr(v6_listener, v6_peer, true),
            Some(SocketAddr::new(v6_peer, 179))
        );

        // Bound to one IPv6 address, a listener takes no IPv4 connections.
        let v6_only_listener: SocketAddr = "[2001:db8::2]:179".parse().unwrap();
        assert_eq!(listener_key_addr(v6_only_listener, v4_peer, false), None);
        assert_eq!(
            listener_key_addr(v6_only_listener, v6_peer, false),
            Some(SocketAddr::new(v6_peer, 179))
        );

        // Bound to a v4-mapped address, an IPv6 socket takes only IPv4 ones.
        let mapped_listener: SocketAddr = "[::ffff:192.0.2.9]:179".parse().unwrap();
        assert_eq!(
            listener_key_addr(mapped_listener, v4_peer, false),
            Some("[::ffff:192.0.2.1]:179".parse().unwrap())
        );
        assert_eq!(listener_key_addr(mapped_listener, v6_peer, false), None);
    }

    #[test]
    fn only_passive_peers_out_of_the_listeners_reach_are_reported() {
        let active = |address| PeerConfig {
            passive: false,
            ..md5_peer(address, true, Some("md5-password"))
        };
        let peers = [
            md5_peer("192.0.2.1", true, Some("md5-password")),
            md5_peer("2001:db8::1", true, Some("md5-password")),
            // Without authentication a passive peer depends on the listener
            // just the same.
            md5_peer("2001:db8::2", true, None),
            md5_peer("2001:db8::3", false, Some("disabled-peer")),
            // The README's dual-stack example: an active IPv6 peer next to an
            // IPv4 listener dials out and is fine.
            active("2001:db8::4"),
            active("192.0.2.4"),
        ];
        let unreachable = |listener: &str, v6_only: bool| -> Vec<&str> {
            unreachable_passive_peers(listener.parse().unwrap(), &peers, v6_only)
                .into_iter()
                .map(|peer| peer.address.as_str())
                .collect()
        };

        assert_eq!(
            unreachable("0.0.0.0:179", false),
            ["2001:db8::1", "2001:db8::2"]
        );
        assert_eq!(unreachable("[2001:db8::9]:179", false), ["192.0.2.1"]);
        assert!(unreachable_passive_peers("[::]:179".parse().unwrap(), &peers, false).is_empty());
        // bindv6only=1: the IPv4 passive peer is stranded, the IPv6 ones are not.
        assert_eq!(unreachable("[::]:179", true), ["192.0.2.1"]);
    }

    #[test]
    fn tcp_ao_peers_need_a_kernel_with_tcp_ao() {
        let ao_peer = |address, enabled| PeerConfig {
            tcp_ao_keys: vec![TcpAoKeyConfig {
                send_id: 1,
                recv_id: 2,
                algorithm: crate::config::TcpAoAlgorithm::HmacSha1_96,
                secret: "ao-secret".to_string(),
                current: false,
            }],
            ..md5_peer(address, enabled, None)
        };
        let peers = [
            md5_peer("192.0.2.1", true, Some("md5-password")),
            ao_peer("192.0.2.2", true),
            ao_peer("192.0.2.3", false),
            ao_peer("2001:db8::4", true),
        ];
        require_tcp_ao_support(&peers, true).expect("the kernel has TCP-AO");

        let error = require_tcp_ao_support(&peers, false)
            .expect_err("an enabled TCP-AO peer cannot run without TCP-AO")
            .to_string();
        assert!(error.contains("192.0.2.2, 2001:db8::4"), "{error}");
        assert!(error.contains("CONFIG_TCP_AO"), "{error}");
        assert!(!error.contains("192.0.2.1"), "{error}");
        assert!(!error.contains("192.0.2.3"), "{error}");

        // TCP-MD5 peers and disabled TCP-AO peers do not need it.
        require_tcp_ao_support(&peers[..1], false).unwrap();
        require_tcp_ao_support(&peers[2..3], false).unwrap();
    }

    /// `FoclConfig::load` is not the only way to a config: one built in code
    /// must not get a peer that names two mechanisms past `peer_auth`.
    #[tokio::test]
    async fn service_refuses_a_config_that_fails_validation() {
        let mut cfg = test_service_config();
        cfg.peers.push(PeerConfig {
            tcp_ao_keys: vec![TcpAoKeyConfig {
                send_id: 1,
                recv_id: 2,
                algorithm: crate::config::TcpAoAlgorithm::HmacSha1_96,
                secret: "ao-secret".to_string(),
                current: false,
            }],
            ..md5_peer("192.0.2.1", true, Some("md5-password"))
        });
        let (event_tx, _) = broadcast::channel::<EventEnvelope>(4);
        let error = BgpService::new(&cfg, event_tx)
            .await
            .err()
            .expect("a peer with a password and TCP-AO keys must be refused");
        assert!(format!("{error:#}").contains("pick one"), "{error:#}");
    }

    fn md5_peer(address: &str, enabled: bool, password: Option<&str>) -> PeerConfig {
        PeerConfig {
            address: address.to_string(),
            remote_as: 65_002,
            local_as: None,
            hold_time_secs: 90,
            connect_retry_secs: 5,
            remote_port: 179,
            local_address: None,
            enabled,
            passive: true,
            route_refresh: true,
            name: None,
            password: password.map(str::to_string),
            tcp_ao_keys: vec![],
        }
    }

    #[test]
    fn local_open_advertises_the_configured_hold_time_including_zero() {
        for advertised in [0u16, 30, 90] {
            let BgpMessage::Open(open) =
                local_open(Ipv4Addr::new(192, 0, 2, 1), 65_001, advertised, true)
            else {
                panic!()
            };
            assert_eq!(
                open.hold_time, advertised,
                "the OPEN must advertise the configured hold time unchanged"
            );
        }
    }

    #[test]
    fn negotiated_hold_time_is_zero_if_either_side_disables_it_else_the_minimum() {
        assert_eq!(negotiate_hold_time(0, 180), 0);
        assert_eq!(negotiate_hold_time(90, 30), 30);
        assert_eq!(negotiate_hold_time(90, 0), 0);
        assert_eq!(negotiate_hold_time(90, 180), 90);
        assert_eq!(negotiate_hold_time(30, 30), 30);
    }

    #[test]
    fn a_capability_less_peer_still_carries_ipv4_unicast() {
        let plain = NegotiatedCapabilities::default();
        assert!(plain.plain_ipv4());
        assert!(plain.carries(Afi::Ipv4, Safi::Unicast));
        assert!(!plain.carries(Afi::Ipv6, Safi::Unicast));

        let v6_only = NegotiatedCapabilities {
            families: HashSet::from([(Afi::Ipv6, Safi::Unicast)]),
            ..Default::default()
        };
        assert!(!v6_only.carries(Afi::Ipv4, Safi::Unicast));
        assert!(v6_only.carries(Afi::Ipv6, Safi::Unicast));
    }

    #[test]
    fn end_of_rib_markers_are_empty_per_family() {
        let BgpMessage::Update(v4) = end_of_rib(Afi::Ipv4) else {
            panic!("not an UPDATE")
        };
        assert!(v4.withdrawn_prefixes.is_empty());
        assert!(v4.announced_prefixes.is_empty());
        assert!(v4.attributes.into_attributes_iter().next().is_none());

        let BgpMessage::Update(v6) = end_of_rib(Afi::Ipv6) else {
            panic!("not an UPDATE")
        };
        assert!(v6.withdrawn_prefixes.is_empty());
        assert!(v6.announced_prefixes.is_empty());
        let unreach = v6
            .attributes
            .get_unreachable_nlri()
            .expect("MP_UNREACH present");
        assert_eq!(unreach.afi, Afi::Ipv6);
        assert!(unreach.prefixes.is_empty());
    }

    #[test]
    fn prefix_state_layers_runtime_overrides_over_config() {
        let config = vec![
            PrefixEntry {
                network: "192.0.2.0/24".parse().unwrap(),
                next_hop: Some("192.0.2.1".parse().unwrap()),
                dev_attr255_interval_secs: None,
            },
            PrefixEntry {
                network: "2001:db8::/48".parse().unwrap(),
                next_hop: None,
                dev_attr255_interval_secs: None,
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
            dev_attr255_interval_secs: None,
        }));
        assert_eq!(state.effective().len(), 2);
        assert_eq!(state.override_count(), 0);

        // A runtime-only entry is added and dropped without residue.
        let runtime_only: IpNet = "198.51.100.0/24".parse().unwrap();
        assert!(state.add(PrefixEntry {
            network: runtime_only,
            next_hop: None,
            dev_attr255_interval_secs: None,
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
            dev_attr255_interval_secs: None,
        }]);
        assert!(state.remove(&suppressed));
        assert!(state.add(PrefixEntry {
            network: runtime_only,
            next_hop: None,
            dev_attr255_interval_secs: None,
        }));

        let added: IpNet = "203.0.113.0/24".parse().unwrap();
        let (announce, withdraw) = state.reset_overrides(vec![PrefixEntry {
            network: added,
            next_hop: None,
            dev_attr255_interval_secs: None,
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
            dev_attr255_interval_secs: None,
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
    fn reload_re_announces_changed_attributes_and_withdraws_gone_networks() {
        let network: IpNet = "192.0.2.0/24".parse().unwrap();
        let entry = |next_hop: &str, interval: Option<u32>| PrefixEntry {
            network,
            next_hop: Some(next_hop.parse().unwrap()),
            dev_attr255_interval_secs: interval,
        };
        let mut state = PrefixState::new(vec![entry("10.0.0.1", Some(1800))]);

        // An unchanged config produces an empty delta.
        let (announce, withdraw) = state.reset_overrides(vec![entry("10.0.0.1", Some(1800))]);
        assert!(announce.is_empty(), "unchanged config must not re-announce");
        assert!(withdraw.is_empty());

        // A new configured next hop only reaches the wire on a re-announcement.
        let (announce, withdraw) = state.reset_overrides(vec![entry("10.0.0.9", Some(1800))]);
        assert_eq!(announce.len(), 1);
        assert_eq!(announce[0].next_hop, Some("10.0.0.9".parse().unwrap()));
        assert!(announce[0].dev_attr255_interval_secs == Some(1800));
        assert!(withdraw.is_empty());

        // Clearing the attribute-255 clock changes the wire attributes too.
        let (announce, withdraw) = state.reset_overrides(vec![entry("10.0.0.9", None)]);
        assert_eq!(announce.len(), 1);
        assert_eq!(announce[0].dev_attr255_interval_secs, None);
        assert!(withdraw.is_empty());

        // A network that disappeared stays a withdrawal, not an announcement.
        let (announce, withdraw) = state.reset_overrides(vec![]);
        assert!(announce.is_empty());
        assert_eq!(withdraw, vec![network]);
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
                dev_attr255_interval_secs: None,
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
    fn configured_next_hop_must_match_the_prefix_family() {
        use crate::config::PrefixConfig;

        fn entry_config(network: &str, next_hop: &str) -> FoclConfig {
            let mut cfg = test_service_config();
            cfg.prefixes = vec![PrefixConfig {
                network: network.to_string(),
                next_hop: Some(next_hop.to_string()),
                dev_attr255_interval_secs: None,
            }];
            cfg
        }

        // A v6 next hop on a v4 prefix would reach classic NEXT_HOP encoding.
        let error = parse_prefix_entries(&entry_config("192.0.2.0/24", "2001:db8::1"))
            .expect_err("a v6 next hop on a v4 prefix must be rejected");
        let message = format!("{error:#}");
        assert!(
            message.contains("192.0.2.0/24") && message.contains("2001:db8::1"),
            "the error names the entry: {message}"
        );
        assert!(
            message.contains("does not match the prefix family"),
            "{message}"
        );

        // The inverse: a v4 next hop on a v6 prefix is dropped later, so it is
        // rejected at parse time too.
        let error = parse_prefix_entries(&entry_config("2001:db8::/48", "192.0.2.1"))
            .expect_err("a v4 next hop on a v6 prefix must be rejected");
        let message = format!("{error:#}");
        assert!(
            message.contains("2001:db8::/48") && message.contains("192.0.2.1"),
            "the error names the entry: {message}"
        );

        // Matching pairs still parse.
        let entries = parse_prefix_entries(&entry_config("192.0.2.0/24", "192.0.2.1"))
            .expect("a matching v4 pair must parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].next_hop, Some("192.0.2.1".parse().unwrap()));
        let entries = parse_prefix_entries(&entry_config("2001:db8::/48", "2001:db8::1"))
            .expect("a matching v6 pair must parse");
        assert_eq!(entries[0].network.to_string(), "2001:db8::/48");
        assert_eq!(entries[0].next_hop, Some("2001:db8::1".parse().unwrap()));
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
            dev_attr255_interval_secs: None,
        }));
        // Same next hop again: nothing to announce.
        assert!(!state.add(PrefixEntry {
            network,
            next_hop: Some(first),
            dev_attr255_interval_secs: None,
        }));
        // A different next hop must re-announce, and the effective entry follows.
        assert!(state.add(PrefixEntry {
            network,
            next_hop: Some(second),
            dev_attr255_interval_secs: None,
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
            dev_attr255_interval_secs: None,
        }]);

        assert!(!state.add(PrefixEntry {
            network,
            next_hop: Some(configured),
            dev_attr255_interval_secs: None,
        }));
        assert!(state.add(PrefixEntry {
            network,
            next_hop: Some(override_hop),
            dev_attr255_interval_secs: None,
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
    fn remove_after_a_next_hop_override_suppresses_the_configured_prefix() {
        let network: IpNet = "192.0.2.0/24".parse().unwrap();
        let mut state = PrefixState::new(vec![PrefixEntry {
            network,
            next_hop: Some("10.0.0.1".parse().unwrap()),
            dev_attr255_interval_secs: None,
        }]);

        // A runtime override on a configured network.
        assert!(state.add(PrefixEntry {
            network,
            next_hop: Some("10.0.0.9".parse().unwrap()),
            dev_attr255_interval_secs: None,
        }));

        // Removing it must suppress the config baseline as well: dropping only
        // the override leaves the network announced through the config entry.
        assert!(state.remove(&network));
        assert!(
            state
                .effective()
                .iter()
                .all(|entry| entry.network != network),
            "the config baseline must not stay in the effective set"
        );
        assert_eq!(state.status_of(&network), PrefixStatus::Suppressed);
        assert_eq!(state.source_of(&network), Some(PrefixSource::Config));
        // Removing it again changes nothing.
        assert!(!state.remove(&network));
        assert_eq!(state.override_count(), 1);
    }

    #[test]
    fn prefix_list_reports_the_runtime_override_for_a_configured_network() {
        let network: IpNet = "192.0.2.0/24".parse().unwrap();
        let mut state = PrefixState::new(vec![PrefixEntry {
            network,
            next_hop: Some("10.0.0.1".parse().unwrap()),
            dev_attr255_interval_secs: None,
        }]);
        assert!(state.add(PrefixEntry {
            network,
            next_hop: Some("10.0.0.9".parse().unwrap()),
            dev_attr255_interval_secs: None,
        }));

        let rows = state.view();
        assert_eq!(
            rows.len(),
            1,
            "the override must not add a second row for the same network"
        );
        assert_eq!(rows[0].network, network.to_string());
        assert_eq!(
            rows[0].next_hop.as_deref(),
            Some("10.0.0.9"),
            "the row must describe the entry that is announced"
        );
        assert_eq!(rows[0].source, PrefixSource::Runtime);
        assert_eq!(rows[0].status, PrefixStatus::Announced);
    }

    #[test]
    fn default_next_hop_comes_from_the_config_only() {
        let v4: IpNet = "192.0.2.0/24".parse().unwrap();
        let v6: IpNet = "2001:db8::/48".parse().unwrap();
        let mut state = PrefixState::new(vec![PrefixEntry {
            network: v4,
            next_hop: Some("10.0.0.1".parse().unwrap()),
            dev_attr255_interval_secs: None,
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
            dev_attr255_interval_secs: None,
        });
        assert_eq!(state.default_next_hop(&v6), None);
    }

    #[test]
    fn dev_attr255_clock_payload_is_a_fixed_13_byte_vector() {
        let payload = dev_attr255_clock_payload(1_800_000_000, 1800);
        assert_eq!(payload.len(), 13);
        assert_eq!(
            payload,
            vec![
                0x42, 0x47, 0x50, 0x4b, 0x49, 0x54, // "BGPKIT"
                0x01, // version
                0x42, 0x40, // round = (1_800_000_000 / 1800) % 65_536
                0x6b, 0x49, 0xd2, 0x00, // 1_800_000_000 as u32
            ]
        );

        // The round field wraps at 65_536: `unix / interval` is taken mod
        // 65_536, so it cycles with period 65_536 * interval and stays small
        // for large unix values.
        let at_wrap: u64 = 65_536 * 1800;
        let first = dev_attr255_clock_payload(at_wrap, 1800);
        assert_eq!(&first[7..9], &[0x00, 0x00][..]);
        let after_wrap = dev_attr255_clock_payload(at_wrap + 1800, 1800);
        assert_eq!(&after_wrap[7..9], &[0x00, 0x01][..]);
        // A full period later the round repeats while the unix field advances.
        let period = dev_attr255_clock_payload(1_800_000_000 + at_wrap, 1800);
        assert_eq!(&period[7..9], &[0x42, 0x40][..]);

        // A zero interval cannot come from a validated config, but the payload
        // builder must not divide by zero if one reaches it.
        assert_eq!(dev_attr255_clock_payload(1_800_000_000, 0).len(), 13);
    }

    #[test]
    fn announce_updates_carry_the_attribute_255_clock_only_when_configured() {
        // Walks the encoded attribute list into (flags, code, value) triples.
        fn attributes_of(message: &BgpMessage, asn_len: AsnLength) -> Vec<(u8, u8, Vec<u8>)> {
            let BgpMessage::Update(update) = message else {
                panic!("not an UPDATE")
            };
            let mut buf = bytes::BytesMut::new();
            update.attributes.encode_to(asn_len, &mut buf).unwrap();
            let mut attrs = Vec::new();
            let mut p = 0;
            while p < buf.len() {
                let flags = buf[p];
                let code = buf[p + 1];
                let (length, header) = if flags & 0x10 != 0 {
                    (u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize, 4)
                } else {
                    (buf[p + 2] as usize, 3)
                };
                attrs.push((flags, code, buf[p + header..p + header + length].to_vec()));
                p += header + length;
            }
            attrs
        }

        let negotiated = NegotiatedCapabilities {
            families: HashSet::from([(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]),
            asn4: true,
            ..Default::default()
        };
        let router_id = Ipv4Addr::new(192, 0, 2, 1);
        let v6_local: IpAddr = "2001:db8::2".parse().unwrap();
        let v4 = PrefixEntry {
            network: "192.0.2.0/24".parse().unwrap(),
            next_hop: None,
            dev_attr255_interval_secs: Some(1800),
        };
        let v6 = PrefixEntry {
            network: "2001:db8::/48".parse().unwrap(),
            next_hop: None,
            dev_attr255_interval_secs: Some(1800),
        };

        // 0xc0 flags (OPTIONAL|TRANSITIVE, no PARTIAL), code 255, length 13,
        // then the BGPKIT magic and the version octet.
        let expected = [0xc0u8, 0xff, 0x0d, 0x42, 0x47, 0x50, 0x4b, 0x49, 0x54, 0x01];
        let v4_update = build_announce_updates(
            std::slice::from_ref(&v4),
            router_id,
            IpAddr::V4(router_id),
            65_001,
            &negotiated,
        )
        .remove(0);
        let v6_update = build_announce_updates(
            std::slice::from_ref(&v6),
            router_id,
            v6_local,
            65_001,
            &negotiated,
        )
        .remove(0);

        for update in [&v4_update, &v6_update] {
            let raw = update.encode(AsnLength::Bits32).unwrap();
            assert!(
                raw.windows(expected.len())
                    .any(|window| window == &expected[..]),
                "expected the flagged attribute-255 clock on the wire"
            );
            let clock = attributes_of(update, AsnLength::Bits32)
                .into_iter()
                .find(|(_, code, _)| *code == 255)
                .expect("development attribute present");
            assert_eq!(clock.0, 0xc0, "OPTIONAL|TRANSITIVE, no PARTIAL bit");
            assert_eq!(clock.2.len(), 13);
            assert!(clock.2.starts_with(b"BGPKIT\x01"));
        }

        // Parsing the v4 message back keeps the originating flags.
        let mut parsed_bytes = v4_update.encode(AsnLength::Bits32).unwrap();
        let parsed = parse_bgp_message(&mut parsed_bytes, false, &AsnLength::Bits32).unwrap();
        let BgpMessage::Update(parsed_update) = parsed else {
            panic!("not an UPDATE")
        };
        let clock = parsed_update
            .attributes
            .clone()
            .into_attributes_iter()
            .find(|attribute| matches!(attribute.value, AttributeValue::Development(_)))
            .expect("parsed development attribute");
        assert!(clock.flag.contains(AttrFlags::OPTIONAL));
        assert!(clock.flag.contains(AttrFlags::TRANSITIVE));
        assert!(!clock.flag.contains(AttrFlags::PARTIAL));

        // Without a configured interval the attribute must not appear at all.
        let mut plain = [v4.clone(), v6.clone()];
        for entry in &mut plain {
            entry.dev_attr255_interval_secs = None;
        }
        let updates = build_announce_updates(&plain, router_id, v6_local, 65_001, &negotiated);
        assert_eq!(updates.len(), 2);
        for update in &updates {
            let raw = update.encode(AsnLength::Bits32).unwrap();
            assert!(
                !raw.windows(expected.len())
                    .any(|window| window == &expected[..]),
                "an unconfigured prefix must not carry the development attribute"
            );
            assert!(attributes_of(update, AsnLength::Bits32)
                .iter()
                .all(|(_, code, _)| *code != 255));
        }
    }

    #[tokio::test]
    async fn runtime_readd_keeps_the_configured_clock() {
        use crate::config::PrefixConfig;

        let network: IpNet = "2001:db8::/48".parse().unwrap();
        let mut cfg = test_service_config();
        cfg.prefixes.push(PrefixConfig {
            network: network.to_string(),
            next_hop: Some("2001:db8::1".to_string()),
            dev_attr255_interval_secs: Some(3600),
        });
        let (event_tx, _) = broadcast::channel::<EventEnvelope>(4);
        let service = BgpService::new(&cfg, event_tx).await.unwrap();

        assert!(service.prefix_remove(network, false).await.unwrap().changed);
        let added = service.prefix_add(network, None, false).await.unwrap();
        assert!(added.changed);

        let entry = service
            .inner
            .prefix_state
            .read()
            .await
            .effective()
            .into_iter()
            .find(|entry| entry.network == network)
            .expect("the re-added prefix is effective again");
        assert_eq!(entry.dev_attr255_interval_secs, Some(3600));
    }

    #[tokio::test]
    async fn a_station_reconnect_asks_each_peer_for_its_table_once_per_cooldown() {
        let cfg = test_service_config();
        let (event_tx, _) = broadcast::channel::<EventEnvelope>(4);
        let service = BgpService::new(&cfg, event_tx).await.unwrap();

        let peer = "192.0.2.2";
        let (tx, mut rx) = mpsc::channel(8);
        service.inner.session_ops.write().await.insert(
            peer.to_string(),
            SessionHandle {
                tx,
                supports_v4: true,
                supports_v6: false,
                refresh_v4: true,
                refresh_v6: false,
            },
        );

        // The station's first reconnect asks for the one family this session can refresh.
        assert!(service.redump_peer(peer).await);
        match rx.recv().await {
            Some(SessionOp::RequestRefresh { afi }) => assert_eq!(afi, Afi::Ipv4),
            other => panic!("expected a route refresh for ipv4, got {other:?}"),
        }

        // A peer that never negotiated route refresh is not asked: an unanswered request would make
        // a station wait for a table that is not coming.
        let (tx, mut quiet) = mpsc::channel(8);
        service.inner.session_ops.write().await.insert(
            "192.0.2.3".to_string(),
            SessionHandle {
                tx,
                supports_v4: true,
                supports_v6: false,
                refresh_v4: false,
                refresh_v6: false,
            },
        );
        assert!(!service.redump_peer("192.0.2.3").await);
        assert!(quiet.try_recv().is_err());
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

    #[tokio::test]
    async fn dry_run_add_reports_a_next_hop_change_and_family_targets() {
        use crate::config::PrefixConfig;

        let network: IpNet = "192.0.2.0/24".parse().unwrap();
        let configured: IpAddr = "192.0.2.1".parse().unwrap();
        let override_hop: IpAddr = "192.0.2.9".parse().unwrap();
        let mut cfg = test_service_config();
        cfg.prefixes.push(PrefixConfig {
            network: network.to_string(),
            next_hop: Some(configured.to_string()),
            dev_attr255_interval_secs: None,
        });
        let (event_tx, _) = broadcast::channel::<EventEnvelope>(4);
        let service = BgpService::new(&cfg, event_tx).await.unwrap();

        // One dual-stack session and one IPv6-only session: only the peers that
        // can carry the network's family may be named as targets.
        for (peer, supports_v4, supports_v6) in
            [("192.0.2.2", true, true), ("2001:db8::2", false, true)]
        {
            let (tx, _rx) = mpsc::channel(4);
            service.inner.session_ops.write().await.insert(
                peer.to_string(),
                SessionHandle {
                    tx,
                    supports_v4,
                    supports_v6,
                    refresh_v4: true,
                    refresh_v6: true,
                },
            );
        }

        let dry = service
            .prefix_add(network, Some(override_hop), true)
            .await
            .unwrap();
        assert!(
            dry.changed,
            "a next-hop change is a change in a dry run too"
        );
        assert!(dry.dry_run);
        assert_eq!(dry.peers_notified, vec!["192.0.2.2".to_string()]);
        assert_eq!(dry.status, PrefixStatus::Announced);

        // A new v6 network reaches both sessions.
        let v6: IpNet = "2001:db8:1::/48".parse().unwrap();
        let dry_v6 = service.prefix_add(v6, None, true).await.unwrap();
        assert!(dry_v6.changed);
        assert_eq!(
            dry_v6.peers_notified,
            vec!["192.0.2.2".to_string(), "2001:db8::2".to_string()]
        );

        // The dry runs must not have touched the state.
        let rows = service.prefix_view().await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].next_hop.as_deref(), Some("192.0.2.1"));
        let effective = service.inner.prefix_state.read().await.effective();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].next_hop, Some(configured));
    }

    #[tokio::test]
    async fn prefix_remove_reads_provenance_under_the_mutation_lock() {
        let cfg = test_service_config();
        let (event_tx, _) = broadcast::channel::<EventEnvelope>(4);
        let service = BgpService::new(&cfg, event_tx).await.unwrap();
        let network: IpNet = "198.51.100.0/24".parse().unwrap();

        let added = service.prefix_add(network, None, false).await.unwrap();
        assert_eq!(added.source, Some(PrefixSource::Runtime));

        // The source has to be read before the entry is dropped, while holding
        // `prefix_ops`, so no concurrent mutation can change it in between.
        let removed = service.prefix_remove(network, false).await.unwrap();
        assert!(removed.changed);
        assert_eq!(removed.source, Some(PrefixSource::Runtime));
        assert_eq!(removed.status, PrefixStatus::Absent);

        // A network the state never knew reports null, from the same locked read.
        let again = service.prefix_remove(network, false).await.unwrap();
        assert!(!again.changed);
        assert_eq!(again.source, None);
    }

    /// The session loop must answer a ROUTE-REFRESH while a control client
    /// holds the mutation lock: the loop is the only drain for its own queue,
    /// so waiting on a lock a blocked producer holds would never resolve.
    #[tokio::test]
    async fn route_refresh_replay_does_not_wait_for_the_mutation_lock() {
        let cfg = test_service_config();
        let (event_tx, _) = broadcast::channel::<EventEnvelope>(4);
        let service = BgpService::new(&cfg, event_tx).await.unwrap();
        let network: IpNet = "198.51.100.0/24".parse().unwrap();
        service.prefix_add(network, None, false).await.unwrap();

        let peer = PeerConfig {
            address: "192.0.2.9".to_string(),
            remote_as: 65_002,
            local_as: None,
            hold_time_secs: 30,
            connect_retry_secs: 1,
            remote_port: 179,
            local_address: None,
            enabled: true,
            passive: true,
            route_refresh: true,
            name: None,
            password: None,
            tcp_ao_keys: vec![],
        };
        let negotiated = NegotiatedCapabilities {
            families: HashSet::from([(Afi::Ipv4, Safi::Unicast)]),
            asn4: true,
            route_refresh: true,
            graceful_restart: false,
        };
        let refresh = BgpRouteRefreshMessage {
            afi: 1,
            subtype: 0,
            safi: 1,
            data: vec![],
        };

        let guard = service.inner.prefix_ops.lock().await;
        let mut out = Vec::new();
        timeout(
            Duration::from_secs(5),
            service.replay_route_refresh(
                &peer,
                &mut out,
                &negotiated,
                "192.0.2.1".parse().unwrap(),
                &refresh,
            ),
        )
        .await
        .expect("the replay must not wait for the mutation lock")
        .unwrap();
        drop(guard);

        assert!(
            !out.is_empty(),
            "the replay writes the table and the family's End-of-RIB"
        );
    }

    /// A stalled clock task must not replay every missed tick: the same round
    /// would be dispatched once per tick and can fill a session queue.
    #[tokio::test(start_paused = true)]
    async fn clock_ticker_skips_missed_ticks() {
        let mut ticker = clock_ticker(30);
        ticker.tick().await;
        tokio::time::advance(Duration::from_secs(95)).await;

        let mut immediate = 0;
        while timeout(Duration::ZERO, ticker.tick()).await.is_ok() {
            immediate += 1;
            assert!(immediate < 4, "a stall must not burst the missed ticks");
        }
        assert_eq!(immediate, 1, "one tick after a stall, not three");
    }
}
