use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoclConfig {
    pub global: GlobalConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub prefixes: Vec<PrefixConfig>,
    #[serde(default)]
    pub archive: ArchiveConfig,
    /// Forwarding what this daemon's sessions see to a monitoring station (RFC 7854).
    #[serde(default)]
    pub bmp: BmpConfig,
}

/// `[bmp]`: forwarding this daemon's sessions to a monitoring station.
///
/// The station is a `bgpviews`-style collector, and focl is the exporter: BMP has no
/// station-initiated mode, so this daemon dials and the station never dials back. Absent this
/// table, nothing is exported and no socket is opened.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmpConfig {
    #[serde(default)]
    pub enabled: bool,
    /// One connection per station. Two stations may carry the two directions of the same session:
    /// what the peers sent us (Adj-RIB-In) and what we sent them (Adj-RIB-Out), which a station
    /// records under different views and therefore as different connections.
    #[serde(default)]
    pub stations: Vec<BmpStationConfig>,
    /// Exporter name the station records as this feed's identity.
    #[serde(default = "default_bmp_sys_name")]
    pub sys_name: String,
    #[serde(default = "default_bmp_sys_descr")]
    pub sys_descr: String,
    /// Interval between Statistics Reports. They are the only liveness signal BMP offers, so a
    /// station behind a stateful firewall needs this shorter than that firewall's idle timeout.
    #[serde(default = "default_bmp_stats_interval")]
    pub stats_interval_secs: u64,
    /// Frames that may wait for the station before the session is dropped. Sized to absorb one
    /// full table: a station that cannot keep up ends the connection, which the archive records as
    /// a gap, rather than losing frames silently or stalling a BGP session.
    #[serde(default = "default_bmp_queue")]
    pub queue_frames: usize,
    /// Shortest interval between two table requests for the same peer. A station that reconnects in
    /// a loop must not be able to make this daemon ask its peers for a full table each time.
    #[serde(default = "default_bmp_redump_cooldown")]
    pub redump_cooldown_secs: u64,
}

impl Default for BmpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            stations: Vec::new(),
            sys_name: default_bmp_sys_name(),
            sys_descr: default_bmp_sys_descr(),
            stats_interval_secs: default_bmp_stats_interval(),
            queue_frames: default_bmp_queue(),
            redump_cooldown_secs: default_bmp_redump_cooldown(),
        }
    }
}

/// One `[[bmp.stations]]` table: a connection this daemon opens to a station.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmpStationConfig {
    /// The station's `host:port`.
    pub address: String,
    /// What this connection carries. `false` (the default) is pre-policy Adj-RIB-In, what the
    /// peers sent us. `true` is Adj-RIB-Out (RFC 8671), what we sent them, flagged with `O` and
    /// `L` so a station can tell it apart from the inbound direction.
    #[serde(default)]
    pub rib_out: bool,
    /// Peers to export on this connection, by configured address or name. Empty exports every
    /// peer that comes up.
    #[serde(default)]
    pub peers: Vec<String>,
    /// When this station connects while peers are already up, ask those peers to resend their
    /// tables (RFC 2918), so the station records a baseline instead of starting from changes only.
    /// Ignored on a `rib_out` connection, which carries no tables to rebuild.
    #[serde(default = "default_true")]
    pub redump_on_connect: bool,
}

fn default_bmp_sys_name() -> String {
    "focl".to_string()
}

fn default_bmp_sys_descr() -> String {
    concat!("focl ", env!("CARGO_PKG_VERSION")).to_string()
}

fn default_bmp_stats_interval() -> u64 {
    60
}

fn default_bmp_queue() -> usize {
    65_536
}

fn default_bmp_redump_cooldown() -> u64 {
    300
}

impl FoclConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML in {}", path.display()))?;
        cfg.validate()
            .with_context(|| format!("config validation failed for {}", path.display()))?;
        Ok(cfg)
    }

    /// Refuses a `[bmp]` table that cannot do what it says.
    ///
    /// Every rule here exists because the alternative fails silently: a missing station exports
    /// nothing, an unparseable one only fails once the daemon is running, and a peer name that
    /// matches no configured peer would look like a healthy feed of an idle session.
    fn validate_bmp(&self) -> Result<()> {
        if !self.bmp.enabled {
            if !self.bmp.stations.is_empty() {
                bail!("[[bmp.stations]] is set but [bmp].enabled is false");
            }
            return Ok(());
        }
        if self.bmp.stations.is_empty() {
            bail!("[bmp].enabled requires at least one [[bmp.stations]] entry");
        }
        // One connection per station address: a station serves one view per listening port, so a
        // second connection to the same port would replace the first rather than add a direction.
        let mut seen: std::collections::HashMap<&str, bool> = std::collections::HashMap::new();
        for station in &self.bmp.stations {
            if station.address.parse::<std::net::SocketAddr>().is_err() {
                bail!(
                    "[[bmp.stations]].address {} is not host:port",
                    station.address
                );
            }
            if let Some(first_rib_out) = seen.insert(station.address.as_str(), station.rib_out) {
                bail!(
                    "[[bmp.stations]] names {} twice (rib_out {first_rib_out} and {}); a station \
                     serves one view per port, so use one entry per direction and port",
                    station.address,
                    station.rib_out
                );
            }
        }
        if self.bmp.sys_name.trim().is_empty() {
            bail!(
                "[bmp].sys_name must not be empty; the station records it as this feed's identity"
            );
        }
        if self.bmp.stats_interval_secs == 0 {
            bail!("[bmp].stats_interval_secs must be at least 1");
        }
        if self.bmp.queue_frames == 0 {
            bail!("[bmp].queue_frames must be at least 1");
        }
        if self.bmp.redump_cooldown_secs == 0 {
            bail!("[bmp].redump_cooldown_secs must be at least 1; a station that flaps must not pull a table on every reconnect");
        }
        for station in &self.bmp.stations {
            if station.rib_out && station.redump_on_connect {
                // An outbound connection describes what this daemon sends; there is no table for the
                // station to rebuild, so the setting would silently ask peers for transfers nobody
                // needs.
                bail!(
                    "[[bmp.stations]] {} sets redump_on_connect with rib_out = true; an Adj-RIB-Out \
                     connection has no table to rebuild",
                    station.address
                );
            }
        }
        for station in &self.bmp.stations {
            for wanted in &station.peers {
                let known = self.peers.iter().any(|peer| {
                    peer.address == *wanted || peer.name.as_deref() == Some(wanted.as_str())
                });
                if !known {
                    bail!(
                        "[[bmp.stations]].peers names {wanted}, which is neither a peer address \
                         nor a peer name"
                    );
                }
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.global.asn == 0 {
            bail!("[global].asn must be non-zero");
        }

        if self.global.router_id.parse::<std::net::Ipv4Addr>().is_err() {
            bail!("[global].router_id must be a valid IPv4 address");
        }

        // One peer per address: an inbound connection matches a peer by IP, so
        // two spellings of the same address (`192.0.2.1` and `::ffff:192.0.2.1`)
        // would leave the choice of peer, its remote AS and its key undefined.
        let mut seen: std::collections::HashMap<std::net::IpAddr, &str> =
            std::collections::HashMap::new();
        for peer in &self.peers {
            if let Ok(address) = peer.address.parse::<std::net::IpAddr>() {
                if let Some(first) = seen.insert(address.to_canonical(), peer.address.as_str()) {
                    bail!(
                        "peers {first} and {} are the same address in different spellings",
                        peer.address
                    );
                }
            }
            if peer.remote_as == 0 {
                bail!("peer {} has invalid remote_as 0", peer.address);
            }
            if peer.remote_port == 0 {
                bail!("peer {} has invalid remote_port 0", peer.address);
            }
            if peer.hold_time_secs != 0 && peer.hold_time_secs < 3 {
                bail!(
                    "peer {} has invalid hold_time_secs {}; must be 0 or >=3",
                    peer.address,
                    peer.hold_time_secs
                );
            }
            if let Some(local) = &peer.local_address {
                let ok = local.parse::<std::net::SocketAddr>().is_ok()
                    || local.parse::<std::net::IpAddr>().is_ok();
                if !ok {
                    bail!(
                        "peer {} has invalid local_address {}; expected IP or socket address",
                        peer.address,
                        local
                    );
                }
            }
            validate_peer_auth(peer)?;
        }

        self.validate_bmp()?;

        for prefix in &self.prefixes {
            prefix.network.parse::<IpNet>().with_context(|| {
                format!("invalid IP prefix in [[prefixes]]: {}", prefix.network)
            })?;
            if prefix.dev_attr255_interval_secs == Some(0) {
                bail!(
                    "[[prefixes]] {} has invalid dev_attr255_interval_secs; must be > 0",
                    prefix.network
                );
            }
        }

        self.archive.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub asn: u32,
    pub router_id: String,
    #[serde(default = "default_listen")]
    pub listen: bool,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_control_socket")]
    pub control_socket: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_listen() -> bool {
    true
}

fn default_listen_addr() -> String {
    "0.0.0.0:179".to_string()
}

fn default_control_socket() -> PathBuf {
    PathBuf::from("/tmp/focld.sock")
}

fn default_log_level() -> String {
    "info".to_string()
}

/// One `[[peers]]` table. An unknown key is an error: a misspelled `password`
/// or `tcp_ao_keys` would otherwise leave the peer without the authentication
/// its config asks for.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub address: String,
    pub remote_as: u32,
    #[serde(default)]
    pub local_as: Option<u32>,
    #[serde(default = "default_hold_time")]
    pub hold_time_secs: u16,
    #[serde(default = "default_connect_retry")]
    pub connect_retry_secs: u16,
    #[serde(default = "default_remote_port")]
    pub remote_port: u16,
    #[serde(default)]
    pub local_address: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub passive: bool,
    #[serde(default = "default_true")]
    pub route_refresh: bool,
    #[serde(default)]
    pub name: Option<String>,
    /// TCP-MD5 (RFC 2385) password. Mutually exclusive with `tcp_ao_keys`.
    #[serde(default)]
    pub password: Option<String>,
    /// TCP-AO (RFC 5925) master key tuples. Mutually exclusive with
    /// `password`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_ao_keys: Vec<TcpAoKeyConfig>,
}

/// Stands in for a secret in `Debug` output.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Leaves the TCP-MD5 password out, so a peer can end up in a log or a panic
/// message. The destructuring makes a new field a compile error here rather
/// than a field that silently goes unprinted.
impl fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            address,
            remote_as,
            local_as,
            hold_time_secs,
            connect_retry_secs,
            remote_port,
            local_address,
            enabled,
            passive,
            route_refresh,
            name,
            password,
            tcp_ao_keys,
        } = self;
        f.debug_struct("PeerConfig")
            .field("address", address)
            .field("remote_as", remote_as)
            .field("local_as", local_as)
            .field("hold_time_secs", hold_time_secs)
            .field("connect_retry_secs", connect_retry_secs)
            .field("remote_port", remote_port)
            .field("local_address", local_address)
            .field("enabled", enabled)
            .field("passive", passive)
            .field("route_refresh", route_refresh)
            .field("name", name)
            .field("password", &password.as_ref().map(|_| Redacted))
            .field("tcp_ao_keys", tcp_ao_keys)
            .finish()
    }
}

/// The longest TCP-MD5 password or TCP-AO secret the Linux kernel accepts.
pub const TCP_AUTH_MAX_KEY_LEN: usize = 80;

/// One TCP-AO master key tuple (RFC 5925 s3.1). `send_id` goes into the KeyID
/// of outgoing segments and has to equal the peer's `recv_id`, and vice versa.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpAoKeyConfig {
    pub send_id: u8,
    pub recv_id: u8,
    pub algorithm: TcpAoAlgorithm,
    pub secret: String,
    /// On a connection focl opens: sign outgoing segments with this key and
    /// ask the peer to do the same, the first key when no key sets it. On a
    /// connection the peer opens its SYN picks both keys, and this only
    /// decides whether focl warns about the ones it picked.
    #[serde(default)]
    pub current: bool,
}

/// Leaves the secret out, so a key can end up in a log or a panic message.
impl fmt::Debug for TcpAoKeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            send_id,
            recv_id,
            algorithm,
            secret: _,
            current,
        } = self;
        f.debug_struct("TcpAoKeyConfig")
            .field("send_id", send_id)
            .field("recv_id", recv_id)
            .field("algorithm", algorithm)
            .field("secret", &Redacted)
            .field("current", current)
            .finish()
    }
}

/// The RFC 5926 MAC algorithms, both with a 96-bit MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpAoAlgorithm {
    #[serde(rename = "hmac-sha1-96")]
    HmacSha1_96,
    #[serde(rename = "aes-128-cmac-96")]
    Aes128Cmac96,
}

fn validate_peer_auth(peer: &PeerConfig) -> Result<()> {
    if let Some(password) = &peer.password {
        if password.is_empty() || password.len() > TCP_AUTH_MAX_KEY_LEN {
            bail!(
                "peer {} has an invalid password; must be 1-{TCP_AUTH_MAX_KEY_LEN} bytes",
                peer.address
            );
        }
    }
    // Sessions are keyed by a literal address: the active path parses the peer
    // address, the listener matches inbound connections against it, and both
    // kernel authentication options are keyed by address.
    if peer.address.parse::<std::net::IpAddr>().is_err() {
        bail!("peer {} needs a literal IP address", peer.address);
    }
    if peer.tcp_ao_keys.is_empty() {
        return Ok(());
    }
    if peer.password.is_some() {
        bail!(
            "peer {} sets both password (TCP-MD5) and tcp_ao_keys (TCP-AO); pick one",
            peer.address
        );
    }
    let mut send_ids = std::collections::HashSet::new();
    let mut recv_ids = std::collections::HashSet::new();
    for key in &peer.tcp_ao_keys {
        if key.secret.is_empty() || key.secret.len() > TCP_AUTH_MAX_KEY_LEN {
            bail!(
                "peer {} has a TCP-AO key (send_id {}) with an invalid secret; must be 1-{TCP_AUTH_MAX_KEY_LEN} bytes",
                peer.address,
                key.send_id
            );
        }
        // RFC 5925 s3.1: a KeyID has to identify a single MKT per direction.
        if !send_ids.insert(key.send_id) {
            bail!(
                "peer {} has duplicate TCP-AO send_id {}",
                peer.address,
                key.send_id
            );
        }
        if !recv_ids.insert(key.recv_id) {
            bail!(
                "peer {} has duplicate TCP-AO recv_id {}",
                peer.address,
                key.recv_id
            );
        }
    }
    if peer.tcp_ao_keys.iter().filter(|key| key.current).count() > 1 {
        bail!(
            "peer {} marks more than one TCP-AO key as current",
            peer.address
        );
    }
    Ok(())
}

fn default_true() -> bool {
    true
}

fn default_hold_time() -> u16 {
    90
}

fn default_connect_retry() -> u16 {
    5
}

fn default_remote_port() -> u16 {
    179
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixConfig {
    pub network: String,
    #[serde(default)]
    pub next_hop: Option<String>,
    /// Attaches attribute 255 (reserved for development, RFC 2042) to this
    /// prefix's announcements, carrying a BGPKIT clock payload, re-announced
    /// every N seconds. Absent = no attribute.
    #[serde(default)]
    pub dev_attr255_interval_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_collector_id")]
    pub collector_id: String,
    #[serde(default)]
    pub layout_profile: LayoutProfile,
    #[serde(default = "default_updates_interval")]
    pub updates_interval_secs: u32,
    #[serde(default = "default_ribs_interval")]
    pub ribs_interval_secs: u32,
    #[serde(default)]
    pub compression: CompressionKind,
    #[serde(default = "default_archive_root")]
    pub root: PathBuf,
    #[serde(default = "default_archive_tmp_root")]
    pub tmp_root: PathBuf,
    #[serde(default = "default_true")]
    pub fsync_on_rotate: bool,
    #[serde(default = "default_true")]
    pub include_peer_state_records: bool,
    #[serde(default)]
    pub rib_source: RibSource,
    #[serde(default)]
    pub custom_templates: Option<CustomLayoutTemplates>,
    #[serde(default)]
    pub destinations: Vec<ArchiveDestinationConfig>,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            collector_id: default_collector_id(),
            layout_profile: LayoutProfile::RouteViews,
            updates_interval_secs: default_updates_interval(),
            ribs_interval_secs: default_ribs_interval(),
            compression: CompressionKind::Gzip,
            root: default_archive_root(),
            tmp_root: default_archive_tmp_root(),
            fsync_on_rotate: true,
            include_peer_state_records: true,
            rib_source: RibSource::AdjRibIn,
            custom_templates: None,
            destinations: vec![ArchiveDestinationConfig {
                destination_type: DestinationType::Local,
                mode: DestinationMode::Primary,
                path: Some(default_archive_root()),
                required: Some(true),
                endpoint: None,
                bucket: None,
                prefix: None,
                upload_concurrency: Some(4),
                retry_backoff_secs: Some(5),
                max_retries: Some(0),
                region: None,
                access_key_id: None,
                secret_access_key: None,
                session_token: None,
            }],
        }
    }
}

impl ArchiveConfig {
    pub fn validate(&self) -> Result<()> {
        validate_collector_id(&self.collector_id)?;
        if self.layout_profile == LayoutProfile::Custom {
            let templates = self
                .custom_templates
                .as_ref()
                .context("[archive].layout_profile=custom requires [archive.custom_templates]")?;
            templates.validate()?;
        }

        if !self.enabled {
            return Ok(());
        }

        if self.updates_interval_secs == 0 || 3600 % self.updates_interval_secs != 0 {
            bail!(
                "[archive].updates_interval_secs must be >0 and divide 3600, got {}",
                self.updates_interval_secs
            );
        }

        if self.ribs_interval_secs == 0
            || !self
                .ribs_interval_secs
                .is_multiple_of(self.updates_interval_secs)
        {
            bail!(
                "[archive].ribs_interval_secs must be >0 and a multiple of updates_interval_secs"
            );
        }

        if self.destinations.is_empty() {
            bail!("[archive].destinations must include at least one destination");
        }

        let primary_count = self
            .destinations
            .iter()
            .filter(|d| d.mode == DestinationMode::Primary)
            .count();

        if primary_count == 0 {
            bail!("[archive].destinations must include at least one mode=primary destination");
        }

        for destination in &self.destinations {
            destination.validate()?;
        }

        Ok(())
    }
}

fn default_collector_id() -> String {
    "focl01".to_string()
}

fn default_updates_interval() -> u32 {
    900
}

fn default_ribs_interval() -> u32 {
    7200
}

fn default_archive_root() -> PathBuf {
    PathBuf::from("/var/lib/focld/archive")
}

fn default_archive_tmp_root() -> PathBuf {
    PathBuf::from("/var/lib/focld/archive/.tmp")
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum LayoutProfile {
    #[serde(rename = "routeviews", alias = "route_views")]
    #[default]
    RouteViews,
    #[serde(rename = "ris")]
    Ris,
    #[serde(rename = "custom")]
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomLayoutTemplates {
    pub updates: String,
    pub ribs: String,
}

impl CustomLayoutTemplates {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [("updates", &self.updates), ("ribs", &self.ribs)] {
            validate_relative_template(value).with_context(|| {
                format!("[archive.custom_templates].{name} must be a safe relative path")
            })?;
            if !value.contains("{collector}") {
                bail!(
                    "[archive.custom_templates].{} must contain {{collector}} token",
                    name
                );
            }
            if !value.contains("{yyyymmdd}") || !value.contains("{hhmm}") {
                bail!(
                    "[archive.custom_templates].{} must contain {{yyyymmdd}} and {{hhmm}} tokens",
                    name
                );
            }
        }
        Ok(())
    }
}

fn validate_collector_id(collector_id: &str) -> Result<()> {
    let bytes = collector_id.as_bytes();
    let valid = (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid {
        bail!("[archive].collector_id must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$");
    }
    Ok(())
}

pub(crate) fn validate_relative_template(template: &str) -> Result<()> {
    let bytes = template.as_bytes();
    let has_drive_prefix = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if template.starts_with('/') || template.starts_with('\\') || has_drive_prefix {
        bail!("template must not be absolute");
    }
    if template.contains('\\') {
        bail!("template must not contain backslashes");
    }
    if template.chars().any(char::is_control) {
        bail!("template must not contain control characters");
    }
    if template.split('/').any(|component| component.is_empty()) {
        bail!("template must not contain empty path components");
    }
    if template.split('/').any(|component| component == "..") {
        bail!("template must not contain parent path components");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompressionKind {
    #[default]
    Gzip,
    Bzip2,
    Zstd,
}

impl CompressionKind {
    pub fn extension(self) -> &'static str {
        match self {
            CompressionKind::Gzip => "gz",
            CompressionKind::Bzip2 => "bz2",
            CompressionKind::Zstd => "zst",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RibSource {
    #[default]
    AdjRibIn,
    LocRib,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ArchiveDestinationConfig {
    #[serde(rename = "type")]
    pub destination_type: DestinationType,
    pub mode: DestinationMode,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub required: Option<bool>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub upload_concurrency: Option<usize>,
    #[serde(default)]
    pub retry_backoff_secs: Option<u64>,
    #[serde(default)]
    pub max_retries: Option<u32>,
    #[serde(default)]
    pub region: Option<String>,
    // TODO: deprecate `access_key_id`, `secret_access_key` and
    // `session_token`. Nothing has ever read them: the replicator builds its
    // S3 client from the default AWS credential chain (environment, profile,
    // instance role), so setting them here has no effect. Warn at load when
    // one is set, then drop them.
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub session_token: Option<String>,
}

/// Leaves the S3 secret access key and session token out, so a destination
/// can end up in a log or a panic message. The access key id stays: it names
/// the credential in use and is no secret, as every signed request carries it
/// in clear.
impl fmt::Debug for ArchiveDestinationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            destination_type,
            mode,
            path,
            required,
            endpoint,
            bucket,
            prefix,
            upload_concurrency,
            retry_backoff_secs,
            max_retries,
            region,
            access_key_id,
            secret_access_key,
            session_token,
        } = self;
        f.debug_struct("ArchiveDestinationConfig")
            .field("destination_type", destination_type)
            .field("mode", mode)
            .field("path", path)
            .field("required", required)
            .field("endpoint", endpoint)
            .field("bucket", bucket)
            .field("prefix", prefix)
            .field("upload_concurrency", upload_concurrency)
            .field("retry_backoff_secs", retry_backoff_secs)
            .field("max_retries", max_retries)
            .field("region", region)
            .field("access_key_id", access_key_id)
            .field(
                "secret_access_key",
                &secret_access_key.as_ref().map(|_| Redacted),
            )
            .field("session_token", &session_token.as_ref().map(|_| Redacted))
            .finish()
    }
}

impl ArchiveDestinationConfig {
    pub fn validate(&self) -> Result<()> {
        match self.destination_type {
            DestinationType::Local => {
                if self.path.is_none() {
                    bail!("archive destination type=local requires path");
                }
            }
            DestinationType::S3 => {
                if self.endpoint.is_none() || self.bucket.is_none() {
                    bail!("archive destination type=s3 requires endpoint and bucket");
                }
            }
        }
        Ok(())
    }

    pub fn retry_backoff_secs(&self) -> u64 {
        self.retry_backoff_secs.unwrap_or(5)
    }

    pub fn max_retries(&self) -> u32 {
        self.max_retries.unwrap_or(0)
    }

    pub fn upload_concurrency(&self) -> usize {
        self.upload_concurrency.unwrap_or(4)
    }

    pub fn destination_key(&self) -> String {
        match self.destination_type {
            DestinationType::Local => format!(
                "local:{}",
                self.path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<missing>".to_string())
            ),
            DestinationType::S3 => format!(
                "s3:{}:{}",
                self.endpoint.as_deref().unwrap_or("<missing>"),
                self.bucket.as_deref().unwrap_or("<missing>")
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationType {
    Local,
    S3,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationMode {
    Primary,
    AsyncReplica,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_archive_defaults() {
        let cfg = ArchiveConfig {
            enabled: true,
            ..ArchiveConfig::default()
        };
        cfg.validate()
            .expect("default archive config should validate");
    }

    #[test]
    fn rejects_non_dividing_updates_interval() {
        let cfg = ArchiveConfig {
            enabled: true,
            updates_interval_secs: 1000,
            ..ArchiveConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_custom_without_templates() {
        let cfg = ArchiveConfig {
            enabled: true,
            layout_profile: LayoutProfile::Custom,
            custom_templates: None,
            ..ArchiveConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_routeviews_layout_profile_literal() {
        let raw = r#"
[global]
asn = 65001
router_id = "192.0.2.1"

[archive]
enabled = true
layout_profile = "routeviews"
"#;

        let cfg: FoclConfig = toml::from_str(raw).expect("toml should parse");
        assert_eq!(cfg.archive.layout_profile, LayoutProfile::RouteViews);
    }

    #[test]
    fn prefix_config_roundtrips_dev_attr255_interval() {
        let raw = r#"
[global]
asn = 65001
router_id = "192.0.2.1"

[[prefixes]]
network = "2001:db8::/48"
dev_attr255_interval_secs = 1800

[[prefixes]]
network = "192.0.2.0/24"
"#;
        let cfg: FoclConfig = toml::from_str(raw).expect("toml should parse");
        assert_eq!(cfg.prefixes[0].dev_attr255_interval_secs, Some(1800));
        assert_eq!(cfg.prefixes[1].dev_attr255_interval_secs, None);

        let encoded = toml::to_string(&cfg).expect("config should serialize");
        let reparsed: FoclConfig = toml::from_str(&encoded).expect("roundtrip should parse");
        assert_eq!(reparsed.prefixes[0].dev_attr255_interval_secs, Some(1800));
        assert_eq!(reparsed.prefixes[1].dev_attr255_interval_secs, None);
    }

    #[test]
    fn rejects_zero_dev_attr255_interval() {
        let raw = r#"
[global]
asn = 65001
router_id = "192.0.2.1"

[[prefixes]]
network = "192.0.2.0/24"
dev_attr255_interval_secs = 0
"#;
        let cfg: FoclConfig = toml::from_str(raw).expect("toml should parse");
        let error = cfg
            .validate()
            .expect_err("a zero refresh interval must be rejected");
        assert!(
            error
                .to_string()
                .contains("dev_attr255_interval_secs; must be > 0"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_absolute_custom_template() {
        let templates = CustomLayoutTemplates {
            updates: "/{collector}/updates.{yyyymmdd}.{hhmm}.{ext}".to_string(),
            ribs: "{collector}/ribs.{yyyymmdd}.{hhmm}.{ext}".to_string(),
        };
        assert!(templates.validate().is_err());
    }

    #[test]
    fn rejects_parent_traversal_in_custom_template() {
        let templates = CustomLayoutTemplates {
            updates: "{collector}/../updates.{yyyymmdd}.{hhmm}.{ext}".to_string(),
            ribs: "{collector}/ribs.{yyyymmdd}.{hhmm}.{ext}".to_string(),
        };
        assert!(templates.validate().is_err());
    }

    #[test]
    fn rejects_collector_id_with_slash() {
        let cfg = ArchiveConfig {
            collector_id: "focl/01".to_string(),
            ..ArchiveConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn valid_custom_template_still_passes() {
        let templates = CustomLayoutTemplates {
            updates: "{collector}/{yyyy}/updates.{yyyymmdd}.{hhmm}.{ext}".to_string(),
            ribs: "{collector}/{yyyy}/ribs.{yyyymmdd}.{hhmm}.{ext}".to_string(),
        };
        templates.validate().expect("safe template should validate");
    }

    const TCP_AO_PEER: &str = r#"
[global]
asn = 65001
router_id = "192.0.2.1"

[[peers]]
address = "192.0.2.2"
remote_as = 65002

[[peers.tcp_ao_keys]]
send_id = 1
recv_id = 2
algorithm = "hmac-sha1-96"
secret = "first"

[[peers.tcp_ao_keys]]
send_id = 3
recv_id = 4
algorithm = "aes-128-cmac-96"
secret = "second"
current = true
"#;

    fn tcp_ao_config() -> FoclConfig {
        toml::from_str(TCP_AO_PEER).expect("toml should parse")
    }

    fn validation_error(cfg: &FoclConfig) -> String {
        cfg.validate()
            .expect_err("config should be rejected")
            .to_string()
    }

    #[test]
    fn parses_and_roundtrips_tcp_ao_keys() {
        let cfg = tcp_ao_config();
        cfg.validate().expect("TCP-AO peer should validate");
        let keys = &cfg.peers[0].tcp_ao_keys;
        assert_eq!(
            keys[0],
            TcpAoKeyConfig {
                send_id: 1,
                recv_id: 2,
                algorithm: TcpAoAlgorithm::HmacSha1_96,
                secret: "first".to_string(),
                current: false,
            }
        );
        assert_eq!(keys[1].algorithm, TcpAoAlgorithm::Aes128Cmac96);
        assert!(keys[1].current);

        let encoded = toml::to_string(&cfg).expect("config should serialize");
        let reparsed: FoclConfig = toml::from_str(&encoded).expect("roundtrip should parse");
        assert_eq!(reparsed.peers[0].tcp_ao_keys, *keys);
    }

    #[test]
    fn debug_output_leaves_out_the_tcp_ao_secret() {
        let cfg = tcp_ao_config();
        let printed = format!("{:?}", cfg.peers[0]);
        assert!(printed.contains("send_id: 1"), "{printed}");
        assert!(printed.contains("secret: <redacted>"), "{printed}");
        assert!(!printed.contains("first"), "{printed}");
        assert!(!printed.contains("second"), "{printed}");
    }

    #[test]
    fn debug_output_leaves_out_the_md5_password() {
        let mut cfg = tcp_ao_config();
        let peer = &mut cfg.peers[0];
        peer.tcp_ao_keys.clear();
        assert!(format!("{peer:?}").contains("password: None"));

        peer.password = Some("md5-password".to_string());
        let printed = format!("{cfg:?}");
        assert!(printed.contains("address: \"192.0.2.2\""), "{printed}");
        assert!(printed.contains("password: Some(<redacted>)"), "{printed}");
        assert!(!printed.contains("md5-password"), "{printed}");
    }

    #[test]
    fn debug_output_leaves_out_the_s3_secrets() {
        let mut cfg = tcp_ao_config();
        let destination = &mut cfg.archive.destinations[0];
        assert!(format!("{destination:?}").contains("secret_access_key: None"));

        destination.access_key_id = Some("AKIDEXAMPLE".to_string());
        destination.secret_access_key = Some("s3-secret".to_string());
        destination.session_token = Some("s3-token".to_string());
        let printed = format!("{cfg:?}");
        assert!(
            printed.contains("access_key_id: Some(\"AKIDEXAMPLE\")"),
            "{printed}"
        );
        assert!(
            printed.contains("secret_access_key: Some(<redacted>)"),
            "{printed}"
        );
        assert!(
            printed.contains("session_token: Some(<redacted>)"),
            "{printed}"
        );
        assert!(!printed.contains("s3-secret"), "{printed}");
        assert!(!printed.contains("s3-token"), "{printed}");
    }

    #[test]
    fn rejects_unknown_tcp_ao_algorithm() {
        let raw = TCP_AO_PEER.replace("aes-128-cmac-96", "hmac-md5");
        assert!(toml::from_str::<FoclConfig>(&raw).is_err());
    }

    /// A typo must not quietly drop a key's `current` mark, or the keys
    /// (and with them the peer's authentication) altogether.
    #[test]
    fn rejects_unknown_peer_and_tcp_ao_key_fields() {
        let parse_error = |raw: &str| {
            toml::from_str::<FoclConfig>(raw)
                .expect_err("an unknown field should be rejected")
                .to_string()
        };

        let error = parse_error(&TCP_AO_PEER.replace("current = true", "currnet = true"));
        assert!(error.contains("unknown field `currnet`"), "{error}");

        let error =
            parse_error(&TCP_AO_PEER.replace("[[peers.tcp_ao_keys]]", "[[peers.tcp_ao_key]]"));
        assert!(error.contains("unknown field `tcp_ao_key`"), "{error}");

        let error = parse_error(
            &TCP_AO_PEER.replace("remote_as = 65002", "remote_as = 65002\npasswrod = \"md5\""),
        );
        assert!(error.contains("unknown field `passwrod`"), "{error}");
    }

    #[test]
    fn shipped_example_configs_still_parse_and_validate() {
        for (name, raw) in [
            ("focl.toml", include_str!("../../focl.toml")),
            (
                "focl-vultr-example.toml",
                include_str!("../../focl-vultr-example.toml"),
            ),
            (
                "scripts/interop/focl-interop.toml",
                include_str!("../../scripts/interop/focl-interop.toml"),
            ),
            (
                "scripts/interop/focl-interop-md5.toml",
                include_str!("../../scripts/interop/focl-interop-md5.toml"),
            ),
        ] {
            let cfg: FoclConfig =
                toml::from_str(raw).unwrap_or_else(|error| panic!("{name}: {error}"));
            cfg.validate()
                .unwrap_or_else(|error| panic!("{name}: {error:#}"));
        }
    }

    #[test]
    fn rejects_password_together_with_tcp_ao_keys() {
        let mut cfg = tcp_ao_config();
        cfg.peers[0].password = Some("md5".to_string());
        assert!(validation_error(&cfg).contains("pick one"));
    }

    #[test]
    fn rejects_a_hostname_peer() {
        let mut cfg = tcp_ao_config();
        cfg.peers[0].address = "router.example".to_string();
        assert!(validation_error(&cfg).contains("literal IP address"));

        // The same rule applies to a peer with no authentication at all.
        let mut cfg = tcp_ao_config();
        cfg.peers[0].tcp_ao_keys.clear();
        cfg.peers[0].address = "router.example".to_string();
        assert!(validation_error(&cfg).contains("literal IP address"));
    }

    #[test]
    fn rejects_two_spellings_of_one_peer_address() {
        let mut cfg = tcp_ao_config();
        cfg.peers[0].address = "192.0.2.1".to_string();
        let mut alias = cfg.peers[0].clone();
        alias.address = "::ffff:192.0.2.1".to_string();
        cfg.peers.push(alias);
        assert!(validation_error(&cfg).contains("same address in different spellings"));
    }

    #[test]
    fn rejects_duplicate_tcp_ao_key_ids() {
        let mut cfg = tcp_ao_config();
        cfg.peers[0].tcp_ao_keys[1].send_id = 1;
        assert!(validation_error(&cfg).contains("duplicate TCP-AO send_id 1"));

        let mut cfg = tcp_ao_config();
        cfg.peers[0].tcp_ao_keys[1].recv_id = 2;
        assert!(validation_error(&cfg).contains("duplicate TCP-AO recv_id 2"));
    }

    #[test]
    fn rejects_more_than_one_current_tcp_ao_key() {
        let mut cfg = tcp_ao_config();
        cfg.peers[0].tcp_ao_keys[0].current = true;
        assert!(validation_error(&cfg).contains("more than one TCP-AO key as current"));
    }

    #[test]
    fn rejects_empty_or_oversized_secrets_and_passwords() {
        for secret in [String::new(), "x".repeat(TCP_AUTH_MAX_KEY_LEN + 1)] {
            let mut cfg = tcp_ao_config();
            cfg.peers[0].tcp_ao_keys[0].secret = secret.clone();
            assert!(validation_error(&cfg).contains("invalid secret"));

            let mut cfg = tcp_ao_config();
            cfg.peers[0].tcp_ao_keys.clear();
            cfg.peers[0].password = Some(secret);
            assert!(validation_error(&cfg).contains("invalid password"));
        }

        let mut cfg = tcp_ao_config();
        cfg.peers[0].tcp_ao_keys[0].secret = "x".repeat(TCP_AUTH_MAX_KEY_LEN);
        cfg.validate()
            .expect("an 80-byte secret is the kernel maximum");
    }
}
