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

    pub fn validate(&self) -> Result<()> {
        if self.global.asn == 0 {
            bail!("[global].asn must be non-zero");
        }

        if self.global.router_id.parse::<std::net::Ipv4Addr>().is_err() {
            bail!("[global].router_id must be a valid IPv4 address");
        }

        for peer in &self.peers {
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

#[derive(Clone, Serialize, Deserialize)]
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
pub struct TcpAoKeyConfig {
    pub send_id: u8,
    pub recv_id: u8,
    pub algorithm: TcpAoAlgorithm,
    pub secret: String,
    /// Sign outgoing segments with this key and ask the peer to do the same.
    /// Defaults to the first key when no key sets it.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub session_token: Option<String>,
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
    fn rejects_unknown_tcp_ao_algorithm() {
        let raw = TCP_AO_PEER.replace("aes-128-cmac-96", "hmac-md5");
        assert!(toml::from_str::<FoclConfig>(&raw).is_err());
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
