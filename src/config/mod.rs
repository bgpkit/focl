use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
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
            if peer.hold_time_secs != 0 && peer.hold_time_secs < 3 {
                bail!(
                    "peer {} has invalid hold_time_secs {}; must be 0 or >=3",
                    peer.address,
                    peer.hold_time_secs
                );
            }
        }

        for prefix in &self.prefixes {
            prefix.network.parse::<Ipv4Net>().with_context(|| {
                format!("invalid IPv4 prefix in [[prefixes]]: {}", prefix.network)
            })?;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub address: String,
    pub remote_as: u32,
    #[serde(default)]
    pub local_as: Option<u32>,
    #[serde(default = "default_hold_time")]
    pub hold_time_secs: u16,
    #[serde(default = "default_connect_retry")]
    pub connect_retry_secs: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub passive: bool,
    #[serde(default = "default_true")]
    pub route_refresh: bool,
    #[serde(default)]
    pub name: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixConfig {
    pub network: String,
    #[serde(default)]
    pub next_hop: Option<String>,
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
        if !self.enabled {
            return Ok(());
        }

        if self.collector_id.trim().is_empty() {
            bail!("[archive].collector_id must not be empty");
        }

        if self.updates_interval_secs == 0 || 3600 % self.updates_interval_secs != 0 {
            bail!(
                "[archive].updates_interval_secs must be >0 and divide 3600, got {}",
                self.updates_interval_secs
            );
        }

        if self.ribs_interval_secs == 0 || self.ribs_interval_secs % self.updates_interval_secs != 0
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

        if self.layout_profile == LayoutProfile::Custom {
            let templates = self
                .custom_templates
                .as_ref()
                .context("[archive].layout_profile=custom requires [archive.custom_templates]")?;
            templates.validate()?;
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
}
