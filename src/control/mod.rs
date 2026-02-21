use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::types::ControlRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    Ping,
    DaemonStatus,
    Shutdown,
    Reload,
    ArchiveStatus,
    ArchiveRollover,
    ArchiveSnapshotNow,
    ArchiveDestinations,
    ArchiveReplicatorRetry,
    Unsupported,
}

impl CommandKind {
    pub fn from_request(req: &ControlRequest) -> Self {
        match req.cmd.as_str() {
            "ping" => Self::Ping,
            "daemon_status" => Self::DaemonStatus,
            "shutdown" => Self::Shutdown,
            "reload" => Self::Reload,
            "archive_status" => Self::ArchiveStatus,
            "archive_rollover" => Self::ArchiveRollover,
            "archive_snapshot_now" => Self::ArchiveSnapshotNow,
            "archive_destinations" => Self::ArchiveDestinations,
            "archive_replicator_retry" => Self::ArchiveReplicatorRetry,
            _ => Self::Unsupported,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveStream {
    Updates,
    Ribs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveRolloverArgs {
    pub stream: ArchiveStream,
}

impl ArchiveRolloverArgs {
    pub fn from_json(value: &Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveStatusResult {
    pub enabled: bool,
    pub collector_id: String,
    pub updates_interval_secs: u32,
    pub ribs_interval_secs: u32,
    pub updates_open_path: Option<String>,
    pub updates_record_count: u64,
    pub ribs_last_path: Option<String>,
    pub ribs_last_record_count: u64,
    pub queued_replication_jobs: usize,
    pub replication_failures: u64,
}

impl ArchiveStatusResult {
    pub fn as_value(&self) -> Value {
        json!(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveDestinationResult {
    pub key: String,
    pub mode: String,
    #[serde(rename = "type")]
    pub destination_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveDestinationsResult {
    pub destinations: Vec<ArchiveDestinationResult>,
}

impl ArchiveDestinationsResult {
    pub fn as_value(&self) -> Value {
        json!(self)
    }
}
