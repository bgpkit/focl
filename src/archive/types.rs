use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::CompressionKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveStream {
    Updates,
    Ribs,
}

impl ArchiveStream {
    pub fn as_str(self) -> &'static str {
        match self {
            ArchiveStream::Updates => "updates",
            ArchiveStream::Ribs => "ribs",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegmentPaths {
    pub tmp_path: PathBuf,
    pub final_path: PathBuf,
    pub relative_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedSegment {
    pub stream: ArchiveStream,
    pub start_ts: i64,
    pub end_ts: i64,
    pub record_count: u64,
    pub bytes: u64,
    pub compression: CompressionKind,
    pub final_path: PathBuf,
    pub relative_path: PathBuf,
    pub manifest_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRecordInput {
    pub timestamp: i64,
    pub peer_asn: u32,
    pub local_asn: u32,
    pub interface_index: u16,
    pub peer_ip: Ipv4Addr,
    pub local_ip: Ipv4Addr,
    pub bgp_message: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStateRecordInput {
    pub timestamp: i64,
    pub peer_asn: u32,
    pub local_asn: u32,
    pub interface_index: u16,
    pub peer_ip: Ipv4Addr,
    pub local_ip: Ipv4Addr,
    pub old_state: u16,
    pub new_state: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPeer {
    pub peer_bgp_id: Ipv4Addr,
    pub peer_ip: IpAddr,
    pub peer_asn: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRoute {
    pub sequence: u32,
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
    pub peer_index: u16,
    pub originated_time: u32,
    pub path_attributes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RibSnapshotInput {
    pub timestamp: i64,
    pub collector_bgp_id: Ipv4Addr,
    pub view_name: String,
    pub peers: Vec<SnapshotPeer>,
    pub routes: Vec<SnapshotRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveStatus {
    pub enabled: bool,
    pub collector_id: String,
    pub updates_interval_secs: u32,
    pub ribs_interval_secs: u32,
    pub updates_open_path: Option<PathBuf>,
    pub updates_record_count: u64,
    pub ribs_last_path: Option<PathBuf>,
    pub ribs_last_record_count: u64,
    pub queued_replication_jobs: usize,
    pub replication_failures: u64,
}
