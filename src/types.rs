use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRequest {
    pub version: u16,
    pub id: String,
    pub cmd: String,
    #[serde(default)]
    pub args: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    pub version: u16,
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ControlError>,
}

impl ControlResponse {
    pub fn ok(id: impl Into<String>, result: Value) -> Self {
        Self {
            version: 1,
            id: id.into(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: impl Into<String>, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            version: 1,
            id: id.into(),
            ok: false,
            result: None,
            error: Some(ControlError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

/// How a peer's TCP connection is authenticated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerAuthMode {
    #[default]
    None,
    /// TCP-MD5 (RFC 2385).
    Md5,
    /// TCP-AO (RFC 5925).
    TcpAo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload")]
pub enum Event {
    #[serde(rename = "peer_state")]
    PeerState { peer: String, state: PeerState },
    #[serde(rename = "archive_segment_opened")]
    ArchiveSegmentOpened {
        stream: String,
        path: String,
        start_ts: i64,
    },
    #[serde(rename = "archive_segment_finalized")]
    ArchiveSegmentFinalized {
        stream: String,
        path: String,
        end_ts: i64,
        records: u64,
    },
    #[serde(rename = "archive_replication_succeeded")]
    ArchiveReplicationSucceeded { destination: String, path: String },
    #[serde(rename = "archive_replication_failed")]
    ArchiveReplicationFailed {
        destination: String,
        path: String,
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub version: u16,
    #[serde(rename = "type")]
    pub envelope_type: String,
    #[serde(flatten)]
    pub event: Event,
}

impl EventEnvelope {
    pub fn new(event: Event) -> Self {
        Self {
            version: 1,
            envelope_type: "event".to_string(),
            event,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The control protocol spells its enum values in snake_case.
    #[test]
    fn peer_auth_mode_serializes_in_snake_case_like_peer_state() {
        let encoded = |mode| serde_json::to_value::<PeerAuthMode>(mode).unwrap();
        assert_eq!(encoded(PeerAuthMode::None), "none");
        assert_eq!(encoded(PeerAuthMode::Md5), "md5");
        assert_eq!(encoded(PeerAuthMode::TcpAo), "tcp_ao");
        assert_eq!(
            serde_json::to_value(PeerState::OpenSent).unwrap(),
            "open_sent"
        );
    }
}
