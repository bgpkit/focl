//! The BMP frames focl sends, byte for byte.
//!
//! Every function here returns one complete BMP message, common header included, so the caller
//! can hand it straight to a socket. Nothing in this module reads the BGP PDUs it carries: a
//! Route Monitoring frame wraps the bytes the peer sent us, which is the whole point of exporting
//! (an encoder that rebuilt the PDU from parsed fields would drop any attribute this build does
//! not model).
//!
//! Wire facts this module depends on, all from RFC 7854 and its extensions:
//!
//! ```text
//! Common header (6 bytes):  version=3 | message length (u32, includes this header) | type
//! Per-peer header (42):     peer type | flags | distinguisher (u64) | address (16)
//!                           | peer AS (u32) | peer BGP ID (u32) | seconds | microseconds
//! Types:                    0 route monitoring, 1 statistics, 2 peer down, 3 peer up,
//!                           4 initiation, 5 termination, 6 route mirroring
//! Flags (RFC 8671 §4):      V=0x80 IPv6, L=0x40 post-policy, A=0x20 2-octet AS_PATH, O=0x10 Adj-RIB-Out
//! ```

use std::net::{IpAddr, Ipv4Addr};

/// Protocol version this module emits; RFC 7854 defines exactly one.
pub const BMP_VERSION: u8 = 3;

/// Message types, in the numbering RFC 7854 gives them.
pub const MSG_ROUTE_MONITORING: u8 = 0;
pub const MSG_STATISTICS_REPORT: u8 = 1;
pub const MSG_PEER_DOWN: u8 = 2;
pub const MSG_PEER_UP: u8 = 3;
pub const MSG_INITIATION: u8 = 4;

/// Peer type "global instance peer": the only type focl exports, because it reports one BGP
/// session rather than a VRF or a local RIB.
const PEER_TYPE_GLOBAL: u8 = 0;

const FLAG_IPV6: u8 = 0x80;
const FLAG_AS_16BIT: u8 = 0x20;

/// Peer Down reasons used by this exporter. Both carry no payload, so a station can parse the
/// frame without knowing anything about focl's FSM.
pub const PEER_DOWN_REMOTE_NO_DATA: u8 = 4;
pub const PEER_DOWN_DE_CONFIGURED: u8 = 5;

/// Initiation and Peer Up information TLV types (IANA "BMP Initiation Information TLVs").
const TLV_SYS_DESCR: u16 = 1;
const TLV_SYS_NAME: u16 = 2;

/// The parts of a monitored peer that every per-peer header repeats.
///
/// focl builds one of these when a session reaches Established and keeps it for the life of the
/// session, so the frame encoders never have to reach back into session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHeader {
    pub peer_ip: IpAddr,
    pub peer_asn: u32,
    pub peer_bgp_id: Ipv4Addr,
    /// True when the session negotiated a two-octet AS_PATH. The A flag is what tells the station
    /// how to read the AS_PATH inside the PDU, and it must agree with the session's own
    /// negotiation or every path is misread.
    pub asn_16bit: bool,
}

impl PeerHeader {
    fn flags(&self) -> u8 {
        let mut flags = 0u8;
        if self.peer_ip.is_ipv6() {
            flags |= FLAG_IPV6;
        }
        if self.asn_16bit {
            flags |= FLAG_AS_16BIT;
        }
        flags
    }
}

/// Wall-clock microseconds since the Unix epoch, the unit every BMP timestamp field uses.
pub fn now_micros() -> i64 {
    chrono::Utc::now().timestamp_micros()
}

fn common_header(msg_type: u8, body_len: usize) -> Vec<u8> {
    let total = 6 + body_len;
    let mut out = Vec::with_capacity(total);
    out.push(BMP_VERSION);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.push(msg_type);
    out
}

fn per_peer_header(peer: &PeerHeader, at_micros: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(42);
    out.push(PEER_TYPE_GLOBAL);
    out.push(peer.flags());
    // Peer distinguisher: zero for a global instance peer.
    out.extend_from_slice(&0u64.to_be_bytes());
    match peer.peer_ip {
        IpAddr::V4(v4) => {
            out.extend_from_slice(&[0u8; 12]);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
    // The Peer AS field is four octets even when the A flag announces a two-octet AS_PATH; the
    // flag describes the encapsulated PDU, not this header.
    out.extend_from_slice(&peer.peer_asn.to_be_bytes());
    out.extend_from_slice(&peer.peer_bgp_id.octets());
    let seconds = at_micros.div_euclid(1_000_000);
    let micros = at_micros.rem_euclid(1_000_000);
    // A timestamp before 1970 cannot be represented and cannot be true for a frame we just wrote;
    // clamp rather than wrap into the future.
    out.extend_from_slice(&u32::try_from(seconds).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&(micros as u32).to_be_bytes());
    out
}

fn tlv(out: &mut Vec<u8>, info_type: u16, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&info_type.to_be_bytes());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The first frame on every connection: who is exporting.
///
/// A station records `sys_name` and `sys_descr` as the exporter's identity, which is how an
/// operator tells two daemons apart in the archive. Both are required here rather than defaulted
/// silently, because an unnamed exporter makes every session in the archive anonymous.
pub fn initiation(sys_name: &str, sys_descr: &str) -> Vec<u8> {
    let mut body = Vec::new();
    tlv(&mut body, TLV_SYS_DESCR, sys_descr);
    tlv(&mut body, TLV_SYS_NAME, sys_name);
    let mut out = common_header(MSG_INITIATION, body.len());
    out.extend_from_slice(&body);
    out
}

/// Announces a monitored peer, with the two OPENs the session exchanged.
///
/// The sent and received OPENs must be the PDUs that actually crossed the wire, 19-byte header
/// included: a station derives the peer's address families, BGP identifier and add-path
/// negotiation from them, and a synthesised OPEN makes the archive describe a session that never
/// happened.
pub fn peer_up(
    peer: &PeerHeader,
    local_ip: IpAddr,
    local_port: u16,
    remote_port: u16,
    sent_open: &[u8],
    received_open: &[u8],
    at_micros: i64,
) -> Vec<u8> {
    let mut body = per_peer_header(peer, at_micros);
    match local_ip {
        IpAddr::V4(v4) => {
            body.extend_from_slice(&[0u8; 12]);
            body.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => body.extend_from_slice(&v6.octets()),
    }
    body.extend_from_slice(&local_port.to_be_bytes());
    body.extend_from_slice(&remote_port.to_be_bytes());
    body.extend_from_slice(sent_open);
    body.extend_from_slice(received_open);
    let mut out = common_header(MSG_PEER_UP, body.len());
    out.extend_from_slice(&body);
    out
}

/// Closes a monitored peer. A session that ends without this frame looks permanently established
/// to the station, which then reports a stale table rather than a gap.
pub fn peer_down(peer: &PeerHeader, reason: u8, at_micros: i64) -> Vec<u8> {
    let mut body = per_peer_header(peer, at_micros);
    body.push(reason);
    let mut out = common_header(MSG_PEER_DOWN, body.len());
    out.extend_from_slice(&body);
    out
}

/// Wraps one BGP UPDATE exactly as it arrived.
///
/// The PDU keeps its own 19-byte header: BMP carries a complete BGP message, and a station that
/// strips the header before parsing would read the marker as a length. An empty UPDATE (the
/// End-of-RIB marker) is a legal Route Monitoring frame and is how a station learns the peer's
/// initial table finished.
pub fn route_monitoring(peer: &PeerHeader, pdu: &[u8], at_micros: i64) -> Vec<u8> {
    let mut body = per_peer_header(peer, at_micros);
    body.extend_from_slice(pdu);
    let mut out = common_header(MSG_ROUTE_MONITORING, body.len());
    out.extend_from_slice(&body);
    out
}

/// A Statistics Report with no counters, sent on a timer.
///
/// This is not telemetry focl cares about; it is the only thing that tells the station the
/// exporter is alive. BMP has no keepalive, so without it a silent daemon and a dead TCP
/// connection are the same observation.
pub fn statistics_report(peer: &PeerHeader, at_micros: i64) -> Vec<u8> {
    let mut body = per_peer_header(peer, at_micros);
    body.extend_from_slice(&0u32.to_be_bytes());
    let mut out = common_header(MSG_STATISTICS_REPORT, body.len());
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use bgpkit_parser::bmp::messages::{BmpMessageBody, InitiationTlvType, PeerDownReason};
    use bgpkit_parser::models::{AsnLength, BgpMessage, BgpOpenMessage};
    use bgpkit_parser::parse_bmp_msg;
    use bytes::Bytes;

    fn peer() -> PeerHeader {
        PeerHeader {
            peer_ip: "192.0.2.7".parse().unwrap(),
            peer_asn: 64500,
            peer_bgp_id: "192.0.2.7".parse().unwrap(),
            asn_16bit: false,
        }
    }

    fn open_pdu(asn: u32, hold: u16) -> Vec<u8> {
        BgpMessage::Open(BgpOpenMessage {
            version: 4,
            asn: asn.into(),
            hold_time: hold,
            bgp_identifier: "192.0.2.1".parse().unwrap(),
            extended_length: false,
            opt_params: vec![],
        })
        .encode(AsnLength::Bits32)
        .unwrap()
        .to_vec()
    }

    fn parse(frame: &[u8]) -> bgpkit_parser::bmp::messages::BmpMessage {
        // The station's own parser reads everything focl writes; anything this test cannot parse
        // is a frame bgpviews would reject.
        let mut bytes = Bytes::copy_from_slice(frame);
        parse_bmp_msg(&mut bytes).unwrap()
    }

    #[test]
    fn initiation_names_the_exporter() {
        let frame = initiation("focl-duck", "focl 0.1.0");
        assert_eq!(frame[0], BMP_VERSION);
        assert_eq!(frame[5], MSG_INITIATION);
        assert_eq!(
            u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize,
            frame.len()
        );
        let parsed = parse(&frame);
        match parsed.message_body {
            BmpMessageBody::InitiationMessage(msg) => {
                let name = msg
                    .tlvs
                    .iter()
                    .find(|tlv| tlv.info_type == InitiationTlvType::SysName)
                    .unwrap();
                assert_eq!(name.info, "focl-duck");
                let descr = msg
                    .tlvs
                    .iter()
                    .find(|tlv| tlv.info_type == InitiationTlvType::SysDescr)
                    .unwrap();
                assert_eq!(descr.info, "focl 0.1.0");
            }
            other => panic!("expected initiation, got {other:?}"),
        }
    }

    #[test]
    fn peer_up_carries_both_opens_and_the_socket_ports() {
        let peer = peer();
        let sent = open_pdu(65001, 90);
        let received = open_pdu(64500, 90);
        let frame = peer_up(
            &peer,
            "192.0.2.1".parse().unwrap(),
            179,
            51234,
            &sent,
            &received,
            1_700_000_000_123_456,
        );
        let parsed = parse(&frame);
        let header = parsed
            .per_peer_header
            .expect("peer up carries a per-peer header");
        assert_eq!(header.peer_asn.to_u32(), 64500);
        assert_eq!(header.peer_bgp_id, "192.0.2.7".parse::<Ipv4Addr>().unwrap());
        assert!((header.timestamp - 1_700_000_000.123_456).abs() < 1e-6);
        match parsed.message_body {
            BmpMessageBody::PeerUpNotification(msg) => {
                assert_eq!(msg.local_addr, "192.0.2.1".parse::<IpAddr>().unwrap());
                assert_eq!(msg.local_port, 179);
                assert_eq!(msg.remote_port, 51234);
                let asn_of = |message: &BgpMessage| match message {
                    BgpMessage::Open(open) => open.asn.to_u32(),
                    other => panic!("expected an OPEN, got {other:?}"),
                };
                assert_eq!(asn_of(&msg.sent_open), 65001);
                assert_eq!(asn_of(&msg.received_open), 64500);
            }
            other => panic!("expected peer up, got {other:?}"),
        }
    }

    #[test]
    fn an_ipv6_peer_sets_the_v_flag_and_packs_the_address() {
        let peer = PeerHeader {
            peer_ip: "2001:db8::1".parse().unwrap(),
            peer_asn: 64500,
            peer_bgp_id: "192.0.2.7".parse().unwrap(),
            asn_16bit: false,
        };
        let frame = route_monitoring(&peer, &open_pdu(64500, 90), 1_700_000_000_000_000);
        let parsed = parse(&frame);
        let header = parsed
            .per_peer_header
            .expect("route monitoring has a header");
        assert_eq!(header.peer_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_two_octet_session_sets_the_a_flag() {
        let peer = PeerHeader {
            asn_16bit: true,
            ..peer()
        };
        let frame = statistics_report(&peer, 0);
        let parsed = parse(&frame);
        let header = parsed.per_peer_header.expect("statistics has a header");
        assert_eq!(header.asn_length(), AsnLength::Bits16);
    }

    #[test]
    fn route_monitoring_wraps_the_pdu_without_touching_it() {
        let peer = peer();
        let mut pdu = open_pdu(64500, 90);
        // A KEEPALIVE-shaped PDU only to prove the bytes survive verbatim; the station parses the
        // payload as an UPDATE, which is why this test reads the frame at the byte level.
        pdu[18] = 4;
        let frame = route_monitoring(&peer, &pdu, 1_700_000_000_000_000);
        let body_at = 6 + 42;
        assert_eq!(&frame[body_at..], &pdu[..]);
    }

    #[test]
    fn both_peer_down_reasons_parse_without_a_payload() {
        let peer = peer();
        for reason in [PEER_DOWN_REMOTE_NO_DATA, PEER_DOWN_DE_CONFIGURED] {
            let frame = peer_down(&peer, reason, 1_700_000_000_000_000);
            let parsed = parse(&frame);
            match parsed.message_body {
                BmpMessageBody::PeerDownNotification(msg) => {
                    let expected = if reason == PEER_DOWN_REMOTE_NO_DATA {
                        PeerDownReason::RemoteSystemsClosedNoData
                    } else {
                        PeerDownReason::PeerDeConfigured
                    };
                    assert_eq!(msg.reason, expected);
                    assert!(msg.data.is_none());
                }
                other => panic!("expected peer down, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_statistics_report_parses_as_the_liveness_signal() {
        let frame = statistics_report(&peer(), 1_700_000_000_000_000);
        assert_eq!(frame[5], MSG_STATISTICS_REPORT);
        let parsed = parse(&frame);
        match parsed.message_body {
            BmpMessageBody::StatsReport(msg) => {
                assert_eq!(msg.stats_count, 0);
                assert!(msg.counters.is_empty());
            }
            other => panic!("expected statistics report, got {other:?}"),
        }
    }
}
