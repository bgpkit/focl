use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{anyhow, bail, Context, Result};
use bgpkit_parser::models::{
    Asn, AsnLength, Bgp4MpEnum, Bgp4MpMessage, Bgp4MpStateChange, Bgp4MpType, BgpMessage, BgpState,
    CommonHeader, EntryType, MrtMessage, NetworkPrefix, Peer, PeerIndexTable, RibAfiEntries,
    RibEntry, TableDumpV2Message, TableDumpV2Type,
};
use bgpkit_parser::parser::bgp::attributes::parse_attributes;
use bgpkit_parser::parser::bgp::parse_bgp_message;
use bytes::Bytes;
use ipnet::{IpNet, Ipv4Net};

use crate::archive::types::{PeerStateRecordInput, RibSnapshotInput, UpdateRecordInput};

pub fn encode_bgp4mp_message_as4(input: &UpdateRecordInput) -> Result<Vec<u8>> {
    let bgp_message = parse_update_message(&input.bgp_message)?;

    let msg = Bgp4MpMessage {
        msg_type: Bgp4MpType::MessageAs4,
        peer_asn: Asn::new_32bit(input.peer_asn),
        local_asn: Asn::new_32bit(input.local_asn),
        interface_index: input.interface_index,
        peer_ip: IpAddr::V4(input.peer_ip),
        local_ip: IpAddr::V4(input.local_ip),
        bgp_message,
    };

    let message = MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(msg));
    Ok(encode_mrt_message(
        input.timestamp as u32,
        EntryType::BGP4MP,
        Bgp4MpType::MessageAs4 as u16,
        message,
    ))
}

pub fn encode_bgp4mp_state_change_as4(input: &PeerStateRecordInput) -> Result<Vec<u8>> {
    let old_state = BgpState::try_from(input.old_state)
        .map_err(|_| anyhow!("invalid old_state value {}", input.old_state))?;
    let new_state = BgpState::try_from(input.new_state)
        .map_err(|_| anyhow!("invalid new_state value {}", input.new_state))?;

    let state_change = Bgp4MpStateChange {
        msg_type: Bgp4MpType::StateChangeAs4,
        peer_asn: Asn::new_32bit(input.peer_asn),
        local_asn: Asn::new_32bit(input.local_asn),
        interface_index: input.interface_index,
        peer_ip: IpAddr::V4(input.peer_ip),
        local_addr: IpAddr::V4(input.local_ip),
        old_state,
        new_state,
    };

    let message = MrtMessage::Bgp4Mp(Bgp4MpEnum::StateChange(state_change));
    Ok(encode_mrt_message(
        input.timestamp as u32,
        EntryType::BGP4MP,
        Bgp4MpType::StateChangeAs4 as u16,
        message,
    ))
}

pub fn build_table_dump_v2(snapshot: &RibSnapshotInput) -> Result<Vec<Vec<u8>>> {
    let mut records = Vec::with_capacity(1 + snapshot.routes.len());

    let peer_index_table = build_peer_index_table(snapshot)?;
    records.push(encode_mrt_message(
        snapshot.timestamp as u32,
        EntryType::TABLE_DUMP_V2,
        TableDumpV2Type::PeerIndexTable as u16,
        MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(
            peer_index_table.clone(),
        )),
    ));

    for route in &snapshot.routes {
        if route.prefix_len > 32 {
            bail!("invalid IPv4 prefix length {}", route.prefix_len);
        }

        if !peer_index_table.id_peer_map.contains_key(&route.peer_index) {
            bail!(
                "route references unknown peer_index {} (peers: {})",
                route.peer_index,
                peer_index_table.id_peer_map.len()
            );
        }

        let ipv4_prefix = Ipv4Net::new(route.prefix, route.prefix_len).with_context(|| {
            format!("invalid route prefix {}/{}", route.prefix, route.prefix_len)
        })?;
        let prefix = NetworkPrefix::new(IpNet::V4(ipv4_prefix), None);

        let attributes = parse_attributes(
            Bytes::from(route.path_attributes.clone()),
            &AsnLength::Bits32,
            false,
            None,
            None,
            None,
        )
        .with_context(|| format!("failed parsing route attributes for prefix {}", ipv4_prefix))?;

        let rib_entry = RibEntry {
            peer_index: route.peer_index,
            originated_time: route.originated_time,
            path_id: None,
            attributes,
        };

        let rib = RibAfiEntries {
            rib_type: TableDumpV2Type::RibIpv4Unicast,
            sequence_number: route.sequence,
            prefix,
            rib_entries: vec![rib_entry],
        };

        records.push(encode_mrt_message(
            snapshot.timestamp as u32,
            EntryType::TABLE_DUMP_V2,
            TableDumpV2Type::RibIpv4Unicast as u16,
            MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(rib)),
        ));
    }

    Ok(records)
}

fn build_peer_index_table(snapshot: &RibSnapshotInput) -> Result<PeerIndexTable> {
    if snapshot.peers.len() > u16::MAX as usize {
        bail!("peer count exceeds TABLE_DUMP_V2 limit");
    }

    let mut id_peer_map = HashMap::new();
    let mut peer_ip_id_map = HashMap::new();

    for (idx, peer) in snapshot.peers.iter().enumerate() {
        let peer_id = idx as u16;
        let parsed_peer = Peer::new(
            peer.peer_bgp_id,
            peer.peer_ip,
            Asn::new_32bit(peer.peer_asn),
        );

        id_peer_map.insert(peer_id, parsed_peer);
        peer_ip_id_map.insert(parsed_peer.peer_ip, peer_id);
    }

    Ok(PeerIndexTable {
        collector_bgp_id: snapshot.collector_bgp_id,
        view_name: snapshot.view_name.clone(),
        id_peer_map,
        peer_ip_id_map,
    })
}

fn parse_update_message(raw: &[u8]) -> Result<BgpMessage> {
    let mut data = Bytes::copy_from_slice(raw);
    let parsed = parse_bgp_message(&mut data, false, &AsnLength::Bits32)
        .or_else(|_| {
            let mut fallback = Bytes::copy_from_slice(raw);
            parse_bgp_message(&mut fallback, false, &AsnLength::Bits16)
        })
        .map_err(|e| anyhow!("failed to parse BGP message with bgpkit-parser: {e}"))?;

    if !matches!(parsed, BgpMessage::Update(_)) {
        bail!(
            "expected BGP UPDATE message payload, got {:?}",
            parsed.msg_type()
        );
    }

    Ok(parsed)
}

fn encode_mrt_message(
    timestamp: u32,
    entry_type: EntryType,
    subtype: u16,
    message: MrtMessage,
) -> Vec<u8> {
    let payload = message.encode(subtype);
    let header = CommonHeader {
        timestamp,
        microsecond_timestamp: None,
        entry_type,
        entry_subtype: subtype,
        length: payload.len() as u32,
    };

    let header_bytes = header.encode();

    let mut out = Vec::with_capacity(header_bytes.len() + payload.len());
    out.extend_from_slice(header_bytes.as_ref());
    out.extend_from_slice(payload.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};

    use bgpkit_parser::models::{Bgp4MpType, EntryType};
    use bgpkit_parser::parse_mrt_record;

    use super::*;
    use crate::archive::types::{RibSnapshotInput, SnapshotPeer, SnapshotRoute, UpdateRecordInput};

    #[test]
    fn encodes_bgp4mp_update_record_with_bgpkit_models() {
        let input = UpdateRecordInput {
            timestamp: 1_700_000_000,
            peer_asn: 64496,
            local_asn: 64497,
            interface_index: 0,
            peer_ip: Ipv4Addr::new(198, 51, 100, 1),
            local_ip: Ipv4Addr::new(198, 51, 100, 2),
            bgp_message: valid_update_withdraw_message(),
        };

        let bytes = encode_bgp4mp_message_as4(&input).expect("update encoding should succeed");

        let mut cursor = Cursor::new(bytes);
        let parsed = parse_mrt_record(&mut cursor).expect("record should parse");
        assert_eq!(parsed.common_header.entry_type, EntryType::BGP4MP);
        assert_eq!(
            parsed.common_header.entry_subtype,
            Bgp4MpType::MessageAs4 as u16
        );
    }

    #[test]
    fn encodes_bgp4mp_state_change_record_with_bgpkit_models() {
        let input = PeerStateRecordInput {
            timestamp: 1_700_000_000,
            peer_asn: 64496,
            local_asn: 64497,
            interface_index: 0,
            peer_ip: Ipv4Addr::new(198, 51, 100, 1),
            local_ip: Ipv4Addr::new(198, 51, 100, 2),
            old_state: 3,
            new_state: 6,
        };

        let bytes = encode_bgp4mp_state_change_as4(&input).expect("state change encoding");
        let mut cursor = Cursor::new(bytes);
        let parsed = parse_mrt_record(&mut cursor).expect("record should parse");
        assert_eq!(parsed.common_header.entry_type, EntryType::BGP4MP);
        assert_eq!(
            parsed.common_header.entry_subtype,
            Bgp4MpType::StateChangeAs4 as u16
        );
    }

    #[test]
    fn builds_table_dump_v2_records() {
        let snapshot = RibSnapshotInput {
            timestamp: 1_700_000_000,
            collector_bgp_id: Ipv4Addr::new(192, 0, 2, 1),
            view_name: "main".to_string(),
            peers: vec![SnapshotPeer {
                peer_bgp_id: Ipv4Addr::new(198, 51, 100, 1),
                peer_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                peer_asn: 64_512,
            }],
            routes: vec![SnapshotRoute {
                sequence: 1,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                prefix_len: 24,
                peer_index: 0,
                originated_time: 1_700_000_000,
                path_attributes: vec![],
            }],
        };

        let records = build_table_dump_v2(&snapshot).expect("table dump should be built");
        assert_eq!(records.len(), 2);

        let mut first = Cursor::new(records[0].clone());
        let first_record = parse_mrt_record(&mut first).expect("peer index should parse");
        assert_eq!(
            first_record.common_header.entry_type,
            EntryType::TABLE_DUMP_V2
        );

        let mut second = Cursor::new(records[1].clone());
        let second_record = parse_mrt_record(&mut second).expect("rib entry should parse");
        assert_eq!(
            second_record.common_header.entry_type,
            EntryType::TABLE_DUMP_V2
        );
    }

    fn valid_update_withdraw_message() -> Vec<u8> {
        let mut msg = vec![0xff; 16];
        // total length 24 bytes: 19-byte header + 5-byte payload
        msg.extend_from_slice(&24u16.to_be_bytes());
        msg.push(2); // UPDATE
        msg.extend_from_slice(&1u16.to_be_bytes()); // withdrawn routes length
        msg.push(0); // withdraw 0.0.0.0/0
        msg.extend_from_slice(&0u16.to_be_bytes()); // path attributes length
        msg
    }
}
