use std::collections::{BTreeMap, HashMap};
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
use ipnet::IpNet;

use crate::archive::types::{PeerStateRecordInput, RibSnapshotInput, UpdateRecordInput};

/// Encodes an UPDATE through bgpkit-parser's model encoder. This remains available
/// for callers that need a validated, canonical MRT record, but it is not the
/// archive path because model encoding cannot preserve the original wire frame.
pub fn encode_bgp4mp_message_as4(input: &UpdateRecordInput) -> Result<Vec<u8>> {
    if input.peer_ip.is_ipv4() != input.local_ip.is_ipv4() {
        bail!("BGP4MP peer and local IP addresses must use the same family");
    }
    let bgp_message = parse_update_message(&input.bgp_message)?;

    let msg = Bgp4MpMessage {
        msg_type: Bgp4MpType::MessageAs4,
        peer_asn: Asn::new_32bit(input.peer_asn),
        local_asn: Asn::new_32bit(input.local_asn),
        interface_index: input.interface_index,
        peer_ip: input.peer_ip,
        local_ip: input.local_ip,
        bgp_message,
    };

    let message = MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(msg));
    encode_mrt_message(
        input.timestamp as u32,
        EntryType::BGP4MP,
        Bgp4MpType::MessageAs4 as u16,
        message,
    )
}

/// Builds a BGP4MP_MESSAGE_AS4 envelope without parsing or re-encoding the
/// embedded BGP UPDATE. The archive always uses this path so malformed yet
/// archivable frames retain their exact original bytes.
pub fn encode_bgp4mp_raw_as4(input: &UpdateRecordInput) -> Result<Vec<u8>> {
    let (address_family, peer_address, local_address) = match (input.peer_ip, input.local_ip) {
        (IpAddr::V4(peer), IpAddr::V4(local)) => {
            (1_u16, peer.octets().to_vec(), local.octets().to_vec())
        }
        (IpAddr::V6(peer), IpAddr::V6(local)) => {
            (2_u16, peer.octets().to_vec(), local.octets().to_vec())
        }
        _ => bail!("BGP4MP peer and local IP addresses must use the same family"),
    };

    let mut payload =
        Vec::with_capacity(12 + peer_address.len() + local_address.len() + input.bgp_message.len());
    payload.extend_from_slice(&input.peer_asn.to_be_bytes());
    payload.extend_from_slice(&input.local_asn.to_be_bytes());
    payload.extend_from_slice(&input.interface_index.to_be_bytes());
    payload.extend_from_slice(&address_family.to_be_bytes());
    payload.extend_from_slice(&peer_address);
    payload.extend_from_slice(&local_address);
    payload.extend_from_slice(&input.bgp_message);

    encode_common_header(
        input.timestamp as u32,
        EntryType::BGP4MP,
        Bgp4MpType::MessageAs4 as u16,
        payload,
    )
}

pub fn encode_bgp4mp_state_change_as4(input: &PeerStateRecordInput) -> Result<Vec<u8>> {
    let old_state = BgpState::try_from(input.old_state)
        .map_err(|_| anyhow!("invalid old_state value {}", input.old_state))?;
    let new_state = BgpState::try_from(input.new_state)
        .map_err(|_| anyhow!("invalid new_state value {}", input.new_state))?;

    if input.peer_ip.is_ipv4() != input.local_ip.is_ipv4() {
        bail!("BGP4MP peer and local IP addresses must use the same family");
    }

    let state_change = Bgp4MpStateChange {
        msg_type: Bgp4MpType::StateChangeAs4,
        peer_asn: Asn::new_32bit(input.peer_asn),
        local_asn: Asn::new_32bit(input.local_asn),
        interface_index: input.interface_index,
        peer_ip: input.peer_ip,
        local_addr: input.local_ip,
        old_state,
        new_state,
    };

    let message = MrtMessage::Bgp4Mp(Bgp4MpEnum::StateChange(state_change));
    encode_mrt_message(
        input.timestamp as u32,
        EntryType::BGP4MP,
        Bgp4MpType::StateChangeAs4 as u16,
        message,
    )
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
    )?);

    let mut grouped_routes: BTreeMap<(u8, Vec<u8>, u8), (IpNet, Vec<&_>)> = BTreeMap::new();
    for route in &snapshot.routes {
        validate_route_prefix(route.prefix)?;
        if !peer_index_table.id_peer_map.contains_key(&route.peer_index) {
            bail!(
                "route references unknown peer_index {} (peers: {})",
                route.peer_index,
                peer_index_table.id_peer_map.len()
            );
        }

        let key = prefix_sort_key(route.prefix);
        grouped_routes
            .entry(key)
            .or_insert_with(|| (route.prefix, Vec::new()))
            .1
            .push(route);
    }

    let mut sequence_number = 0_u32;
    for (_, (prefix_net, mut routes)) in grouped_routes {
        routes.sort_by_key(|route| route.peer_index);
        let uses_add_path = routes.iter().any(|route| route.path_id.is_some());
        if uses_add_path && routes.iter().any(|route| route.path_id.is_none()) {
            bail!("all entries for an ADD-PATH RIB prefix must provide path_id");
        }

        let rib_type = rib_type_for_prefix(prefix_net, uses_add_path);
        let prefix = NetworkPrefix::new(prefix_net, None);
        let rib_entries = routes
            .into_iter()
            .map(|route| {
                let attributes = parse_attributes(
                    Bytes::from(route.path_attributes.clone()),
                    &AsnLength::Bits32,
                    uses_add_path,
                    None,
                    None,
                    None,
                )
                .with_context(|| {
                    format!(
                        "failed parsing route attributes for prefix {}",
                        route.prefix
                    )
                })?;
                Ok(RibEntry {
                    peer_index: route.peer_index,
                    originated_time: route.originated_time,
                    path_id: route.path_id,
                    attributes,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let rib = RibAfiEntries {
            rib_type,
            sequence_number,
            prefix,
            rib_entries,
        };
        sequence_number = sequence_number.wrapping_add(1);
        records.push(encode_mrt_message(
            snapshot.timestamp as u32,
            EntryType::TABLE_DUMP_V2,
            rib_type as u16,
            MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(rib)),
        )?);
    }

    Ok(records)
}

fn validate_route_prefix(prefix: IpNet) -> Result<()> {
    let valid = match prefix {
        IpNet::V4(network) => network.prefix_len() <= 32,
        IpNet::V6(network) => network.prefix_len() <= 128,
    };
    if valid {
        Ok(())
    } else {
        bail!("invalid prefix length for {prefix}")
    }
}

fn prefix_sort_key(prefix: IpNet) -> (u8, Vec<u8>, u8) {
    match prefix {
        IpNet::V4(network) => (4, network.network().octets().to_vec(), network.prefix_len()),
        IpNet::V6(network) => (6, network.network().octets().to_vec(), network.prefix_len()),
    }
}

fn rib_type_for_prefix(prefix: IpNet, uses_add_path: bool) -> TableDumpV2Type {
    match (prefix, uses_add_path) {
        (IpNet::V4(_), false) => TableDumpV2Type::RibIpv4Unicast,
        (IpNet::V4(_), true) => TableDumpV2Type::RibIpv4UnicastAddPath,
        (IpNet::V6(_), false) => TableDumpV2Type::RibIpv6Unicast,
        (IpNet::V6(_), true) => TableDumpV2Type::RibIpv6UnicastAddPath,
    }
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
        .map_err(|error| anyhow!("failed to parse BGP message with bgpkit-parser: {error}"))?;
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
) -> Result<Vec<u8>> {
    let payload = message
        .encode(subtype)
        .map_err(|error| anyhow!("failed encoding MRT message: {error}"))?;
    encode_common_header(timestamp, entry_type, subtype, payload.to_vec())
}

fn encode_common_header(
    timestamp: u32,
    entry_type: EntryType,
    subtype: u16,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let length = u32::try_from(payload.len()).context("MRT payload exceeds u32 length")?;
    let header = CommonHeader {
        timestamp,
        microsecond_timestamp: None,
        entry_type,
        entry_subtype: subtype,
        length,
    };
    let header_bytes = header.encode();
    let mut out = Vec::with_capacity(header_bytes.len() + payload.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use bgpkit_parser::models::{
        Bgp4MpType, EntryType, MrtMessage, TableDumpV2Message, TableDumpV2Type,
    };
    use bgpkit_parser::parse_mrt_record;

    use super::*;
    use crate::archive::types::{RibSnapshotInput, SnapshotPeer, SnapshotRoute, UpdateRecordInput};

    #[test]
    fn raw_bgp4mp_v4_round_trips_original_frame() -> Result<()> {
        let input = update_input(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        );
        assert_raw_bgp4mp_round_trip(&input)
    }

    #[test]
    fn raw_bgp4mp_v6_round_trips_original_frame_and_addresses() -> Result<()> {
        let input = update_input(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        );
        assert_raw_bgp4mp_round_trip(&input)
    }

    #[test]
    fn raw_bgp4mp_preserves_unparseable_frame_bytes() -> Result<()> {
        let mut input = update_input(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        );
        input.bgp_message = vec![0x01, 0x02, 0x03, 0x04];

        let bytes = encode_bgp4mp_raw_as4(&input)?;
        assert_eq!(&bytes[32..], input.bgp_message.as_slice());
        Ok(())
    }

    #[test]
    fn parsed_encoder_remains_available_for_valid_updates() -> Result<()> {
        let input = update_input(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        );
        let bytes = encode_bgp4mp_message_as4(&input)?;
        let parsed = parse_mrt_record(&mut Cursor::new(bytes))?;
        assert_eq!(
            parsed.common_header.entry_subtype,
            Bgp4MpType::MessageAs4 as u16
        );
        Ok(())
    }

    #[test]
    fn state_change_encoder_supports_ipv6_envelopes() -> Result<()> {
        let input = PeerStateRecordInput {
            timestamp: 1_700_000_000,
            peer_asn: 64_496,
            local_asn: 64_497,
            interface_index: 7,
            peer_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            local_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            old_state: BgpState::OpenConfirm as u16,
            new_state: BgpState::Established as u16,
        };

        let bytes = encode_bgp4mp_state_change_as4(&input)?;
        let parsed = parse_mrt_record(&mut Cursor::new(bytes))?;
        match parsed.message {
            MrtMessage::Bgp4Mp(Bgp4MpEnum::StateChange(state)) => {
                assert_eq!(state.peer_ip, input.peer_ip);
                assert_eq!(state.local_addr, input.local_ip);
            }
            message => bail!("unexpected MRT message: {message:?}"),
        }
        Ok(())
    }

    #[test]
    fn groups_dual_stack_and_add_path_rib_entries() -> Result<()> {
        let snapshot = RibSnapshotInput {
            timestamp: 1_700_000_000,
            collector_bgp_id: Ipv4Addr::new(192, 0, 2, 1),
            view_name: "main".to_string(),
            peers: vec![
                SnapshotPeer {
                    peer_bgp_id: Ipv4Addr::new(198, 51, 100, 1),
                    peer_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                    peer_asn: 64_512,
                },
                SnapshotPeer {
                    peer_bgp_id: Ipv4Addr::new(198, 51, 100, 2),
                    peer_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                    peer_asn: 64_513,
                },
            ],
            routes: vec![
                SnapshotRoute {
                    prefix: "203.0.113.0/24".parse()?,
                    peer_index: 1,
                    originated_time: 1_700_000_001,
                    path_id: None,
                    path_attributes: vec![],
                },
                SnapshotRoute {
                    prefix: "203.0.113.0/24".parse()?,
                    peer_index: 0,
                    originated_time: 1_700_000_000,
                    path_id: None,
                    path_attributes: vec![],
                },
                SnapshotRoute {
                    prefix: "2001:db8:1::/48".parse()?,
                    peer_index: 1,
                    originated_time: 1_700_000_002,
                    path_id: Some(99),
                    path_attributes: vec![],
                },
            ],
        };

        let records = build_table_dump_v2(&snapshot)?;
        assert_eq!(records.len(), 3);
        let peer_index = parse_mrt_record(&mut Cursor::new(&records[0]))?;
        assert!(matches!(
            peer_index.message,
            MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(_))
        ));

        let v4 = parse_rib_record(&records[1])?;
        assert_eq!(v4.rib_type, TableDumpV2Type::RibIpv4Unicast);
        assert_eq!(v4.sequence_number, 0);
        assert_eq!(v4.rib_entries.len(), 2);
        assert_eq!(v4.rib_entries[0].peer_index, 0);
        assert_eq!(v4.rib_entries[1].peer_index, 1);

        let v6 = parse_rib_record(&records[2])?;
        assert_eq!(v6.rib_type, TableDumpV2Type::RibIpv6UnicastAddPath);
        assert_eq!(v6.sequence_number, 1);
        assert_eq!(v6.rib_entries.len(), 1);
        assert_eq!(v6.rib_entries[0].peer_index, 1);
        assert_eq!(v6.rib_entries[0].path_id, Some(99));
        Ok(())
    }

    fn update_input(peer_ip: IpAddr, local_ip: IpAddr) -> UpdateRecordInput {
        UpdateRecordInput {
            timestamp: 1_700_000_000,
            peer_asn: 64496,
            local_asn: 64497,
            interface_index: 7,
            peer_ip,
            local_ip,
            bgp_message: valid_update_withdraw_message(),
        }
    }

    fn assert_raw_bgp4mp_round_trip(input: &UpdateRecordInput) -> Result<()> {
        let bytes = encode_bgp4mp_raw_as4(input)?;
        let parsed = parse_mrt_record(&mut Cursor::new(&bytes))?;
        assert_eq!(parsed.common_header.entry_type, EntryType::BGP4MP);
        assert_eq!(
            parsed.common_header.entry_subtype,
            Bgp4MpType::MessageAs4 as u16
        );
        match parsed.message {
            MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(message)) => {
                assert_eq!(message.peer_ip, input.peer_ip);
                assert_eq!(message.local_ip, input.local_ip);
                let decoded = message
                    .bgp_message
                    .encode(AsnLength::Bits32)
                    .map_err(|error| anyhow!("failed re-encoding parsed BGP message: {error}"))?;
                assert_eq!(decoded.as_ref(), input.bgp_message.as_slice());
            }
            message => panic!("unexpected MRT message: {message:?}"),
        }

        let address_len = if input.peer_ip.is_ipv4() { 4 } else { 16 };
        let frame_start = 12 + 12 + 2 * address_len;
        assert_eq!(&bytes[frame_start..], input.bgp_message.as_slice());
        Ok(())
    }

    fn parse_rib_record(bytes: &[u8]) -> Result<RibAfiEntries> {
        let record = parse_mrt_record(&mut Cursor::new(bytes))?;
        match record.message {
            MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(rib)) => Ok(rib),
            message => bail!("unexpected MRT message: {message:?}"),
        }
    }

    fn valid_update_withdraw_message() -> Vec<u8> {
        let mut msg = vec![0xff; 16];
        msg.extend_from_slice(&24_u16.to_be_bytes());
        msg.push(2);
        msg.extend_from_slice(&1_u16.to_be_bytes());
        msg.push(0);
        msg.extend_from_slice(&0_u16.to_be_bytes());
        msg
    }
}
