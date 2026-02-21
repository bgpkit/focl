use std::net::Ipv4Addr;

use focl::archive::types::UpdateRecordInput;
use focl::archive::ArchiveService;
use focl::config::{
    ArchiveConfig, ArchiveDestinationConfig, CompressionKind, DestinationMode, DestinationType,
};

#[tokio::test]
async fn writes_updates_segment_and_manifest_on_rollover() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("archive");
    let tmp_root = root.join(".tmp");

    let mut cfg = ArchiveConfig {
        enabled: true,
        root: root.clone(),
        tmp_root,
        compression: CompressionKind::Gzip,
        ..ArchiveConfig::default()
    };

    cfg.destinations = vec![ArchiveDestinationConfig {
        destination_type: DestinationType::Local,
        mode: DestinationMode::Primary,
        path: Some(root.clone()),
        required: Some(true),
        endpoint: None,
        bucket: None,
        prefix: None,
        upload_concurrency: Some(1),
        retry_backoff_secs: Some(1),
        max_retries: Some(0),
        region: None,
        access_key_id: None,
        secret_access_key: None,
        session_token: None,
    }];

    cfg.validate().unwrap();

    let service = ArchiveService::new(cfg, Ipv4Addr::new(192, 0, 2, 1))
        .await
        .unwrap();

    service
        .ingest_update(UpdateRecordInput {
            timestamp: 1_700_000_001,
            peer_asn: 64512,
            local_asn: 64513,
            interface_index: 0,
            peer_ip: Ipv4Addr::new(198, 51, 100, 1),
            local_ip: Ipv4Addr::new(198, 51, 100, 2),
            bgp_message: valid_update_withdraw_message(),
        })
        .await
        .unwrap();

    service
        .rollover(focl::archive::types::ArchiveStream::Updates)
        .await
        .unwrap();

    let mut found_segment = false;
    let mut found_manifest = false;

    for entry in walkdir::WalkDir::new(&root) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            let p = entry.path().to_string_lossy();
            if p.ends_with(".gz") {
                found_segment = true;
            }
            if p.ends_with(".gz.json") {
                found_manifest = true;
            }
        }
    }

    assert!(found_segment, "expected at least one gz segment file");
    assert!(found_manifest, "expected at least one segment manifest");
}

fn valid_update_withdraw_message() -> Vec<u8> {
    let mut msg = vec![0xff; 16];
    msg.extend_from_slice(&24u16.to_be_bytes());
    msg.push(2); // UPDATE
    msg.extend_from_slice(&1u16.to_be_bytes()); // withdrawn routes length
    msg.push(0); // withdraw 0.0.0.0/0
    msg.extend_from_slice(&0u16.to_be_bytes()); // path attributes length
    msg
}
