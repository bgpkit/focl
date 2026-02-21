pub mod layout;
pub mod manifest;
pub mod queue;
pub mod replicator;
pub mod snapshot;
pub mod types;
pub mod writer;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::sync::{broadcast, Mutex};

use crate::archive::layout::{aligned_epoch, segment_paths};
use crate::archive::replicator::Replicator;
use crate::archive::snapshot::{
    build_table_dump_v2, encode_bgp4mp_message_as4, encode_bgp4mp_state_change_as4,
};
use crate::archive::types::{
    ArchiveStatus, ArchiveStream, FinalizedSegment, PeerStateRecordInput, RibSnapshotInput,
    UpdateRecordInput,
};
use crate::archive::writer::SegmentWriter;
use crate::config::{ArchiveConfig, DestinationMode};
use crate::types::{Event, EventEnvelope};

pub struct ArchiveService {
    cfg: ArchiveConfig,
    collector_bgp_id: Ipv4Addr,
    updates_writer: Mutex<Option<SegmentWriter>>,
    ribs_last: Mutex<Option<FinalizedSegment>>,
    last_rib_bucket: Mutex<Option<i64>>,
    replicator: Option<Arc<Replicator>>,
    event_tx: broadcast::Sender<EventEnvelope>,
}

impl ArchiveService {
    pub async fn new(cfg: ArchiveConfig, collector_bgp_id: Ipv4Addr) -> Result<Arc<Self>> {
        let (event_tx, _event_rx) = broadcast::channel(512);

        let replicator = if cfg.enabled {
            std::fs::create_dir_all(&cfg.root)
                .with_context(|| format!("failed creating archive root {}", cfg.root.display()))?;
            std::fs::create_dir_all(&cfg.tmp_root).with_context(|| {
                format!(
                    "failed creating archive tmp root {}",
                    cfg.tmp_root.display()
                )
            })?;
            cleanup_tmp_root(&cfg.tmp_root)
                .with_context(|| format!("failed cleaning tmp root {}", cfg.tmp_root.display()))?;

            let queue = crate::archive::queue::ReplicationQueue::new(&cfg.root)?;
            Some(Arc::new(Replicator::new(
                &cfg,
                queue,
                Some(event_tx.clone()),
            )))
        } else {
            None
        };

        let service = Arc::new(Self {
            cfg,
            collector_bgp_id,
            updates_writer: Mutex::new(None),
            ribs_last: Mutex::new(None),
            last_rib_bucket: Mutex::new(None),
            replicator,
            event_tx,
        });

        if service.cfg.enabled {
            service
                .ensure_updates_writer(Utc::now().timestamp())
                .await?;
            service.spawn_background_tasks();
        }

        Ok(service)
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
        self.event_tx.subscribe()
    }

    pub fn destinations(&self) -> Vec<(String, String, String)> {
        self.cfg
            .destinations
            .iter()
            .map(|d| {
                let dtype = match d.destination_type {
                    crate::config::DestinationType::Local => "local",
                    crate::config::DestinationType::S3 => "s3",
                }
                .to_string();
                let mode = match d.mode {
                    DestinationMode::Primary => "primary",
                    DestinationMode::AsyncReplica => "async_replica",
                }
                .to_string();
                (d.destination_key(), mode, dtype)
            })
            .collect()
    }

    pub async fn ingest_update(&self, update: UpdateRecordInput) -> Result<()> {
        if !self.cfg.enabled {
            return Ok(());
        }

        self.ensure_updates_writer(update.timestamp).await?;

        let record = encode_bgp4mp_message_as4(&update)?;
        let mut writer_guard = self.updates_writer.lock().await;
        let writer = writer_guard
            .as_mut()
            .context("updates writer not initialized")?;
        writer.write_record(&record)?;

        Ok(())
    }

    pub async fn ingest_peer_state(&self, state: PeerStateRecordInput) -> Result<()> {
        if !self.cfg.enabled || !self.cfg.include_peer_state_records {
            return Ok(());
        }

        self.ensure_updates_writer(state.timestamp).await?;

        let record = encode_bgp4mp_state_change_as4(&state)?;
        let mut writer_guard = self.updates_writer.lock().await;
        let writer = writer_guard
            .as_mut()
            .context("updates writer not initialized")?;
        writer.write_record(&record)?;

        Ok(())
    }

    pub async fn snapshot_now(&self, mut input: RibSnapshotInput) -> Result<FinalizedSegment> {
        if !self.cfg.enabled {
            anyhow::bail!("archive is disabled");
        }

        if input.collector_bgp_id == Ipv4Addr::UNSPECIFIED {
            input.collector_bgp_id = self.collector_bgp_id;
        }

        let paths = segment_paths(&self.cfg, ArchiveStream::Ribs, input.timestamp)?;
        self.emit(Event::ArchiveSegmentOpened {
            stream: ArchiveStream::Ribs.as_str().to_string(),
            path: paths.final_path.display().to_string(),
            start_ts: aligned_epoch(input.timestamp, self.cfg.ribs_interval_secs),
        });

        let mut writer = SegmentWriter::new(
            &self.cfg,
            ArchiveStream::Ribs,
            aligned_epoch(input.timestamp, self.cfg.ribs_interval_secs),
            paths,
        )?;

        let records = build_table_dump_v2(&input)?;
        for rec in records {
            writer.write_record(&rec)?;
        }

        let finalized = writer.finalize(input.timestamp)?;
        self.emit(Event::ArchiveSegmentFinalized {
            stream: ArchiveStream::Ribs.as_str().to_string(),
            path: finalized.final_path.display().to_string(),
            end_ts: finalized.end_ts,
            records: finalized.record_count,
        });

        if let Some(replicator) = &self.replicator {
            replicator.enqueue_segment(&finalized)?;
        }

        {
            let mut last = self.ribs_last.lock().await;
            *last = Some(finalized.clone());
        }

        Ok(finalized)
    }

    pub async fn rollover(&self, stream: ArchiveStream) -> Result<()> {
        if !self.cfg.enabled {
            return Ok(());
        }

        match stream {
            ArchiveStream::Updates => {
                self.rotate_updates(Utc::now().timestamp()).await?;
            }
            ArchiveStream::Ribs => {
                let now = Utc::now().timestamp();
                let snapshot = RibSnapshotInput {
                    timestamp: now,
                    collector_bgp_id: self.collector_bgp_id,
                    view_name: "main".to_string(),
                    peers: vec![],
                    routes: vec![],
                };
                self.snapshot_now(snapshot).await?;
            }
        }

        Ok(())
    }

    pub async fn retry_failed_replications(&self) -> Result<usize> {
        match &self.replicator {
            Some(rep) => rep.retry_failed(),
            None => Ok(0),
        }
    }

    pub async fn status(&self) -> Result<ArchiveStatus> {
        let updates_guard = self.updates_writer.lock().await;
        let ribs_guard = self.ribs_last.lock().await;

        let queued = match &self.replicator {
            Some(rep) => rep.queue().pending_count()?,
            None => 0,
        };

        let failures = match &self.replicator {
            Some(rep) => rep.failures(),
            None => 0,
        };

        Ok(ArchiveStatus {
            enabled: self.cfg.enabled,
            collector_id: self.cfg.collector_id.clone(),
            updates_interval_secs: self.cfg.updates_interval_secs,
            ribs_interval_secs: self.cfg.ribs_interval_secs,
            updates_open_path: updates_guard.as_ref().map(|w| w.path().to_path_buf()),
            updates_record_count: updates_guard
                .as_ref()
                .map(|w| w.record_count())
                .unwrap_or(0),
            ribs_last_path: ribs_guard.as_ref().map(|r| r.final_path.clone()),
            ribs_last_record_count: ribs_guard.as_ref().map(|r| r.record_count).unwrap_or(0),
            queued_replication_jobs: queued,
            replication_failures: failures,
        })
    }

    fn spawn_background_tasks(self: &Arc<Self>) {
        if let Some(replicator) = &self.replicator {
            let rep = Arc::clone(replicator);
            rep.spawn();
        }

        let service = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                if let Err(err) = service.tick().await {
                    tracing::error!(error=%err, "archive scheduler tick failed");
                }
            }
        });
    }

    async fn tick(&self) -> Result<()> {
        if !self.cfg.enabled {
            return Ok(());
        }

        let now = Utc::now().timestamp();
        self.ensure_updates_writer(now).await?;

        let rib_bucket = aligned_epoch(now, self.cfg.ribs_interval_secs);
        let mut last_rib = self.last_rib_bucket.lock().await;
        if last_rib.map(|v| v != rib_bucket).unwrap_or(true) {
            let snapshot = RibSnapshotInput {
                timestamp: now,
                collector_bgp_id: self.collector_bgp_id,
                view_name: "main".to_string(),
                peers: vec![],
                routes: vec![],
            };
            self.snapshot_now(snapshot).await?;
            *last_rib = Some(rib_bucket);
        }

        Ok(())
    }

    async fn ensure_updates_writer(&self, now_ts: i64) -> Result<()> {
        let update_bucket = aligned_epoch(now_ts, self.cfg.updates_interval_secs);

        let mut writer_guard = self.updates_writer.lock().await;
        let needs_rotate = writer_guard
            .as_ref()
            .map(|w| w.start_ts() != update_bucket)
            .unwrap_or(true);

        if needs_rotate {
            if let Some(old_writer) = writer_guard.take() {
                let finalized = old_writer.finalize(now_ts)?;
                self.emit(Event::ArchiveSegmentFinalized {
                    stream: ArchiveStream::Updates.as_str().to_string(),
                    path: finalized.final_path.display().to_string(),
                    end_ts: finalized.end_ts,
                    records: finalized.record_count,
                });
                if let Some(rep) = &self.replicator {
                    rep.enqueue_segment(&finalized)?;
                }
            }

            let paths = segment_paths(&self.cfg, ArchiveStream::Updates, now_ts)?;
            self.emit(Event::ArchiveSegmentOpened {
                stream: ArchiveStream::Updates.as_str().to_string(),
                path: paths.final_path.display().to_string(),
                start_ts: update_bucket,
            });
            let writer =
                SegmentWriter::new(&self.cfg, ArchiveStream::Updates, update_bucket, paths)?;
            *writer_guard = Some(writer);
        }

        Ok(())
    }

    async fn rotate_updates(&self, now_ts: i64) -> Result<()> {
        {
            let mut writer_guard = self.updates_writer.lock().await;
            if let Some(old_writer) = writer_guard.take() {
                let finalized = old_writer.finalize(now_ts)?;
                self.emit(Event::ArchiveSegmentFinalized {
                    stream: ArchiveStream::Updates.as_str().to_string(),
                    path: finalized.final_path.display().to_string(),
                    end_ts: finalized.end_ts,
                    records: finalized.record_count,
                });
                if let Some(rep) = &self.replicator {
                    rep.enqueue_segment(&finalized)?;
                }
            }
        }

        self.ensure_updates_writer(now_ts).await
    }

    fn emit(&self, event: Event) {
        let _ = self.event_tx.send(EventEnvelope::new(event));
    }
}

fn cleanup_tmp_root(tmp_root: &std::path::Path) -> Result<()> {
    if !tmp_root.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(tmp_root)
        .with_context(|| format!("failed reading tmp root {}", tmp_root.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed removing temp segment {}", path.display()))?;
        }
    }

    Ok(())
}
