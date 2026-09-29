use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aws_sdk_s3::primitives::ByteStream;
use aws_types::region::Region;
use tokio::time::sleep;

use crate::archive::manifest::SegmentManifest;
use crate::archive::queue::{ReplicationJob, ReplicationQueue};
use crate::archive::types::FinalizedSegment;
use crate::config::{ArchiveConfig, ArchiveDestinationConfig, DestinationMode, DestinationType};
use crate::types::{Event, EventEnvelope};

pub struct Replicator {
    queue: ReplicationQueue,
    destinations: HashMap<String, ArchiveDestinationConfig>,
    failures: AtomicU64,
    event_tx: Option<tokio::sync::broadcast::Sender<EventEnvelope>>,
}

impl Replicator {
    pub fn new(
        cfg: &ArchiveConfig,
        queue: ReplicationQueue,
        event_tx: Option<tokio::sync::broadcast::Sender<EventEnvelope>>,
    ) -> Self {
        let destinations = cfg
            .destinations
            .iter()
            .cloned()
            .map(|d| (d.destination_key(), d))
            .collect();

        Self {
            queue,
            destinations,
            failures: AtomicU64::new(0),
            event_tx,
        }
    }

    pub fn queue(&self) -> &ReplicationQueue {
        &self.queue
    }

    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    pub fn enqueue_segment(&self, segment: &FinalizedSegment) -> Result<()> {
        for destination in self.destinations.values() {
            if destination.mode != DestinationMode::AsyncReplica {
                continue;
            }
            self.queue.enqueue(
                &segment.final_path,
                &segment.manifest_path,
                &destination.destination_key(),
                destination.max_retries(),
            )?;
        }
        Ok(())
    }

    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                if let Err(err) = self.run_once().await {
                    tracing::error!(error=%err, "replicator run_once failed");
                }
                sleep(Duration::from_secs(2)).await;
            }
        })
    }

    pub async fn run_once(&self) -> Result<()> {
        let jobs = self.queue.claim_ready(32)?;
        for job in jobs {
            if let Err(err) = self.process_job(&job).await {
                self.failures.fetch_add(1, Ordering::Relaxed);
                let retry_secs = self
                    .destinations
                    .get(&job.destination_key)
                    .map(|d| d.retry_backoff_secs())
                    .unwrap_or(5);
                self.queue
                    .mark_failed(&job, &err.to_string(), retry_secs)
                    .with_context(|| {
                        format!("failed marking replication job {} as failed", job.id)
                    })?;
                self.emit(Event::ArchiveReplicationFailed {
                    destination: job.destination_key.clone(),
                    path: job.segment_path.display().to_string(),
                    error: err.to_string(),
                });
                continue;
            }

            self.queue.mark_success(job.id).with_context(|| {
                format!("failed marking replication job {} as successful", job.id)
            })?;
            self.emit(Event::ArchiveReplicationSucceeded {
                destination: job.destination_key.clone(),
                path: job.segment_path.display().to_string(),
            });
        }

        Ok(())
    }

    pub fn retry_failed(&self) -> Result<usize> {
        self.queue.retry_failed()
    }

    async fn process_job(&self, job: &ReplicationJob) -> Result<()> {
        let destination = self
            .destinations
            .get(&job.destination_key)
            .with_context(|| format!("destination {} not found", job.destination_key))?;

        let manifest_json = fs::read_to_string(&job.manifest_path)
            .with_context(|| format!("failed reading manifest {}", job.manifest_path.display()))?;
        let manifest: SegmentManifest = serde_json::from_str(&manifest_json)
            .with_context(|| format!("failed parsing manifest {}", job.manifest_path.display()))?;

        match destination.destination_type {
            DestinationType::Local => {
                self.copy_to_local(destination, job, &manifest)?;
            }
            DestinationType::S3 => {
                self.copy_to_s3(destination, job, &manifest).await?;
            }
        }

        Ok(())
    }

    fn copy_to_local(
        &self,
        destination: &ArchiveDestinationConfig,
        job: &ReplicationJob,
        manifest: &SegmentManifest,
    ) -> Result<()> {
        let base = destination
            .path
            .as_ref()
            .context("local destination path missing")?;
        let relative_path = contained_relative_path(manifest)?;
        let target_segment = base.join(&relative_path);
        if !target_segment.starts_with(base) {
            bail!(
                "manifest path {} escapes the destination root {}",
                manifest.relative_path,
                base.display()
            );
        }
        let target_manifest = PathBuf::from(format!("{}.json", target_segment.display()));

        if let Some(parent) = target_segment.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating destination dir {}", parent.display()))?;
        }

        fs::copy(&job.segment_path, &target_segment).with_context(|| {
            format!(
                "failed copying segment {} -> {}",
                job.segment_path.display(),
                target_segment.display()
            )
        })?;
        fs::copy(&job.manifest_path, &target_manifest).with_context(|| {
            format!(
                "failed copying manifest {} -> {}",
                job.manifest_path.display(),
                target_manifest.display()
            )
        })?;

        Ok(())
    }

    async fn copy_to_s3(
        &self,
        destination: &ArchiveDestinationConfig,
        job: &ReplicationJob,
        manifest: &SegmentManifest,
    ) -> Result<()> {
        let endpoint = destination
            .endpoint
            .as_deref()
            .context("s3 endpoint missing")?;
        let bucket = destination.bucket.as_deref().context("s3 bucket missing")?;
        let prefix = destination.prefix.as_deref().unwrap_or_default();

        let region = destination
            .region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_string());

        let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(region))
            .load()
            .await;

        let s3_conf = aws_sdk_s3::config::Builder::from(&shared_config)
            .endpoint_url(endpoint)
            .force_path_style(true)
            .build();

        let client = aws_sdk_s3::Client::from_conf(s3_conf);

        let relative_path = contained_relative_path(manifest)?;
        let key = object_key(prefix, &relative_path.to_string_lossy());
        let manifest_key = format!("{}.json", key);

        let body = ByteStream::from_path(Path::new(&job.segment_path)).await?;
        client
            .put_object()
            .bucket(bucket)
            .key(&key)
            .body(body)
            .send()
            .await
            .with_context(|| format!("failed uploading segment to s3://{bucket}/{key}"))?;

        let manifest_body = ByteStream::from_path(Path::new(&job.manifest_path)).await?;
        client
            .put_object()
            .bucket(bucket)
            .key(&manifest_key)
            .body(manifest_body)
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed uploading manifest to s3://{bucket}/{}",
                    manifest_key
                )
            })?;

        Ok(())
    }

    fn emit(&self, event: Event) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(EventEnvelope::new(event));
        }
    }
}

fn object_key(prefix: &str, relative: &str) -> String {
    if prefix.is_empty() {
        return relative.trim_start_matches('/').to_string();
    }

    let normalized_prefix = prefix.trim_matches('/');
    format!("{}/{}", normalized_prefix, relative.trim_start_matches('/'))
}

/// Resolves a manifest's relative path, refusing anything that is not a plain
/// relative path. The queue is re-read from disk on every retry, so a manifest
/// changed after it was queued must not be able to redirect the copy: an
/// absolute path discards the destination root in `Path::join`, and a `..`
/// component climbs out of it.
fn contained_relative_path(manifest: &SegmentManifest) -> Result<PathBuf> {
    let mut safe = PathBuf::new();
    for component in Path::new(&manifest.relative_path).components() {
        match component {
            Component::Normal(part) => safe.push(part),
            _ => bail!(
                "manifest relative path is not a plain relative path: {}",
                manifest.relative_path
            ),
        }
    }
    if safe.as_os_str().is_empty() {
        bail!("manifest relative path is empty");
    }
    Ok(safe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CompressionKind, LayoutProfile};

    fn manifest(relative_path: &str) -> SegmentManifest {
        SegmentManifest {
            collector_id: "test".to_string(),
            stream: "updates".to_string(),
            start_ts: 0,
            end_ts: 1,
            record_count: 1,
            bytes: 1,
            sha256: "0".repeat(64),
            compression: CompressionKind::Gzip,
            layout_profile: LayoutProfile::RouteViews,
            relative_path: relative_path.to_string(),
        }
    }

    #[test]
    fn manifest_paths_must_stay_relative() {
        for path in [
            "/etc/passwd",
            "../escaped.gz",
            "a/../../escaped.gz",
            "..",
            "",
        ] {
            assert!(
                contained_relative_path(&manifest(path)).is_err(),
                "{path} must be refused"
            );
        }
        assert_eq!(
            contained_relative_path(&manifest("route-views2/bgpdata/updates.1700000000.gz"))
                .expect("a plain relative path is accepted"),
            PathBuf::from("route-views2/bgpdata/updates.1700000000.gz")
        );
    }

    /// The retry path re-reads the manifest from disk, so a queued manifest
    /// that was changed afterwards must not be able to write outside the
    /// replica root.
    #[test]
    fn copy_to_local_refuses_a_manifest_that_escapes_the_root() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let replica = temp.path().join("replica");
        let mut cfg = ArchiveConfig::default();
        cfg.destinations[0].path = Some(replica.clone());
        let destination = cfg.destinations[0].clone();
        assert!(
            matches!(destination.destination_type, DestinationType::Local),
            "the default destination is a local one"
        );
        let replicator = Replicator::new(
            &cfg,
            ReplicationQueue::new(&temp.path().join("queue"))?,
            None,
        );

        let segment = temp.path().join("updates.1700000000.gz");
        fs::write(&segment, b"segment")?;
        let job = ReplicationJob {
            id: 1,
            segment_path: segment,
            manifest_path: temp.path().join("manifest.json"),
            destination_key: destination.destination_key(),
            attempts: 1,
            max_retries: 3,
        };

        let error = replicator
            .copy_to_local(&destination, &job, &manifest("../escaped.gz"))
            .expect_err("a path leaving the replica root must be refused");
        assert!(
            error.to_string().contains("not a plain relative path"),
            "{error}"
        );
        assert!(
            !temp.path().join("escaped.gz").exists(),
            "nothing may be written outside the replica root"
        );
        Ok(())
    }
}
