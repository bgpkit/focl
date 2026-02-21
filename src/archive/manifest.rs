use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::archive::types::ArchiveStream;
use crate::config::CompressionKind;
use crate::config::LayoutProfile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentManifest {
    pub collector_id: String,
    pub stream: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub record_count: u64,
    pub bytes: u64,
    pub sha256: String,
    pub compression: CompressionKind,
    pub layout_profile: LayoutProfile,
    pub relative_path: String,
}

impl SegmentManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        collector_id: impl Into<String>,
        stream: ArchiveStream,
        start_ts: i64,
        end_ts: i64,
        record_count: u64,
        compression: CompressionKind,
        layout_profile: LayoutProfile,
        segment_path: &Path,
        relative_path: &Path,
    ) -> Result<Self> {
        let metadata = fs::metadata(segment_path)
            .with_context(|| format!("failed to stat segment {}", segment_path.display()))?;
        let bytes = metadata.len();

        let sha256 = compute_sha256(segment_path)?;

        Ok(Self {
            collector_id: collector_id.into(),
            stream: stream.as_str().to_string(),
            start_ts,
            end_ts,
            record_count,
            bytes,
            sha256,
            compression,
            layout_profile,
            relative_path: relative_path.to_string_lossy().to_string(),
        })
    }

    pub fn write_sidecar(&self, segment_path: &Path) -> Result<PathBuf> {
        let manifest_path = PathBuf::from(format!("{}.json", segment_path.display()));
        let json = serde_json::to_vec_pretty(self)?;
        fs::write(&manifest_path, json)
            .with_context(|| format!("failed to write manifest {}", manifest_path.display()))?;
        Ok(manifest_path)
    }
}

fn compute_sha256(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open segment for hashing {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("failed reading {} for hashing", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CompressionKind, LayoutProfile};

    #[test]
    fn writes_manifest_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("updates.20260221.1200.gz");
        fs::write(&segment, b"test-bytes").unwrap();

        let manifest = SegmentManifest::build(
            "focl01",
            ArchiveStream::Updates,
            100,
            200,
            3,
            CompressionKind::Gzip,
            LayoutProfile::RouteViews,
            &segment,
            Path::new("focl01/2026.02/UPDATES/updates.20260221.1200.gz"),
        )
        .unwrap();

        let path = manifest.write_sidecar(&segment).unwrap();
        assert!(path.exists());
    }
}
