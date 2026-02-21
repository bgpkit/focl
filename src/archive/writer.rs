use std::fs::{self, File};
use std::io::{BufWriter, Write};

use anyhow::{Context, Result};
use bzip2::write::BzEncoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::archive::manifest::SegmentManifest;
use crate::archive::types::{ArchiveStream, FinalizedSegment, SegmentPaths};
use crate::config::{ArchiveConfig, CompressionKind};

enum SegmentEncoder {
    Gzip(GzEncoder<BufWriter<File>>),
    Bzip2(BzEncoder<BufWriter<File>>),
    Zstd(ZstdEncoder<'static, BufWriter<File>>),
}

impl SegmentEncoder {
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match self {
            SegmentEncoder::Gzip(writer) => writer.write_all(buf)?,
            SegmentEncoder::Bzip2(writer) => writer.write_all(buf)?,
            SegmentEncoder::Zstd(writer) => writer.write_all(buf)?,
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            SegmentEncoder::Gzip(writer) => writer.flush()?,
            SegmentEncoder::Bzip2(writer) => writer.flush()?,
            SegmentEncoder::Zstd(writer) => writer.flush()?,
        }
        Ok(())
    }

    fn finish(mut self) -> Result<File> {
        self.flush()?;
        let file = match self {
            SegmentEncoder::Gzip(writer) => writer
                .finish()
                .context("failed to finish gzip stream")?
                .into_inner()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            SegmentEncoder::Bzip2(writer) => writer
                .finish()
                .context("failed to finish bzip2 stream")?
                .into_inner()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            SegmentEncoder::Zstd(writer) => writer
                .finish()
                .context("failed to finish zstd stream")?
                .into_inner()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        };
        Ok(file)
    }
}

pub struct SegmentWriter {
    cfg: ArchiveConfig,
    stream: ArchiveStream,
    start_ts: i64,
    paths: SegmentPaths,
    encoder: SegmentEncoder,
    record_count: u64,
}

impl SegmentWriter {
    pub fn new(
        cfg: &ArchiveConfig,
        stream: ArchiveStream,
        start_ts: i64,
        paths: SegmentPaths,
    ) -> Result<Self> {
        if let Some(parent) = paths.tmp_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create tmp directory {}", parent.display()))?;
        }
        if let Some(parent) = paths.final_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create final directory {}", parent.display())
            })?;
        }

        let file = File::create(&paths.tmp_path).with_context(|| {
            format!("failed to create tmp segment {}", paths.tmp_path.display())
        })?;
        let buffered = BufWriter::new(file);

        let encoder = match cfg.compression {
            CompressionKind::Gzip => {
                SegmentEncoder::Gzip(GzEncoder::new(buffered, Compression::default()))
            }
            CompressionKind::Bzip2 => {
                SegmentEncoder::Bzip2(BzEncoder::new(buffered, bzip2::Compression::default()))
            }
            CompressionKind::Zstd => {
                let enc = ZstdEncoder::new(buffered, 3).context("failed to create zstd encoder")?;
                SegmentEncoder::Zstd(enc)
            }
        };

        Ok(Self {
            cfg: cfg.clone(),
            stream,
            start_ts,
            paths,
            encoder,
            record_count: 0,
        })
    }

    pub fn write_record(&mut self, record: &[u8]) -> Result<()> {
        self.encoder.write_all(record)?;
        self.record_count += 1;
        Ok(())
    }

    pub fn path(&self) -> &std::path::Path {
        &self.paths.final_path
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    pub fn start_ts(&self) -> i64 {
        self.start_ts
    }

    pub fn finalize(self, end_ts: i64) -> Result<FinalizedSegment> {
        let file = self.encoder.finish()?;
        if self.cfg.fsync_on_rotate {
            file.sync_all().context("failed to fsync archive segment")?;
        }
        drop(file);

        fs::rename(&self.paths.tmp_path, &self.paths.final_path).with_context(|| {
            format!(
                "failed to atomically move {} to {}",
                self.paths.tmp_path.display(),
                self.paths.final_path.display()
            )
        })?;

        let manifest = SegmentManifest::build(
            self.cfg.collector_id.clone(),
            self.stream,
            self.start_ts,
            end_ts,
            self.record_count,
            self.cfg.compression,
            self.cfg.layout_profile,
            &self.paths.final_path,
            &self.paths.relative_path,
        )?;

        let manifest_path = manifest.write_sidecar(&self.paths.final_path)?;

        Ok(FinalizedSegment {
            stream: self.stream,
            start_ts: self.start_ts,
            end_ts,
            record_count: self.record_count,
            bytes: manifest.bytes,
            compression: self.cfg.compression,
            final_path: self.paths.final_path,
            relative_path: self.paths.relative_path,
            manifest_path,
        })
    }
}
