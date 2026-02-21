use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use chrono::{Datelike, TimeZone, Timelike, Utc};

use crate::archive::types::{ArchiveStream, SegmentPaths};
use crate::config::{ArchiveConfig, LayoutProfile};

pub fn aligned_epoch(timestamp: i64, interval_secs: u32) -> i64 {
    let interval = interval_secs as i64;
    timestamp - (timestamp.rem_euclid(interval))
}

pub fn segment_paths(
    cfg: &ArchiveConfig,
    stream: ArchiveStream,
    timestamp: i64,
) -> Result<SegmentPaths> {
    let aligned = match stream {
        ArchiveStream::Updates => aligned_epoch(timestamp, cfg.updates_interval_secs),
        ArchiveStream::Ribs => aligned_epoch(timestamp, cfg.ribs_interval_secs),
    };

    let dt = Utc
        .timestamp_opt(aligned, 0)
        .single()
        .ok_or_else(|| anyhow::anyhow!("invalid timestamp {aligned}"))?;

    let year_month = format!("{:04}.{:02}", dt.year(), dt.month());
    let yyyymmdd = format!("{:04}{:02}{:02}", dt.year(), dt.month(), dt.day());
    let hhmm = format!("{:02}{:02}", dt.hour(), dt.minute());

    let ext = cfg.compression.extension();

    let relative_path = match cfg.layout_profile {
        LayoutProfile::RouteViews => match stream {
            ArchiveStream::Updates => PathBuf::from(format!(
                "{}/{}/UPDATES/updates.{}.{}.{}",
                cfg.collector_id, year_month, yyyymmdd, hhmm, ext
            )),
            ArchiveStream::Ribs => PathBuf::from(format!(
                "{}/{}/RIBS/rib.{}.{}.{}",
                cfg.collector_id, year_month, yyyymmdd, hhmm, ext
            )),
        },
        LayoutProfile::Ris => match stream {
            ArchiveStream::Updates => PathBuf::from(format!(
                "{}/{}/updates.{}.{}.{}",
                cfg.collector_id, year_month, yyyymmdd, hhmm, ext
            )),
            ArchiveStream::Ribs => PathBuf::from(format!(
                "{}/{}/bview.{}.{}.{}",
                cfg.collector_id, year_month, yyyymmdd, hhmm, ext
            )),
        },
        LayoutProfile::Custom => {
            let templates = cfg.custom_templates.as_ref().ok_or_else(|| {
                anyhow::anyhow!("custom layout profile requires archive.custom_templates")
            })?;
            let template = match stream {
                ArchiveStream::Updates => &templates.updates,
                ArchiveStream::Ribs => &templates.ribs,
            };
            build_custom_relative_path(
                template,
                &cfg.collector_id,
                dt.year(),
                dt.month(),
                dt.day(),
                dt.hour(),
                dt.minute(),
                ext,
            )?
        }
    };

    let final_path = cfg.root.join(&relative_path);
    let tmp_relative = if let Some(file_name) = relative_path.file_name() {
        let tmp_file = format!(
            ".{}.tmp",
            file_name
                .to_string_lossy()
                .trim_start_matches('.')
                .replace('/', "_")
        );
        let mut p = relative_path.clone();
        p.set_file_name(tmp_file);
        p
    } else {
        bail!("cannot derive temporary file name for archive segment");
    };

    let tmp_path = cfg.tmp_root.join(tmp_relative);

    Ok(SegmentPaths {
        tmp_path,
        final_path,
        relative_path,
    })
}

fn build_custom_relative_path(
    template: &str,
    collector: &str,
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    ext: &str,
) -> Result<PathBuf> {
    if !template.contains("{collector}")
        || !template.contains("{yyyymmdd}")
        || !template.contains("{hhmm}")
    {
        bail!("custom template must contain {{collector}}, {{yyyymmdd}}, and {{hhmm}} tokens");
    }

    let yyyymmdd = format!("{:04}{:02}{:02}", year, month, day);
    let hhmm = format!("{:02}{:02}", hour, minute);

    let rendered = template
        .replace("{collector}", collector)
        .replace("{yyyy}", &format!("{:04}", year))
        .replace("{mm}", &format!("{:02}", month))
        .replace("{dd}", &format!("{:02}", day))
        .replace("{yyyymmdd}", &yyyymmdd)
        .replace("{hhmm}", &hhmm)
        .replace("{ext}", ext);

    let mut path = PathBuf::from(rendered);
    if Path::new(&path)
        .extension()
        .and_then(|e| e.to_str())
        .is_none()
    {
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("custom template did not produce file name"))?
            .to_string_lossy();
        path.set_file_name(format!("{}.{}", file_name, ext));
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ArchiveConfig, LayoutProfile};

    #[test]
    fn routeviews_layout_matches_expected_convention() {
        let cfg = ArchiveConfig {
            enabled: true,
            collector_id: "focl01".to_string(),
            ..ArchiveConfig::default()
        };
        let ts = Utc
            .with_ymd_and_hms(2026, 2, 21, 13, 43, 0)
            .unwrap()
            .timestamp();
        let paths = segment_paths(&cfg, ArchiveStream::Updates, ts).unwrap();
        assert_eq!(
            paths.relative_path.to_string_lossy(),
            "focl01/2026.02/UPDATES/updates.20260221.1330.gz"
        );
    }

    #[test]
    fn ris_layout_matches_expected_convention() {
        let cfg = ArchiveConfig {
            enabled: true,
            layout_profile: LayoutProfile::Ris,
            collector_id: "rrc00".to_string(),
            ..ArchiveConfig::default()
        };
        let ts = Utc
            .with_ymd_and_hms(2026, 2, 21, 13, 43, 0)
            .unwrap()
            .timestamp();
        let paths = segment_paths(&cfg, ArchiveStream::Ribs, ts).unwrap();
        assert_eq!(
            paths.relative_path.to_string_lossy(),
            "rrc00/2026.02/bview.20260221.1200.gz"
        );
    }

    #[test]
    fn custom_layout_uses_tokens() {
        let mut cfg = ArchiveConfig {
            enabled: true,
            layout_profile: LayoutProfile::Custom,
            ..ArchiveConfig::default()
        };
        cfg.custom_templates = Some(crate::config::CustomLayoutTemplates {
            updates: "{collector}/{yyyy}/{mm}/updates.{yyyymmdd}.{hhmm}.{ext}".to_string(),
            ribs: "{collector}/{yyyy}/{mm}/ribs.{yyyymmdd}.{hhmm}.{ext}".to_string(),
        });

        let ts = Utc
            .with_ymd_and_hms(2026, 2, 21, 13, 43, 0)
            .unwrap()
            .timestamp();
        let paths = segment_paths(&cfg, ArchiveStream::Updates, ts).unwrap();
        assert_eq!(
            paths.relative_path.to_string_lossy(),
            "focl01/2026/02/updates.20260221.1330.gz"
        );
    }

    #[test]
    fn aligns_epoch_boundaries() {
        assert_eq!(aligned_epoch(1_700_000_001, 900), 1_699_999_200);
    }
}
