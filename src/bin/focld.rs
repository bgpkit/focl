use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use focl::archive::types::ArchiveStream;
use focl::archive::ArchiveService;
use focl::bgp::BgpService;
use focl::config::FoclConfig;
use focl::control::{ArchiveRolloverArgs, ArchiveStatusResult, CommandKind, PeerKeyArgs};
use focl::types::{ControlRequest, ControlResponse};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, default_value = "focl.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let cfg = FoclConfig::load(&args.config)?;
    init_tracing(&cfg.global.log_level);

    let collector_bgp_id = cfg
        .global
        .router_id
        .parse::<std::net::Ipv4Addr>()
        .context("global.router_id must be valid IPv4")?;

    let archive = ArchiveService::new(cfg.archive.clone(), collector_bgp_id).await?;
    let events_tx = archive.event_sender();
    let bgp = BgpService::new(&cfg, events_tx).await?;

    let socket_path = cfg.global.control_socket.clone();
    cleanup_socket(&socket_path)?;

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed binding control socket {}", socket_path.display()))?;

    tracing::info!(socket=%socket_path.display(), "focld started");

    let (shutdown_tx, _) = broadcast::channel::<()>(8);
    let mut shutdown_rx = shutdown_tx.subscribe();

    let accept_task = {
        let archive = Arc::clone(&archive);
        let bgp = bgp.clone();
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move { run_control_server(listener, archive, bgp, shutdown_tx).await })
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
        }
        _ = shutdown_rx.recv() => {
            tracing::info!("received shutdown command");
        }
    }

    let _ = shutdown_tx.send(());
    accept_task.abort();
    cleanup_socket(&socket_path)?;

    Ok(())
}

fn init_tracing(level: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .json()
        .init();
}

fn cleanup_socket(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("failed removing stale socket {}", path.display()))?;
    }
    Ok(())
}

async fn run_control_server(
    listener: UnixListener,
    archive: Arc<ArchiveService>,
    bgp: BgpService,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<()> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let archive = Arc::clone(&archive);
        let bgp = bgp.clone();
        let shutdown_tx = shutdown_tx.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, archive, bgp, shutdown_tx).await {
                tracing::warn!(error=%err, "control connection failed");
            }
        });
    }
}

async fn handle_client(
    stream: UnixStream,
    archive: Arc<ArchiveService>,
    bgp: BgpService,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            return Ok(());
        }

        let req = match serde_json::from_str::<ControlRequest>(line.trim_end()) {
            Ok(req) => req,
            Err(err) => {
                let resp = ControlResponse::err("unknown", "invalid_request", err.to_string());
                write_response(&mut write_half, &resp).await?;
                continue;
            }
        };

        let cmd = CommandKind::from_request(&req);
        let response = match cmd {
            CommandKind::Ping => ControlResponse::ok(req.id, json!({"pong": true})),
            CommandKind::DaemonStatus => {
                let status = archive.status().await?;
                let rib = bgp.rib_summary().await;
                ControlResponse::ok(
                    req.id,
                    json!({
                        "daemon": "focld",
                        "archive_enabled": status.enabled,
                        "queued_replication_jobs": status.queued_replication_jobs,
                        "peers_total": rib.peers_total,
                        "peers_established": rib.peers_established,
                    }),
                )
            }
            CommandKind::Reload => ControlResponse::ok(req.id, json!({"reloaded": true})),
            CommandKind::Shutdown => {
                let _ = shutdown_tx.send(());
                ControlResponse::ok(req.id, json!({"shutting_down": true}))
            }
            CommandKind::ArchiveStatus => {
                let status = archive.status().await?;
                let result = ArchiveStatusResult {
                    enabled: status.enabled,
                    collector_id: status.collector_id,
                    updates_interval_secs: status.updates_interval_secs,
                    ribs_interval_secs: status.ribs_interval_secs,
                    updates_open_path: status.updates_open_path.map(|p| p.display().to_string()),
                    updates_record_count: status.updates_record_count,
                    ribs_last_path: status.ribs_last_path.map(|p| p.display().to_string()),
                    ribs_last_record_count: status.ribs_last_record_count,
                    queued_replication_jobs: status.queued_replication_jobs,
                    replication_failures: status.replication_failures,
                };
                ControlResponse::ok(req.id, result.as_value())
            }
            CommandKind::ArchiveRollover => {
                let args = match ArchiveRolloverArgs::from_json(&req.args) {
                    Ok(args) => args,
                    Err(err) => {
                        let response = ControlResponse::err(
                            req.id,
                            "invalid_args",
                            format!("archive_rollover args error: {err}"),
                        );
                        write_response(&mut write_half, &response).await?;
                        continue;
                    }
                };
                if args.stream == focl::control::ArchiveStream::Updates {
                    archive.rollover(ArchiveStream::Updates).await?;
                } else {
                    archive.rollover(ArchiveStream::Ribs).await?;
                }
                ControlResponse::ok(req.id, json!({"ok": true}))
            }
            CommandKind::ArchiveSnapshotNow => {
                let snapshot = focl::archive::types::RibSnapshotInput {
                    timestamp: chrono::Utc::now().timestamp(),
                    collector_bgp_id: std::net::Ipv4Addr::UNSPECIFIED,
                    view_name: "main".to_string(),
                    peers: vec![],
                    routes: vec![],
                };
                let result = archive.snapshot_now(snapshot).await?;
                ControlResponse::ok(
                    req.id,
                    json!({
                        "path": result.final_path.display().to_string(),
                        "records": result.record_count,
                    }),
                )
            }
            CommandKind::ArchiveDestinations => {
                let rows = archive
                    .destinations()
                    .into_iter()
                    .map(|(key, mode, destination_type)| {
                        json!({"key": key, "mode": mode, "type": destination_type})
                    })
                    .collect::<Vec<_>>();
                ControlResponse::ok(req.id, json!({"destinations": rows}))
            }
            CommandKind::ArchiveReplicatorRetry => {
                let count = archive.retry_failed_replications().await?;
                ControlResponse::ok(req.id, json!({"retried_jobs": count}))
            }
            CommandKind::PeerList => {
                let peers = bgp.peer_list().await;
                ControlResponse::ok(req.id, json!({"peers": peers}))
            }
            CommandKind::PeerShow => {
                let args = match PeerKeyArgs::from_json(&req.args) {
                    Ok(args) => args,
                    Err(err) => {
                        let response = ControlResponse::err(
                            req.id,
                            "invalid_args",
                            format!("peer_show args error: {err}"),
                        );
                        write_response(&mut write_half, &response).await?;
                        continue;
                    }
                };
                match bgp.peer_show(&args.peer).await {
                    Some(peer) => ControlResponse::ok(req.id, json!({"peer": peer})),
                    None => ControlResponse::err(req.id, "peer_not_found", "peer not found"),
                }
            }
            CommandKind::PeerReset => {
                let args = match PeerKeyArgs::from_json(&req.args) {
                    Ok(args) => args,
                    Err(err) => {
                        let response = ControlResponse::err(
                            req.id,
                            "invalid_args",
                            format!("peer_reset args error: {err}"),
                        );
                        write_response(&mut write_half, &response).await?;
                        continue;
                    }
                };
                match bgp.peer_reset(&args.peer).await {
                    Ok(()) => ControlResponse::ok(req.id, json!({"reset": true})),
                    Err(err) => ControlResponse::err(req.id, "peer_reset_failed", err.to_string()),
                }
            }
            CommandKind::RibSummary => {
                let summary = bgp.rib_summary().await;
                ControlResponse::ok(req.id, json!({"summary": summary}))
            }
            CommandKind::RibIn => {
                let args = match PeerKeyArgs::from_json(&req.args) {
                    Ok(args) => args,
                    Err(err) => {
                        let response = ControlResponse::err(
                            req.id,
                            "invalid_args",
                            format!("rib_in args error: {err}"),
                        );
                        write_response(&mut write_half, &response).await?;
                        continue;
                    }
                };
                match bgp.rib_in(&args.peer).await {
                    Ok(prefixes) => ControlResponse::ok(
                        req.id,
                        json!({"peer": args.peer, "prefixes": prefixes}),
                    ),
                    Err(err) => ControlResponse::err(req.id, "rib_in_failed", err.to_string()),
                }
            }
            CommandKind::RibOut => {
                let args = match PeerKeyArgs::from_json(&req.args) {
                    Ok(args) => args,
                    Err(err) => {
                        let response = ControlResponse::err(
                            req.id,
                            "invalid_args",
                            format!("rib_out args error: {err}"),
                        );
                        write_response(&mut write_half, &response).await?;
                        continue;
                    }
                };
                match bgp.rib_out(&args.peer).await {
                    Ok(prefixes) => ControlResponse::ok(
                        req.id,
                        json!({"peer": args.peer, "prefixes": prefixes}),
                    ),
                    Err(err) => ControlResponse::err(req.id, "rib_out_failed", err.to_string()),
                }
            }
            CommandKind::Unsupported => {
                if req.cmd == "events_subscribe" {
                    let resp = ControlResponse::ok(req.id.clone(), json!({"subscribed": true}));
                    write_response(&mut write_half, &resp).await?;
                    let mut rx = archive.subscribe_events();
                    loop {
                        match rx.recv().await {
                            Ok(event) => {
                                let payload = serde_json::to_string(&event)?;
                                write_half.write_all(payload.as_bytes()).await?;
                                write_half.write_all(b"\n").await?;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                        }
                    }
                }

                ControlResponse::err(
                    req.id,
                    "unsupported_command",
                    format!("unsupported cmd: {}", req.cmd),
                )
            }
        };

        write_response(&mut write_half, &response).await?;
    }
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    response: &ControlResponse,
) -> Result<()> {
    let payload = serde_json::to_string(response)?;
    writer.write_all(payload.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}
