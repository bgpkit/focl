use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use focl::types::{ControlRequest, ControlResponse};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Debug, Parser)]
#[command(name = "focl", about = "CLI for focld control plane")]
struct Cli {
    #[arg(long, default_value = "/tmp/focld.sock")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Start {
        #[arg(short, long, default_value = "focl.toml")]
        config: PathBuf,
    },
    Stop,
    Reload,
    Archive {
        #[command(subcommand)]
        command: ArchiveCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ArchiveCommands {
    Status,
    Rollover {
        #[arg(long, value_parser = ["updates", "ribs"])]
        stream: String,
    },
    Snapshot,
    Destinations,
    Retry,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => {
            let focld_bin = locate_focld_binary()?;
            let child = std::process::Command::new(focld_bin)
                .arg("--config")
                .arg(config)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("failed spawning focld")?;
            println!("{{\"started\":true,\"pid\":{}}}", child.id());
        }
        Commands::Stop => {
            let response = send_control_request(&cli.socket, "shutdown", json!({})).await?;
            print_response(response);
        }
        Commands::Reload => {
            let response = send_control_request(&cli.socket, "reload", json!({})).await?;
            print_response(response);
        }
        Commands::Archive { command } => match command {
            ArchiveCommands::Status => {
                let response =
                    send_control_request(&cli.socket, "archive_status", json!({})).await?;
                print_response(response);
            }
            ArchiveCommands::Rollover { stream } => {
                let response = send_control_request(
                    &cli.socket,
                    "archive_rollover",
                    json!({"stream": stream}),
                )
                .await?;
                print_response(response);
            }
            ArchiveCommands::Snapshot => {
                let response =
                    send_control_request(&cli.socket, "archive_snapshot_now", json!({})).await?;
                print_response(response);
            }
            ArchiveCommands::Destinations => {
                let response =
                    send_control_request(&cli.socket, "archive_destinations", json!({})).await?;
                print_response(response);
            }
            ArchiveCommands::Retry => {
                let response =
                    send_control_request(&cli.socket, "archive_replicator_retry", json!({}))
                        .await?;
                print_response(response);
            }
        },
    }

    Ok(())
}

fn locate_focld_binary() -> Result<PathBuf> {
    let current = std::env::current_exe().context("failed resolving current executable")?;
    let sibling = current.with_file_name("focld");
    if sibling.exists() {
        return Ok(sibling);
    }
    Ok(PathBuf::from("focld"))
}

async fn send_control_request(
    socket: &PathBuf,
    cmd: &str,
    args: serde_json::Value,
) -> Result<ControlResponse> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("failed connecting to {}", socket.display()))?;

    let req = ControlRequest {
        version: 1,
        id: uuid_like_id(),
        cmd: cmd.to_string(),
        args,
    };

    let payload = serde_json::to_string(&req)?;
    stream.write_all(payload.as_bytes()).await?;
    stream.write_all(b"\n").await?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let response: ControlResponse = serde_json::from_str(line.trim_end())?;
    Ok(response)
}

fn uuid_like_id() -> String {
    format!(
        "req-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    )
}

fn print_response(response: ControlResponse) {
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
    );
}
