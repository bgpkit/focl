use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use focl::bgp::{PrefixMutation, PrefixSource, PrefixStatus, PrefixView};
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
    Peer {
        #[command(subcommand)]
        command: PeerCommands,
    },
    Rib {
        #[command(subcommand)]
        command: RibCommands,
    },
    /// Runtime announce/withdraw of originated prefixes (in-memory overrides;
    /// `reload` resets them to the config file)
    Prefix {
        #[command(subcommand)]
        command: PrefixCommands,
    },
    Archive {
        #[command(subcommand)]
        command: ArchiveCommands,
    },
}

#[derive(Debug, Subcommand)]
enum PeerCommands {
    List,
    Show { peer: String },
    Reset { peer: String },
}

#[derive(Debug, Subcommand)]
enum RibCommands {
    Summary,
    In { peer: String },
    Out { peer: String },
}

#[derive(Debug, Subcommand)]
enum PrefixCommands {
    /// Announce a prefix now (no session reset); also clears a suppression
    Add {
        /// Network in CIDR notation, e.g. 2620:aa:a000::/48
        network: String,
        /// Next hop for the announcement. Defaults to the configured next hop
        /// of the same family; otherwise IPv4 falls back to the router ID and
        /// IPv6 to the session's own address when that address is IPv6
        #[arg(long)]
        next_hop: Option<String>,
        /// Validate and report what would be sent without sending it
        #[arg(long)]
        dry_run: bool,
        /// Print the raw control response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Withdraw a prefix now: a configured prefix is suppressed, a
    /// runtime-only one is dropped
    Remove {
        /// Network in CIDR notation
        network: String,
        /// Validate and report what would be sent without sending it
        #[arg(long)]
        dry_run: bool,
        /// Print the raw control response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show the effective originated prefix set (config plus runtime overrides)
    List {
        /// Print the raw control response as JSON
        #[arg(long)]
        json: bool,
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
        Commands::Peer { command } => match command {
            PeerCommands::List => {
                let response = send_control_request(&cli.socket, "peer_list", json!({})).await?;
                print_response(response);
            }
            PeerCommands::Show { peer } => {
                let response =
                    send_control_request(&cli.socket, "peer_show", json!({"peer": peer})).await?;
                print_response(response);
            }
            PeerCommands::Reset { peer } => {
                let response =
                    send_control_request(&cli.socket, "peer_reset", json!({"peer": peer})).await?;
                print_response(response);
            }
        },
        Commands::Rib { command } => match command {
            RibCommands::Summary => {
                let response = send_control_request(&cli.socket, "rib_summary", json!({})).await?;
                print_response(response);
            }
            RibCommands::In { peer } => {
                let response =
                    send_control_request(&cli.socket, "rib_in", json!({"peer": peer})).await?;
                print_response(response);
            }
            RibCommands::Out { peer } => {
                let response =
                    send_control_request(&cli.socket, "rib_out", json!({"peer": peer})).await?;
                print_response(response);
            }
        },
        Commands::Prefix { command } => match command {
            PrefixCommands::Add {
                network,
                next_hop,
                dry_run,
                json,
            } => {
                let response = send_control_request(
                    &cli.socket,
                    "prefix_add",
                    json!({"network": network, "next_hop": next_hop, "dry_run": dry_run}),
                )
                .await?;
                finish_prefix_response(response, json)?;
            }
            PrefixCommands::Remove {
                network,
                dry_run,
                json,
            } => {
                let response = send_control_request(
                    &cli.socket,
                    "prefix_remove",
                    json!({"network": network, "dry_run": dry_run}),
                )
                .await?;
                finish_prefix_response(response, json)?;
            }
            PrefixCommands::List { json } => {
                let response = send_control_request(&cli.socket, "prefix_list", json!({})).await?;
                if json {
                    print_response(response);
                } else {
                    fail_on_error(&response)?;
                    print_prefix_list(&response)?;
                }
            }
        },
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

/// Prints the raw control response. `--json` changes formatting only: a failed
/// response still exits non-zero so scripts can detect it.
fn print_response(response: ControlResponse) {
    let ok = response.ok;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
    );
    if !ok {
        std::process::exit(1);
    }
}

fn fail_on_error(response: &ControlResponse) -> Result<()> {
    if response.ok {
        return Ok(());
    }
    match &response.error {
        Some(error) => eprintln!("error: {} ({})", error.message, error.code),
        None => eprintln!("error: control request failed"),
    }
    std::process::exit(1);
}

/// One-line result for `prefix add` / `prefix remove`, or the raw response
/// with `--json`.
fn finish_prefix_response(response: ControlResponse, json: bool) -> Result<()> {
    if json {
        print_response(response);
        return Ok(());
    }
    fail_on_error(&response)?;
    let mutation: PrefixMutation = serde_json::from_value(response.result.unwrap_or_default())?;
    let peers = mutation.peers_notified.len();
    let peer_list = if mutation.peers_notified.is_empty() {
        String::new()
    } else {
        format!(": {}", mutation.peers_notified.join(", "))
    };
    if mutation.dry_run {
        if mutation.changed {
            println!(
                "dry-run: would {} {} ({}) to {} established peer(s){}",
                mutation.action, mutation.network, mutation.family, peers, peer_list
            );
        } else {
            println!(
                "dry-run: no change for {} ({})",
                mutation.network, mutation.family
            );
        }
    } else if mutation.changed {
        let verb = if mutation.action == "announce" {
            "announced"
        } else {
            "withdrew"
        };
        println!(
            "{} {} ({}) to {} established peer(s){}",
            verb, mutation.network, mutation.family, peers, peer_list
        );
    } else {
        println!(
            "no change: {} ({}) is already {}",
            mutation.network,
            mutation.family,
            status_word(mutation.status)
        );
    }
    Ok(())
}

fn print_prefix_list(response: &ControlResponse) -> Result<()> {
    let result = response.result.clone().unwrap_or_default();
    let prefixes: Vec<PrefixView> =
        serde_json::from_value(result.get("prefixes").cloned().unwrap_or_default())?;
    if prefixes.is_empty() {
        println!("no originated prefixes");
        return Ok(());
    }
    let network_width = prefixes
        .iter()
        .map(|prefix| prefix.network.len())
        .max()
        .unwrap_or(0)
        .max("NETWORK".len());
    println!(
        "{:<network_width$}  {:<6}  {:<10}  {:<7}  NEXT HOP",
        "NETWORK", "FAMILY", "STATUS", "SOURCE"
    );
    for prefix in prefixes {
        println!(
            "{:<network_width$}  {:<6}  {:<10}  {:<7}  {}",
            prefix.network,
            prefix.family,
            status_word(prefix.status),
            source_word(prefix.source),
            prefix.next_hop.unwrap_or_else(|| "-".to_string())
        );
    }
    Ok(())
}

fn status_word(status: PrefixStatus) -> &'static str {
    match status {
        PrefixStatus::Announced => "announced",
        PrefixStatus::Suppressed => "suppressed",
        PrefixStatus::Absent => "absent",
    }
}

fn source_word(source: PrefixSource) -> &'static str {
    match source {
        PrefixSource::Config => "config",
        PrefixSource::Runtime => "runtime",
    }
}
