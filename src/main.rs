//! fee1dead CLI entry point.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use fee1dead::config::Config;
use fee1dead::pipeline::Pipeline;

#[derive(Parser)]
#[command(
    name = "fee1dead",
    about = "AI-CLI-agnostic vulnerability discovery harness"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the pipeline stages listed in the config.
    Run {
        /// Path to the harness config TOML.
        #[arg(short, long, default_value = "config/harness.toml")]
        config: PathBuf,
    },
    /// Parse and validate a config, printing the resolved stages.
    Check {
        #[arg(short, long, default_value = "config/harness.toml")]
        config: PathBuf,
    },
    /// Print the firewall allow-list (one host per line) for init-firewall.sh.
    FirewallHosts {
        #[arg(short, long, default_value = "config/harness.toml")]
        config: PathBuf,
    },
    /// Compile a finished or partial run's hunter output into one reviewable
    /// findings.json, without running any agent. Use after a run that spent its
    /// token budget before the review stages.
    Aggregate {
        #[arg(short, long, default_value = "config/harness.toml")]
        config: PathBuf,
        /// Read artifacts from this directory instead of the config's
        /// `run.out_dir`. Use when the config points at a container path (e.g.
        /// `/work/out`) but the artifacts are on the host (e.g. `./out`).
        #[arg(short, long)]
        out_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run { config } => {
            let cfg = Config::load(&config)?;
            let pipeline = Pipeline::new(cfg)?;
            pipeline.run().await
        }
        Command::Check { config } => {
            let cfg = Config::load(&config)?;
            println!(
                "config OK: provider={}, stages={}",
                cfg.provider.default,
                cfg.stages.enabled.join(" -> ")
            );
            Ok(())
        }
        Command::FirewallHosts { config } => {
            let cfg = Config::load(&config)?;
            for host in &cfg.firewall.allow {
                println!("{host}");
            }
            Ok(())
        }
        Command::Aggregate { config, out_dir } => {
            let cfg = Config::load(&config)?;
            let dir = out_dir.unwrap_or_else(|| cfg.run.out_dir.clone());
            fee1dead::pipeline::aggregate_dir(&dir)
        }
    }
}
