use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use fee1dead::config::Config;
use fee1dead::pipeline::{self, Pipeline};

#[derive(Parser)]
#[command(
    name = "fee1dead",
    about = "AI-CLI-agnostic vulnerability discovery harness"
)]
struct Cli {
    /// Path to the harness config TOML.
    #[arg(short, long, global = true, default_value = "config/harness.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the pipeline stages listed in the config.
    Run {
        /// Continue the last run in `run.out_dir`: skip recon and keep every
        /// artifact, so hunt picks up the tasks left unprocessed.
        #[arg(long)]
        resume: bool,
    },
    /// Validate a config, printing the resolved stages.
    Check,
    /// Print the firewall allow-list, one host per line, for init-firewall.sh.
    FirewallHosts,
    /// Acquire the target and run its `[target].setup` script; the container
    /// entrypoint runs this as root before the firewall comes up.
    Setup,
    /// Compile a finished or partial run into findings.json, with no agent.
    Aggregate {
        /// Read artifacts here instead of `run.out_dir`, e.g. the host's
        /// `./out` when the config names the container's `/work/out`.
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
    let cfg = Config::load(&cli.config)?;
    match cli.command {
        Command::Run { resume } => {
            let pipeline = Pipeline::new(cfg)?;
            if resume {
                pipeline.resume().await
            } else {
                pipeline.run().await
            }
        }
        Command::Check => {
            let stages: Vec<&str> = cfg.stages.enabled.iter().map(|s| s.name()).collect();
            println!(
                "config OK: provider={}, stages={}",
                cfg.provider.default,
                stages.join(" -> ")
            );
            Ok(())
        }
        Command::FirewallHosts => {
            for host in &cfg.firewall.allow {
                println!("{host}");
            }
            Ok(())
        }
        Command::Setup => fee1dead::target::run_setup(&cfg),
        Command::Aggregate { out_dir } => {
            pipeline::aggregate_dir(out_dir.unwrap_or(cfg.run.out_dir))
        }
    }
}
