//! fee1dead CLI entry point.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use fee1dead::config::Config;
use fee1dead::pipeline::Pipeline;

#[derive(Parser)]
#[command(name = "fee1dead", about = "AI-CLI-agnostic vulnerability discovery harness")]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
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
    }
}
