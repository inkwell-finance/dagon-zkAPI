//! Standalone `dagon-zkapi-indexerd` binary, equivalent to `dagon-zkapi indexer`,
//! packaged as its own daemon image.

use clap::Parser;
use std::path::PathBuf;
use zkapi_indexerd::{run_indexer, IndexerConfig};

#[derive(Debug, Parser)]
#[command(
    name = "dagon-zkapi-indexerd",
    about = "Dagon zkAPI Solana vault tree indexer daemon"
)]
struct Args {
    /// Network identity file (genesis hash and vault).
    #[arg(long, env = "ZKAPI_SOLANA_IDENTITY")]
    solana_identity: PathBuf,
    /// Solana JSON-RPC endpoint of the identity's cluster (may carry an API key).
    #[arg(long, env = "SOLANA_RPC_URL", hide_env_values = true)]
    rpc_url: String,
    /// HTTP listen address.
    #[arg(long, default_value = "0.0.0.0:3001")]
    listen: String,
    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    poll_interval_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    run_indexer(IndexerConfig::from_identity_file(
        &args.solana_identity,
        args.rpc_url,
        args.listen,
        args.poll_interval_ms,
    )?)
    .await
}
