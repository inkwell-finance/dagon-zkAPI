//! Standalone `dagon-zkapi-indexerd` binary.
//!
//! Mirrors the same functionality as `dagon-zkapi indexer`, but as a first-class
//! daemon binary so it can be packaged into its own container image (Week 9).

use clap::Parser;
use zkapi_indexerd::{run_indexer, IndexerConfig, IndexerLedger, PollerConfig, SolanaPollerConfig};

#[derive(Debug, Parser)]
#[command(
    name = "dagon-zkapi-indexerd",
    about = "Dagon zkAPI ledger indexer daemon"
)]
struct Args {
    /// HTTP listen address.
    #[arg(long, default_value = "0.0.0.0:3001")]
    listen: String,
    /// Ledger backend: `solana` (production) or `ethereum` (compatibility).
    #[arg(long, default_value = "solana")]
    ledger: String,
    /// JSON-RPC endpoint to poll.
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,
    /// Compatibility Ethereum ZkApiVault contract address (0x-prefixed).
    #[arg(long)]
    contract_address: Option<String>,
    /// Dagon zkAPI Solana program ID.
    #[arg(long)]
    program_id: Option<String>,
    /// Dagon zkAPI Solana vault-state PDA.
    #[arg(long)]
    vault_state: Option<String>,
    /// First block to scan from on a fresh start.
    #[arg(long, default_value_t = 0)]
    from_block: u64,
    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    poll_interval_ms: u64,
    /// Path to persist the last-processed-block cursor across restarts.
    #[arg(long)]
    cursor_path: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let ledger = match args.ledger.as_str() {
        "solana" => IndexerLedger::Solana(SolanaPollerConfig {
            rpc_url: args.rpc_url,
            program_id: args
                .program_id
                .ok_or_else(|| anyhow::anyhow!("--program-id is required for Solana"))?,
            vault_state: args
                .vault_state
                .ok_or_else(|| anyhow::anyhow!("--vault-state is required for Solana"))?,
        }),
        "ethereum" | "evm" => IndexerLedger::Ethereum(PollerConfig {
            rpc_url: args.rpc_url,
            contract_address: args.contract_address.ok_or_else(|| {
                anyhow::anyhow!("--contract-address is required for Ethereum compatibility")
            })?,
            from_block: args.from_block,
            cursor_path: args.cursor_path,
        }),
        other => anyhow::bail!("unsupported ledger backend `{other}`"),
    };
    run_indexer(IndexerConfig {
        listen_addr: args.listen,
        poll_interval_ms: args.poll_interval_ms,
        ledger,
    })
    .await
}
