//! Operator-run v2 challenge daemon; see docs/challenge-service.md.
use anyhow::Context;
use clap::Parser;
use dagon_zkapi_profile::{NetworkIdentity, SharedProfile};
use dagon_zkapi_solana_ledger::{SolanaCreditLedger, SolanaLedgerConfig};
use solana_keypair::read_keypair_file;
use std::{path::PathBuf, sync::Arc, time::Duration};
use zkapi_serverd::{
    ledger_challenge_service::{
        LedgerChallengeService, LedgerChallengeServiceConfig, SolanaKeypairTransactionSigner,
    },
    nullifier_store::NullifierStore,
};

#[derive(Parser)]
#[command(
    name = "dagon-zkapi-challenged",
    about = "Defeat stale escapes and raise under-conceded escapes on the Solana vault using the \
             v2 server evidence database"
)]
struct Args {
    /// Network identity file (genesis hash, vault, treasury token account).
    #[arg(long, env = "ZKAPI_SOLANA_IDENTITY")]
    solana_identity: PathBuf,
    /// Solana JSON-RPC endpoint of the identity's cluster (may carry an API key).
    #[arg(long, env = "SOLANA_RPC_URL", hide_env_values = true)]
    solana_rpc_url: String,
    /// JSON keypair file for the dedicated challenge/rent payer.
    #[arg(long, env = "ZKAPI_CHALLENGE_SOLANA_KEYPAIR")]
    solana_keypair: PathBuf,
    /// The server's transcript database (read for request evidence).
    #[arg(long)]
    db_path: PathBuf,
    /// Durable challenge checkpoint; a sibling `.lock` file guards it.
    #[arg(long)]
    checkpoint: PathBuf,
    /// Directory containing the v2 Groth16 request verifying key.
    #[arg(long)]
    proof_setup_dir: PathBuf,
    #[arg(long, default_value_t = 1000)]
    poll_interval_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    anyhow::ensure!(args.poll_interval_ms > 0, "poll interval must be positive");
    let profile = SharedProfile::embedded();
    let identity_file = NetworkIdentity::load(&args.solana_identity)?;
    let identity = identity_file.resolve(profile)?;
    let keypair = read_keypair_file(&args.solana_keypair)
        .map_err(|error| anyhow::anyhow!("failed to read Solana challenge keypair: {error}"))?;
    // Defeat and raise need no Merkle path, so no indexer is involved.
    let ledger = Arc::new(SolanaCreditLedger::new(SolanaLedgerConfig::from_identity(
        args.solana_rpc_url,
        None,
        identity_file.network,
        profile,
        &identity,
    ))?);
    ledger.assert_profile_deployment(profile, &identity).await?;
    anyhow::ensure!(
        args.db_path.is_file(),
        "server transcript database does not exist"
    );
    if let Some(parent) = args
        .checkpoint
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(args.checkpoint.with_extension("lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("another challenge daemon holds this checkpoint")?;
    let store = Arc::new(NullifierStore::new(&args.db_path)?);
    let signer = Arc::new(SolanaKeypairTransactionSigner::new(keypair));
    let mut service = LedgerChallengeService::new(
        LedgerChallengeServiceConfig {
            checkpoint: args.checkpoint,
            proof_setup_dir: args.proof_setup_dir,
            raise_lead_seconds: profile.server.raise_lead_seconds,
        },
        store,
        ledger,
        signer,
    )?;
    let mut ticker = tokio::time::interval(Duration::from_millis(args.poll_interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = ticker.tick() => if let Err(error) = service.poll_once().await {
                tracing::error!(error = %error, "Solana challenge poll failed; durable work will retry");
            }
        }
    }
}
