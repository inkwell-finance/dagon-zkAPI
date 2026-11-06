//! Operator-run v2 challenge daemon; see docs/challenge-service.md.
use anyhow::{bail, Context};
use clap::{Parser, ValueEnum};
use dagon_zkapi_solana_ledger::{SolanaCreditLedger, SolanaLedgerConfig};
use solana_keypair::read_keypair_file;
use std::{path::PathBuf, sync::Arc, time::Duration};
use zkapi_serverd::{
    challenge_service::{ChallengeService, ChallengeServiceConfig},
    ledger_challenge_service::{
        LedgerChallengeService, LedgerChallengeServiceConfig, SolanaKeypairTransactionSigner,
    },
    nullifier_store::NullifierStore,
};
use zkapi_types::Felt252;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum ChallengeLedger {
    #[default]
    Solana,
    Evm,
}

#[derive(Parser)]
#[command(
    name = "dagon-zkapi-challenged",
    about = "Defeat stale escapes and raise under-conceded escapes using the v2 server evidence database"
)]
struct Args {
    /// Production defaults to the Solana Groth16 ledger. EVM is compatibility-only.
    #[arg(long, value_enum, default_value_t = ChallengeLedger::Solana)]
    ledger: ChallengeLedger,

    #[arg(long, env = "ZKAPI_CHALLENGE_SOLANA_RPC_URL")]
    solana_rpc_url: Option<String>,
    #[arg(long, env = "ZKAPI_CHALLENGE_SOLANA_PROGRAM_ID")]
    solana_program_id: Option<String>,
    #[arg(long, env = "ZKAPI_CHALLENGE_SOLANA_VAULT_STATE")]
    solana_vault_state: Option<String>,
    #[arg(long, env = "ZKAPI_CHALLENGE_SOLANA_GENESIS_HASH")]
    solana_genesis_hash: Option<String>,
    #[arg(long, env = "ZKAPI_CHALLENGE_SOLANA_NETWORK")]
    solana_network: Option<String>,
    /// JSON keypair file for the dedicated challenge/rent payer.
    #[arg(long, env = "ZKAPI_CHALLENGE_SOLANA_KEYPAIR")]
    solana_keypair: Option<PathBuf>,

    /// Compatibility EVM RPC supporting eth_sendTransaction for --sender.
    #[arg(long, env = "ZKAPI_CHALLENGE_RPC_URL")]
    rpc_url: Option<String>,
    /// Dedicated EVM gas-paying account managed by the configured signer RPC.
    #[arg(long, env = "ZKAPI_CHALLENGE_SENDER")]
    sender: Option<String>,
    #[arg(long)]
    contract_address: Option<String>,
    #[arg(long)]
    chain_id: Option<u64>,
    /// EVM vault deployment block; never start at the current head on a restart.
    #[arg(long)]
    from_block: Option<u64>,
    #[arg(long, default_value_t = 2)]
    confirmations: u64,

    #[arg(long)]
    db_path: PathBuf,
    #[arg(long)]
    checkpoint: PathBuf,
    #[arg(long)]
    proof_setup_dir: PathBuf,
    #[arg(long, default_value_t = 1000)]
    poll_interval_ms: u64,
    /// Raise an unsettled, possibly delivered request to its solvency bound
    /// this many seconds before the escape deadline. The server's startup
    /// timing check uses the same value.
    #[arg(long, default_value_t = 3_600)]
    raise_lead_seconds: u64,
    /// EVM only: the signer's gas price cap. Fee bumps for a nonce that may
    /// hold an earlier transaction never exceed it.
    #[arg(long, env = "ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI", default_value_t = 10_000_000_000)]
    max_gas_price_wei: u128,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    anyhow::ensure!(args.poll_interval_ms > 0, "poll interval must be positive");
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
    let interval = Duration::from_millis(args.poll_interval_ms);

    match args.ledger {
        ChallengeLedger::Solana => run_solana(args, store, interval).await,
        ChallengeLedger::Evm => run_evm(args, store, interval).await,
    }
}

async fn run_solana(
    args: Args,
    store: Arc<NullifierStore>,
    interval: Duration,
) -> anyhow::Result<()> {
    reject_evm_options(&args)?;
    let config = SolanaLedgerConfig {
        rpc_url: required(&args.solana_rpc_url, "--solana-rpc-url")?.clone(),
        // Defeat and raise need no Merkle path, so no indexer is involved.
        indexer_url: None,
        network: required(&args.solana_network, "--solana-network")?.clone(),
        program_id: base58_identity(
            "Solana program ID",
            required(&args.solana_program_id, "--solana-program-id")?,
        )?,
        vault_state: base58_identity(
            "Solana vault state",
            required(&args.solana_vault_state, "--solana-vault-state")?,
        )?,
        genesis_hash: base58_identity(
            "Solana genesis hash",
            required(&args.solana_genesis_hash, "--solana-genesis-hash")?,
        )?,
    };
    let keypair_path = required(&args.solana_keypair, "--solana-keypair")?;
    let keypair = read_keypair_file(keypair_path)
        .map_err(|error| anyhow::anyhow!("failed to read Solana challenge keypair: {error}"))?;
    let ledger = Arc::new(SolanaCreditLedger::new(config)?);
    ledger.assert_immutable_program().await?;
    ledger.finalized_vault().await?;
    let signer = Arc::new(SolanaKeypairTransactionSigner::new(keypair));
    let mut service = LedgerChallengeService::new(
        LedgerChallengeServiceConfig {
            checkpoint: args.checkpoint,
            proof_setup_dir: args.proof_setup_dir,
            raise_lead_seconds: args.raise_lead_seconds,
        },
        store,
        ledger,
        signer,
    )?;
    poll_ledger_service(&mut service, interval).await
}

async fn run_evm(args: Args, store: Arc<NullifierStore>, interval: Duration) -> anyhow::Result<()> {
    reject_solana_options(&args)?;
    let config = ChallengeServiceConfig {
        rpc_url: required(&args.rpc_url, "--rpc-url")?.clone(),
        sender: required(&args.sender, "--sender")?.clone(),
        contract_address: Felt252::from_hex(required(
            &args.contract_address,
            "--contract-address",
        )?)
        .map_err(anyhow::Error::msg)?,
        chain_id: *required(&args.chain_id, "--chain-id")?,
        from_block: *required(&args.from_block, "--from-block")?,
        confirmations: args.confirmations,
        checkpoint: args.checkpoint,
        proof_setup_dir: args.proof_setup_dir,
        raise_lead_seconds: args.raise_lead_seconds,
        max_gas_price_wei: args.max_gas_price_wei,
    };
    let mut service = ChallengeService::new(config, store)?;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = ticker.tick() => if let Err(error) = service.poll_once().await {
                tracing::error!(error = %error, "EVM challenge poll failed; durable work will retry");
            }
        }
    }
}

async fn poll_ledger_service(
    service: &mut LedgerChallengeService,
    interval: Duration,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(interval);
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

fn required<'a, T>(value: &'a Option<T>, flag: &str) -> anyhow::Result<&'a T> {
    value
        .as_ref()
        .with_context(|| format!("{flag} is required for the selected challenge ledger"))
}

fn base58_identity(label: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = bs58::decode(value)
        .into_vec()
        .with_context(|| format!("invalid {label}"))?;
    let identity: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must encode exactly 32 bytes"))?;
    anyhow::ensure!(identity != [0; 32], "{label} cannot be zero");
    Ok(identity)
}

fn reject_evm_options(args: &Args) -> anyhow::Result<()> {
    if args.rpc_url.is_some()
        || args.sender.is_some()
        || args.contract_address.is_some()
        || args.chain_id.is_some()
        || args.from_block.is_some()
    {
        bail!("Solana challenge mode rejects EVM compatibility options");
    }
    Ok(())
}

fn reject_solana_options(args: &Args) -> anyhow::Result<()> {
    if args.solana_rpc_url.is_some()
        || args.solana_program_id.is_some()
        || args.solana_vault_state.is_some()
        || args.solana_genesis_hash.is_some()
        || args.solana_network.is_some()
        || args.solana_keypair.is_some()
    {
        bail!("EVM challenge mode rejects Solana options");
    }
    Ok(())
}
