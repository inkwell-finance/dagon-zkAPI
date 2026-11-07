use anyhow::{ensure, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use dagon_zkapi_deploy::{initialize_instruction, observe, validate_effective_profile, Rpc};
use dagon_zkapi_profile::{
    parity_violations, vault_state_address, NetworkIdentity, SharedProfile, IDENTITY_SCHEMA,
    MAINNET_GENESIS_HASH,
};
use serde_json::{json, Value};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::{path::PathBuf, str::FromStr, time::Duration};
use zkapi_proof::compact::CompactSigner;
use zkapi_types::Felt252;

#[derive(Parser)]
#[command(about = "Immutable, profile-bound Solana deployment and parity")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a network identity file (genesis from the RPC, vault PDA derived from the authority).
    Identity {
        #[arg(long)]
        network: String,
        #[arg(long)]
        solana_rpc_url: String,
        #[arg(long)]
        vault_authority: String,
        /// The classic-Token USDC account (any owner) that receives treasury withdrawals.
        #[arg(long)]
        treasury_token_account: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Initialize the vault with every parameter from the embedded profile (immutable, pinned program only).
    InitVault {
        #[arg(long)]
        solana_identity: PathBuf,
        #[arg(long)]
        solana_rpc_url: String,
        #[arg(long)]
        authority_keypair: PathBuf,
    },
    /// Print the effective profile observed on chain (program, vault, USDC mint and token programs, runtime features).
    Observe {
        #[arg(long)]
        solana_identity: PathBuf,
        #[arg(long)]
        solana_rpc_url: String,
    },
    /// Print the mainnet reference profile (profile + identity + live mainnet USDC/runtime observations).
    Expected {
        #[arg(long)]
        solana_identity: PathBuf,
        #[arg(
            long,
            env = "MAINNET_RPC_URL",
            default_value = "https://api.mainnet-beta.solana.com"
        )]
        mainnet_rpc_url: String,
    },
    /// Fail unless two effective profiles differ only in allowed network-identity keys.
    Diff { local: PathBuf, reference: PathBuf },
}
fn output(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let p = SharedProfile::embedded();
    match Cli::parse().command {
        Command::Identity {
            network,
            solana_rpc_url,
            vault_authority,
            treasury_token_account,
            out,
        } => {
            let rpc = Rpc::new(solana_rpc_url)?;
            let authority = Pubkey::from_str(&vault_authority)?;
            let genesis_hash = rpc
                .call("getGenesisHash", json!([]))
                .await?
                .as_str()
                .context("genesis hash")?
                .to_owned();
            let identity = NetworkIdentity {
                schema: IDENTITY_SCHEMA.into(),
                network,
                genesis_hash,
                vault_authority: Some(vault_authority),
                vault_state: Some(
                    Pubkey::new_from_array(vault_state_address(
                        &p.program_id(),
                        &authority.to_bytes(),
                    ))
                    .to_string(),
                ),
                treasury_token_account: Some(treasury_token_account),
            };
            let text = serde_json::to_string_pretty(&identity)?;
            NetworkIdentity::parse(&text)?.resolve(p)?;
            std::fs::write(out, format!("{text}\n"))?;
        }
        Command::InitVault {
            solana_identity,
            solana_rpc_url,
            authority_keypair,
        } => {
            let identity = NetworkIdentity::load(&solana_identity)?;
            let resolved = identity.resolve(p)?;
            let rpc = Rpc::new(solana_rpc_url)?;
            rpc.check_genesis(&identity).await?;
            let program = rpc.program(&p.program.program_id).await?;
            ensure!(
                program["upgrade_authority"].is_null(),
                "program upgrade authority must be None"
            );
            ensure!(
                program["executable_sha256"] == p.program.executable_sha256,
                "program executable differs from profile"
            );
            let bytes: Vec<u8> = serde_json::from_slice(&std::fs::read(authority_keypair)?)?;
            let authority = Keypair::try_from(bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("invalid authority keypair: {e}"))?;
            ensure!(
                authority.pubkey().to_bytes() == resolved.vault_authority,
                "authority keypair differs from identity"
            );
            let seed = |name: &str| -> Result<CompactSigner> {
                let s = std::env::var(name).with_context(|| format!("{name} must be set"))?;
                let felt = Felt252::from_hex(&s).map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
                Ok(CompactSigner::from_seed(&felt))
            };
            let state = seed("ZKAPI_STATE_SEED")?;
            let clearance = seed("ZKAPI_CLEAR_SEED")?;
            let instruction = initialize_instruction(p, &identity, &state, &clearance)?;
            let latest = rpc
                .call("getLatestBlockhash", json!([{"commitment":"confirmed"}]))
                .await?;
            let hash = Hash::from_str(latest["value"]["blockhash"].as_str().context("blockhash")?)?;
            // Initialization can exceed the default 200k CU allowance. Use the
            // same transaction ceiling as the real-validator lifecycle test.
            let message = Message::new_with_blockhash(
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                    instruction,
                ],
                Some(&authority.pubkey()),
                &hash,
            )
            .serialize();
            let mut tx = vec![1];
            tx.extend_from_slice(authority.sign_message(&message).as_ref());
            tx.extend_from_slice(&message);
            let sig=rpc.call("sendTransaction",json!([base64::engine::general_purpose::STANDARD.encode(tx),{"encoding":"base64","preflightCommitment":"confirmed"}])).await?;
            let mut finalized = false;
            for _ in 0..120 {
                let statuses = rpc
                    .call(
                        "getSignatureStatuses",
                        json!([[sig],{"searchTransactionHistory":true}]),
                    )
                    .await?;
                let status = &statuses["value"][0];
                ensure!(status["err"].is_null(), "initialization failed: {status}");
                if status["confirmationStatus"] == "finalized" {
                    finalized = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            ensure!(finalized, "initialization did not finalize");
            output(&json!({"signature":sig,"vault_state":identity.vault_state}))?;
        }
        Command::Observe {
            solana_identity,
            solana_rpc_url,
        } => output(
            &observe(
                &Rpc::new(solana_rpc_url)?,
                &NetworkIdentity::load(&solana_identity)?,
                false,
            )
            .await?,
        )?,
        Command::Expected {
            solana_identity,
            mainnet_rpc_url,
        } => {
            let identity = NetworkIdentity::load(&solana_identity)?;
            ensure!(
                identity.network == "mainnet-beta" && identity.genesis_hash == MAINNET_GENESIS_HASH,
                "expected requires the mainnet identity"
            );
            // Fail closed when mainnet cannot be read: no guessed USDC or runtime reference.
            output(&observe(&Rpc::new(mainnet_rpc_url)?, &identity, true).await?)?;
        }
        Command::Diff { local, reference } => {
            let local = serde_json::from_slice(&std::fs::read(local)?)?;
            let reference = serde_json::from_slice(&std::fs::read(reference)?)?;
            validate_effective_profile(&local).context("invalid local parity document")?;
            validate_effective_profile(&reference).context("invalid reference parity document")?;
            let violations = parity_violations(&local, &reference);
            for violation in &violations {
                eprintln!("{violation}");
            }
            ensure!(
                violations.is_empty(),
                "Solana parity failed: {} violation(s)",
                violations.len()
            );
            println!("Solana parity PASS (only explicit network identity may differ)");
        }
    }
    Ok(())
}
