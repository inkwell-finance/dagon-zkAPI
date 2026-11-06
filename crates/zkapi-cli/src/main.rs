use clap::{Parser, Subcommand};
use dagon_zkapi_profile::{NetworkIdentity, SharedProfile};
use std::path::PathBuf;
use zkapi_serverd::config::{OpenRouterLeaseSourceConfig, ServerConfig};
use zkapi_types::Felt252;

#[derive(Debug, Parser)]
#[command(
    name = "dagon-zkapi",
    about = "Dagon zkAPI Solana operator commands. Shared parameters come from the embedded \
             deployment profile; a network differs only through its identity file."
)]
struct Cli {
    /// Directory containing the v2 Groth16 proving/verifying keys.
    #[arg(
        long,
        env = "ZKAPI_PROOF_SETUP_DIR",
        default_value = "protocol/setup/v2"
    )]
    proof_setup_dir: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Generate a fresh development setup in a new directory.
    Setup {
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Derive deployment-pinned public signing keys from server seeds.
    SigningKeys {
        #[arg(long, env = "ZKAPI_STATE_SEED", hide_env_values = true)]
        state_seed: String,
        #[arg(long, env = "ZKAPI_CLEAR_SEED", hide_env_values = true)]
        clear_seed: String,
    },
    /// Run the request server against the identity's vault.
    #[command(name = "serverd")]
    Serverd {
        /// Network identity file (genesis hash, vault, treasury, Pyth account).
        #[arg(long, env = "ZKAPI_SOLANA_IDENTITY")]
        solana_identity: PathBuf,
        /// Solana JSON-RPC endpoint of the identity's cluster (may carry an API key).
        #[arg(long, env = "SOLANA_RPC_URL", hide_env_values = true)]
        solana_rpc_url: String,
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
        /// Indexer serving the tree snapshot used for deposit paths.
        #[arg(long)]
        indexer_url: Option<String>,
        /// Finalized root refresh interval.
        #[arg(long, default_value_t = 1_000)]
        root_poll_interval_ms: u64,
        #[arg(long, default_value = "zkapi-server.db")]
        db_path: String,
        /// State-signing secret seed (the vault pins its public key).
        #[arg(long, env = "ZKAPI_STATE_SEED", hide_env_values = true)]
        state_seed: String,
        /// Clearance-signing secret seed (the vault pins its public key).
        #[arg(long, env = "ZKAPI_CLEAR_SEED", hide_env_values = true)]
        clear_seed: String,
        /// OpenRouter management API base for direct lease provisioning.
        #[arg(long, default_value = "https://openrouter.ai/api")]
        openrouter_api_base: String,
        /// OpenRouter Management API key used only to mint bounded runtime leases.
        #[arg(
            long,
            env = "ZKAPI_OPENROUTER_MANAGEMENT_KEY",
            hide_env_values = true,
            conflicts_with = "oa_org_url"
        )]
        openrouter_management_key: Option<String>,
        /// OA org base URL used to obtain station-issued, verifier-backed keys
        /// (shared secret from ZKAPI_OA_ORG_SHARED_SECRET).
        #[arg(long)]
        oa_org_url: Option<String>,
        /// Drill-only misbehaviour (cargo feature `adversary`, debug builds).
        #[cfg(feature = "adversary")]
        #[arg(long, value_enum)]
        adversary: Option<zkapi_serverd::adversary::AdversaryMode>,
    },
    /// Mirror the identity's vault tree for wallets.
    Indexer {
        /// Network identity file (genesis hash and vault).
        #[arg(long, env = "ZKAPI_SOLANA_IDENTITY")]
        solana_identity: PathBuf,
        /// Solana JSON-RPC endpoint of the identity's cluster (may carry an API key).
        #[arg(long, env = "SOLANA_RPC_URL", hide_env_values = true)]
        rpc_url: String,
        #[arg(long, default_value = "127.0.0.1:3001")]
        listen: String,
        #[arg(long, default_value_t = 1_000)]
        poll_interval_ms: u64,
    },
}

fn build_server_config(cli: &Cli) -> anyhow::Result<ServerConfig> {
    let Commands::Serverd {
        solana_identity,
        solana_rpc_url,
        listen,
        indexer_url,
        root_poll_interval_ms,
        db_path,
        state_seed,
        clear_seed,
        openrouter_api_base,
        openrouter_management_key,
        oa_org_url,
        #[cfg(feature = "adversary")]
        adversary,
    } = cli.command.clone()
    else {
        anyhow::bail!("expected serverd command");
    };
    let oa_org_shared_secret = std::env::var("ZKAPI_OA_ORG_SHARED_SECRET")
        .ok()
        .filter(|value| !value.is_empty());
    let lease_source = match (
        openrouter_management_key.filter(|key| !key.is_empty()),
        oa_org_url,
        oa_org_shared_secret,
    ) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            anyhow::bail!(
                "configure either direct OpenRouter management or OA org key issuance, not both"
            )
        }
        (Some(management_key), None, None) => OpenRouterLeaseSourceConfig::OpenRouter {
            management_key,
            api_base: openrouter_api_base,
        },
        (None, Some(org_base_url), Some(shared_secret)) => OpenRouterLeaseSourceConfig::OaOrg {
            org_base_url,
            shared_secret,
        },
        (None, Some(_), None) => {
            anyhow::bail!("--oa-org-url requires ZKAPI_OA_ORG_SHARED_SECRET")
        }
        (None, None, Some(_)) => {
            anyhow::bail!("ZKAPI_OA_ORG_SHARED_SECRET requires --oa-org-url")
        }
        (None, None, None) => anyhow::bail!(
            "configure --openrouter-management-key or --oa-org-url for prompt-private leases"
        ),
    };
    let profile = SharedProfile::embedded();
    let identity_file = NetworkIdentity::load(&solana_identity)?;
    let identity = identity_file.resolve(profile)?;
    let config = ServerConfig {
        listen_addr: listen,
        db_path,
        indexer_url,
        root_poll_interval_ms,
        proof_setup_dir: cli.proof_setup_dir.clone(),
        #[cfg(feature = "adversary")]
        adversary,
        ..ServerConfig::new(
            identity_file.network,
            identity,
            solana_rpc_url,
            lease_source,
            parse_felt("state seed", &state_seed)?,
            parse_felt("clear seed", &clear_seed)?,
        )
    };
    config.validate()?;
    Ok(config)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .init();

    let cli = Cli::parse();

    match cli.command.clone() {
        Commands::Setup { output_dir } => {
            anyhow::ensure!(
                !output_dir.exists(),
                "refusing to overwrite an existing setup directory"
            );
            zkapi_proof::compact::setup(&output_dir)?;
            print_json(&serde_json::json!({
                "status": "ok",
                "proof_backend": "groth16_bn254",
                "output_dir": output_dir,
            }))?;
        }
        Commands::SigningKeys {
            state_seed,
            clear_seed,
        } => {
            let state = zkapi_proof::compact::CompactSigner::from_seed(&parse_felt(
                "state seed",
                &state_seed,
            )?);
            let clearance = zkapi_proof::compact::CompactSigner::from_seed(&parse_felt(
                "clearance seed",
                &clear_seed,
            )?);
            print_json(&serde_json::json!({
                "state_signing_key": state.public_key(),
                "clearance_signing_key": clearance.public_key(),
            }))?;
        }
        Commands::Serverd { .. } => {
            zkapi_serverd::routes::run_server(build_server_config(&cli)?).await?;
        }
        Commands::Indexer {
            solana_identity,
            rpc_url,
            listen,
            poll_interval_ms,
        } => {
            zkapi_indexerd::run_indexer(zkapi_indexerd::IndexerConfig::from_identity_file(
                &solana_identity,
                rpc_url,
                listen,
                poll_interval_ms,
            )?)
            .await?;
        }
    }
    Ok(())
}

fn log_filter() -> tracing_subscriber::EnvFilter {
    const DEFAULT: &str = "warn,zkapi=info,zkapi_serverd=info,zkapi_indexerd=info";
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| DEFAULT.into());

    // ark-r1cs-std instruments fine-grained field operations at INFO under the
    // `r1cs` target. Enabling those spans while proving debug-formats growing
    // constraint systems, turning a ~3-second proof into multi-gigabyte work.
    // Keep them disabled even when a caller uses a broad `RUST_LOG=info`.
    suppress_r1cs_info(filter)
}

fn suppress_r1cs_info(filter: tracing_subscriber::EnvFilter) -> tracing_subscriber::EnvFilter {
    filter.add_directive("r1cs=warn".parse().expect("valid r1cs log directive"))
}

fn parse_felt(label: &str, value: &str) -> anyhow::Result<Felt252> {
    Felt252::from_hex(value).map_err(|err| anyhow::anyhow!("invalid {label}: {err}"))
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete localnet identity for the embedded profile's program.
    fn identity_file(directory: &std::path::Path) -> PathBuf {
        let profile = SharedProfile::embedded();
        let authority = [5u8; 32];
        let vault = dagon_zkapi_profile::vault_state_address(&profile.program_id(), &authority);
        let encode = |bytes: [u8; 32]| bs58::encode(bytes).into_string();
        let path = directory.join("localnet.identity.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "schema": dagon_zkapi_profile::IDENTITY_SCHEMA,
                "network": "localnet",
                "genesis_hash": encode([3; 32]),
                "vault_authority": encode(authority),
                "vault_state": encode(vault),
                "treasury": encode([7; 32]),
                "pyth_price_account": encode(profile.pyth_push_account()),
            })
            .to_string(),
        )
        .unwrap();
        path
    }

    fn serverd_args(identity: &std::path::Path) -> Vec<String> {
        [
            "zkapi",
            "serverd",
            "--solana-identity",
            identity.to_str().unwrap(),
            "--solana-rpc-url",
            "http://127.0.0.1:8899",
            "--state-seed",
            "0x123",
            "--clear-seed",
            "0x456",
            "--openrouter-management-key",
            "test-only",
        ]
        .map(String::from)
        .to_vec()
    }

    #[test]
    fn retired_wallet_and_auth_commands_are_rejected() {
        for command in [
            "client",
            "clientd",
            "keygen",
            "prepare-deposit",
            "confirm-deposit",
            "withdraw",
            "request",
            "server",
        ] {
            assert!(Cli::try_parse_from(["zkapi", command]).is_err());
        }
        assert!(
            Cli::try_parse_from(["zkapi", "--auth-scheme", "blind-signature", "signing-keys"])
                .is_err()
        );
    }

    /// Shared parameters have no flags: the profile is the only source.
    #[test]
    fn shared_parameter_flags_do_not_exist() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity_file(directory.path());
        assert!(Cli::try_parse_from(serverd_args(&identity)).is_ok());
        for flag in [
            ["--ledger", "solana"],
            ["--solana-program-id", "x"],
            ["--solana-vault-state", "x"],
            ["--solana-genesis-hash", "x"],
            ["--solana-network", "x"],
            ["--pyth-price-account", "x"],
            ["--pyth-max-age-seconds", "30"],
            ["--openrouter-lease-ttl-seconds", "300"],
            ["--challenge-period-seconds", "86400"],
            ["--raise-lead-seconds", "3600"],
            ["--initial-root", "0x0"],
        ] {
            let mut args = serverd_args(&identity);
            args.extend(flag.map(String::from));
            assert!(Cli::try_parse_from(args).is_err(), "{flag:?}");
        }
        for global in [["--chain-id", "1"], ["--request-charge-cap", "1"]] {
            let mut args = vec!["zkapi".to_string()];
            args.extend(global.map(String::from));
            args.extend(serverd_args(&identity).into_iter().skip(1));
            assert!(Cli::try_parse_from(args).is_err(), "{global:?}");
        }
    }

    #[test]
    fn server_config_derives_everything_from_profile_and_identity() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity_file(directory.path());
        let cli = Cli::try_parse_from(serverd_args(&identity)).unwrap();
        let config = build_server_config(&cli).unwrap();
        assert_eq!(&config.profile, SharedProfile::embedded());
        assert_eq!(config.network, "localnet");
        assert_eq!(config.chain_id(), zkapi_types::solana_chain_id(&[3; 32]));
        assert_eq!(
            config.contract_address(),
            zkapi_types::solana_deployment_binding(
                &SharedProfile::embedded().program_id(),
                &config.identity.vault_state,
                &[3; 32]
            )
        );
        assert_eq!(
            config.billing_pins().feed_account,
            bs58::encode(SharedProfile::embedded().pyth_push_account()).into_string()
        );
        assert_eq!(
            config.request_charge_cap(),
            u128::from(SharedProfile::embedded().vault.request_charge_cap)
        );
    }

    #[test]
    fn server_requires_identity_seeds_and_exactly_one_lease_source() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity_file(directory.path());
        let args = serverd_args(&identity);
        for missing in [
            "--solana-identity",
            "--solana-rpc-url",
            "--state-seed",
            "--clear-seed",
        ] {
            let index = args.iter().position(|arg| arg == missing).unwrap();
            let mut filtered = args.clone();
            filtered.drain(index..index + 2);
            // Required flags fall back to their environment variables only.
            if std::env::var_os(match missing {
                "--solana-identity" => "ZKAPI_SOLANA_IDENTITY",
                "--solana-rpc-url" => "SOLANA_RPC_URL",
                "--state-seed" => "ZKAPI_STATE_SEED",
                _ => "ZKAPI_CLEAR_SEED",
            })
            .is_none()
            {
                assert!(Cli::try_parse_from(filtered).is_err(), "{missing}");
            }
        }
        let mut both = args.clone();
        both.extend(["--oa-org-url", "https://org.example"].map(String::from));
        assert!(Cli::try_parse_from(both).is_err());
        let mut undeployed = args.clone();
        let mainnet = directory.path().join("mainnet.identity.json");
        std::fs::write(&mainnet, dagon_zkapi_profile::MAINNET_IDENTITY_JSON).unwrap();
        undeployed[3] = mainnet.to_string_lossy().into_owned();
        let error = build_server_config(&Cli::try_parse_from(undeployed).unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("undeployed"), "{error}");
    }

    #[test]
    fn indexer_and_signing_commands_remain_available() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity_file(directory.path());
        assert!(Cli::try_parse_from([
            "zkapi",
            "indexer",
            "--solana-identity",
            identity.to_str().unwrap(),
            "--rpc-url",
            "http://127.0.0.1:8899",
        ])
        .is_ok());
        for removed in [
            ["--ledger", "solana"],
            ["--program-id", "x"],
            ["--from-block", "1"],
        ] {
            let mut args = vec![
                "zkapi",
                "indexer",
                "--solana-identity",
                identity.to_str().unwrap(),
                "--rpc-url",
                "http://127.0.0.1:8899",
            ];
            args.extend(removed);
            assert!(Cli::try_parse_from(args).is_err(), "{removed:?}");
        }
        assert!(Cli::try_parse_from([
            "zkapi",
            "signing-keys",
            "--state-seed",
            "0x1",
            "--clear-seed",
            "0x2"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["zkapi", "setup"]).is_err());
    }
}
