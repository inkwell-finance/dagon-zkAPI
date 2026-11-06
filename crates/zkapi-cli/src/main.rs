use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zkapi_serverd::config::{
    LedgerBackend, OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig,
    SolanaServerConfig,
};
use zkapi_serverd::sol_billing::{parse_solana_identity, PythBillingConfig};
use zkapi_types::Felt252;

#[derive(Debug, Parser)]
#[command(
    name = "dagon-zkapi",
    about = "Dagon zkAPI Solana operator commands (explicit EVM compatibility)"
)]
struct Cli {
    #[arg(long, default_value_t = 2)]
    protocol_version: u16,
    #[arg(long)]
    chain_id: Option<u64>,
    #[arg(long)]
    contract_address: Option<String>,
    #[arg(long, default_value_t = 50_000)]
    request_charge_cap: u128,
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
        #[arg(long, env = "ZKAPI_STATE_SEED")]
        state_seed: String,
        #[arg(long, env = "ZKAPI_CLEAR_SEED")]
        clear_seed: String,
    },
    #[command(name = "serverd", alias = "server",
        group(clap::ArgGroup::new("billing_rpc").args(["solana_rpc_url", "native_billing_rpc_url"]).required(true)))]
    Serverd {
        #[arg(long, value_enum, default_value = "solana")]
        ledger: LedgerBackend,
        #[command(flatten)]
        solana: SolanaServerArgs,
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
        /// OpenRouter management API base for direct lease provisioning.
        #[arg(long, default_value = "https://openrouter.ai/api")]
        openrouter_api_base: String,
        /// OpenRouter Management API key used only to mint bounded runtime leases.
        #[arg(long)]
        openrouter_management_key: Option<String>,
        /// OA org base URL used to obtain station-issued, verifier-backed keys.
        #[arg(long)]
        oa_org_url: Option<String>,
        /// Validity of each prompt-private runtime key.
        #[arg(long, default_value_t = 300)]
        openrouter_lease_ttl_seconds: u64,
        /// Usage propagation delay after key expiry before settlement.
        #[arg(long, default_value_t = 5)]
        openrouter_settlement_grace_seconds: u64,
        #[arg(long, default_value_t = 2)]
        openrouter_settlement_poll_seconds: u64,
        /// Required native ETH oracle RPC for gwei billing.
        #[arg(
            long,
            env = "ZKAPI_NATIVE_BILLING_RPC_URL",
            required_if_eq("ledger", "evm"),
            requires = "native_price_feed_address",
            conflicts_with = "solana_rpc_url"
        )]
        native_billing_rpc_url: Option<String>,
        #[arg(
            long,
            env = "ZKAPI_NATIVE_PRICE_FEED_ADDRESS",
            required_if_eq("ledger", "evm"),
            conflicts_with = "solana_rpc_url"
        )]
        native_price_feed_address: Option<String>,
        #[arg(long, default_value_t = 8, conflicts_with = "solana_rpc_url")]
        native_price_feed_decimals: u8,
        #[arg(long, default_value_t = 3600, conflicts_with = "solana_rpc_url")]
        native_price_max_age_seconds: u64,
        #[arg(long, default_value = "zkapi-server.db")]
        db_path: String,
        /// State-signing secret seed. Falls back to ZKAPI_STATE_SEED, then 0x1.
        #[arg(long)]
        state_seed: Option<String>,
        /// Clearance-signing secret seed. Falls back to ZKAPI_CLEAR_SEED, then 0x2.
        #[arg(long)]
        clear_seed: Option<String>,
        #[arg(long)]
        initial_root: Option<String>,
        #[arg(long)]
        indexer_url: Option<String>,
        #[arg(long, default_value_t = 1_000)]
        root_poll_interval_ms: u64,
        /// The vault's escape challenge period. Startup refuses a lease TTL,
        /// settlement grace and raise lead that cannot settle within it.
        #[arg(long, default_value_t = 86_400)]
        challenge_period_seconds: u64,
        /// The challenger's raise lead (`dagon-zkapi-challenged --raise-lead-seconds`).
        #[arg(long, default_value_t = 3_600)]
        raise_lead_seconds: u64,
        /// Drill-only misbehaviour (cargo feature `adversary`, debug builds).
        #[cfg(feature = "adversary")]
        #[arg(long, value_enum)]
        adversary: Option<zkapi_serverd::adversary::AdversaryMode>,
    },
    Indexer {
        #[arg(long, default_value = "127.0.0.1:3001")]
        listen: String,
        /// Ledger backend: `solana` (production) or `ethereum` (compatibility).
        #[arg(long, default_value = "solana")]
        ledger: String,
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: String,
        #[arg(long)]
        contract_address: Option<String>,
        #[arg(long)]
        program_id: Option<String>,
        #[arg(long)]
        vault_state: Option<String>,
        #[arg(long, default_value_t = 0)]
        from_block: u64,
        #[arg(long, default_value_t = 1_000)]
        poll_interval_ms: u64,
        #[arg(long)]
        cursor_path: Option<String>,
    },
}

#[derive(Debug, Clone, clap::Args)]
struct SolanaServerArgs {
    #[arg(long, required_if_eq("ledger", "solana"), requires_all = ["solana_program_id", "solana_vault_state", "solana_genesis_hash", "pyth_price_account"], conflicts_with_all = ["native_billing_rpc_url", "native_price_feed_address"])]
    solana_rpc_url: Option<String>,
    #[arg(long, required_if_eq("ledger", "solana"), requires = "solana_rpc_url")]
    solana_program_id: Option<String>,
    #[arg(long, required_if_eq("ledger", "solana"), requires = "solana_rpc_url")]
    solana_vault_state: Option<String>,
    #[arg(long, required_if_eq("ledger", "solana"), requires = "solana_rpc_url")]
    solana_genesis_hash: Option<String>,
    #[arg(long, requires = "solana_rpc_url")]
    solana_network: Option<String>,
    #[arg(long, required_if_eq("ledger", "solana"), requires = "solana_rpc_url")]
    pyth_price_account: Option<String>,
    #[arg(
        long,
        default_value = "rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ",
        requires = "solana_rpc_url"
    )]
    pyth_receiver_program: String,
    #[arg(
        long,
        default_value = "0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d",
        requires = "solana_rpc_url"
    )]
    pyth_feed_id: String,
    #[arg(long, default_value_t = 30, requires = "solana_rpc_url")]
    pyth_max_age_seconds: u64,
    #[arg(long, default_value_t = 100, requires = "solana_rpc_url")]
    pyth_max_confidence_bps: u16,
}

impl SolanaServerArgs {
    fn into_config(self, indexer_url: Option<String>) -> anyhow::Result<SolanaServerConfig> {
        let required = |name: &str, value: Option<String>| {
            value.ok_or_else(|| anyhow::anyhow!("{name} is required"))
        };
        Ok(SolanaServerConfig {
            ledger: zkapi_serverd::config::SolanaLedgerConfig {
                rpc_url: required("Solana RPC", self.solana_rpc_url)?,
                indexer_url,
                network: self.solana_network.unwrap_or_else(|| "mainnet-beta".into()),
                program_id: parse_solana_identity(
                    "program ID",
                    &required("program ID", self.solana_program_id)?,
                )?,
                vault_state: parse_solana_identity(
                    "vault state",
                    &required("vault state", self.solana_vault_state)?,
                )?,
                genesis_hash: parse_solana_identity(
                    "genesis hash",
                    &required("genesis hash", self.solana_genesis_hash)?,
                )?,
            },
            billing: PythBillingConfig {
                price_account: required("Pyth price account", self.pyth_price_account)?,
                receiver_program: self.pyth_receiver_program,
                feed_id: self.pyth_feed_id,
                max_age_seconds: self.pyth_max_age_seconds,
                max_confidence_bps: self.pyth_max_confidence_bps,
            },
        })
    }
}

fn build_server_config(cli: &Cli) -> anyhow::Result<ServerConfig> {
    let Commands::Serverd {
        ledger,
        solana,
        listen,
        openrouter_api_base,
        openrouter_management_key,
        oa_org_url,
        openrouter_lease_ttl_seconds,
        openrouter_settlement_grace_seconds,
        openrouter_settlement_poll_seconds,
        native_billing_rpc_url,
        native_price_feed_address,
        native_price_feed_decimals,
        native_price_max_age_seconds,
        db_path,
        state_seed,
        clear_seed,
        initial_root,
        indexer_url,
        root_poll_interval_ms,
        challenge_period_seconds,
        raise_lead_seconds,
        #[cfg(feature = "adversary")]
        adversary,
    } = cli.command.clone()
    else {
        anyhow::bail!("expected serverd command");
    };
    let state_seed = resolve_secret(state_seed, std::env::var("ZKAPI_STATE_SEED").ok());
    let clear_seed = resolve_secret(clear_seed, std::env::var("ZKAPI_CLEAR_SEED").ok());
    anyhow::ensure!(
        ledger == LedgerBackend::Evm || (state_seed.is_some() && clear_seed.is_some()),
        "Solana requires explicit state and clearance seeds (flags or environment)"
    );
    let state_seed = state_seed.unwrap_or_else(|| "0x1".to_string());
    let clear_seed = clear_seed.unwrap_or_else(|| "0x2".to_string());
    let openrouter_api_base_for_leases = openrouter_api_base.clone();
    let openrouter_management_key = resolve_secret(
        openrouter_management_key,
        std::env::var("ZKAPI_OPENROUTER_MANAGEMENT_KEY").ok(),
    );
    let oa_org_shared_secret =
        resolve_secret(None, std::env::var("ZKAPI_OA_ORG_SHARED_SECRET").ok());
    let lease_source = match (openrouter_management_key, oa_org_url, oa_org_shared_secret) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            anyhow::bail!(
                "configure either direct OpenRouter management or OA org key issuance, not both"
            )
        }
        (Some(management_key), None, None) => Some(OpenRouterLeaseSourceConfig::OpenRouter {
            management_key,
            api_base: openrouter_api_base_for_leases,
        }),
        (None, Some(org_base_url), Some(shared_secret)) => {
            Some(OpenRouterLeaseSourceConfig::OaOrg {
                org_base_url,
                shared_secret,
            })
        }
        (None, Some(_), None) => {
            anyhow::bail!("--oa-org-url requires an OA org shared secret")
        }
        (None, None, Some(_)) => {
            anyhow::bail!("an OA org shared secret requires --oa-org-url")
        }
        (None, None, None) => anyhow::bail!(
            "configure an OA org or OpenRouter management credential for native leases"
        ),
    };
    let openrouter_leases = lease_source.map(|source| OpenRouterLeaseConfig {
        source,
        ttl_seconds: openrouter_lease_ttl_seconds,
        settlement_grace_seconds: openrouter_settlement_grace_seconds,
        settlement_poll_seconds: openrouter_settlement_poll_seconds,
    });
    let (solana, native_billing, chain_id, contract_address) = match ledger {
        LedgerBackend::Solana => {
            anyhow::ensure!(
                cli.chain_id.is_none() && cli.contract_address.is_none() && initial_root.is_none(),
                "Solana rejects legacy --chain-id/--contract-address/--initial-root overrides"
            );
            anyhow::ensure!(
                native_billing_rpc_url.is_none() && native_price_feed_address.is_none(),
                "Solana rejects native ETH billing flags"
            );
            let config = solana.into_config(indexer_url.clone())?;
            let chain_id = zkapi_types::solana_chain_id(&config.ledger.genesis_hash);
            let binding = zkapi_types::solana_deployment_binding(
                &config.ledger.program_id,
                &config.ledger.vault_state,
                &config.ledger.genesis_hash,
            );
            (Some(config), None, chain_id, binding)
        }
        LedgerBackend::Evm => {
            anyhow::ensure!(solana.solana_rpc_url.is_none(), "EVM rejects Solana flags");
            let native = zkapi_serverd::native_billing::NativeBillingConfig {
                rpc_url: native_billing_rpc_url
                    .ok_or_else(|| anyhow::anyhow!("EVM requires oracle RPC"))?,
                feed_address: native_price_feed_address
                    .ok_or_else(|| anyhow::anyhow!("EVM requires pinned feed"))?
                    .to_lowercase(),
                decimals: native_price_feed_decimals,
                max_age_seconds: native_price_max_age_seconds,
            };
            (
                None,
                Some(native),
                cli.chain_id.unwrap_or(1),
                parse_felt(
                    "contract address",
                    cli.contract_address
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("EVM requires --contract-address"))?,
                )?,
            )
        }
    };
    let config = ServerConfig {
        backend: ledger,
        solana,
        protocol_version: cli.protocol_version,
        chain_id,
        testnet_password: None, // Loaded from the private server environment at startup.
        contract_address,
        request_charge_cap: cli.request_charge_cap,
        listen_addr: listen,
        db_path,
        state_seed: parse_felt("state seed", &state_seed)?,
        clear_seed: parse_felt("clear seed", &clear_seed)?,
        initial_root: parse_felt("initial root", initial_root.as_deref().unwrap_or("0x0"))?,
        indexer_url,
        root_poll_interval_ms,
        openrouter_leases,
        native_billing,
        proof_setup_dir: cli.proof_setup_dir.clone(),
        challenge_period_seconds,
        raise_lead_seconds,
        #[cfg(feature = "adversary")]
        adversary,
    };
    config.validate_native_mode()?;
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
            listen,
            ledger,
            rpc_url,
            contract_address,
            program_id,
            vault_state,
            from_block,
            poll_interval_ms,
            cursor_path,
        } => {
            let ledger = match ledger.as_str() {
                "solana" => {
                    zkapi_indexerd::IndexerLedger::Solana(zkapi_indexerd::SolanaPollerConfig {
                        rpc_url,
                        program_id: program_id.ok_or_else(|| {
                            anyhow::anyhow!("--program-id is required for Solana")
                        })?,
                        vault_state: vault_state.ok_or_else(|| {
                            anyhow::anyhow!("--vault-state is required for Solana")
                        })?,
                    })
                }
                "ethereum" | "evm" => {
                    zkapi_indexerd::IndexerLedger::Ethereum(zkapi_indexerd::PollerConfig {
                        rpc_url,
                        contract_address: contract_address.ok_or_else(|| {
                            anyhow::anyhow!(
                                "--contract-address is required for Ethereum compatibility"
                            )
                        })?,
                        from_block,
                        cursor_path,
                    })
                }
                other => anyhow::bail!("unsupported ledger backend `{other}`"),
            };
            let config = zkapi_indexerd::IndexerConfig {
                listen_addr: listen,
                poll_interval_ms,
                ledger,
            };
            zkapi_indexerd::run_indexer(config).await?;
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

fn resolve_secret(cli_value: Option<String>, env_value: Option<String>) -> Option<String> {
    cli_value.or(env_value).filter(|value| !value.is_empty())
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        ] {
            assert!(Cli::try_parse_from(["zkapi", command]).is_err());
        }
        assert!(
            Cli::try_parse_from(["zkapi", "--auth-scheme", "blind-signature", "signing-keys"])
                .is_err()
        );
    }

    #[test]
    fn native_server_requires_oracle_and_feed() {
        assert!(Cli::try_parse_from(["zkapi", "serverd"]).is_err());
        assert!(Cli::try_parse_from([
            "zkapi",
            "serverd",
            "--native-billing-rpc-url",
            "https://rpc.example"
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "zkapi",
            "--chain-id",
            "11155111",
            "serverd",
            "--ledger",
            "evm",
            "--native-billing-rpc-url",
            "https://rpc.example",
            "--native-price-feed-address",
            "0x694AA1769357215DE4FAC081bf1f309aDC325306",
            "--oa-org-url",
            "https://org.example",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Serverd {
                native_billing_rpc_url: Some(_),
                native_price_feed_address: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn solana_server_defaults_require_complete_pins_and_reject_mixed_duplicate_flags() {
        let args = [
            "zkapi",
            "serverd",
            "--solana-rpc-url",
            "http://127.0.0.1:8899",
            "--solana-program-id",
            "program",
            "--solana-vault-state",
            "vault",
            "--solana-genesis-hash",
            "genesis",
            "--pyth-price-account",
            "price",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Serverd {
                ledger: LedgerBackend::Solana,
                ..
            }
        ));
        for missing in [4, 6, 8, 10] {
            let filtered: Vec<_> = args
                .iter()
                .enumerate()
                .filter_map(|(i, a)| {
                    if i == missing || i == missing + 1 {
                        None
                    } else {
                        Some(*a)
                    }
                })
                .collect();
            assert!(Cli::try_parse_from(filtered).is_err());
        }
        for extra in [
            vec![
                "--native-billing-rpc-url",
                "https://eth.example",
                "--native-price-feed-address",
                "0xfeed",
            ],
            vec!["--solana-rpc-url", "https://other.example"],
        ] {
            let mut mixed = args.to_vec();
            mixed.extend(extra);
            assert!(Cli::try_parse_from(mixed).is_err());
        }
    }

    #[test]
    fn server_config_construction_is_derived_and_backend_specific() {
        let args = [
            "zkapi",
            "serverd",
            "--solana-rpc-url",
            "http://127.0.0.1:8899",
            "--solana-program-id",
            "7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H",
            "--solana-vault-state",
            "rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ",
            "--solana-genesis-hash",
            "7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H",
            "--pyth-price-account",
            "rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ",
            "--state-seed",
            "0x123",
            "--clear-seed",
            "0x456",
            "--openrouter-management-key",
            "test-only",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        let config = build_server_config(&cli).unwrap();
        let sol = config.solana.as_ref().unwrap();
        assert_eq!(
            config.chain_id,
            zkapi_types::solana_chain_id(&sol.ledger.genesis_hash)
        );
        assert_eq!(
            config.contract_address,
            zkapi_types::solana_deployment_binding(
                &sol.ledger.program_id,
                &sol.ledger.vault_state,
                &sol.ledger.genesis_hash
            )
        );
        assert!(config.native_billing.is_none());
        assert_eq!(config.initial_root, Felt252::ZERO);
        let mut explicit_root = args.to_vec();
        explicit_root.extend(["--initial-root", "0x0"]);
        assert!(build_server_config(&Cli::try_parse_from(explicit_root).unwrap()).is_err());
        let mut wrong_mode = cli;
        if let Commands::Serverd { ledger, .. } = &mut wrong_mode.command {
            *ledger = LedgerBackend::Evm;
        }
        assert!(build_server_config(&wrong_mode).is_err());
        let evm = Cli::try_parse_from([
            "zkapi",
            "--chain-id",
            "1",
            "--contract-address",
            "0x0000000000000000000000000000000000000001",
            "serverd",
            "--ledger",
            "evm",
            "--native-billing-rpc-url",
            "http://127.0.0.1:8545",
            "--native-price-feed-address",
            "0x694aa1769357215de4fac081bf1f309adc325306",
            "--openrouter-management-key",
            "test-only",
        ])
        .unwrap();
        let config = build_server_config(&evm).unwrap();
        assert_eq!(config.backend, LedgerBackend::Evm);
        assert!(config.solana.is_none() && config.native_billing.is_some());
        assert_eq!(config.challenge_period_seconds, 86_400);
        assert_eq!(config.raise_lead_seconds, 3_600);
    }

    /// Startup refuses a deployment whose leases could still be unsettled at
    /// the challenger's raise decision.
    #[test]
    fn server_refuses_lease_timing_that_outlasts_the_challenge_period() {
        let evm = |period: &'static str| {
            Cli::try_parse_from([
                "zkapi",
                "--chain-id",
                "1",
                "--contract-address",
                "0x0000000000000000000000000000000000000001",
                "serverd",
                "--ledger",
                "evm",
                "--native-billing-rpc-url",
                "http://127.0.0.1:8545",
                "--native-price-feed-address",
                "0x694aa1769357215de4fac081bf1f309adc325306",
                "--openrouter-management-key",
                "test-only",
                "--challenge-period-seconds",
                period,
            ])
            .unwrap()
        };
        let error = build_server_config(&evm("3600")).unwrap_err().to_string();
        assert!(error.contains("challenge timing is unsafe"), "{error}");
        // 300 s TTL + 2 × 5 s grace (direct key drains again after disabling)
        // + 2 × 2 s settlement polls + 600 s usage + 3600 s lead + 1800 s margin.
        assert!(build_server_config(&evm("6314")).is_ok());
        assert!(build_server_config(&evm("6313")).is_err());
    }

    #[test]
    fn indexer_and_signing_commands_remain_available() {
        assert!(Cli::try_parse_from([
            "zkapi",
            "indexer",
            "--ledger",
            "ethereum",
            "--contract-address",
            "0x1234"
        ])
        .is_ok());
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
