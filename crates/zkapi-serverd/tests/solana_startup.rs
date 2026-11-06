#![allow(deprecated)] // Official Solana 2.x fixture encoder, not a production decoder.
use anchor_lang::{AccountSerialize, Owner};
use axum::{extract::State, routing::post, Json, Router};
use base64::Engine;
use dagon_zkapi_vault::VaultState;
use pyth_solana_receiver_sdk::price_update::{PriceFeedMessage, PriceUpdateV2, VerificationLevel};
use serde_json::{json, Value};
use solana_program::{
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    pubkey::Pubkey,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use zkapi_serverd::{
    config::{
        LedgerBackend, OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig,
        SolanaLedgerConfig, SolanaServerConfig,
    },
    native_billing::billing::{BillingQuote, SOL_USD_FEED_ID},
    routes::{prepare_solana_backends, run_server},
    signer::ServerSigner,
    sol_billing::PythBillingConfig,
};
use zkapi_types::{solana_chain_id, solana_deployment_binding, Felt252};

struct Fixture {
    config: ServerConfig,
    vault: VaultState,
    price: PriceUpdateV2,
    accounts: HashMap<String, Value>,
    genesis: String,
}

fn account(owner: Pubkey, executable: bool, bytes: Vec<u8>) -> Value {
    json!({"owner":owner.to_string(),"executable":executable,
        "data":[base64::engine::general_purpose::STANDARD.encode(bytes),"base64"],"lamports":1_000_000_000})
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl Fixture {
    fn new(db_path: String) -> Self {
        let program = dagon_zkapi_vault::ID;
        let authority = Pubkey::new_from_array([7; 32]);
        let (vault_key, bump) =
            Pubkey::find_program_address(&[b"vault", authority.as_ref()], &program);
        let genesis = [3; 32];
        let chain_id = solana_chain_id(&genesis);
        let binding =
            solana_deployment_binding(&program.to_bytes(), &vault_key.to_bytes(), &genesis);
        let signer = ServerSigner::new(&Felt252::from_u64(1), &Felt252::from_u64(2));
        let state_key = signer.state_public_key();
        let clear_key = signer.clearance_public_key();
        let price_key = Pubkey::new_from_array([8; 32]);
        let vault = VaultState {
            version: 1,
            bump,
            paused: false,
            authority,
            treasury: Pubkey::new_from_array([9; 32]),
            genesis_hash: genesis,
            chain_id,
            protocol_binding: *binding.as_bytes(),
            current_root: *Felt252::from_u64(44).as_bytes(),
            next_note_id: 0,
            note_ttl: 86_400,
            challenge_period: 86_400,
            request_charge_cap: 50_000,
            total_credits: 0,
            state_signing_key_x: *state_key.x.as_bytes(),
            state_signing_key_y: *state_key.y.as_bytes(),
            clearance_signing_key_x: *clear_key.x.as_bytes(),
            clearance_signing_key_y: *clear_key.y.as_bytes(),
            paused_at: 0,
            last_pause_end: 0,
            total_paused_duration: 0,
            treasury_accrued: 0,
        };
        let price = PriceUpdateV2 {
            write_authority: authority,
            verification_level: VerificationLevel::Full,
            price_message: PriceFeedMessage {
                feed_id: hex::decode(&SOL_USD_FEED_ID[2..])
                    .unwrap()
                    .try_into()
                    .unwrap(),
                price: 15_000_000_000,
                conf: 15_000_000,
                exponent: -8,
                publish_time: now() as i64,
                prev_publish_time: now() as i64 - 1,
                ema_price: 15_000_000_000,
                ema_conf: 15_000_000,
            },
            posted_slot: 10,
        };
        let config = ServerConfig {
            backend: LedgerBackend::Solana,
            chain_id,
            contract_address: binding,
            request_charge_cap: 50_000,
            db_path,
            listen_addr: "127.0.0.1:0".into(),
            solana: Some(SolanaServerConfig {
                ledger: SolanaLedgerConfig {
                    rpc_url: "http://127.0.0.1:9".into(),
                    indexer_url: None,
                    network: "localnet".into(),
                    program_id: program.to_bytes(),
                    vault_state: vault_key.to_bytes(),
                    genesis_hash: genesis,
                },
                billing: PythBillingConfig {
                    price_account: price_key.to_string(),
                    receiver_program: PriceUpdateV2::owner().to_string(),
                    feed_id: SOL_USD_FEED_ID.into(),
                    max_age_seconds: 30,
                    max_confidence_bps: 100,
                },
            }),
            openrouter_leases: Some(OpenRouterLeaseConfig {
                source: OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key: "test-only".into(),
                    api_base: "http://127.0.0.1:9".into(),
                },
                ttl_seconds: 60,
                settlement_grace_seconds: 0,
                settlement_poll_seconds: 1,
            }),
            ..Default::default()
        };
        let mut accounts = HashMap::new();
        let program_data = bpf_loader_upgradeable::get_program_data_address(&program);
        accounts.insert(
            program.to_string(),
            account(
                bpf_loader_upgradeable::ID,
                true,
                bincode::serialize(&UpgradeableLoaderState::Program {
                    programdata_address: program_data,
                })
                .unwrap(),
            ),
        );
        let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
            slot: 1,
            upgrade_authority_address: None,
        })
        .unwrap();
        data.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
        data.push(1); // mock deployed code
        accounts.insert(
            program_data.to_string(),
            account(bpf_loader_upgradeable::ID, false, data),
        );
        Self {
            config,
            vault,
            price,
            accounts,
            genesis: bs58::encode(genesis).into_string(),
        }
    }
    fn serialize_accounts(&mut self) {
        let sol = self.config.solana.as_ref().unwrap();
        let mut data = Vec::new();
        self.vault.try_serialize(&mut data).unwrap();
        self.accounts.insert(
            bs58::encode(sol.ledger.vault_state).into_string(),
            account(Pubkey::new_from_array(sol.ledger.program_id), false, data),
        );
        let mut data = Vec::new();
        self.price.try_serialize(&mut data).unwrap();
        data.resize(PriceUpdateV2::LEN, 0);
        self.accounts.insert(
            sol.billing.price_account.clone(),
            account(PriceUpdateV2::owner(), false, data),
        );
    }
}

#[derive(Clone)]
struct Rpc {
    accounts: Arc<HashMap<String, Value>>,
    genesis: String,
    wrong_id: bool,
    unavailable: bool,
    genesis_reads: Arc<AtomicUsize>,
    wrong_price_genesis: bool,
}
async fn rpc(State(state): State<Rpc>, Json(request): Json<Value>) -> Json<Value> {
    if state.unavailable {
        return Json(json!({"jsonrpc":"2.0","id":1,"error":{"code":-1}}));
    }
    let result = match request["method"].as_str().unwrap() {
        "getGenesisHash" => {
            let read = state.genesis_reads.fetch_add(1, Ordering::SeqCst);
            if state.wrong_price_genesis && read >= 2 {
                json!(bs58::encode([4; 32]).into_string())
            } else {
                json!(state.genesis)
            }
        }
        "getAccountInfo" => {
            assert_eq!(request["params"][1]["commitment"], "finalized");
            let value = state
                .accounts
                .get(request["params"][0].as_str().unwrap())
                .cloned()
                .unwrap_or(Value::Null);
            json!({"context":{"slot":100},"value":value})
        }
        other => panic!("unexpected RPC {other}"),
    };
    Json(json!({"jsonrpc":"2.0","id":if state.wrong_id {2} else {1},"result":result}))
}
async fn start_rpc(
    f: &mut Fixture,
    mutate: impl FnOnce(&mut HashMap<String, Value>),
    wrong_id: bool,
    unavailable: bool,
    wrong_price_genesis: bool,
) -> tokio::task::JoinHandle<()> {
    f.serialize_accounts();
    mutate(&mut f.accounts);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.config.solana.as_mut().unwrap().ledger.rpc_url =
        format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new().route("/", post(rpc)).with_state(Rpc {
        accounts: Arc::new(f.accounts.clone()),
        genesis: f.genesis.clone(),
        wrong_id,
        unavailable,
        genesis_reads: Arc::new(AtomicUsize::new(0)),
        wrong_price_genesis,
    });
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() })
}

#[tokio::test]
async fn complete_finalized_preflight_is_separate_from_database_and_frozen_quote_math() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("not-opened.db");
    let mut f = Fixture::new(db.to_string_lossy().into_owned());
    let task = start_rpc(&mut f, |_| {}, false, false, false).await;
    let signer = ServerSigner::new(&f.config.state_seed, &f.config.clear_seed);
    let backends = prepare_solana_backends(&f.config, &signer).await.unwrap();
    assert_eq!(backends.initial_root, Felt252::from_u64(44));
    assert!(!db.exists());
    let quote = backends.billing.quote(now()).await.unwrap();
    backends.billing.validate(&quote, now()).await.unwrap();
    let BillingQuote::NativeSol(sol) = &quote else {
        panic!("expected SOL");
    };
    assert_eq!(sol.chain_id, f.config.chain_id.to_string());
    assert_eq!(quote.limit_micro_usd(1_000_000_000).unwrap(), 149_850_000);
    assert_eq!(quote.charge_units(149_850_000).unwrap(), 1_000_000_000);
    let mut expired = sol.clone();
    expired.publish_time = 1;
    expired.expires_at = 31;
    assert!(BillingQuote::NativeSol(expired.clone())
        .assert_fresh(now())
        .is_err());
    assert_eq!(expired.charge_units(149_850_000).unwrap(), 1_000_000_000);
    let mut forged = sol.clone();
    forged.price = "16000000000".into();
    assert!(backends
        .billing
        .validate(&BillingQuote::NativeSol(forged), now())
        .await
        .is_err());
    task.abort();
}

#[tokio::test]
async fn invalid_authoritative_reads_fail_before_database_creation() {
    for case in 0..36 {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("must-not-exist.db");
        let mut f = Fixture::new(db.to_string_lossy().into_owned());
        match case {
            0 => f.genesis = bs58::encode([4; 32]).into_string(),
            1 => f.vault.version += 1,
            2 => f.vault.bump ^= 1,
            3 => f.vault.chain_id += 1,
            4 => f.vault.protocol_binding = [0; 32],
            5 => f.vault.genesis_hash = [4; 32],
            6 => f.vault.paused = true,
            7 => f.vault.request_charge_cap += 1,
            8 => f.vault.state_signing_key_x = [0; 32],
            9 => f.vault.clearance_signing_key_y = [0; 32],
            10 => f.price.verification_level = VerificationLevel::Partial { num_signatures: 10 },
            11 => f.price.price_message.feed_id = [0; 32],
            12 => f.price.price_message.publish_time = now() as i64 - 31,
            13 => f.price.price_message.publish_time = now() as i64 + 31,
            14 => f.price.price_message.price = 0,
            15 => f.price.price_message.price = -1,
            16 => f.price.price_message.conf = 151_000_000,
            17 => f.price.price_message.exponent = i32::MAX,
            18 => f.price.posted_slot = 101,
            33 => f.vault.authority = Pubkey::new_from_array([2; 32]),
            // Regression: --challenge-period-seconds must be the vault's own.
            35 => f.vault.challenge_period = 3_600,
            _ => {}
        }
        let vault_key =
            bs58::encode(f.config.solana.as_ref().unwrap().ledger.vault_state).into_string();
        let price_key = f
            .config
            .solana
            .as_ref()
            .unwrap()
            .billing
            .price_account
            .clone();
        let task = start_rpc(
            &mut f,
            |accounts| match case {
                19 => {
                    accounts.get_mut(&vault_key).unwrap()["owner"] =
                        Pubkey::new_from_array([6; 32]).to_string().into()
                }
                20 => {
                    accounts.get_mut(&price_key).unwrap()["owner"] =
                        Pubkey::new_from_array([6; 32]).to_string().into()
                }
                21 => accounts.get_mut(&price_key).unwrap()["data"] = json!(["AA==", "base64"]),
                24 => accounts.get_mut(&price_key).unwrap()["executable"] = true.into(),
                25 | 26 => {
                    let data = &mut accounts.get_mut(&price_key).unwrap()["data"][0];
                    let mut bytes = base64::engine::general_purpose::STANDARD
                        .decode(data.as_str().unwrap())
                        .unwrap();
                    if case == 25 {
                        bytes[0] ^= 1;
                    } else {
                        *bytes.last_mut().unwrap() = 1;
                    }
                    *data = base64::engine::general_purpose::STANDARD
                        .encode(bytes)
                        .into();
                }
                27 => accounts.get_mut(&price_key).unwrap()["data"][1] = "base58".into(),
                28 => {
                    accounts.remove(&price_key);
                }
                29 => {
                    accounts
                        .get_mut(&dagon_zkapi_vault::ID.to_string())
                        .unwrap()["executable"] = false.into()
                }
                30 => {
                    accounts
                        .get_mut(&dagon_zkapi_vault::ID.to_string())
                        .unwrap()["owner"] = Pubkey::new_from_array([6; 32]).to_string().into()
                }
                32 => accounts.get_mut(&price_key).unwrap()["data"][0] = "A".repeat(70_000).into(),
                34 => {
                    let address =
                        bpf_loader_upgradeable::get_program_data_address(&dagon_zkapi_vault::ID)
                            .to_string();
                    let mut bytes = bincode::serialize(&UpgradeableLoaderState::ProgramData {
                        slot: 1,
                        upgrade_authority_address: Some(Pubkey::new_from_array([7; 32])),
                    })
                    .unwrap();
                    bytes.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
                    bytes.push(1);
                    accounts.get_mut(&address).unwrap()["data"][0] =
                        base64::engine::general_purpose::STANDARD
                            .encode(bytes)
                            .into();
                }
                _ => {}
            },
            case == 22,
            case == 23,
            case == 31,
        )
        .await;
        let result = run_server(f.config).await;
        assert!(result.is_err(), "case {case} unexpectedly passed");
        assert!(!db.exists(), "case {case} opened state");
        task.abort();
    }
}

#[test]
fn mode_pins_and_oracle_bounds_reject_before_transport() {
    let f = Fixture::new("unused.db".into());
    f.config.validate_native_mode().unwrap();
    assert_eq!(ServerConfig::default().backend, LedgerBackend::Solana);
    for case in 0..7 {
        let mut config = f.config.clone();
        match case {
            0 => config.chain_id += 1,
            1 => config.contract_address = Felt252::ZERO,
            2 => config.solana.as_mut().unwrap().billing.max_age_seconds = 61,
            3 => config.solana.as_mut().unwrap().billing.max_confidence_bps = 101,
            4 => config.backend = LedgerBackend::Evm,
            5 => config.initial_root = Felt252::from_u64(1),
            _ => config.solana.as_mut().unwrap().billing.feed_id = "another-feed".into(),
        }
        assert!(config.validate_native_mode().is_err());
    }
}
