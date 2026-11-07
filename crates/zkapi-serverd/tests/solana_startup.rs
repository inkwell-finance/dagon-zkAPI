#![allow(deprecated)] // Official Solana 2.x fixture encoder, not a production decoder.
use anchor_lang::{AccountSerialize, Owner};
use axum::{extract::State, routing::post, Json, Router};
use base64::Engine;
use dagon_zkapi_profile::{
    executable_sha256, to_hex, vault_state_address, SharedProfile, PYTH_MAX_AGE_CEILING_SECONDS,
};
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
        Arc, Mutex,
    },
};
use zkapi_serverd::{
    billing::BillingPriceSource,
    config::{OpenRouterLeaseSourceConfig, ResolvedIdentity, ServerConfig},
    error::ServerError,
    routes::{prepare_solana_backends, run_server},
    signer::ServerSigner,
    sol_billing::PythBillingOracle,
    testnet_auth::TestnetPassword,
};
use zkapi_types::Felt252;

/// Deployed program bytes of the fixture; the profile pins their hash.
const PROGRAM_BYTES: &[u8] = &[1, 2, 3];

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

fn program_data(upgrade_authority: Option<Pubkey>, code: &[u8]) -> Vec<u8> {
    let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 1,
        upgrade_authority_address: upgrade_authority,
    })
    .unwrap();
    data.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
    data.extend_from_slice(code);
    // The loader allocates program data beyond the code; the hash ignores it.
    data.resize(data.len() + 64, 0);
    data
}

impl Fixture {
    fn new(db_path: String) -> Self {
        let mut profile = SharedProfile::embedded().clone();
        profile.program.executable_sha256 = to_hex(&executable_sha256(PROGRAM_BYTES));
        let program = dagon_zkapi_vault::ID;
        assert_eq!(program.to_bytes(), profile.program_id());
        let authority = Pubkey::new_from_array([7; 32]);
        let vault_key = Pubkey::new_from_array(vault_state_address(
            &program.to_bytes(),
            &authority.to_bytes(),
        ));
        let (_, bump) = Pubkey::find_program_address(&[b"vault", authority.as_ref()], &program);
        let genesis = [3; 32];
        let identity = ResolvedIdentity {
            genesis_hash: genesis,
            vault_authority: authority.to_bytes(),
            vault_state: vault_key.to_bytes(),
            treasury: [9; 32],
            pyth_price_account: [8; 32],
        };
        let config = ServerConfig {
            profile,
            db_path,
            listen_addr: "127.0.0.1:0".into(),
            ..ServerConfig::new(
                "localnet".into(),
                identity,
                "http://127.0.0.1:9".into(),
                OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key: "test-only".into(),
                    api_base: "http://127.0.0.1:9".into(),
                },
                Felt252::from_u64(1),
                Felt252::from_u64(2),
            )
        };
        let signer = ServerSigner::new(&config.state_seed, &config.clear_seed);
        let state_key = signer.state_public_key();
        let clear_key = signer.clearance_public_key();
        let vault_profile = &config.profile.vault;
        let vault = VaultState {
            version: vault_profile.version,
            bump,
            paused: false,
            authority,
            treasury: Pubkey::new_from_array(identity.treasury),
            genesis_hash: genesis,
            chain_id: config.chain_id(),
            protocol_binding: *config.contract_address().as_bytes(),
            current_root: *Felt252::from_u64(44).as_bytes(),
            next_note_id: 0,
            note_ttl: vault_profile.note_ttl_seconds,
            challenge_period: vault_profile.challenge_period_seconds,
            request_charge_cap: vault_profile.request_charge_cap,
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
                feed_id: hex::decode(&config.profile.pyth.feed_id[2..])
                    .unwrap()
                    .try_into()
                    .unwrap(),
                price: 15_000_000_000,
                conf: 15_000_000,
                exponent: -8,
                publish_time: now() as i64 - 2,
                prev_publish_time: now() as i64 - 3,
                ema_price: 15_000_000_000,
                ema_conf: 15_000_000,
            },
            posted_slot: 10,
        };
        let mut accounts = HashMap::new();
        let program_data_address = bpf_loader_upgradeable::get_program_data_address(&program);
        accounts.insert(
            program.to_string(),
            account(
                bpf_loader_upgradeable::ID,
                true,
                bincode::serialize(&UpgradeableLoaderState::Program {
                    programdata_address: program_data_address,
                })
                .unwrap(),
            ),
        );
        accounts.insert(
            program_data_address.to_string(),
            account(
                bpf_loader_upgradeable::ID,
                false,
                program_data(None, PROGRAM_BYTES),
            ),
        );
        Self {
            config,
            vault,
            price,
            accounts,
            genesis: bs58::encode(genesis).into_string(),
        }
    }

    fn vault_key(&self) -> String {
        bs58::encode(self.config.identity.vault_state).into_string()
    }

    fn price_key(&self) -> String {
        bs58::encode(self.config.identity.pyth_price_account).into_string()
    }

    fn price_account(&self) -> Value {
        let mut data = Vec::new();
        self.price.try_serialize(&mut data).unwrap();
        data.resize(PriceUpdateV2::LEN, 0);
        account(PriceUpdateV2::owner(), false, data)
    }

    fn serialize_accounts(&mut self) {
        let mut data = Vec::new();
        self.vault.try_serialize(&mut data).unwrap();
        self.accounts.insert(
            self.vault_key(),
            account(dagon_zkapi_vault::ID, false, data),
        );
        self.accounts.insert(self.price_key(), self.price_account());
    }
}

#[derive(Clone)]
struct Rpc {
    accounts: Arc<Mutex<HashMap<String, Value>>>,
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
                .lock()
                .unwrap()
                .get(request["params"][0].as_str().unwrap())
                .cloned()
                .unwrap_or(Value::Null);
            json!({"context":{"slot":100},"value":value})
        }
        other => panic!("unexpected RPC {other}"),
    };
    Json(json!({"jsonrpc":"2.0","id":if state.wrong_id {2} else {1},"result":result}))
}

struct MockRpc {
    accounts: Arc<Mutex<HashMap<String, Value>>>,
    task: tokio::task::JoinHandle<()>,
}

async fn start_rpc(
    f: &mut Fixture,
    mutate: impl FnOnce(&mut HashMap<String, Value>),
    wrong_id: bool,
    unavailable: bool,
    wrong_price_genesis: bool,
) -> MockRpc {
    f.serialize_accounts();
    mutate(&mut f.accounts);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.config.rpc_url = format!("http://{}", listener.local_addr().unwrap());
    let accounts = Arc::new(Mutex::new(f.accounts.clone()));
    let router = Router::new().route("/", post(rpc)).with_state(Rpc {
        accounts: accounts.clone(),
        genesis: f.genesis.clone(),
        wrong_id,
        unavailable,
        genesis_reads: Arc::new(AtomicUsize::new(0)),
        wrong_price_genesis,
    });
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    MockRpc { accounts, task }
}

#[tokio::test]
async fn complete_finalized_preflight_is_separate_from_database_and_frozen_quote_math() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("not-opened.db");
    let mut f = Fixture::new(db.to_string_lossy().into_owned());
    let rpc = start_rpc(&mut f, |_| {}, false, false, false).await;
    let signer = ServerSigner::new(&f.config.state_seed, &f.config.clear_seed);
    let backends = prepare_solana_backends(&f.config, &signer).await.unwrap();
    assert_eq!(backends.initial_root, Felt252::from_u64(44));
    assert!(!db.exists());
    let quote = backends.billing.quote(now()).await.unwrap();
    backends.billing.validate(&quote, now()).await.unwrap();
    assert_eq!(quote.chain_id, f.config.chain_id().to_string());
    assert_eq!(quote.feed_account, f.price_key());
    assert_eq!(quote.limit_micro_usd(1_000_000_000).unwrap(), 149_850_000);
    assert_eq!(quote.charge_units(149_850_000).unwrap(), 1_000_000_000);
    let mut expired = quote.clone();
    expired.publish_time = 1;
    expired.expires_at = 31;
    assert!(expired.assert_fresh(now()).is_err());
    assert_eq!(expired.charge_units(149_850_000).unwrap(), 1_000_000_000);
    let mut forged = quote.clone();
    forged.price = "16000000000".into();
    assert!(backends.billing.validate(&forged, now()).await.is_err());
    rpc.task.abort();
}

/// Mainnet's price account updates faster than a proof is built: a fresh
/// quote this server read stays acceptable after a newer update, while an
/// unobserved, mutated or expired quote is still refused.
#[tokio::test]
async fn observed_quotes_survive_newer_price_updates() {
    let mut f = Fixture::new("unused.db".into());
    let rpc = start_rpc(&mut f, |_| {}, false, false, false).await;
    let oracle = PythBillingOracle::new(&f.config).unwrap();
    let older = oracle.quote(now()).await.unwrap();

    // The finalized account moves on to a newer update.
    f.price.price_message.price = 15_100_000_000;
    f.price.price_message.publish_time += 1;
    f.price.posted_slot += 1;
    rpc.accounts
        .lock()
        .unwrap()
        .insert(f.price_key(), f.price_account());
    oracle.validate(&older, now()).await.unwrap();
    let newer = oracle.quote(now()).await.unwrap();
    assert_ne!(newer, older);
    oracle.validate(&older, now()).await.unwrap();
    oracle.validate(&newer, now()).await.unwrap();

    // Never observed: a well-formed quote one second older.
    let mut unobserved = older.clone();
    unobserved.publish_time -= 1;
    unobserved.expires_at -= 1;
    assert!(matches!(
        oracle.validate(&unobserved, now()).await,
        Err(ServerError::NativeQuoteSuperseded)
    ));
    let mut mutated = older.clone();
    mutated.price = "16000000000".into();
    assert!(matches!(
        oracle.validate(&mutated, now()).await,
        Err(ServerError::NativeQuoteSuperseded)
    ));
    let mut expired = older.clone();
    expired.publish_time = 1;
    expired.expires_at = 1 + f.config.profile.pyth.max_age_seconds;
    assert!(matches!(
        oracle.validate(&expired, now()).await,
        Err(ServerError::NativeQuoteExpired)
    ));

    // A restarted server has observed nothing: only the current update passes.
    let restarted = PythBillingOracle::new(&f.config).unwrap();
    restarted.validate(&newer, now()).await.unwrap();
    assert!(matches!(
        restarted.validate(&older, now()).await,
        Err(ServerError::NativeQuoteSuperseded)
    ));
    rpc.task.abort();
}

#[tokio::test]
async fn admission_reads_new_prices_and_rejects_adverse_supersession_without_cache_fallback() {
    let mut f = Fixture::new("unused.db".into());
    f.price.price_message.publish_time = now() as i64 - 80;
    f.price.price_message.price = 10_000_000_000;
    f.price.price_message.conf = 0;
    let rpc = start_rpc(&mut f, |_| {}, false, false, false).await;
    let oracle = PythBillingOracle::new(&f.config).unwrap();
    let older = oracle.quote(now()).await.unwrap();
    let original_account = f.price_account();

    for (price, conf, rejected) in [
        (10_100_000_000, 0, false),
        (9_900_000_000, 0, false), // exactly 1% lower is allowed
        (9_899_999_999, 0, true),
        (9_950_000_000, 60_000_000, true), // conservative, not raw price
        (10_100_000_000, 0, false),        // a newer recovery permits the old quote
    ] {
        f.price.price_message.publish_time += 1;
        f.price.price_message.price = price;
        f.price.price_message.conf = conf;
        rpc.accounts
            .lock()
            .unwrap()
            .insert(f.price_key(), f.price_account());
        // Do not call quote first: validation itself must fetch the update.
        let result = oracle.validate(&older, now()).await;
        if rejected {
            assert!(matches!(result, Err(ServerError::NativeQuoteSuperseded)));
            assert!(matches!(
                oracle.assert_admissible(&older, now()),
                Err(ServerError::NativeQuoteSuperseded)
            ));
        } else {
            result.unwrap();
        }
    }

    f.price.price_message.publish_time += 1;
    f.price.price_message.price = 9_400_000_000;
    rpc.accounts
        .lock()
        .unwrap()
        .insert(f.price_key(), f.price_account());
    assert!(matches!(
        oracle.validate(&older, now()).await,
        Err(ServerError::NativeQuoteSuperseded)
    ));
    // A lagging RPC response cannot erase the newer, lower observation.
    rpc.accounts
        .lock()
        .unwrap()
        .insert(f.price_key(), original_account);
    assert!(matches!(
        oracle.quote(now()).await,
        Err(ServerError::NativeQuoteSuperseded)
    ));
    assert!(matches!(
        oracle.validate(&older, now()).await,
        Err(ServerError::NativeQuoteSuperseded)
    ));
    rpc.accounts.lock().unwrap().remove(&f.price_key());
    assert!(matches!(
        oracle.validate(&older, now()).await,
        Err(ServerError::InvalidRequest(_))
    ));
    rpc.task.abort();
}

#[tokio::test]
async fn invalid_authoritative_reads_fail_before_database_creation() {
    for case in 0..41 {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("must-not-exist.db");
        let mut f = Fixture::new(db.to_string_lossy().into_owned());
        match case {
            // The RPC's cluster is not the identity's.
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
            // A stalled sponsor: the finalized price is exactly the maximum age old.
            12 => {
                f.price.price_message.publish_time =
                    now() as i64 - f.config.profile.pyth.max_age_seconds as i64
            }
            13 => f.price.price_message.publish_time = now() as i64 + 31,
            14 => f.price.price_message.price = 0,
            15 => f.price.price_message.price = -1,
            16 => f.price.price_message.conf = 151_000_000,
            17 => f.price.price_message.exponent = i32::MAX,
            18 => f.price.posted_slot = 101,
            33 => f.vault.authority = Pubkey::new_from_array([2; 32]),
            35 => f.vault.challenge_period -= 1,
            36 => f.vault.note_ttl -= 1,
            37 => f.vault.treasury = Pubkey::new_from_array([2; 32]),
            // The profile pins other program bytes.
            38 => f.config.profile.program.executable_sha256 = to_hex(&[0x11; 32]),
            _ => {}
        }
        let vault_key = f.vault_key();
        let price_key = f.price_key();
        let program_data_key =
            bpf_loader_upgradeable::get_program_data_address(&dagon_zkapi_vault::ID).to_string();
        let rpc = start_rpc(
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
                    accounts.get_mut(&program_data_key).unwrap()["data"][0] =
                        base64::engine::general_purpose::STANDARD
                            .encode(program_data(
                                Some(Pubkey::new_from_array([7; 32])),
                                PROGRAM_BYTES,
                            ))
                            .into();
                }
                // Immutable, but not the profile's executable.
                39 => {
                    accounts.get_mut(&program_data_key).unwrap()["data"][0] =
                        base64::engine::general_purpose::STANDARD
                            .encode(program_data(None, &[1, 2, 4]))
                            .into();
                }
                40 => {
                    accounts.remove(&program_data_key);
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
        rpc.task.abort();
    }
}

#[test]
fn identity_profile_and_oracle_bounds_reject_before_transport() {
    let f = Fixture::new("unused.db".into());
    f.config.validate().unwrap();
    for case in 0..8 {
        let mut config = f.config.clone();
        match case {
            0 => config.identity.vault_state = [1; 32],
            1 => config.identity.vault_authority = [1; 32],
            2 => config.profile.pyth.max_age_seconds = PYTH_MAX_AGE_CEILING_SECONDS + 1,
            3 => config.profile.pyth.max_confidence_bps = 101,
            4 => config.profile.pyth.feed_id = "another-feed".into(),
            5 => config.profile.pyth.receiver_program = Pubkey::new_from_array([6; 32]).to_string(),
            6 => config.profile.vault.challenge_period_seconds = 3_600,
            _ => {
                config.network = "mainnet-beta".into();
                config.testnet_password =
                    Some(TestnetPassword::new("a-test-only-password-123").unwrap());
            }
        }
        assert!(
            config.validate().is_err(),
            "case {case} unexpectedly passed"
        );
    }
}
