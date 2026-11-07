#![allow(deprecated)] // Official Solana 2.x fixture encoder, not a production decoder.
use anchor_lang::AccountSerialize;
use axum::{extract::State, routing::post, Json, Router};
use base64::Engine;
use dagon_zkapi_profile::{
    executable_sha256, to_hex, usdc_associated_token_address, vault_state_address,
    vault_token_address, SharedProfile,
};
use dagon_zkapi_vault::{token, VaultState};
use serde_json::{json, Value};
use solana_program::{
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    pubkey::Pubkey,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use zkapi_serverd::{
    config::{OpenRouterLeaseSourceConfig, ResolvedIdentity, ServerConfig},
    routes::{prepare_solana_backends, run_server},
    signer::ServerSigner,
    testnet_auth::TestnetPassword,
};
use zkapi_types::Felt252;

/// Deployed program bytes of the fixture; the profile pins their hash.
const PROGRAM_BYTES: &[u8] = &[1, 2, 3];
/// Byte offset of a classic SPL Token account's state.
const TOKEN_ACCOUNT_STATE_OFFSET: usize = 108;

struct Fixture {
    config: ServerConfig,
    vault: VaultState,
    /// USDC held by the vault token account.
    vault_token_balance: u64,
    accounts: HashMap<String, Value>,
    genesis: String,
}

fn account(owner: Pubkey, executable: bool, bytes: Vec<u8>) -> Value {
    json!({"owner":owner.to_string(),"executable":executable,
        "data":[base64::engine::general_purpose::STANDARD.encode(bytes),"base64"]})
}

/// An initialized classic SPL Token account.
fn token_account(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0; token::TOKEN_ACCOUNT_LEN];
    data[..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(owner.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[TOKEN_ACCOUNT_STATE_OFFSET] = token::ACCOUNT_STATE_INITIALIZED;
    data
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
        let (vault_token, vault_token_bump) =
            Pubkey::find_program_address(&[b"vault-token", vault_key.as_ref()], &program);
        assert_eq!(
            vault_token.to_bytes(),
            vault_token_address(&program.to_bytes(), &vault_key.to_bytes())
        );
        let genesis = [3; 32];
        let identity = ResolvedIdentity {
            genesis_hash: genesis,
            vault_authority: authority.to_bytes(),
            vault_state: vault_key.to_bytes(),
            treasury_token_account: usdc_associated_token_address(&[9; 32]),
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
            treasury_token: Pubkey::new_from_array(identity.treasury_token_account),
            mint: token::USDC_MINT,
            vault_token,
            vault_token_bump,
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
            deferred_payouts: 0,
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
            vault_token_balance: 0,
            accounts,
            genesis: bs58::encode(genesis).into_string(),
        }
    }

    fn vault_key(&self) -> String {
        bs58::encode(self.config.identity.vault_state).into_string()
    }

    fn vault_token_key(&self) -> String {
        self.vault.vault_token.to_string()
    }

    fn serialize_accounts(&mut self) {
        let mut data = Vec::new();
        self.vault.try_serialize(&mut data).unwrap();
        self.accounts.insert(
            self.vault_key(),
            account(dagon_zkapi_vault::ID, false, data),
        );
        let vault_key = Pubkey::new_from_array(self.config.identity.vault_state);
        self.accounts.insert(
            self.vault_token_key(),
            account(
                token::TOKEN_PROGRAM_ID,
                false,
                token_account(token::USDC_MINT, vault_key, self.vault_token_balance),
            ),
        );
    }
}

#[derive(Clone)]
struct Rpc {
    accounts: Arc<Mutex<HashMap<String, Value>>>,
    genesis: String,
    wrong_id: bool,
    unavailable: bool,
}
async fn rpc(State(state): State<Rpc>, Json(request): Json<Value>) -> Json<Value> {
    if state.unavailable {
        return Json(json!({"jsonrpc":"2.0","id":1,"error":{"code":-1}}));
    }
    let result = match request["method"].as_str().unwrap() {
        "getGenesisHash" => json!(state.genesis),
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
    task: tokio::task::JoinHandle<()>,
}

async fn start_rpc(
    f: &mut Fixture,
    mutate: impl FnOnce(&mut HashMap<String, Value>),
    wrong_id: bool,
    unavailable: bool,
) -> MockRpc {
    f.serialize_accounts();
    mutate(&mut f.accounts);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.config.rpc_url = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new().route("/", post(rpc)).with_state(Rpc {
        accounts: Arc::new(Mutex::new(f.accounts.clone())),
        genesis: f.genesis.clone(),
        wrong_id,
        unavailable,
    });
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    MockRpc { task }
}

/// The startup gate reads only the finalized program and vault (with its
/// USDC token account); no price source is involved and no state is opened.
#[tokio::test]
async fn complete_finalized_preflight_is_separate_from_database() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("not-opened.db");
    let mut f = Fixture::new(db.to_string_lossy().into_owned());
    // Donated surplus beyond the vault's liabilities is not a mismatch.
    f.vault_token_balance = 5;
    let rpc = start_rpc(&mut f, |_| {}, false, false).await;
    let signer = ServerSigner::new(&f.config.state_seed, &f.config.clear_seed);
    let backends = prepare_solana_backends(&f.config, &signer).await.unwrap();
    assert_eq!(backends.initial_root, Felt252::from_u64(44));
    let asset = &backends.ledger.deployment().asset;
    assert_eq!(asset.symbol, "USDC");
    assert_eq!(asset.decimals, 6);
    assert_eq!(
        asset.mint.as_ref().map(|mint| mint.0),
        Some(token::USDC_MINT.to_bytes())
    );
    assert!(!db.exists());
    rpc.task.abort();
}

#[tokio::test]
async fn invalid_authoritative_reads_fail_before_database_creation() {
    for case in 0..27 {
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
            10 => f.vault.authority = Pubkey::new_from_array([2; 32]),
            11 => f.vault.challenge_period -= 1,
            12 => f.vault.note_ttl -= 1,
            // The vault pins another treasury token account than the identity.
            13 => f.vault.treasury_token = Pubkey::new_from_array([2; 32]),
            14 => f.vault.mint = Pubkey::new_from_array([2; 32]),
            // A vault token account other than the canonical PDA.
            15 => f.vault.vault_token = Pubkey::new_from_array([2; 32]),
            // The profile pins other program bytes.
            16 => f.config.profile.program.executable_sha256 = to_hex(&[0x11; 32]),
            _ => {}
        }
        let vault_key = f.vault_key();
        let vault_token_key = f.vault_token_key();
        let program_data_key =
            bpf_loader_upgradeable::get_program_data_address(&dagon_zkapi_vault::ID).to_string();
        let vault_pda = Pubkey::new_from_array(f.config.identity.vault_state);
        let rpc = start_rpc(
            &mut f,
            |accounts| match case {
                17 => {
                    accounts.get_mut(&vault_key).unwrap()["owner"] =
                        Pubkey::new_from_array([6; 32]).to_string().into()
                }
                18 => {
                    accounts.remove(&vault_token_key);
                }
                // A Token-2022 vault token account is never the vault's.
                19 => {
                    accounts.get_mut(&vault_token_key).unwrap()["owner"] =
                        token::TOKEN_2022_PROGRAM_ID.to_string().into()
                }
                20 => {
                    *accounts.get_mut(&vault_token_key).unwrap() = account(
                        token::TOKEN_PROGRAM_ID,
                        false,
                        token_account(Pubkey::new_from_array([2; 32]), vault_pda, 0),
                    )
                }
                21 => {
                    *accounts.get_mut(&vault_token_key).unwrap() = account(
                        token::TOKEN_PROGRAM_ID,
                        false,
                        token_account(token::USDC_MINT, Pubkey::new_from_array([2; 32]), 0),
                    )
                }
                22 => {
                    accounts
                        .get_mut(&dagon_zkapi_vault::ID.to_string())
                        .unwrap()["executable"] = false.into()
                }
                23 => {
                    accounts
                        .get_mut(&dagon_zkapi_vault::ID.to_string())
                        .unwrap()["owner"] = Pubkey::new_from_array([6; 32]).to_string().into()
                }
                24 => {
                    accounts.get_mut(&program_data_key).unwrap()["data"][0] =
                        base64::engine::general_purpose::STANDARD
                            .encode(program_data(
                                Some(Pubkey::new_from_array([7; 32])),
                                PROGRAM_BYTES,
                            ))
                            .into();
                }
                // Immutable, but not the profile's executable.
                25 => {
                    accounts.get_mut(&program_data_key).unwrap()["data"][0] =
                        base64::engine::general_purpose::STANDARD
                            .encode(program_data(None, &[1, 2, 4]))
                            .into();
                }
                26 => {
                    accounts.remove(&program_data_key);
                }
                _ => {}
            },
            false,
            false,
        )
        .await;
        let result = run_server(f.config).await;
        assert!(result.is_err(), "case {case} unexpectedly passed");
        assert!(!db.exists(), "case {case} opened state");
        rpc.task.abort();
    }
    // A mismatched JSON-RPC id and an unavailable RPC fail the same way.
    for (wrong_id, unavailable) in [(true, false), (false, true)] {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("must-not-exist.db");
        let mut f = Fixture::new(db.to_string_lossy().into_owned());
        let rpc = start_rpc(&mut f, |_| {}, wrong_id, unavailable).await;
        assert!(run_server(f.config).await.is_err());
        assert!(!db.exists());
        rpc.task.abort();
    }
}

#[test]
fn identity_and_profile_bounds_reject_before_transport() {
    let f = Fixture::new("unused.db".into());
    f.config.validate().unwrap();
    for case in 0..4 {
        let mut config = f.config.clone();
        match case {
            0 => config.identity.vault_state = [1; 32],
            1 => config.identity.vault_authority = [1; 32],
            2 => config.profile.vault.challenge_period_seconds = 3_600,
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
