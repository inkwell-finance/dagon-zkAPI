//! Test-only commands for a disposable local validator (feature `dev`; never in a release build).
//!
//! `keygen`/`airdrop`/`vault_init` stand up a vault with throwaway keypairs, and the `pyth_*` commands write a hand-built
//! `PriceUpdateV2` through the mock updater program (see solana/dev/mock-pyth-writer). That is a mock oracle: no
//! Wormhole/guardian verification happens. The commands that talk to a chain accept ONE explicitly named loopback validator.

use anchor_lang::{AccountDeserialize, AccountSerialize, InstructionData, Owner, ToAccountMetas};
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use dagon_zkapi_ledger::{CreditLedger, DepositRequest, LedgerAccount, LedgerCommitment, PreparedLedgerOperation};
use dagon_zkapi_solana_ledger::{SolanaCreditLedger, SolanaLedgerConfig};
use dagon_zkapi_vault as vault_program;
use pyth_solana_receiver_sdk::price_update::{PriceFeedMessage, PriceUpdateV2, VerificationLevel};
use serde_json::{json, Value};
use solana_keypair::Keypair;
use solana_program::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use solana_signer::Signer;
use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use zkapi_browser::{BrowserWalletConfig, ConfirmDepositArgs, TreeSnapshot};
use zkapi_proof::compact::{CompactSigner, CIRCUIT_ID};
use zkapi_types::Felt252;

use crate::chain::Chain;
use crate::driver::{read_keypair, Deployment, WalletDriver, SOLANA_BACKEND};

/// The sponsored Pyth SOL/USD feed ID (the same constant the clientd defaults and serverd quote use).
const SOL_USD_FEED_ID: &str = "0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";

#[derive(Default)]
pub struct DevState {
    chain: Option<Chain>,
    payer: Option<Keypair>,
}

fn compute_budget_instructions(units: u32, heap_bytes: u32) -> [Instruction; 2] {
    let program_id = Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap();
    let with = |tag: u8, value: u32| {
        let mut data = vec![tag];
        data.extend_from_slice(&value.to_le_bytes());
        Instruction { program_id, accounts: vec![], data }
    };
    [with(1, heap_bytes), with(2, units)]
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn price_update_bytes(authority: Pubkey, price: i64, conf: u64, exponent: i32, posted_slot: u64) -> Result<Vec<u8>> {
    let now = unix_now();
    let update = PriceUpdateV2 {
        write_authority: authority,
        verification_level: VerificationLevel::Full,
        price_message: PriceFeedMessage {
            feed_id: hex::decode(&SOL_USD_FEED_ID[2..])?.try_into().map_err(|_| anyhow::anyhow!("feed id"))?,
            price,
            conf,
            exponent,
            publish_time: now,
            prev_publish_time: now - 1,
            ema_price: price,
            ema_conf: conf,
        },
        posted_slot,
    };
    let mut data = Vec::new();
    update.try_serialize(&mut data)?;
    data.resize(PriceUpdateV2::LEN, 0);
    Ok(data)
}

async fn send_operation(chain: &Chain, operation: PreparedLedgerOperation, signer: &Keypair) -> Result<String> {
    ensure!(!operation.transactions.is_empty(), "empty ledger operation");
    let mut last = None;
    for transaction in operation.transactions {
        ensure!(transaction.required_signers == vec![LedgerAccount::new(signer.pubkey().to_bytes())], "unexpected required signer");
        last = Some(chain.send_message(transaction.bytes, signer, false).await?);
    }
    Ok(last.unwrap())
}

fn loopback_chain(rpc: &str) -> Result<Chain> {
    ensure!(
        rpc.starts_with("http://127.0.0.1:") || rpc.starts_with("http://localhost:"),
        "this helper only talks to a loopback validator"
    );
    Chain::new(rpc)
}

impl WalletDriver {
    fn dev_chain(&self) -> Result<&Chain> {
        self.dev.chain.as_ref().context("run chain_connect first")
    }

    pub fn handle_dev(&mut self, command: &Value) -> Result<Value> {
        match command["command"].as_str().context("command must be a string")? {
            "public_keys" => Ok(json!({
                "state_signing_key": CompactSigner::from_seed(&Felt252::from_u64(1)).public_key(),
                "clearance_signing_key": CompactSigner::from_seed(&Felt252::from_u64(2)).public_key(),
                "circuit_id": CIRCUIT_ID,
            })),
            "keygen" => {
                let path = command["path"].as_str().context("path")?;
                let keypair = if std::path::Path::new(path).exists() {
                    read_keypair(path)?
                } else {
                    let keypair = Keypair::new();
                    std::fs::write(path, serde_json::to_vec(&keypair.to_bytes().to_vec())?)?;
                    keypair
                };
                Ok(json!({"pubkey": keypair.pubkey().to_string()}))
            }
            "chain_connect" => {
                let chain = loopback_chain(command["rpc_url"].as_str().context("rpc_url")?)?;
                let genesis = self.rt.block_on(chain.call("getGenesisHash", json!([])))?;
                self.dev.chain = Some(chain);
                Ok(json!({"genesis_hash": genesis}))
            }
            "airdrop" => {
                let pubkey = command["pubkey"].as_str().context("pubkey")?;
                let lamports = command["lamports"].as_u64().context("lamports")?;
                let chain = self.dev_chain()?;
                self.rt.block_on(async {
                    let signature = chain.call("requestAirdrop", json!([pubkey, lamports])).await?;
                    chain.wait(signature.as_str().context("signature")?, false).await
                })?;
                Ok(json!({"airdropped": lamports}))
            }
            "vault_init" => {
                ensure!(self.deployment.is_none(), "vault already initialized");
                let payer = read_keypair(command["keypair"].as_str().context("keypair")?)?;
                let cap = command["request_charge_cap"].as_u64().context("request_charge_cap")?;
                let chain = self.dev_chain()?;
                let genesis = self.rt.block_on(chain.call("getGenesisHash", json!([])))?;
                let genesis_hash = Hash::from_str(genesis.as_str().context("genesis")?)?.to_bytes();
                let state_key = CompactSigner::from_seed(&Felt252::from_u64(1)).public_key();
                let clear_key = CompactSigner::from_seed(&Felt252::from_u64(2)).public_key();
                let (vault, _) = Pubkey::find_program_address(&[b"vault", payer.pubkey().as_ref()], &vault_program::ID);
                let initialize = Instruction {
                    program_id: vault_program::ID,
                    accounts: vault_program::accounts::Initialize {
                        vault,
                        authority: payer.pubkey(),
                        treasury: payer.pubkey(),
                        system_program: anchor_lang::system_program::ID,
                    }
                    .to_account_metas(None),
                    data: vault_program::instruction::Initialize {
                        args: vault_program::InitializeArgs {
                            genesis_hash,
                            note_ttl: command["note_ttl"].as_u64().unwrap_or(30 * 86_400),
                            challenge_period: command["challenge_period"].as_u64().unwrap_or(86_400),
                            request_charge_cap: cap,
                            state_signing_key_x: *state_key.x.as_bytes(),
                            state_signing_key_y: *state_key.y.as_bytes(),
                            clearance_signing_key_x: *clear_key.x.as_bytes(),
                            clearance_signing_key_y: *clear_key.y.as_bytes(),
                        },
                    }
                    .data(),
                };
                // Initialize needs more than the default 200k units on some genesis hashes (observed: exceeded the meter on
                // 1 of 4 fresh validators), so request the same budget the ledger's own operations use.
                let budget = compute_budget_instructions(1_400_000, 128 * 1_024);
                self.rt.block_on(chain.send_instructions(&[budget[0].clone(), budget[1].clone(), initialize], &payer, true))?;
                let ledger_config = SolanaLedgerConfig {
                    rpc_url: chain.rpc.clone(),
                    indexer_url: None,
                    network: "localnet".into(),
                    program_id: vault_program::ID.to_bytes(),
                    vault_state: vault.to_bytes(),
                    genesis_hash,
                };
                let ledger = SolanaCreditLedger::new(ledger_config.clone())?;
                let deployment = ledger.deployment().clone();
                let rpc = chain.rpc.clone();
                self.config = Some(BrowserWalletConfig {
                    protocol_version: 2,
                    ledger_backend: SOLANA_BACKEND.into(),
                    chain_id: deployment.chain_id,
                    contract_address: deployment.protocol_binding,
                    request_charge_cap: u128::from(cap),
                    policy_charge_cap: 0,
                    policy_enabled: false,
                    state_signing_key: state_key,
                    clearance_signing_key: clear_key,
                });
                self.dev.payer = Some(payer);
                self.deployment = Some(Deployment { ledger, ledger_config, chain: Chain::new(&rpc)?, program: vault_program::ID, vault });
                Ok(json!({
                    "program_id": vault_program::ID.to_string(),
                    "vault_state": vault.to_string(),
                    "genesis_hash": genesis,
                    "chain_id": deployment.chain_id.to_string(),
                }))
            }
            "attach_indexer" => {
                // Whole-tree snapshots (deposit paths) come from the finalized-account indexer, as in production.
                let deployment = self.deployment.as_mut().context("run vault_init first")?;
                let url = command["indexer_url"].as_str().context("indexer_url")?;
                ensure!(url.starts_with("http://127.0.0.1:"), "loopback indexer only");
                deployment.ledger_config.indexer_url = Some(url.to_string());
                deployment.ledger = SolanaCreditLedger::new(deployment.ledger_config.clone())?;
                Ok(json!({"indexer_url": url}))
            }
            "deposit" => {
                ensure!(self.state.is_none(), "wallet already has a note");
                let amount = command["amount"].as_u64().context("amount")?;
                let deployment = self.deployment.as_ref().context("run vault_init first")?;
                let payer = self.dev.payer.as_ref().context("run vault_init first")?;
                let config = self.config.as_ref().context("run vault_init first")?;
                let params = zkapi_browser::generate_deposit_params();
                let state = self.rt.block_on(async {
                    let snapshot = deployment.ledger.snapshot(LedgerCommitment::Finalized).await?;
                    let note_id = snapshot.state.next_note_id;
                    let path = zkapi_browser::tree_path(
                        TreeSnapshot { root: snapshot.state.root, next_note_id: note_id, leaves: snapshot.leaves },
                        note_id,
                        false,
                    )?;
                    let operation = deployment
                        .ledger
                        .prepare_deposit(DepositRequest {
                            payer: LedgerAccount::new(payer.pubkey().to_bytes()),
                            expected_note_id: note_id,
                            commitment: params.registration_commitment,
                            amount: u128::from(amount),
                            zero_path: path.siblings.try_into().map_err(|_| anyhow::anyhow!("path length"))?,
                        })
                        .await?;
                    let signature = send_operation(&deployment.chain, operation, payer).await?;
                    deployment.chain.wait(&signature, true).await?;
                    let (note_address, _) =
                        Pubkey::find_program_address(&[b"note", deployment.vault.as_ref(), &note_id.to_le_bytes()], &vault_program::ID);
                    let (_, data) = deployment.chain.account(&note_address, "finalized").await?.context("note account missing")?;
                    let note = vault_program::NoteState::try_deserialize(&mut data.as_slice())?;
                    ensure!(note.deposit_amount == amount, "on-chain deposit amount mismatch");
                    zkapi_browser::confirm_deposit(
                        config,
                        ConfirmDepositArgs { secret: params.secret, note_id, amount: u128::from(amount), expiry_ts: note.expiry },
                    )
                })?;
                self.state = Some(state);
                Ok(self.status())
            }
            "vault_snapshot" => {
                let deployment = self.deployment.as_ref().context("run vault_init first")?;
                let snapshot = self.rt.block_on(deployment.ledger.snapshot(LedgerCommitment::Finalized))?;
                let lamports = self.rt.block_on(deployment.chain.call(
                    "getBalance",
                    json!([deployment.vault.to_string(), {"commitment":"finalized"}]),
                ))?;
                Ok(json!({
                    "root": snapshot.state.root,
                    "next_note_id": snapshot.state.next_note_id,
                    "vault_lamports": lamports["value"],
                }))
            }
            "balance" => {
                let chain = self.dev_chain()?;
                let address = Pubkey::from_str(command["pubkey"].as_str().context("pubkey")?)?;
                let lamports = self.rt.block_on(chain.lamports(&address, "finalized"))?;
                Ok(json!({"lamports": lamports}))
            }
            "pyth_account_file" => {
                // Initial price account for `solana-test-validator --account`; owned by the receiver program.
                let (address, path) = (command["address"].as_str().context("address")?, command["path"].as_str().context("path")?);
                let authority = Pubkey::from_str(command["authority"].as_str().context("authority")?)?;
                let data = price_update_bytes(
                    authority,
                    command["price"].as_i64().context("price")?,
                    command["conf"].as_u64().context("conf")?,
                    command["exponent"].as_i64().context("exponent")? as i32,
                    1,
                )?;
                let account = json!({"pubkey": address, "account": {
                    "lamports": 10_000_000u64,
                    "data": [base64::engine::general_purpose::STANDARD.encode(&data), "base64"],
                    "owner": PriceUpdateV2::owner().to_string(),
                    "executable": false, "rentEpoch": 0u64, "space": data.len()}});
                std::fs::write(path, serde_json::to_vec(&account)?)?;
                Ok(json!({"space": data.len(), "owner": PriceUpdateV2::owner().to_string()}))
            }
            "pyth_update" => {
                let payer = read_keypair(command["keypair"].as_str().context("keypair")?)?;
                let address = Pubkey::from_str(command["address"].as_str().context("address")?)?;
                let chain = self.dev_chain()?;
                self.rt.block_on(async {
                    // posted_slot must not exceed the finalized read's context slot.
                    let slot = chain.call("getSlot", json!([{"commitment":"finalized"}])).await?;
                    let data = price_update_bytes(
                        payer.pubkey(),
                        command["price"].as_i64().context("price")?,
                        command["conf"].as_u64().context("conf")?,
                        command["exponent"].as_i64().context("exponent")? as i32,
                        slot.as_u64().context("slot")?,
                    )?;
                    chain
                        .send_instructions(
                            &[Instruction { program_id: PriceUpdateV2::owner(), accounts: vec![AccountMeta::new(address, false)], data }],
                            &payer,
                            false,
                        )
                        .await
                })?;
                Ok(json!({"updated": true}))
            }
            "init" => {
                ensure!(self.config.is_none(), "wallet is already initialized");
                let config: BrowserWalletConfig = serde_json::from_value(command["config"].clone())?;
                ensure!(config.protocol_version == 2, "only protocol v2 is supported");
                ensure!(!config.contract_address.is_zero(), "vault binding is required");
                self.config = Some(config);
                Ok(self.status())
            }
            "discard_request" => {
                // Only after serverd answered a retriable 409 that reserved nothing (native_quote_stale):
                // mirrors the browser SDK clearing its journal once the server confirms non-acceptance.
                self.journal = None;
                Ok(self.status())
            }
            "wallet_snapshot_tree" => {
                // Whole-tree snapshot straight from the finalized vault accounts (no indexer needed).
                let deployment = self.deployment.as_ref().context("run vault_init first")?;
                let snapshot = self.rt.block_on(deployment.ledger.snapshot(LedgerCommitment::Finalized))?;
                Ok(json!({"root": snapshot.state.root, "next_note_id": snapshot.state.next_note_id, "leaves": snapshot.leaves}))
            }
            _ => bail!("unsupported command"),
        }
    }
}
