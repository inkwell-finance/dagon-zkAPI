//! Profile-bound initialization and chain observations shared with the local lifecycle test.
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use dagon_zkapi_profile::{
    effective_profile, executable_sha256, to_hex, vault_token_address, NetworkIdentity,
    SharedProfile, UPGRADEABLE_LOADER,
};
use dagon_zkapi_vault as vault;
use serde_json::{json, Map, Value};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use std::{str::FromStr, sync::LazyLock, time::Duration};
use zkapi_proof::compact::CompactSigner;

pub const FEATURE_PROGRAM: &str = "Feature111111111111111111111111111111111111";
/// The non-upgradeable BPF loader (v2) that owns the classic Token and ATA
/// programs on mainnet.
pub const BPF_LOADER_2: &str = "BPFLoader2111111111111111111111111111111111";
// FEATURE_NAMES from the exact release, not every historical Feature account.
// The explicitly enumerated retired IDs were confirmed absent from that source.
static RUNTIME_FEATURES: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("agave-4.4.1-features.json"))
        .expect("pinned Agave feature registry")
});

pub fn initialize_instruction(
    profile: &SharedProfile,
    identity: &NetworkIdentity,
    state: &CompactSigner,
    clearance: &CompactSigner,
) -> Result<Instruction> {
    let id = identity.resolve(profile)?;
    let s = state.public_key();
    let c = clearance.public_key();
    let program_id = profile.program_id();
    Ok(Instruction {
        program_id: Pubkey::new_from_array(program_id),
        accounts: vault::accounts::Initialize {
            vault: Pubkey::new_from_array(id.vault_state),
            authority: Pubkey::new_from_array(id.vault_authority),
            treasury_token: Pubkey::new_from_array(id.treasury_token_account),
            mint: Pubkey::new_from_array(profile.usdc_mint()),
            vault_token: Pubkey::new_from_array(vault_token_address(&program_id, &id.vault_state)),
            token_program: Pubkey::new_from_array(profile.token_program()),
            system_program: anchor_lang::system_program::ID,
        }
        .to_account_metas(None),
        data: vault::instruction::Initialize {
            args: vault::InitializeArgs {
                genesis_hash: id.genesis_hash,
                note_ttl: profile.vault.note_ttl_seconds,
                challenge_period: profile.vault.challenge_period_seconds,
                request_charge_cap: profile.vault.request_charge_cap,
                state_signing_key_x: *s.x.as_bytes(),
                state_signing_key_y: *s.y.as_bytes(),
                clearance_signing_key_x: *c.x.as_bytes(),
                clearance_signing_key_y: *c.y.as_bytes(),
            },
        }
        .data(),
    })
}

pub struct Rpc {
    client: reqwest::Client,
    pub url: String,
}
pub struct Account {
    pub owner: String,
    pub executable: bool,
    pub data: Vec<u8>,
}
impl Rpc {
    pub fn new(url: String) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            url,
        })
    }
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let v: Value = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if let Some(e) = v.get("error") {
            bail!("{method}: {e}");
        }
        v.get("result")
            .cloned()
            .context("RPC response has no result")
    }
    async fn optional_account(&self, address: &str) -> Result<Option<Account>> {
        let v = self
            .call(
                "getAccountInfo",
                json!([address,{"encoding":"base64","commitment":"finalized"}]),
            )
            .await?;
        let a = v
            .get("value")
            .context("RPC account response has no value")?;
        if a.is_null() {
            return Ok(None);
        }
        Ok(Some(Account {
            owner: a["owner"].as_str().context("account owner")?.into(),
            executable: a["executable"].as_bool().context("account executable")?,
            data: base64::engine::general_purpose::STANDARD
                .decode(a["data"][0].as_str().context("account data")?)?,
        }))
    }
    pub async fn account(&self, address: &str) -> Result<Account> {
        self.optional_account(address)
            .await?
            .with_context(|| format!("account {address} is absent"))
    }
    pub async fn check_genesis(&self, identity: &NetworkIdentity) -> Result<()> {
        ensure!(
            self.call("getGenesisHash", json!([])).await? == identity.genesis_hash,
            "RPC genesis differs from identity"
        );
        Ok(())
    }
    pub async fn program(&self, address: &str) -> Result<Value> {
        let program = self.account(address).await?;
        self.program_account(address, program).await
    }
    /// A program owned by either the non-upgradeable BPF loader (the bytes
    /// are the account data) or the upgradeable loader (the bytes follow the
    /// ProgramData metadata, and the upgrade authority is reported too).
    pub async fn any_loader_program(&self, address: &str) -> Result<Value> {
        let program = self.account(address).await?;
        if program.owner == BPF_LOADER_2 {
            ensure!(program.executable, "{address}: not executable");
            return Ok(json!({
                "loader": BPF_LOADER_2, "executable": true,
                "executable_sha256": to_hex(&executable_sha256(&program.data))
            }));
        }
        self.program_account(address, program).await
    }
    async fn program_account(&self, address: &str, program: Account) -> Result<Value> {
        ensure!(
            program.executable && program.owner == UPGRADEABLE_LOADER,
            "{address}: not an upgradeable-loader executable"
        );
        ensure!(
            program.data.len() == 36 && program.data[..4] == 2u32.to_le_bytes(),
            "invalid loader Program account"
        );
        let data_address = Pubkey::new_from_array(program.data[4..36].try_into()?);
        let data = self.account(&data_address.to_string()).await?;
        ensure!(
            data.owner == UPGRADEABLE_LOADER && !data.executable,
            "invalid ProgramData owner/executable"
        );
        decode_program_data(&data.data)
    }
    pub async fn active_features(&self) -> Result<Vec<String>> {
        let result = self
            .call(
                "getProgramAccounts",
                json!([FEATURE_PROGRAM, {
                    "encoding":"base64", "commitment":"finalized", "withContext":true
                }]),
            )
            .await?;
        decode_active_features(&result)
    }
}

/// Compare IDs, not activation slots: the local genesis activates the same
/// runtime features at slot zero. A future scheduled activation is not active.
pub fn decode_active_features(result: &Value) -> Result<Vec<String>> {
    let slot = result["context"]["slot"]
        .as_u64()
        .context("feature observation slot")?;
    let accounts = result["value"].as_array().context("feature account list")?;
    let mut active = Vec::with_capacity(accounts.len());
    for entry in accounts {
        let account = &entry["account"];
        ensure!(
            account["owner"] == FEATURE_PROGRAM && account["executable"] == false,
            "invalid feature account owner/executable"
        );
        let data = base64::engine::general_purpose::STANDARD
            .decode(account["data"][0].as_str().context("feature data")?)?;
        match data.first() {
            Some(0) => {}
            Some(1) if data.len() == 9 => {
                if u64::from_le_bytes(data[1..9].try_into()?) <= slot {
                    let key = entry["pubkey"].as_str().context("feature pubkey")?;
                    Pubkey::from_str(key).context("invalid feature pubkey")?;
                    active.push(key.to_owned());
                }
            }
            _ => bail!("invalid feature activation encoding"),
        }
    }
    active.sort_unstable();
    ensure!(
        active.windows(2).all(|pair| pair[0] != pair[1]),
        "duplicate feature accounts"
    );
    Ok(active)
}

fn known_active_features(active: &[String]) -> Result<Vec<&str>> {
    let known = RUNTIME_FEATURES["feature_ids"].as_array().unwrap();
    let retired = RUNTIME_FEATURES["retired_in_software"].as_array().unwrap();
    let contains = |set: &[Value], key: &str| {
        set.binary_search_by(|v| v.as_str().unwrap().cmp(key))
            .is_ok()
    };
    let mut result = Vec::with_capacity(active.len());
    for key in active {
        if contains(known, key) {
            result.push(key.as_str());
        } else {
            ensure!(contains(retired, key), "unclassified active feature {key}: update the pinned software/registry; refusing parity");
        }
    }
    Ok(result)
}

async fn runtime_observation(rpc: &Rpc, expected: bool) -> Result<Value> {
    let local_version = rpc.call("getVersion", json!([])).await?;
    let mainnet_version = if expected {
        local_version.clone()
    } else {
        ensure!(
            local_version["solana-core"] == RUNTIME_FEATURES["version"],
            "local validator must be the pinned Agave release"
        );
        Rpc::new(
            std::env::var("MAINNET_RPC_URL")
                .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".into()),
        )?
        .call("getVersion", json!([]))
        .await?
    };
    ensure!(
        mainnet_version["solana-core"]
            .as_str()
            .is_some_and(|v| v.starts_with("4.4.")),
        "mainnet software release changed; review the pinned runtime"
    );
    let active = rpc.active_features().await?;
    Ok(json!({
        "software_version":RUNTIME_FEATURES["version"],
        "mainnet_get_version":mainnet_version,
        "active_feature_ids":known_active_features(&active)?,
        "retired_in_software":RUNTIME_FEATURES["retired_in_software"],
        "feature_registry_git_blob":RUNTIME_FEATURES["source_git_blob"]
    }))
}

pub fn decode_program_data(data: &[u8]) -> Result<Value> {
    ensure!(
        data.len() > 45 && data[..4] == 3u32.to_le_bytes(),
        "invalid ProgramData account"
    );
    let authority = match data[12] {
        0 => Value::Null,
        1 => json!(Pubkey::new_from_array(data[13..45].try_into()?).to_string()),
        _ => bail!("invalid upgrade authority option"),
    };
    Ok(
        json!({"loader":UPGRADEABLE_LOADER,"executable":true,"upgrade_authority":authority,"executable_sha256":to_hex(&executable_sha256(&data[45..]))}),
    )
}

/// Classic SPL Token account layout (165 bytes): the fields parity relies on.
pub struct TokenAccount {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    /// 1 = initialized, 2 = frozen.
    pub state: u8,
    pub is_native: bool,
    pub close_authority: Option<Pubkey>,
}

fn coption_pubkey(data: &[u8]) -> Result<Option<Pubkey>> {
    match u32::from_le_bytes(data[..4].try_into()?) {
        0 => Ok(None),
        1 => Ok(Some(Pubkey::new_from_array(data[4..36].try_into()?))),
        _ => bail!("invalid COption tag"),
    }
}

/// Decode a classic-Token account; any other owner or layout is rejected.
pub fn decode_token_account(profile: &SharedProfile, account: &Account) -> Result<TokenAccount> {
    ensure!(
        account.owner == profile.asset.token_program && !account.executable,
        "token account is not owned by the classic Token program"
    );
    let d = &account.data;
    ensure!(d.len() == 165, "invalid token account length");
    let state = d[108];
    ensure!(state == 1 || state == 2, "token account is not initialized");
    Ok(TokenAccount {
        mint: Pubkey::new_from_array(d[..32].try_into()?),
        owner: Pubkey::new_from_array(d[32..64].try_into()?),
        amount: u64::from_le_bytes(d[64..72].try_into()?),
        delegate: coption_pubkey(&d[72..108])?,
        state,
        is_native: match u32::from_le_bytes(d[109..113].try_into()?) {
            0 => false,
            1 => true,
            _ => bail!("invalid is_native tag"),
        },
        close_authority: coption_pubkey(&d[129..165])?,
    })
}

/// The mint facts both networks must share. Supply legitimately differs
/// (the local mint is a clone frozen at clone time) and is not reported.
pub fn decode_mint(address: &str, account: &Account) -> Result<Value> {
    let d = &account.data;
    ensure!(d.len() == 82, "invalid mint length");
    let authority = |option: Option<Pubkey>| option.map_or(Value::Null, |k| json!(k.to_string()));
    Ok(json!({
        "address": address,
        "owner": account.owner,
        "executable": account.executable,
        "decimals": d[44],
        "is_initialized": match d[45] { 0 => false, 1 => true, _ => bail!("invalid mint is_initialized") },
        "mint_authority": authority(coption_pubkey(&d[..36])?),
        "freeze_authority": authority(coption_pubkey(&d[46..82])?),
    }))
}

/// The USDC facts parity compares: the mint account (owner, decimals,
/// initialization, mint and freeze authorities) and the executables of the
/// classic Token and ATA programs, read from the observed chain.
pub async fn asset_observation(rpc: &Rpc, profile: &SharedProfile) -> Result<Value> {
    let mint = rpc.account(&profile.asset.mint).await?;
    Ok(json!({
        "mint": decode_mint(&profile.asset.mint, &mint)?,
        "token_program": rpc.any_loader_program(&profile.asset.token_program).await?,
        "associated_token_program": rpc.any_loader_program(&profile.asset.associated_token_program).await?,
    }))
}

/// The vault's token-account facts that hold on every correct deployment:
/// the pinned mint, the canonical vault-token PDA (classic Token, USDC,
/// token authority = the vault, no delegate or close authority) and an
/// initialized, unfrozen classic-USDC treasury account. Balances and the
/// treasury's owner are per-deployment and not reported.
pub fn vault_token_facts(profile: &SharedProfile) -> Value {
    json!({
        "mint": profile.asset.mint,
        "vault_token": {
            "canonical_pda": true, "token_program": profile.asset.token_program,
            "mint": profile.asset.mint, "authority_is_vault": true, "state": "initialized",
            "is_native": false, "delegate": null, "close_authority": null
        },
        "treasury_token": {
            "token_program": profile.asset.token_program, "mint": profile.asset.mint,
            "state": "initialized", "is_native": false
        }
    })
}

/// Decode the vault: identity fields go into `identity`, the shared vault
/// parameters are returned with the state for the token-account checks.
pub fn decode_vault(
    data: &[u8],
    identity: &mut Map<String, Value>,
) -> Result<(Value, vault::VaultState)> {
    let v = vault::VaultState::try_deserialize(&mut &*data).context("invalid VaultState")?;
    identity.insert("vault_authority".into(), json!(v.authority.to_string()));
    identity.insert(
        "treasury_token_account".into(),
        json!(v.treasury_token.to_string()),
    );
    identity.insert(
        "genesis_hash".into(),
        json!(bs58::encode(v.genesis_hash).into_string()),
    );
    identity.insert("chain_id".into(), json!(v.chain_id));
    identity.insert(
        "deployment_binding".into(),
        json!(to_hex(&v.protocol_binding)),
    );
    identity.insert(
        "state_signing_key".into(),
        json!([
            to_hex(&v.state_signing_key_x),
            to_hex(&v.state_signing_key_y)
        ]),
    );
    identity.insert(
        "clearance_signing_key".into(),
        json!([
            to_hex(&v.clearance_signing_key_x),
            to_hex(&v.clearance_signing_key_y)
        ]),
    );
    Ok((
        json!({"version":v.version,"request_charge_cap":v.request_charge_cap,"note_ttl_seconds":v.note_ttl,"challenge_period_seconds":v.challenge_period,"paused":v.paused}),
        v,
    ))
}

/// Read the vault's token accounts and reduce them to [`vault_token_facts`]
/// form; anything that is not the canonical layout is reported as found.
pub async fn vault_token_observation(
    rpc: &Rpc,
    profile: &SharedProfile,
    vault_state: &Pubkey,
    vault_mint: &str,
    vault_token: &str,
    treasury_token: &str,
) -> Result<Value> {
    let state = |s: u8| if s == 1 { "initialized" } else { "frozen" };
    let canonical = Pubkey::new_from_array(vault_token_address(
        &profile.program_id(),
        &vault_state.to_bytes(),
    ));
    let held = rpc.account(vault_token).await?;
    let vt = decode_token_account(profile, &held).context("vault token account")?;
    let treasury = rpc.account(treasury_token).await?;
    let tt = decode_token_account(profile, &treasury).context("treasury token account")?;
    let key = |k: Option<Pubkey>| k.map_or(Value::Null, |k| json!(k.to_string()));
    Ok(json!({
        "mint": vault_mint,
        "vault_token": {
            "canonical_pda": vault_token == canonical.to_string(), "token_program": held.owner,
            "mint": vt.mint.to_string(), "authority_is_vault": vt.owner == *vault_state,
            "state": state(vt.state), "is_native": vt.is_native,
            "delegate": key(vt.delegate), "close_authority": key(vt.close_authority)
        },
        "treasury_token": {
            "token_program": treasury.owner, "mint": tt.mint.to_string(),
            "state": state(tt.state), "is_native": tt.is_native
        }
    }))
}

/// Validate a complete parity document independently of the other side.
/// Equality of two incomplete or identically misconfigured observations is
/// not evidence that either deployment implements the compiled profile.
pub fn validate_effective_profile(value: &Value) -> Result<()> {
    let p = SharedProfile::embedded();
    let object = value
        .as_object()
        .context("effective profile must be an object")?;
    ensure!(
        object.len() == 3 && object.contains_key("identity") && object.contains_key("observed"),
        "effective profile requires exactly profile, identity and observed"
    );
    ensure!(
        value["profile"] == p.to_value(),
        "shared profile differs from compiled profile"
    );
    let identity = value["identity"]
        .as_object()
        .context("identity must be an object")?;
    for (key, field) in identity {
        ensure!(
            dagon_zkapi_profile::IDENTITY_KEYS.contains(&key.as_str()),
            "unknown identity key {key}"
        );
        let valid = match key.as_str() {
            "chain_id" => field.as_u64().is_some(),
            "state_signing_key" | "clearance_signing_key" => field
                .as_array()
                .is_some_and(|parts| parts.len() == 2 && parts.iter().all(Value::is_string)),
            "vault_authority" | "vault_state" | "treasury_token_account" => {
                field.is_null() || field.is_string()
            }
            _ => field.is_string(),
        };
        ensure!(valid, "invalid identity value for {key}");
    }
    let mut declared = Map::new();
    declared.insert("schema".into(), json!(dagon_zkapi_profile::IDENTITY_SCHEMA));
    for key in [
        "network",
        "genesis_hash",
        "vault_authority",
        "vault_state",
        "treasury_token_account",
    ] {
        declared.insert(
            key.into(),
            identity
                .get(key)
                .with_context(|| format!("missing identity {key}"))?
                .clone(),
        );
    }
    let declared = NetworkIdentity::parse(&Value::Object(declared).to_string())?;
    if declared.vault_state.is_some() {
        declared.resolve(p)?;
    } else {
        ensure!(
            declared.network == dagon_zkapi_profile::MAINNET_BETA,
            "only the undeployed mainnet reference may omit vault accounts"
        );
    }
    ensure!(
        identity.get("rpc_url").is_some_and(Value::is_string),
        "missing identity RPC URL"
    );
    let observed = &value["observed"];
    ensure!(
        observed["program"]
            == json!({
                "loader": p.program.loader, "executable": true,
                "upgrade_authority": p.program.upgrade_authority,
                "executable_sha256": p.program.executable_sha256
            }),
        "observed program differs from compiled profile"
    );
    ensure!(
        observed["vault"]
            == json!({
                "version": p.vault.version, "request_charge_cap": p.vault.request_charge_cap,
                "note_ttl_seconds": p.vault.note_ttl_seconds,
                "challenge_period_seconds": p.vault.challenge_period_seconds, "paused": false,
                "tokens": vault_token_facts(p)
            }),
        "observed vault differs from compiled profile or is paused"
    );
    let asset = &observed["asset"];
    let mint = &asset["mint"];
    let optional_key =
        |v: &Value| v.is_null() || v.as_str().is_some_and(|s| Pubkey::from_str(s).is_ok());
    ensure!(
        mint["address"] == p.asset.mint
            && mint["owner"] == p.asset.token_program
            && mint["executable"] == false
            && mint["decimals"] == p.asset.decimals
            && mint["is_initialized"] == true
            && optional_key(&mint["mint_authority"])
            && optional_key(&mint["freeze_authority"])
            && mint.as_object().is_some_and(|m| m.len() == 7),
        "observed mint is not the profile's initialized classic-Token USDC mint"
    );
    for name in ["token_program", "associated_token_program"] {
        let program = &asset[name];
        let fields = program.as_object().map_or(0, Map::len);
        ensure!(
            program["executable"] == true
                && program["executable_sha256"]
                    .as_str()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                && ((program["loader"] == BPF_LOADER_2 && fields == 3)
                    || (program["loader"] == UPGRADEABLE_LOADER
                        && fields == 4
                        && (program["upgrade_authority"].is_null()
                            || program["upgrade_authority"].is_string()))),
            "missing or malformed asset program {name}"
        );
    }
    let runtime = &observed["runtime"];
    ensure!(
        runtime["software_version"] == RUNTIME_FEATURES["version"]
            && runtime["retired_in_software"] == RUNTIME_FEATURES["retired_in_software"]
            && runtime["feature_registry_git_blob"] == RUNTIME_FEATURES["source_git_blob"]
            && runtime["mainnet_get_version"]["solana-core"]
                .as_str()
                .is_some_and(|s| s.starts_with("4.4."))
            && runtime["mainnet_get_version"]["feature-set"]
                .as_u64()
                .is_some(),
        "missing or unsupported runtime observation"
    );
    let active: Vec<String> = serde_json::from_value(runtime["active_feature_ids"].clone())
        .context("missing or malformed active feature IDs")?;
    ensure!(
        !active.is_empty()
            && active.windows(2).all(|pair| pair[0] < pair[1])
            && known_active_features(&active)?.len() == active.len(),
        "active feature IDs must be nonempty, sorted, unique and known"
    );
    Ok(())
}

pub async fn observe(rpc: &Rpc, identity: &NetworkIdentity, expected: bool) -> Result<Value> {
    let p = SharedProfile::embedded();
    rpc.check_genesis(identity).await?;
    let mut id = serde_json::to_value(identity)?.as_object().unwrap().clone();
    id.remove("schema");
    id.insert("rpc_url".into(), json!(rpc.url));
    let program = if expected {
        match rpc.optional_account(&p.program.program_id).await? {
            Some(account) => rpc.program_account(&p.program.program_id, account).await?,
            None => {
                json!({"loader":p.program.loader,"executable":true,"upgrade_authority":p.program.upgrade_authority,"executable_sha256":p.program.executable_sha256})
            }
        }
    } else {
        rpc.program(&p.program.program_id).await?
    };
    let vault_observation = if expected && identity.vault_state.is_none() {
        json!({"version":p.vault.version,"request_charge_cap":p.vault.request_charge_cap,"note_ttl_seconds":p.vault.note_ttl_seconds,"challenge_period_seconds":p.vault.challenge_period_seconds,"paused":false,"tokens":vault_token_facts(p)})
    } else {
        let resolved = identity.resolve(p)?;
        let a = rpc
            .account(identity.vault_state.as_deref().unwrap())
            .await?;
        ensure!(
            a.owner == p.program.program_id && !a.executable,
            "vault owner/executable mismatch"
        );
        let (mut observation, state) = decode_vault(&a.data, &mut id)?;
        ensure!(
            id["vault_authority"] == identity.vault_authority.as_deref().unwrap()
                && id["treasury_token_account"]
                    == identity.treasury_token_account.as_deref().unwrap()
                && id["genesis_hash"] == identity.genesis_hash,
            "vault identity differs from declared identity"
        );
        ensure!(resolved.genesis_hash != [0; 32], "missing genesis");
        observation["tokens"] = vault_token_observation(
            rpc,
            p,
            &Pubkey::new_from_array(resolved.vault_state),
            &state.mint.to_string(),
            &state.vault_token.to_string(),
            &state.treasury_token.to_string(),
        )
        .await?;
        observation
    };
    let asset = asset_observation(rpc, p).await?;
    let observed = json!({"program":program,"vault":vault_observation,"asset":asset,"runtime":runtime_observation(rpc,expected).await?});
    let result = effective_profile(p, id, observed.as_object().unwrap().clone());
    validate_effective_profile(&result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::{Discriminator, Space};
    use dagon_zkapi_profile::parity_violations;
    #[test]
    fn runtime_registry_is_sorted_and_never_silently_ignores_unknown_features() {
        for name in ["feature_ids", "retired_in_software"] {
            let ids = RUNTIME_FEATURES[name].as_array().unwrap();
            assert!(ids.windows(2).all(|v| v[0].as_str() < v[1].as_str()));
            for id in ids {
                Pubkey::from_str(id.as_str().unwrap()).unwrap();
            }
        }
        let known = RUNTIME_FEATURES["feature_ids"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let retired = RUNTIME_FEATURES["retired_in_software"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let active = vec![known.clone(), retired];
        assert_eq!(
            known_active_features(&active).unwrap(),
            vec![known.as_str()]
        );
        assert!(known_active_features(&[Pubkey::default().to_string()]).is_err());
        assert_eq!(
            RUNTIME_FEATURES["feature_ids"].as_array().unwrap().len(),
            290
        );
    }
    #[test]
    fn feature_observations_sort_active_ids_and_reject_malformed_data() {
        let entry = |key: &str, activation: Option<u64>| {
            let mut data = vec![0; 9];
            if let Some(slot) = activation {
                data[0] = 1;
                data[1..].copy_from_slice(&slot.to_le_bytes());
            }
            json!({"pubkey":key,"account":{"owner":FEATURE_PROGRAM,"executable":false,"data":[base64::engine::general_purpose::STANDARD.encode(data),"base64"]}})
        };
        let a = Pubkey::new_from_array([1; 32]).to_string();
        let b = Pubkey::new_from_array([2; 32]).to_string();
        let mut response = json!({"context":{"slot":10},"value":[entry(&b,Some(10)),entry(&a,Some(0)),entry(FEATURE_PROGRAM,Some(11)),entry(&Pubkey::new_from_array([3; 32]).to_string(),None)]});
        let mut expected = vec![a, b];
        expected.sort_unstable();
        assert_eq!(decode_active_features(&response).unwrap(), expected);
        let local = json!({"observed":{"runtime":{"active_feature_ids":expected}}});
        let mut mainnet = local.clone();
        mainnet["observed"]["runtime"]["active_feature_ids"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(!parity_violations(&local, &mainnet).is_empty());
        response["value"][0]["account"]["data"][0] = json!("Ag==");
        assert!(decode_active_features(&response).is_err());
    }
    fn token_account(owner: &str, mint: Pubkey, authority: Pubkey, state: u8) -> Account {
        let mut data = vec![0; 165];
        data[..32].copy_from_slice(mint.as_ref());
        data[32..64].copy_from_slice(authority.as_ref());
        data[64..72].copy_from_slice(&7u64.to_le_bytes());
        data[108] = state;
        Account {
            owner: owner.into(),
            executable: false,
            data,
        }
    }
    #[test]
    fn decoders_preserve_security_fields_and_separate_identity() {
        let p = SharedProfile::embedded();
        let mint = Pubkey::new_from_array(p.usdc_mint());
        let authority = Pubkey::new_from_array([4; 32]);
        let account = token_account(&p.asset.token_program, mint, authority, 2);
        let decoded = decode_token_account(p, &account).unwrap();
        assert_eq!(
            (decoded.mint, decoded.owner, decoded.amount),
            (mint, authority, 7)
        );
        assert_eq!(decoded.state, 2);
        assert!(decoded.delegate.is_none() && decoded.close_authority.is_none());
        let mut mint_data = vec![0; 82];
        mint_data[..4].copy_from_slice(&1u32.to_le_bytes());
        mint_data[4..36].fill(0x11);
        mint_data[36..44].copy_from_slice(&123u64.to_le_bytes());
        mint_data[44] = 6;
        mint_data[45] = 1;
        let observation = decode_mint(
            &p.asset.mint,
            &Account {
                owner: p.asset.token_program.clone(),
                executable: false,
                data: mint_data,
            },
        )
        .unwrap();
        assert_eq!(observation["decimals"], 6);
        assert_eq!(observation["is_initialized"], true);
        assert_eq!(
            observation["mint_authority"],
            Pubkey::new_from_array([0x11; 32]).to_string()
        );
        assert!(observation["freeze_authority"].is_null());
        assert!(
            observation.get("supply").is_none(),
            "supply legitimately differs and is not compared"
        );
        let mut data = vec![0; 8 + vault::VaultState::INIT_SPACE];
        data[..8].copy_from_slice(vault::VaultState::DISCRIMINATOR);
        data[8] = 1;
        data[10] = 1;
        let mut identity = Map::new();
        let (v, _) = decode_vault(&data, &mut identity).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["paused"], true);
        assert_eq!(v["request_charge_cap"], 0);
        assert!(identity.contains_key("state_signing_key"));
        assert!(identity.contains_key("clearance_signing_key"));
        assert!(identity.contains_key("treasury_token_account"));
        assert!(!v
            .as_object()
            .unwrap()
            .contains_key("treasury_token_account"));
    }
    #[test]
    fn loader_decoding_is_strict_and_trims_padding() {
        let mut data = vec![0; 45];
        data[..4].copy_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3, 0, 0]);
        let v = decode_program_data(&data).unwrap();
        assert!(v["upgrade_authority"].is_null());
        assert_eq!(
            v["executable_sha256"],
            to_hex(&executable_sha256(&[1, 2, 3]))
        );
        data[12] = 2;
        assert!(decode_program_data(&data).is_err());
        assert!(decode_program_data(&[0; 44]).is_err());
    }
    #[test]
    fn diff_allows_only_identity_not_observed_security_fields() {
        let a = json!({"identity":{"network":"localnet"},"observed":{"vault":{"challenge_period_seconds":86400},"program":{"executable_sha256":"a"}}});
        let mut b = a.clone();
        b["identity"]["network"] = json!("mainnet-beta");
        assert!(parity_violations(&a, &b).is_empty());
        b["observed"]["vault"]["challenge_period_seconds"] = json!(40);
        assert_eq!(parity_violations(&a, &b).len(), 1);
        b["observed"]["program"]["executable_sha256"] = json!("b");
        assert_eq!(parity_violations(&a, &b).len(), 2);
    }
    #[test]
    fn malformed_token_accounts_mints_and_vaults_are_rejected() {
        let p = SharedProfile::embedded();
        let mint = Pubkey::new_from_array(p.usdc_mint());
        let key = Pubkey::new_from_array([4; 32]);
        // Token-2022, uninitialized, wrong length.
        let token_2022 = vault::token::TOKEN_2022_PROGRAM_ID.to_string();
        assert!(decode_token_account(p, &token_account(&token_2022, mint, key, 1)).is_err());
        assert!(
            decode_token_account(p, &token_account(&p.asset.token_program, mint, key, 0)).is_err()
        );
        let mut long = token_account(&p.asset.token_program, mint, key, 1);
        long.data.push(0);
        assert!(decode_token_account(p, &long).is_err());
        let mut bad_tag = token_account(&p.asset.token_program, mint, key, 1);
        bad_tag.data[72] = 2;
        assert!(decode_token_account(p, &bad_tag).is_err());
        let mint_account = |data: Vec<u8>| Account {
            owner: p.asset.token_program.clone(),
            executable: false,
            data,
        };
        assert!(decode_mint(&p.asset.mint, &mint_account(vec![0; 83])).is_err());
        let mut bad = vec![0; 82];
        bad[45] = 2;
        assert!(decode_mint(&p.asset.mint, &mint_account(bad)).is_err());
        assert!(decode_vault(&[0; 400], &mut Map::new()).is_err());
    }

    fn valid_effective_profile() -> Value {
        let p = SharedProfile::embedded();
        let mut identity = serde_json::to_value(NetworkIdentity::mainnet()).unwrap();
        identity.as_object_mut().unwrap().remove("schema");
        identity["rpc_url"] = json!("https://api.mainnet-beta.solana.com");
        let program = json!({"loader":p.program.loader,"executable":true,"upgrade_authority":null,"executable_sha256":p.program.executable_sha256});
        json!({
            "profile": p.to_value(), "identity": identity,
            "observed": {
                "program": program,
                "vault": {"version":p.vault.version,"request_charge_cap":p.vault.request_charge_cap,"note_ttl_seconds":p.vault.note_ttl_seconds,"challenge_period_seconds":p.vault.challenge_period_seconds,"paused":false,"tokens":vault_token_facts(p)},
                "asset": {
                    "mint":{"address":p.asset.mint,"owner":p.asset.token_program,"executable":false,"decimals":6,"is_initialized":true,"mint_authority":Pubkey::new_from_array([1; 32]).to_string(),"freeze_authority":Pubkey::new_from_array([2; 32]).to_string()},
                    "token_program":{"loader":BPF_LOADER_2,"executable":true,"executable_sha256":"00".repeat(32)},
                    "associated_token_program":{"loader":BPF_LOADER_2,"executable":true,"executable_sha256":"11".repeat(32)}
                },
                "runtime": {
                    "software_version":RUNTIME_FEATURES["version"],
                    "mainnet_get_version":{"solana-core":"4.4.1","feature-set":2681577653u64},
                    "active_feature_ids":[RUNTIME_FEATURES["feature_ids"][0]],
                    "retired_in_software":RUNTIME_FEATURES["retired_in_software"],
                    "feature_registry_git_blob":RUNTIME_FEATURES["source_git_blob"]
                }
            }
        })
    }

    #[test]
    fn parity_documents_fail_closed_even_when_both_sides_match() {
        let valid = valid_effective_profile();
        validate_effective_profile(&valid).unwrap();
        for malformed in [json!({}), json!(null), json!({"profile":{}})] {
            assert!(validate_effective_profile(&malformed).is_err());
        }
        for pointer in [
            "/observed/program/executable_sha256",
            "/observed/program/upgrade_authority",
            "/observed/vault/challenge_period_seconds",
            "/observed/vault/tokens/vault_token/authority_is_vault",
            "/observed/vault/tokens/treasury_token/state",
            "/observed/asset/mint/decimals",
            "/observed/asset/mint/owner",
            "/observed/asset/mint/mint_authority",
            "/observed/asset/token_program",
            "/observed/asset/associated_token_program/executable_sha256",
            "/observed/runtime/active_feature_ids",
            "/profile/server/lease_ttl_seconds",
            "/identity/rpc_url",
        ] {
            let mut bad = valid.clone();
            *bad.pointer_mut(pointer).unwrap() = json!({"challenge_period_seconds":40});
            assert!(validate_effective_profile(&bad).is_err(), "{pointer}");
        }
        let mut override_vault = valid;
        override_vault["observed"]["vault"]["challenge_period_seconds"] = json!(40);
        assert!(parity_violations(&override_vault, &override_vault).is_empty());
        assert!(validate_effective_profile(&override_vault).is_err());
        // Both sides observing the same Token-2022 mint is still refused.
        let mut token_2022 = valid_effective_profile();
        token_2022["observed"]["asset"]["mint"]["owner"] =
            json!(vault::token::TOKEN_2022_PROGRAM_ID.to_string());
        assert!(parity_violations(&token_2022, &token_2022).is_empty());
        assert!(validate_effective_profile(&token_2022).is_err());
        let mut frozen_vault = valid_effective_profile();
        frozen_vault["observed"]["vault"]["tokens"]["vault_token"]["state"] = json!("frozen");
        assert!(validate_effective_profile(&frozen_vault).is_err());
        let mut removed_key = valid_effective_profile();
        removed_key["identity"]["treasury"] = json!(null);
        assert!(validate_effective_profile(&removed_key).is_err());
        let mut changed_asset = valid_effective_profile();
        changed_asset["profile"]["asset"]["decimals"] = json!(9);
        assert!(parity_violations(&changed_asset, &changed_asset).is_empty());
        assert!(validate_effective_profile(&changed_asset).is_err());
    }
}
