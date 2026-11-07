import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keccak_256 } from '@noble/hashes/sha3';
import { PublicKey } from '@solana/web3.js';
import { ASSOCIATED_TOKEN_PROGRAM_ID, MICRO_USDC_PER_USDC, TOKEN_PROGRAM_ID, USDC_DECIMALS, USDC_MINT }
    from './services/zkapiUsdc.mjs';

const sdkRoot = path.dirname(fileURLToPath(import.meta.url));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

export const PROFILE_SCHEMA = 'dagon-zkapi.solana-profile.v1';
export const IDENTITY_SCHEMA = 'dagon-zkapi.solana-identity.v1';
export const DEPLOYMENT_SCHEMA = 'dagon-zkapi.sdk-deployment.v1';
const IDENTITY_KEYS = ['schema', 'network', 'genesis_hash', 'vault_authority', 'vault_state',
    'treasury_token_account'];
const DEPLOYMENT_KEYS = ['schema', 'deployment_manifest_url', 'protocol_server_url', 'indexer_url', 'rpc_url',
    'openrouter_inference_base', 'oa_verifier_url', 'state_signing_key', 'clearance_signing_key'];
const MAINNET_BETA = 'mainnet-beta';
const MAINNET_GENESIS_HASH = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
// Wallet Standard chain identifiers of the Solana clusters a wallet can sign for.
const WALLET_STANDARD_CHAINS = Object.freeze({
    'mainnet-beta': 'solana:mainnet',
    devnet: 'solana:devnet',
    testnet: 'solana:testnet',
    localnet: 'solana:localnet'
});
// BN254 scalar field order: the v2 statements' field.
const FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CHAIN_ID_DOMAIN = 'dagon.zkapi.solana.chain-id.v1';
const DEPLOYMENT_DOMAIN = 'dagon.zkapi.solana.deployment.v1';
const FELT = /^0x[0-9a-f]{1,64}$/i;

function base58Account(value, label) {
    let key;
    try {
        key = new PublicKey(value);
    } catch {
        throw new Error(`${label} is not a base58 Solana account.`);
    }
    if (key.toBase58() !== value || key.toBytes().every(byte => byte === 0)) {
        throw new Error(`${label} is not a canonical nonzero base58 Solana account.`);
    }
    return key;
}

function exactKeys(value, keys, label) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be a JSON object.`);
    const unknown = Object.keys(value).filter(key => !keys.includes(key));
    const missing = keys.filter(key => !Object.hasOwn(value, key));
    if (unknown.length || missing.length) {
        throw new Error(`${label} has ${unknown.length ? `unknown fields ${unknown.join(', ')}` : ''}${unknown.length && missing.length ? ' and ' : ''}${missing.length ? `missing fields ${missing.join(', ')}` : ''}.`);
    }
}

function secureUrl(value, label) {
    let url;
    try {
        url = new URL(value);
    } catch {
        throw new Error(`${label} must be an absolute URL.`);
    }
    if (url.username || url.password || url.hash
        || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname)))) {
        throw new Error(`${label} must be a credential-free HTTPS or loopback URL.`);
    }
    return url.href.replace(/\/+$/, '');
}

function signingKey(value, label) {
    if (!value || typeof value !== 'object' || Object.keys(value).sort().join() !== 'x,y'
        || !FELT.test(value.x || '') || !FELT.test(value.y || '')
        || BigInt(value.x) >= FIELD_ORDER || BigInt(value.y) >= FIELD_ORDER) {
        throw new Error(`${label} must be {x, y} field elements, as printed by \`dagon-zkapi signing-keys\`.`);
    }
    return { x: value.x.toLowerCase(), y: value.y.toLowerCase() };
}

function u64BigEndian(value) {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
    return bytes;
}

function concat(...parts) {
    const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
    let offset = 0;
    for (const part of parts) { output.set(part, offset); offset += part.length; }
    return output;
}

const utf8 = value => new TextEncoder().encode(value);
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

/** The v2 `chain_id` of a Solana cluster: zkapi-types `solana_chain_id`. */
export function solanaChainId(genesisHash) {
    const digestBytes = keccak_256(concat(utf8(CHAIN_ID_DOMAIN), genesisHash));
    return new DataView(digestBytes.buffer, digestBytes.byteOffset, 8).getBigUint64(0).toString(10);
}

/** The v2 `contract_address` of one vault: zkapi-types `solana_deployment_binding`. */
export function solanaDeploymentBinding(programId, vaultState, genesisHash) {
    const payload = concat(programId, vaultState, genesisHash);
    for (let counter = 0; counter <= 0xffff_ffff; counter += 1) {
        const counterBytes = new Uint8Array(4);
        new DataView(counterBytes.buffer).setUint32(0, counter);
        const candidate = keccak_256(concat(utf8(DEPLOYMENT_DOMAIN), u64BigEndian(payload.length), payload, counterBytes));
        if (BigInt(`0x${hex(candidate)}`) < FIELD_ORDER) return `0x${hex(candidate)}`;
    }
    throw new Error('Solana deployment binding rejection counter exhausted.');
}

/** The shared Solana profile packaged with the SDK (generated from solana/profile/shared.json). */
export async function readPackagedSolanaProfile() {
    const profile = JSON.parse(await fs.readFile(path.join(sdkRoot, 'assets/config/profile.json'), 'utf8'));
    if (profile.schema !== PROFILE_SCHEMA) throw new Error('The packaged Solana profile has an unsupported schema.');
    const asset = profile.asset;
    if (asset?.symbol !== 'USDC' || asset.mint !== USDC_MINT || asset.decimals !== USDC_DECIMALS
        || asset.token_program !== TOKEN_PROGRAM_ID || asset.associated_token_program !== ASSOCIATED_TOKEN_PROGRAM_ID) {
        throw new Error('The packaged Solana profile must settle in Circle USDC under the classic SPL Token program.');
    }
    return profile;
}

/** Read and verify the package's public artifacts without building protocol source. */
export async function verifyBrowserSdkAssets() {
    const manifest = JSON.parse(await fs.readFile(path.join(sdkRoot, 'assets/manifest.json'), 'utf8'));
    for (const [relative, expected] of Object.entries(manifest.files)) {
        const resolved = path.resolve(sdkRoot, relative);
        if (!resolved.startsWith(`${sdkRoot}${path.sep}`)) throw new Error('Invalid SDK asset path.');
        if (digest(await fs.readFile(resolved)) !== expected) {
            throw new Error(`zkAPI SDK asset integrity check failed: ${relative}.`);
        }
    }
    const profile = await readPackagedSolanaProfile();
    if (manifest.circuitId !== profile.protocol.circuit_id) {
        throw new Error('The SDK proof artifacts and the packaged Solana profile pin different circuits.');
    }
    return manifest;
}

/**
 * Validate a network identity exactly like the operator binaries
 * (`dagon_zkapi_profile::NetworkIdentity::{parse, resolve}`): every account is
 * required, so an undeployed identity (null accounts) is refused.
 */
export function resolveSolanaIdentity(identity, profile) {
    exactKeys(identity, IDENTITY_KEYS, 'The Solana network identity');
    if (identity.schema !== IDENTITY_SCHEMA) throw new Error(`Unsupported identity schema ${identity.schema}.`);
    if (typeof identity.network !== 'string' || !/^[a-z0-9-]+$/.test(identity.network)) {
        throw new Error('The identity network label must be lowercase [a-z0-9-].');
    }
    const genesis = base58Account(identity.genesis_hash, 'genesis_hash');
    if ((identity.network === MAINNET_BETA) !== (identity.genesis_hash === MAINNET_GENESIS_HASH)) {
        throw new Error('The mainnet-beta label and the mainnet genesis hash must go together.');
    }
    const walletStandardChain = WALLET_STANDARD_CHAINS[identity.network];
    if (!walletStandardChain) {
        throw new Error(`No Wallet Standard chain is known for Solana network ${identity.network}.`);
    }
    const required = name => {
        if (identity[name] == null) {
            throw new Error(`The ${identity.network} identity has no ${name} (undeployed); refusing to build a deployment for it.`);
        }
        return base58Account(identity[name], name);
    };
    const authority = required('vault_authority');
    const vault = required('vault_state');
    required('treasury_token_account');
    const program = base58Account(profile.program.program_id, 'program_id');
    const [expectedVault] = PublicKey.findProgramAddressSync([utf8('vault'), authority.toBytes()], program);
    if (!expectedVault.equals(vault)) {
        throw new Error('vault_state is not the vault PDA of vault_authority under the profile program.');
    }
    return {
        network: identity.network,
        genesisHash: genesis,
        vaultState: vault,
        walletStandardChain,
        programId: program
    };
}

/**
 * The browser trust anchor of one deployment: shared parameters from the
 * packaged profile, identity from the network identity file, and the
 * operator's public endpoints and signing keys as deployment inputs. A host
 * that routes deployment requests through a same-origin rewrite passes its
 * path as `deploymentApiProxyPath` (for example '/zkapi-deployment/').
 */
export async function solanaBrowserConfig({ identity, deployment, deploymentApiProxyPath = null }) {
    const manifest = await verifyBrowserSdkAssets();
    if (deploymentApiProxyPath != null && (typeof deploymentApiProxyPath !== 'string'
        || !/^\/(?!\/)[^?#]*\/$/.test(deploymentApiProxyPath) || deploymentApiProxyPath.split('/').includes('..'))) {
        throw new TypeError('deploymentApiProxyPath must be an absolute same-origin directory path ending with /.');
    }
    const profile = await readPackagedSolanaProfile();
    const resolved = resolveSolanaIdentity(identity, profile);
    exactKeys(deployment, DEPLOYMENT_KEYS, 'The SDK deployment inputs');
    if (deployment.schema !== DEPLOYMENT_SCHEMA) throw new Error(`Unsupported deployment schema ${deployment.schema}.`);
    const verifierUrl = deployment.oa_verifier_url == null ? null : secureUrl(deployment.oa_verifier_url, 'oa_verifier_url');
    const manifestUrl = secureUrl(deployment.deployment_manifest_url, 'deployment_manifest_url');
    const trusted = {
        deployment_id: `dagon-${resolved.network}-${resolved.vaultState.toBase58()}`,
        chain_id: solanaChainId(resolved.genesisHash.toBytes()),
        contract_address: solanaDeploymentBinding(resolved.programId.toBytes(), resolved.vaultState.toBytes(),
            resolved.genesisHash.toBytes()),
        billing_asset: 'usdc',
        billing_unit: 'micro_usdc',
        ledger_backend: 'dagon.solana.groth16.v1',
        base_units_per_asset: String(MICRO_USDC_PER_USDC),
        network: resolved.network,
        genesis_hash: identity.genesis_hash,
        program_id: profile.program.program_id,
        vault_state: identity.vault_state,
        wallet_standard_chain: resolved.walletStandardChain,
        usdc_mint: profile.asset.mint,
        token_program: profile.asset.token_program,
        associated_token_program: profile.asset.associated_token_program,
        request_charge_cap: profile.vault.request_charge_cap,
        note_ttl_seconds: profile.vault.note_ttl_seconds,
        rpc_url: secureUrl(deployment.rpc_url, 'rpc_url'),
        protocol_server_url: secureUrl(deployment.protocol_server_url, 'protocol_server_url'),
        indexer_url: secureUrl(deployment.indexer_url, 'indexer_url'),
        state_signing_key: signingKey(deployment.state_signing_key, 'state_signing_key'),
        clearance_signing_key: signingKey(deployment.clearance_signing_key, 'clearance_signing_key'),
        circuit_id: profile.protocol.circuit_id,
        request_proving_key_sha256: manifest.files['assets/proofs/request.pk'],
        withdrawal_proving_key_sha256: manifest.files['assets/proofs/withdrawal.pk'],
        openrouter_inference_base: secureUrl(deployment.openrouter_inference_base, 'openrouter_inference_base'),
        verifier_url: verifierUrl
    };
    return {
        deployment_manifest_url: manifestUrl,
        allowed_deployment_manifest_urls: [manifestUrl],
        trusted_deployment: trusted,
        proving_keys_base_url: './proofs/',
        require_oa_key_source: verifierUrl !== null,
        ...(deploymentApiProxyPath ? { deployment_api_proxy_path: deploymentApiProxyPath } : {})
    };
}

/** A packaged network identity (`assets/config/<network>.identity.json`). */
export async function readPackagedSolanaIdentity(network) {
    if (typeof network !== 'string' || !/^[a-z0-9-]+$/.test(network)) {
        throw new Error('The identity network label must be lowercase [a-z0-9-].');
    }
    try {
        return JSON.parse(await fs.readFile(path.join(sdkRoot, `assets/config/${network}.identity.json`), 'utf8'));
    } catch (error) {
        if (error.code === 'ENOENT') throw new Error(`The SDK packages no identity for Solana network ${network}.`);
        throw error;
    }
}

/**
 * Publish one deployment's immutable proof assets and trust anchor beneath
 * the host's app route. `identity` is a packaged network name (for example
 * 'mainnet-beta') or a network identity object (for example a localnet
 * identity written by `dagon-zkapi-deploy identity`); `deployment` holds the
 * operator's endpoints and public signing keys. The host supplies its
 * esbuild `build` function; esbuild is not a runtime SDK dependency. No
 * network, private credentials, or Rust are required.
 */
export async function buildBrowserSdkAssets({
    outDir, identity, deployment, deploymentApiProxyPath = null, publicPath = '/zkapi/', build
} = {}) {
    if (!outDir || typeof build !== 'function') throw new TypeError('outDir and an esbuild build function are required.');
    if (!/^\/(?!\/)[^?#]*\/$/.test(publicPath) || publicPath.split('/').includes('..')) {
        throw new TypeError('publicPath must be an absolute same-origin directory path ending with /.');
    }
    const directory = path.resolve(outDir);
    if (directory === path.parse(directory).root || directory === sdkRoot || sdkRoot.startsWith(`${directory}${path.sep}`)
        || directory.startsWith(`${sdkRoot}${path.sep}`)) {
        throw new Error('SDK build output must not overwrite its package source.');
    }
    const identityValue = typeof identity === 'string' ? await readPackagedSolanaIdentity(identity) : identity;
    const config = await solanaBrowserConfig({ identity: identityValue, deployment, deploymentApiProxyPath });
    // solanaBrowserConfig verified every packaged artifact hash.
    const provenance = JSON.parse(await fs.readFile(path.join(sdkRoot, 'assets/manifest.json'), 'utf8'));
    const files = {};
    const write = async (relative, bytes) => {
        const destination = path.join(directory, relative);
        await fs.mkdir(path.dirname(destination), { recursive: true });
        await fs.writeFile(destination, bytes);
        files[relative] = digest(bytes);
    };
    for (const kind of ['request', 'withdrawal']) {
        await write(`proofs/${kind}.pk`, await fs.readFile(path.join(sdkRoot, `assets/proofs/${kind}.pk`)));
    }
    await write('wasm/zkapi_browser_bg.wasm', await fs.readFile(path.join(sdkRoot, 'wasm/zkapi_browser_bg.wasm')));
    await write('browser-config.json', `${JSON.stringify(config, null, 2)}\n`);
    const workerFile = path.join(directory, 'assets/zkapiWasmWorker.js');
    await build({
        entryPoints: [path.join(sdkRoot, 'services/zkapiWasmWorker.js')], outfile: workerFile,
        bundle: true, format: 'esm', platform: 'browser', target: ['es2020'], minify: true, logLevel: 'warning'
    });
    files['assets/zkapiWasmWorker.js'] = digest(await fs.readFile(workerFile));
    const manifest = { schema: 1, network: config.trusted_deployment.network,
        deploymentId: config.trusted_deployment.deployment_id, circuitId: provenance.circuitId,
        protocolRevision: provenance.protocolRevision, files: { ...files } };
    await write('sdk-assets.json', `${JSON.stringify(manifest, null, 2)}\n`);
    return {
        directory, config, manifest, files,
        configUrl: `${publicPath}browser-config.json`, workerUrl: `${publicPath}assets/zkapiWasmWorker.js`
    };
}
