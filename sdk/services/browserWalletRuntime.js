import { browserSdkOptions, beginBrowserSdkInitialization, browserSdkTransport } from '../configure.js';
import { CHAT_SPENDING_TIER_USD } from './zkapiRequestCompat.mjs';
import { sameFelt, waitForExpectedActiveRoot } from './zkapiActiveRoot.mjs';
import { chooseEscapeConcession, exitProofLive, exitProofLiveUntil, exitProofValidUntil, reusableExitProof }
    from './zkapiExitPolicy.mjs';
import { canonicalChainId, sameChainId } from './zkapiLedgerIdentity.mjs';
import { assertSolanaVault, confirmFinalizedSolanaTransaction, isUsdcFunding, leaseLimitUsd,
    readFinalizedSolanaOperationState, readFinalizedSolanaTime, readUsdcTokenAccount,
    sendSignedSolanaTransaction, usdcAccountCreationKeys, usdcAssociatedTokenAddress, usdcBaseUnits,
    validatePreparedSolanaDeposit, validateSolanaFunding, ASSOCIATED_TOKEN_PROGRAM_ID } from './zkapiUsdc.mjs';
import { base58Decode, base58Encode, submitPreparedSolanaOperation }
    from './zkapiSolanaTransport.mjs';
import { prepareLocalSolanaExit, prepareLocalUsdcAccountCreation } from './zkapiSolanaExit.mjs';
import {
    assertSolanaOperationJournal,
    createSolanaOperationJournal,
    recordSolanaFinalizedStage,
    recordSolanaSignedStage,
    recordSolanaSubmittedStage,
    resumeSolanaOperationJournal
} from './zkapiSolanaJournal.mjs';
import {
    createWalletChannel,
    detachBrowserClosedWithdrawal,
    detachBrowserEscapeWithdrawal,
    listBrowserWithdrawals,
    projectBrowserDeposits,
    readBrowserWalletSnapshot,
    requestPersistentStorage,
    updateBrowserWithdrawal,
    withBrowserWalletLock,
    writeBrowserWallet
} from './browserWalletStore.js';

function browserConfigUrl() {
    const configured = browserSdkOptions().configUrl;
    if (!configured) throw new Error('Configure a trusted configUrl before initializing the zkAPI browser SDK.');
    return configured;
}
const REQUIRED_CIRCUIT_ID = 'zkapi-v2-concession-v1';
const MAX_RECOVERY_WAIT_MS = 45_000;
// OA may briefly throttle child-key creation. Keep retrying the same durable,
// idempotent lease request long enough to cross a one-minute limiter without
// ever reproving, waiting indefinitely, or amplifying the limiter with a tight
// retry loop. The production schedule is 5s, 10s, 20s, then 30s.
const LEASE_ISSUE_MAX_WAIT_MS = 75_000;
const LEASE_ISSUE_MAX_ATTEMPTS = 5;
const LEASE_ISSUE_INITIAL_RETRY_MS = 5_000;
const LEASE_ISSUE_MAX_RETRY_MS = 30_000;
// Never begin a potentially long frontier-model stream on a key that is near
// the server's independent settlement boundary. A follow-up inside this
// window transparently closes the old key and obtains a fresh key at the selected model tier.
const MIN_REQUEST_LEASE_REMAINING_SECONDS = 90;
const TAB_OWNER_STORAGE_KEY = 'zkapi-browser-tab-owner-v1';

class BrowserWalletHttpError extends Error {
    constructor(message, status, code, data = null) {
        super(message);
        this.name = 'BrowserWalletHttpError';
        this.status = status;
        this.code = code;
        this.data = data;
    }
}

class WorkerBridge {
    constructor() {
        this.worker = new Worker(browserSdkOptions().workerUrl || new URL('./zkapiWasmWorker.js', import.meta.url), { type: 'module' });
        this.pending = new Map();
        this.sequence = 0;
        this.worker.addEventListener('message', (event) => {
            const entry = this.pending.get(event.data?.id);
            if (!entry) return;
            this.pending.delete(event.data.id);
            if (event.data.error) entry.reject(new Error(event.data.error));
            else entry.resolve(event.data.result);
        });
        this.worker.addEventListener('error', (event) => {
            const error = new Error(event.message || 'The zkAPI proof worker crashed.');
            for (const entry of this.pending.values()) entry.reject(error);
            this.pending.clear();
        });
    }

    call(operation, payload = {}) {
        const id = ++this.sequence;
        return new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
            this.worker.postMessage({ id, operation, payload });
        });
    }
}

function normalizeUrl(value) {
    return String(value || '').replace(/\/+$/, '');
}

function throwIfAborted(signal) {
    if (!signal?.aborted) return;
    const error = new DOMException('The operation was aborted.', 'AbortError');
    error.isCancelled = true;
    throw error;
}

function exactTrustedUrl(supplied, expected, label) {
    if (!expected?.startsWith('https://') && !expected?.startsWith('http://127.0.0.1:')
        && !expected?.startsWith('http://localhost:')) {
        throw new Error(`${label} is not a secure or loopback URL.`);
    }
    if (normalizeUrl(supplied) !== normalizeUrl(expected)) {
        throw new Error(`${label} did not match the deployment trust anchor.`);
    }
}

function delay(milliseconds, signal) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, milliseconds);
        signal?.addEventListener('abort', () => {
            clearTimeout(timer);
            const error = new Error('Request aborted');
            error.name = 'AbortError';
            reject(error);
        }, { once: true });
    });
}

function isExplicitlyRetriableLeaseError(error) {
    const explicitlyRetriable = error?.data?.retriable === true
        || error?.data?.error?.retriable === true;
    // These responses require a new proof or local lost-key reconciliation;
    // repeatedly sending the same lease request cannot resolve either state.
    return explicitlyRetriable
        && !['stale_root', 'lease_pending', 'lease_settlement_pending'].includes(error?.code);
}

function isExplicitlyRetriableLeaseRetirementError(error) {
    const explicitlyRetriable = error?.data?.retriable === true
        || error?.data?.error?.retriable === true;
    return isExplicitlyRetriableLeaseError(error)
        || (explicitlyRetriable
            && ['lease_pending', 'lease_settlement_pending'].includes(error?.code));
}

function isLeaseRateLimit(error) {
    return error?.status === 429
        || /^oa_(?:minute_request_limit|hourly_issuance_budget|rate_limited)$/.test(error?.code || '')
        || /(?:\b429\b|too many requests|rate[ -]?limit)/i.test(error?.message || '');
}

function leaseRetryAfterMilliseconds(error) {
    const candidates = [
        error?.data?.retry_after_seconds,
        error?.data?.error?.retry_after_seconds,
        error?.data?.detail?.retry_after_seconds,
        error?.data?.error?.detail?.retry_after_seconds
    ];
    for (const candidate of candidates) {
        const seconds = Number(candidate);
        if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1_000);
    }
    return null;
}

function describeRetryDelay(milliseconds) {
    const seconds = Math.max(1, Math.ceil(milliseconds / 1_000));
    if (seconds < 60) return seconds === 1 ? '1 second' : `${seconds} seconds`;
    const minutes = Math.ceil(seconds / 60);
    if (minutes < 60) return minutes === 1 ? 'about 1 minute' : `about ${minutes} minutes`;
    const hours = Math.ceil(minutes / 60);
    return hours === 1 ? 'about 1 hour' : `about ${hours} hours`;
}

function makeLeaseRateLimitActionable(error, retryAfterMs = null) {
    if (!isLeaseRateLimit(error)) return error;
    error.shortMessage = retryAfterMs != null
        ? `Temporary-key capacity is full. Your message is saved and was not sent. Try again in ${describeRetryDelay(retryAfterMs)}.`
        : 'The temporary-key service is still busy. Your message is saved and was not sent; use Retry in a moment.';
    return error;
}

function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function browserTabOwnerId() {
    try {
        const existing = sessionStorage.getItem(TAB_OWNER_STORAGE_KEY);
        if (existing && /^[0-9a-f-]{36}$/i.test(existing)) return existing;
        const created = uuid();
        sessionStorage.setItem(TAB_OWNER_STORAGE_KEY, created);
        return created;
    } catch {
        return uuid();
    }
}

// The concession terms an escape proof fixed: the state balance B = f + c,
// the declared concession c and the single bound b released at the escaped
// state (C2), which caps every raise.
function escapeTerms(plan) {
    const inputs = plan?.public_inputs || {};
    const finalBalance = BigInt(inputs.final_balance ?? 0);
    const conceded = BigInt(inputs.conceded ?? 0);
    return {
        finalBalance,
        conceded,
        stateBalance: finalBalance + conceded,
        boundAtState: BigInt(plan?.boundAtState ?? 0)
    };
}

// Record fields of a landed escape. `currentConceded` is the vault's
// concession when it was read, which a raise may already have increased.
function escapeRecordTerms(plan, currentConceded = null) {
    const terms = escapeTerms(plan);
    const onChain = currentConceded == null ? terms.conceded : BigInt(currentConceded);
    return {
        stateBalance: terms.stateBalance,
        concededAtInit: terms.conceded,
        conceded: onChain > terms.conceded ? onChain : terms.conceded,
        boundAtState: terms.boundAtState,
        nextNullifier: plan?.public_inputs?.next_nullifier ?? null,
        concessionRule: plan?.concessionRule ?? null
    };
}

function concessionRecordFields(details) {
    if (details?.stateBalance == null) return {};
    return {
        stateBalance: Number(details.stateBalance),
        concededAtInit: Number(details.concededAtInit ?? 0),
        conceded: Number(details.conceded ?? details.concededAtInit ?? 0),
        boundAtState: Number(details.boundAtState ?? 0),
        nextNullifier: details.nextNullifier ?? null,
        concessionRule: details.concessionRule ?? null
    };
}

function nowSeconds() {
    return Math.floor(Date.now() / 1000);
}

// C3: an exit proof that left the device (to a wallet, an RPC or the ledger)
// keeps its state frozen until it can no longer land.
function exitProofFrozenError(plan) {
    const until = exitProofLiveUntil(plan?.releasedValidUntil ?? null);
    const error = new BrowserWalletHttpError(
        `An exit proof for this balance may still land on-chain until ${new Date(until * 1000).toISOString()} (by both this device's clock and the chain's finalized block time). Finish or check that withdrawal; the balance stays frozen until then.`,
        409,
        'exit_proof_live'
    );
    error.liveUntil = until;
    return error;
}

// C3/E6: valid_until came from this device's clock, but the vault checks it
// against block time. A released proof thaws its state only once this
// device's clock and the host-pinned RPC's finalized block time are both past
// valid_until + margin. An RPC failure keeps the state frozen; the freeze
// only blocks requests, cancel and restore, never exits or finalization.
async function exitProofStillLive(releasedValidUntil, readChainTime) {
    const until = exitProofLiveUntil(releasedValidUntil ?? null);
    if (until == null) return false;
    if (nowSeconds() <= until) return true;
    let chainTime = null;
    try {
        chainTime = await readChainTime();
    } catch {
        // Fail closed: an unreadable chain clock never thaws the state.
    }
    return exitProofLive(releasedValidUntil, nowSeconds(), chainTime);
}

async function responsePayload(response) {
    const text = await response.text();
    try {
        return text ? JSON.parse(text) : {};
    } catch {
        return { raw: text };
    }
}

class BrowserWalletRuntime extends EventTarget {
    constructor() {
        super();
        this.worker = null;
        this.browserConfig = null;
        this.manifest = null;
        this.config = null;
        this.runtime = null;
        this.withdrawals = [];
        this.deposits = [];
        this.activeLease = null;
        this.initialized = false;
        this.initPromise = null;
        this.leasePromise = null;
        this.leasePromiseSession = null;
        this.leasePromiseSpendingLimitUsd = null;
        this.leaseAbortController = null;
        this.leaseWaiterCount = 0;
        this.leaseProgressListeners = new Set();
        this.lastLeaseProgress = null;
        this.retirementPromise = null;
        this.requestProverWarmup = null;
        this.settlementTimer = null;
        this.legacyMigrationInProgress = false;
        this.channel = null;
        // sessionStorage survives a reload in this tab but is isolated from an
        // independently opened browser tab. That lets crash recovery retire a
        // lost in-memory key without allowing another live tab to take it.
        this.ownerId = browserTabOwnerId();
    }

    async init() {
        beginBrowserSdkInitialization();
        if (this.initPromise) return this.initPromise;
        this.initPromise = this.initialize();
        return this.initPromise;
    }

    async initialize() {
        this.browserConfig = await this.loadBrowserConfig();
        const allowedManifests = (this.browserConfig.allowed_deployment_manifest_urls
            || [this.browserConfig.deployment_manifest_url])
            .filter(Boolean)
            .map(value => new URL(value, location.href).href);
        const requestedManifest = new URLSearchParams(location.search).get('zkapiDeployment');
        const storedManifest = localStorage.getItem('zkapi-browser-deployment');
        if (requestedManifest
            && !allowedManifests.includes(new URL(requestedManifest, location.href).href)) {
            throw new Error('The selected deployment manifest is not trusted by this application build.');
        }
        if (storedManifest
            && !allowedManifests.includes(new URL(storedManifest, location.href).href)) {
            localStorage.removeItem('zkapi-browser-deployment');
        }
        const configuredManifest = requestedManifest
            || (storedManifest && allowedManifests.includes(new URL(storedManifest, location.href).href)
                ? storedManifest
                : null)
            || this.browserConfig.deployment_manifest_url;
        if (!configuredManifest) throw new Error('The website has no zkAPI deployment manifest configured.');
        const manifestUrl = new URL(configuredManifest, location.href).href;
        if (!allowedManifests.includes(manifestUrl)) {
            throw new Error('The selected deployment manifest is not trusted by this application build.');
        }
        this.manifest = await this.loadDeploymentManifest(manifestUrl);
        localStorage.setItem('zkapi-browser-deployment', manifestUrl);
        this.config = this.buildClientConfig(this.manifest, this.browserConfig);
        // The finalized vault pins the deployment identity; its challenge
        // period sizes the escape window shown to the user.
        this.vaultState = await assertSolanaVault(this.config.funding);
        this.worker = new WorkerBridge();
        // Initialization participates in the same global lock as every later
        // mutation. This prevents two same-origin deployment tabs from both
        // rebinding the singleton runtime and committing stale snapshots.
        await withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.deploymentId !== this.manifest.deployment_id) {
                this.runtime = await writeBrowserWallet({
                    ...this.runtime,
                    deploymentId: this.manifest.deployment_id,
                    billingAsset: this.manifest.billing_asset
                });
            }
            await this.recoverPendingLocked({ retireLostKey: true, quiet: true });
        });
        this.channel = createWalletChannel(this.manifest.deployment_id, () => {
            // A channel notification can arrive while this tab is awaiting a
            // proof or server response inside a wallet mutation. Reading the
            // singleton IndexedDB snapshot outside the global lock can then
            // install an older in-memory value which the mutation later
            // spreads into a commit. Queue the refresh behind mutations.
            void withBrowserWalletLock(this.manifest.deployment_id, () => this.reload())
                .then(() => this.dispatchEvent(new Event('change')))
                .catch(error => this.dispatchEvent(new CustomEvent('runtime-error', { detail: error })));
        });
        await requestPersistentStorage();
        this.initialized = true;
        return this.snapshot();
    }

    async loadBrowserConfig() {
        const response = await fetch(browserConfigUrl(), { cache: 'no-store', credentials: 'omit' });
        if (!response.ok) throw new Error(`Unable to load browser-config.json (${response.status}).`);
        return response.json();
    }

    deploymentProxyUrl(url) {
        const proxyPath = this.browserConfig?.deployment_api_proxy_path;
        if (!proxyPath) return null;
        const proxyBase = new URL(proxyPath, location.origin);
        if (proxyBase.origin !== location.origin || !proxyBase.pathname.endsWith('/')) {
            throw new Error('browser-config.json contains an invalid deployment API proxy path.');
        }
        const target = new URL(url, location.href);
        const trusted = this.browserConfig?.trusted_deployment;
        const trustedOrigins = new Set([
            trusted?.protocol_server_url,
            trusted?.indexer_url,
            this.browserConfig?.deployment_manifest_url,
            ...(this.browserConfig?.allowed_deployment_manifest_urls || [])
        ].filter(Boolean).map(value => new URL(value, location.href).origin));
        if (!trustedOrigins.has(target.origin)) return null;
        return new URL(`${target.pathname.replace(/^\/+/, '')}${target.search}`, proxyBase).href;
    }

    async loadDeploymentManifest(url) {
        try {
            const manifest = await this.directJson(url);
            this.validateManifest(manifest);
            this.validateManifestTrust(manifest);
            this.exitOnly = false;
            return manifest;
        } catch (error) {
            const trusted = this.browserConfig?.trusted_deployment;
            if (!trusted) throw error;
            // The host's pins already contain every field needed for an exit.
            // Never use untrusted or partially received operator fields here.
            const manifest = {
                ...trusted,
                protocol_version: 2,
                proof_backend: 'groth16_bn254',
                proof_setup: {
                    circuit_id: trusted.circuit_id,
                    request_proving_key_sha256: trusted.request_proving_key_sha256,
                    withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256
                },
                privacy_mode: {
                    openrouter_inference_base: trusted.openrouter_inference_base,
                    verifier_url: trusted.verifier_url
                }
            };
            this.validateManifest(manifest);
            this.validateManifestTrust(manifest);
            this.exitOnly = true;
            return manifest;
        }
    }

    requireOnlineDeployment() {
        if (this.exitOnly) throw new BrowserWalletHttpError(
            'The operator deployment is unavailable or changed. Only exits and recovery are available; reload after it recovers.',
            503, 'deployment_exit_only');
    }

    async directJson(url) {
        const proxyUrl = this.deploymentProxyUrl(url);
        const signal = AbortSignal.timeout(MAX_RECOVERY_WAIT_MS);
        let response = proxyUrl
            ? await fetch(proxyUrl, { cache: 'no-store', credentials: 'omit', signal })
            : null;
        // Local static development servers do not necessarily provide the
        // production rewrite. Fall back to the deployment URL only for that
        // unambiguous case; Vercel serves the trusted target at the proxy URL.
        if (!response || response.status === 404) {
            response = await fetch(url, { cache: 'no-store', credentials: 'omit', signal });
        }
        if (!response.ok) throw new Error(`Unable to load ${url} (${response.status}).`);
        return response.json();
    }

    validateManifest(manifest) {
        if (Number(manifest.protocol_version) !== 2 || manifest.proof_backend !== 'groth16_bn254') {
            throw new Error('The selected deployment is not a zkAPI v2 Groth16 deployment.');
        }
        if (manifest.proof_setup?.circuit_id !== REQUIRED_CIRCUIT_ID) {
            const error = new Error('This deployment uses an incompatible legacy proof circuit. Funding is unavailable until the operator publishes a new vault and concession-exit proof setup. Keep existing funds and recovery data with the legacy deployment.');
            error.code = 'incompatible_proof_circuit';
            throw error;
        }
        canonicalChainId(manifest.chain_id, 'deployment chain ID');
        for (const field of ['deployment_id', 'contract_address', 'protocol_server_url', 'indexer_url']) {
            if (!manifest[field]) throw new Error(`The deployment manifest omitted ${field}.`);
        }
        validateSolanaFunding(manifest);
        for (const field of ['protocol_server_url', 'indexer_url']) {
            const url = new URL(manifest[field]);
            if (url.protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(url.hostname)) {
                throw new Error(`The deployment ${field} is not HTTPS or loopback.`);
            }
        }
        if (!manifest.state_signing_key?.x || !manifest.clearance_signing_key?.x) {
            throw new Error('The deployment manifest omitted its pinned server signing keys.');
        }
        if (!manifest.privacy_mode?.openrouter_inference_base) {
            throw new Error('The deployment does not advertise prompt-private OpenRouter leases.');
        }
    }

    validateManifestTrust(manifest) {
        const trusted = this.browserConfig.trusted_deployment;
        if (!trusted) {
            throw new Error('browser-config.json omitted its trusted deployment pins.');
        }
        const requireEqual = (actual, expected, label, normalize = value => String(value)) => {
            if (expected == null || normalize(actual) !== normalize(expected)) {
                throw new Error(`The deployment manifest changed its pinned ${label}.`);
            }
        };
        const lowercase = value => String(value || '').toLowerCase();
        const normalizedUrl = value => normalizeUrl(new URL(value).href);
        requireEqual(manifest.proof_setup?.circuit_id, trusted.circuit_id, 'proof circuit');
        requireEqual(manifest.deployment_id, trusted.deployment_id, 'deployment id');
        requireEqual(manifest.chain_id, trusted.chain_id, 'chain id', canonicalChainId);
        requireEqual(manifest.contract_address, trusted.contract_address, 'deployment binding', lowercase);
        validateSolanaFunding(manifest);
        validateSolanaFunding(trusted);
        for (const [field, label, normalize] of [
            ['billing_asset', 'billing asset', String],
            ['billing_unit', 'billing unit', String],
            ['ledger_backend', 'ledger backend', String],
            ['network', 'Solana network', String],
            ['program_id', 'Solana program', String],
            ['vault_state', 'Solana vault state', String],
            ['genesis_hash', 'Solana genesis hash', String],
            ['wallet_standard_chain', 'wallet-standard chain', String],
            ['base_units_per_asset', 'USDC asset scale', String],
            ['usdc_mint', 'USDC mint', String],
            ['token_program', 'token program', String],
            ['associated_token_program', 'associated token program', String]
        ]) requireEqual(manifest[field], trusted[field], label, normalize);
        requireEqual(manifest.rpc_url, trusted.rpc_url, 'Solana RPC', normalizedUrl);
        requireEqual(manifest.protocol_server_url, trusted.protocol_server_url, 'protocol server', normalizedUrl);
        requireEqual(manifest.indexer_url, trusted.indexer_url, 'indexer', normalizedUrl);
        requireEqual(manifest.request_charge_cap, trusted.request_charge_cap, 'request charge cap', Number);
        for (const keyName of ['state_signing_key', 'clearance_signing_key']) {
            for (const coordinate of ['x', 'y']) {
                const actual = manifest[keyName]?.[coordinate];
                if (trusted[keyName]?.[coordinate] == null
                    || !/^0x[0-9a-f]{1,64}$/i.test(actual || '')
                    || !sameFelt(actual, trusted[keyName][coordinate])) {
                    throw new Error(`The deployment manifest changed its pinned ${keyName}.${coordinate}.`);
                }
            }
        }
        requireEqual(
            manifest.proof_setup?.request_proving_key_sha256,
            trusted.request_proving_key_sha256,
            'request proving key hash',
            lowercase
        );
        requireEqual(
            manifest.proof_setup?.withdrawal_proving_key_sha256,
            trusted.withdrawal_proving_key_sha256,
            'withdrawal proving key hash',
            lowercase
        );
        requireEqual(
            manifest.privacy_mode?.openrouter_inference_base,
            trusted.openrouter_inference_base,
            'OpenRouter origin',
            normalizedUrl
        );
        // An operator that mints keys itself (no OA verifier) pins null here;
        // a manifest may then not introduce a verifier, and vice versa.
        if ((manifest.privacy_mode?.verifier_url ?? null) !== null || trusted.verifier_url != null) {
            requireEqual(
                manifest.privacy_mode?.verifier_url,
                trusted.verifier_url,
                'OA verifier',
                normalizedUrl
            );
        }
    }

    buildClientConfig(manifest, browserConfig) {
        const keyBase = new URL(browserConfig.proving_keys_base_url || './proofs/', browserConfigUrl());
        const requestKey = new URL('request.pk', keyBase).href;
        const withdrawalKey = new URL('withdrawal.pk', keyBase).href;
        const requestCap = Number(manifest.request_charge_cap);
        validateSolanaFunding(manifest);
        const verifierUrl = manifest.privacy_mode.verifier_url ? normalizeUrl(manifest.privacy_mode.verifier_url) : null;
        if (browserConfig.require_oa_key_source === true && !verifierUrl) {
            throw new Error('browser-config.json requires OA-verified keys but pins no OA verifier.');
        }
        return {
            ux_proposal: String(browserConfig.ux_proposal || 'quiet'),
            credits_per_usd: null,
            request_charge_cap: requestCap,
            request_charge_cap_usd: null,
            policy_charge_cap: Number(manifest.policy_charge_cap || requestCap),
            policy_enabled: Boolean(manifest.policy_enabled),
            upstream_kind: 'openrouter',
            direct_openrouter_available: true,
            request_mode: 'direct_openrouter',
            browser_wallet: true,
            active_lease: null,
            prepared_withdrawal: null,
            wallet_core: {
                protocol_version: Number(manifest.protocol_version),
                chain_id: canonicalChainId(manifest.chain_id),
                contract_address: manifest.contract_address,
                request_charge_cap: requestCap,
                policy_charge_cap: Number(manifest.policy_charge_cap || requestCap),
                policy_enabled: Boolean(manifest.policy_enabled),
                state_signing_key: manifest.state_signing_key,
                clearance_signing_key: manifest.clearance_signing_key
            },
            proving_keys: {
                request: {
                    url: requestKey,
                    sha256: manifest.proof_setup?.request_proving_key_sha256
                },
                withdrawal: {
                    url: withdrawalKey,
                    sha256: manifest.proof_setup?.withdrawal_proving_key_sha256
                }
            },
            openrouter: {
                inference_base: normalizeUrl(manifest.privacy_mode.openrouter_inference_base),
                verifier_url: verifierUrl,
                require_oa_key_source: browserConfig.require_oa_key_source === true
            },
            funding: {
                ledger_backend: manifest.ledger_backend,
                contract_address: manifest.contract_address,
                chain_id: canonicalChainId(manifest.chain_id),
                indexer_url: normalizeUrl(manifest.indexer_url),
                protocol_server_url: normalizeUrl(manifest.protocol_server_url),
                models: manifest.models || [],
                suggested_deposit_amount: Number(browserConfig.suggested_deposit_amount || requestCap * 100),
                rpc_url: manifest.rpc_url,
                billing_token_symbol: 'USDC',
                billing_token_decimals: 6,
                billing_asset: manifest.billing_asset,
                billing_unit: manifest.billing_unit,
                base_units_per_asset: manifest.base_units_per_asset,
                network: manifest.network,
                program_id: manifest.program_id,
                vault_state: manifest.vault_state,
                genesis_hash: manifest.genesis_hash,
                wallet_standard_chain: manifest.wallet_standard_chain,
                usdc_mint: manifest.usdc_mint,
                token_program: manifest.token_program,
                associated_token_program: manifest.associated_token_program,
                note_ttl_seconds: Number(manifest.note_ttl_seconds || 0) || null
            }
        };
    }

    snapshot() {
        const active = this.activeLease && this.activeLease.expires_at > Math.floor(Date.now() / 1000)
            ? {
                session_id: this.activeLease.sessionId,
                client_request_id: this.activeLease.client_request_id,
                expires_at: this.activeLease.expires_at,
                settle_after: this.activeLease.settle_after,
                spending_limit_usd: Number(this.activeLease.spending_limit_usd),
                station_id: this.activeLease.verification?.station_id || null
            }
            : null;
        const prepared = this.runtime?.preparedWithdrawal;
        const pendingDeposit = this.runtime?.pendingDeposit;
        const config = this.config ? {
            exit_only: this.exitOnly === true,
            ...this.config,
            active_lease: active,
            pending_deposit: pendingDeposit ? {
                operation_id: pendingDeposit.operationId || null,
                // A saved Solana journal means signed transactions may exist:
                // the deposit can only be resumed, never re-planned.
                phase: pendingDeposit.solanaJournal ? 'submitting' : (pendingDeposit.phase || 'prepared'),
                amount: Number(pendingDeposit.amount),
                replannable: Boolean(this.config?.funding)
                    && this.canReplanPendingDeposit(pendingDeposit),
                next_note_id: Number(pendingDeposit.next_note_id)
            } : null,
            prepared_withdrawal: prepared ? {
                mode: prepared.mode,
                phase: prepared.solanaJournal ? 'submitting' : (prepared.phase || 'prepared'),
                note_id: prepared.public_inputs?.note_id ?? prepared.noteId ?? prepared.note_id,
                destination: prepared.destination,
                clearance_reserved: prepared.clearanceReserved === true || prepared.mode === 'mutual',
                conceded: prepared.public_inputs?.conceded != null ? String(prepared.public_inputs.conceded) : null,
                concession_rule: prepared.concessionRule || null,
                valid_until: prepared.public_inputs?.valid_until != null ? Number(prepared.public_inputs.valid_until) : null,
                exit_proof_live_until: exitProofLiveUntil(prepared.releasedValidUntil ?? null)
            } : null,
            // The last request's successor was withheld or failed the S3-S5
            // checks: the balance is frozen for requests and should escape.
            successor_withheld: Boolean(this.runtime?.journal?.withheldObservedAt
                || this.runtime?.journal?.invalidSuccessor)
        } : null;
        return {
            config,
            runtime: this.runtime,
            activeLease: active,
            deposits: this.deposits.map(record => ({ ...record })),
            withdrawals: this.withdrawals.map(record => {
                const {
                    state: _state,
                    preparedWithdrawal: _prepared,
                    proof: _proof,
                    withdrawalNullifier: _nullifier,
                    inFlightJournal: _journal,
                    solanaFinalizationJournal: _finalization,
                    ...summary
                } = record;
                return summary;
            })
        };
    }

    async reload() {
        const deploymentId = this.manifest?.deployment_id || this.runtime?.deploymentId || null;
        const snapshot = await readBrowserWalletSnapshot(deploymentId);
        const storedRuntime = snapshot.runtime;
        const hasDurableState = Boolean(
            storedRuntime.state
            || storedRuntime.journal
            || storedRuntime.pendingDeposit
            || storedRuntime.preparedWithdrawal
            || storedRuntime.lease
        );
        if (this.manifest && hasDurableState
            && (!storedRuntime.deploymentId || storedRuntime.deploymentId !== this.manifest.deployment_id
                || (storedRuntime.billingAsset != null
                    && storedRuntime.billingAsset !== this.manifest.billing_asset))) {
            throw new Error(`This browser contains a wallet for ${storedRuntime.deploymentId || 'an unidentified deployment'}. Switch back to that deployment before using or withdrawing it.`);
        }
        this.runtime = storedRuntime.deploymentId
            && this.manifest
            && storedRuntime.deploymentId !== this.manifest.deployment_id
            ? { ...storedRuntime, deploymentId: this.manifest.deployment_id }
            : storedRuntime;
        this.withdrawals = snapshot.withdrawals;
        this.deposits = snapshot.deposits;
        return this.runtime;
    }

    notify() {
        this.channel?.postMessage({ updatedAt: this.runtime.updatedAt });
        this.dispatchEvent(new Event('change'));
    }

    async commit(next, options = {}) {
        this.runtime = await writeBrowserWallet({
            ...next,
            deploymentId: this.manifest.deployment_id,
            billingAsset: this.manifest.billing_asset
        }, options);
        this.deposits = projectBrowserDeposits(this.runtime, this.deposits,
            this.manifest.deployment_id, options.depositConfirmation);
        this.notify();
        return this.runtime;
    }

    async getDepositHistory() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.snapshot().deposits;
        });
    }

    async walletStatus() {
        await this.init();
        const status = await this.worker.call('walletStatus', {
            state: this.runtime.state,
            journal: this.runtime.journal
        });
        // Let the lightweight status needed for the first paint leave the
        // worker before beginning the CPU-heavy decode. The warm-up then runs
        // while a funded user reads or types, without delaying page readiness.
        if (this.runtime.state || this.runtime.pendingDeposit) {
            void this.prewarmRequestProver();
        }
        return status;
    }

    prewarmRequestProver() {
        if (!this.worker || !this.config?.proving_keys?.request) {
            return Promise.resolve(false);
        }
        if (this.requestProverWarmup) return this.requestProverWarmup;
        const warmup = this.worker.call('preloadRequestProver', {
            provingKey: this.config.proving_keys.request
        }).then(() => true).catch(error => {
            // Pre-warming is an optimization. A failed fetch/decode must stay
            // silent here and be retried by the normal Send path later.
            if (this.requestProverWarmup === warmup) this.requestProverWarmup = null;
            console.warn('Unable to pre-warm the zkAPI request prover.', error);
            return false;
        });
        this.requestProverWarmup = warmup;
        return warmup;
    }

    async hasPendingLease() {
        await this.init();
        await this.reload();
        return Boolean(this.activeLease || this.runtime?.journal);
    }

    async getPendingLeaseOwner() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.runtime?.lease?.sessionId || this.activeLease?.sessionId || null;
        });
    }

    async remoteFetch(url, init = {}) {
        const proxyUrl = this.deploymentProxyUrl(url);
        if (proxyUrl) {
            try {
                const response = await fetch(proxyUrl, {
                    ...init,
                    credentials: 'omit'
                });
                if (response.status !== 404) return response;
            } catch {
                // A local static development server may not implement the
                // production rewrite. Keep the existing privacy-proxy/direct
                // fallback available there.
            }
        }
        return browserSdkTransport(url, init, { preferProxy: true });
    }

    async remoteJson(url, init = {}) {
        const response = await this.remoteFetch(url, init);
        let payload = await responsePayload(response);
        if (!response.ok) {
            const retryAfterHeader = response.headers.get('retry-after');
            const retryAfter = retryAfterHeader == null || retryAfterHeader.trim() === ''
                ? Number.NaN
                : Number(retryAfterHeader);
            if (Number.isFinite(retryAfter) && retryAfter >= 0
                && payload?.retry_after_seconds == null) {
                payload = { ...payload, retry_after_seconds: retryAfter };
            }
            const details = payload?.error && typeof payload.error === 'object'
                ? payload.error
                : {};
            throw new BrowserWalletHttpError(
                details.error_message
                    || details.message
                    || payload.error_message
                    || payload.message
                    || `HTTP ${response.status}`,
                response.status,
                details.error_code
                    || details.code
                    || payload.error_code
                    || payload.code,
                payload
            );
        }
        return payload;
    }

    async prepareSolanaLedgerOperation(kind, body) {
        await this.init();
        const funding = this.config?.funding;
        if (!isUsdcFunding(funding)) {
            throw new Error('Prepared Solana operations require a Dagon USDC deployment.');
        }
        if (kind !== 'deposit') return prepareLocalSolanaExit(funding, kind, body);
        this.requireOnlineDeployment();
        const prepared = await this.remoteJson(
            `${funding.protocol_server_url}/v2/ledger/deposits/prepare`,
            { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
        );
        if (prepared?.backend !== funding.ledger_backend
            || prepared?.network !== funding.network
            || !sameChainId(prepared?.chain_id, funding.chain_id)
            || !sameFelt(prepared?.protocol_binding, funding.contract_address)
            || prepared?.vault !== funding.vault_state
            || !Array.isArray(prepared?.operation?.transactions)
            || prepared.operation.transactions.length === 0) {
            throw new Error('The prepared Solana operation belongs to a different deployment.');
        }
        // Authorize all staging bytes, not just the final USDC transfer:
        // the operator must not replace the wallet's commitment or amount.
        return validatePreparedSolanaDeposit(prepared.operation, { funding, payer: body.payer, deposit: body });
    }

    async prepareSolanaDepositOperation(payer, plan = this.runtime?.pendingDeposit) {
        if (!plan || !Array.isArray(plan.zero_path) || plan.zero_path.length !== 32) {
            throw new Error('A complete durable deposit plan is required.');
        }
        return this.prepareSolanaLedgerOperation('deposit', {
            payer,
            expected_note_id: Number(plan.next_note_id),
            commitment: plan.commitment,
            amount: String(plan.amount),
            zero_path: plan.zero_path
        });
    }

    // Exits are leaf-bound: the ledger compares the proof's registration and
    // note fields with the stored note, so the plan carries no Merkle path.
    async prepareSolanaWithdrawalOperation(payer, plan = this.runtime?.preparedWithdrawal) {
        if (!plan || !['mutual', 'escape'].includes(plan.mode)
            || !plan.public_inputs || !plan.proof
            || typeof plan.destination !== 'string') {
            throw new Error('A complete durable withdrawal plan is required.');
        }
        return this.prepareSolanaLedgerOperation(plan.mode, {
            payer,
            destination: plan.destination,
            public_inputs: plan.public_inputs,
            proof: plan.proof
        });
    }

    async prepareSolanaFinalizeEscapeOperation(payer, noteId) {
        if (!Number.isSafeInteger(Number(noteId)) || Number(noteId) < 0) {
            throw new Error('A valid note ID is required to finalize an escape.');
        }
        return this.prepareSolanaLedgerOperation('finalize', { payer, note_id: Number(noteId) });
    }

    async prepareSolanaReleaseEscapePayoutOperation(payer, noteId) {
        if (!Number.isSafeInteger(Number(noteId)) || Number(noteId) < 0) {
            throw new Error('A valid note ID is required to release an escape payout.');
        }
        return this.prepareSolanaLedgerOperation('release', { payer, note_id: Number(noteId) });
    }

    /**
     * Make sure a USDC payout account can be credited before an exit or a
     * parked-payout release. The wallet's own canonical USDC account is
     * created when missing (`CreateIdempotent`, rent paid by the wallet) in a
     * separate, preceding transaction; any other payout account must already
     * be an initialized, unfrozen classic USDC account.
     */
    async ensureUsdcPayoutAccount(destination, { wallet, account, signal = null, onProgress = () => {} } = {}) {
        await this.init();
        const funding = this.config.funding;
        const payer = base58Encode(account?.publicKey);
        if (account?.address !== payer) {
            throw new Error('The Wallet Standard account address does not match its public key.');
        }
        const options = signal ? { signal } : undefined;
        const existing = await readUsdcTokenAccount(funding, destination, options);
        if (existing?.creditable) return existing;
        if (existing || destination !== usdcAssociatedTokenAddress(payer)) {
            const error = new Error(existing
                ? 'The USDC payout account is frozen, uninitialized or holds another token.'
                : 'The USDC payout account does not exist. Create it first, or withdraw to this wallet’s own USDC account.');
            error.code = 'usdc_destination_not_creditable';
            throw error;
        }
        const operation = await prepareLocalUsdcAccountCreation(funding, { payer }, options);
        await submitPreparedSolanaOperation({
            wallet,
            account,
            chain: funding.wallet_standard_chain,
            operation,
            expectedInstruction: {
                programId: base58Decode(ASSOCIATED_TOKEN_PROGRAM_ID, 32, 'associated token program'),
                keys: usdcAccountCreationKeys({ payer, owner: payer })
                    .map(key => ({ ...key, pubkey: key.pubkey.toBytes() })),
                data: [1]
            },
            sendSignedTransaction: event => sendSignedSolanaTransaction(funding, event, options),
            confirmTransaction: event => confirmFinalizedSolanaTransaction(funding, event, options),
            onProgress
        });
        const created = await readUsdcTokenAccount(funding, destination, options);
        if (!created?.creditable) throw new Error('The wallet’s USDC account was not created.');
        return created;
    }

    solanaJournalPlan(scope) {
        if (scope === 'deposit') return this.runtime?.pendingDeposit || null;
        if (scope === 'withdrawal') return this.runtime?.preparedWithdrawal || null;
        throw new Error('Unknown durable Solana operation scope.');
    }

    solanaJournalIdentity(plan, payer = null) {
        const funding = this.config?.funding;
        if (!isUsdcFunding(funding) || !plan?.operationId) {
            throw new Error('A complete Dagon Solana operation is required.');
        }
        return {
            operationId: plan.operationId,
            deploymentId: this.manifest.deployment_id,
            backend: funding.ledger_backend,
            chainId: funding.chain_id,
            protocolBinding: funding.contract_address,
            programId: funding.program_id,
            vault: funding.vault_state,
            ...(payer ? { payer } : {})
        };
    }

    /** Persist the entire prepared plan before the first wallet prompt. */
    async beginSolanaOperationJournal(scope, payer, operation) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const plan = this.solanaJournalPlan(scope);
            const kind = scope === 'deposit' ? 'deposit' : plan?.mode;
            const identity = this.solanaJournalIdentity(plan, payer);
            const created = createSolanaOperationJournal({
                kind,
                ...identity,
                operation
            });
            if (plan.solanaJournal) {
                assertSolanaOperationJournal(plan.solanaJournal, identity);
                if (JSON.stringify(plan.solanaJournal.operation) !== JSON.stringify(created.operation)) {
                    throw new Error('A different Solana transaction plan is already saved for this operation.');
                }
                return plan.solanaJournal;
            }
            const nextPlan = { ...plan, solanaJournal: created };
            await this.commit({
                ...this.runtime,
                ...(scope === 'deposit'
                    ? { pendingDeposit: nextPlan }
                    : { preparedWithdrawal: nextPlan })
            });
            return created;
        });
    }

    /** C3: record, before an exit proof leaves the device, how long it can land. */
    async markPreparedWithdrawalReleased() {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const validUntil = Number(prepared?.public_inputs?.valid_until ?? 0);
            if (!prepared || !validUntil) throw new Error('The durable prepared withdrawal is missing.');
            if (Number(prepared.releasedValidUntil || 0) >= validUntil) return prepared;
            const next = { ...prepared, releasedValidUntil: validUntil };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async currentSolanaOperationJournal(scope) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const plan = this.solanaJournalPlan(scope);
            if (!plan?.solanaJournal) return null;
            assertSolanaOperationJournal(plan.solanaJournal, this.solanaJournalIdentity(plan));
            return plan.solanaJournal;
        });
    }

    async updateSolanaOperationJournal(scope, operationId, update) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const plan = this.solanaJournalPlan(scope);
            if (!plan?.solanaJournal || plan.operationId !== operationId) {
                throw new Error('The durable Solana operation changed in another tab.');
            }
            const identity = this.solanaJournalIdentity(plan);
            assertSolanaOperationJournal(plan.solanaJournal, identity);
            const journal = update(plan.solanaJournal);
            assertSolanaOperationJournal(journal, identity);
            const nextPlan = { ...plan, solanaJournal: journal };
            await this.commit({
                ...this.runtime,
                ...(scope === 'deposit'
                    ? { pendingDeposit: nextPlan }
                    : { preparedWithdrawal: nextPlan })
            });
            return journal;
        });
    }

    rememberSolanaStageSigned(scope, operationId, event) {
        return this.updateSolanaOperationJournal(
            scope,
            operationId,
            journal => recordSolanaSignedStage(journal, event)
        );
    }

    rememberSolanaStageSubmitted(scope, operationId, event) {
        return this.updateSolanaOperationJournal(
            scope,
            operationId,
            journal => recordSolanaSubmittedStage(journal, event)
        );
    }

    rememberSolanaStageFinalized(scope, operationId, event) {
        return this.updateSolanaOperationJournal(
            scope,
            operationId,
            journal => recordSolanaFinalizedStage(journal, event)
        );
    }

    async resumeSolanaOperation(scope) {
        const journal = await this.currentSolanaOperationJournal(scope);
        return journal ? resumeSolanaOperationJournal(journal) : null;
    }

    /** Clear only after the semantic note transition has been independently observed. */
    async clearSolanaOperationJournal(scope, operationId) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const plan = this.solanaJournalPlan(scope);
            if (!plan?.solanaJournal || plan.operationId !== operationId) {
                throw new Error('The durable Solana operation changed before its journal could be cleared.');
            }
            const nextPlan = { ...plan };
            delete nextPlan.solanaJournal;
            await this.commit({
                ...this.runtime,
                ...(scope === 'deposit'
                    ? { pendingDeposit: nextPlan }
                    : { preparedWithdrawal: nextPlan })
            });
            return nextPlan;
        });
    }

    /**
     * Execute or resume the selected deposit/withdrawal's ordered Solana plan.
     * Every callback crosses the strict IndexedDB durability boundary before
     * the next network side effect is allowed to begin.
     */
    async submitSolanaOperation(scope, {
        wallet,
        account,
        signal = null,
        onProgress = () => {}
    } = {}) {
        await this.init();
        if (scope === 'deposit') this.requireOnlineDeployment();
        const funding = this.config?.funding;
        if (!isUsdcFunding(funding)) {
            throw new Error('Solana wallet submission requires a Dagon USDC deployment.');
        }
        const publicKey = account?.publicKey;
        const payer = base58Encode(publicKey);
        if (account?.address !== payer) {
            throw new Error('The Wallet Standard account address does not match its public key.');
        }
        let journal = await this.currentSolanaOperationJournal(scope);
        if (!journal) {
            if (scope !== 'deposit') await this.markPreparedWithdrawalReleased();
            const operation = scope === 'deposit'
                ? await this.prepareSolanaDepositOperation(payer)
                : await this.prepareSolanaWithdrawalOperation(payer);
            journal = await this.beginSolanaOperationJournal(scope, payer, operation);
        }
        assertSolanaOperationJournal(journal, {
            ...this.solanaJournalIdentity(this.solanaJournalPlan(scope)),
            payer
        });
        if (scope === 'deposit') {
            const plan = this.solanaJournalPlan(scope);
            validatePreparedSolanaDeposit(journal.operation, { funding, payer,
                deposit: { expected_note_id: Number(plan.next_note_id), commitment: plan.commitment, amount: plan.amount }
            });
        }
        const resume = resumeSolanaOperationJournal(journal);
        if (resume.completed) return [];
        return submitPreparedSolanaOperation({
            wallet,
            account,
            chain: funding.wallet_standard_chain,
            operation: resume.operation,
            programId: base58Decode(funding.program_id, 32, 'Solana program ID'),
            vaultState: base58Decode(funding.vault_state, 32, 'Solana vault state'),
            signedTransactions: resume.signedTransactions,
            startIndex: resume.startIndex,
            onSigned: event => this.rememberSolanaStageSigned(
                scope,
                journal.operationId,
                event
            ),
            onSubmitted: event => this.rememberSolanaStageSubmitted(
                scope,
                journal.operationId,
                event
            ),
            onConfirmed: event => this.rememberSolanaStageFinalized(
                scope,
                journal.operationId,
                event
            ),
            sendSignedTransaction: event => sendSignedSolanaTransaction(
                funding,
                event,
                signal ? { signal } : undefined
            ),
            confirmTransaction: event => confirmFinalizedSolanaTransaction(
                funding,
                event,
                signal ? { signal } : undefined
            ),
            onProgress
        });
    }

    /**
     * Promote a finalized deposit into private wallet state only after the
     * program-owned note account agrees with the locally generated
     * commitment/amount. The operator's tree mirror is deliberately not
     * consulted: exits are leaf-bound and root-free, so withholding the
     * indexer must never keep a landed deposit from becoming exitable.
     * Requests read and verify the mirror themselves.
     */
    async confirmSolanaDeposit() {
        await this.init();
        const plan = await this.pendingDeposit();
        const journal = await this.currentSolanaOperationJournal('deposit');
        if (!plan || !journal || plan.operationId !== journal.operationId
            || !resumeSolanaOperationJournal(journal).completed) {
            throw new Error('The Solana deposit has not finalized every transaction stage.');
        }
        const funding = this.config.funding;
        const operationState = await readFinalizedSolanaOperationState(
            funding,
            journal.operation,
            { noteId: Number(plan.next_note_id) }
        );
        const note = operationState.note;
        if (!note || note.status !== 'active'
            || !sameFelt(note.commitment, plan.commitment)
            || BigInt(note.amount) !== BigInt(plan.amount)) {
            throw new Error('The finalized Solana note does not match this browser’s deposit.');
        }
        const vault = await assertSolanaVault(funding);
        if (!vault || Number(vault.nextNoteId) <= Number(plan.next_note_id)) {
            throw new Error('The finalized Solana vault has not recorded this deposit.');
        }
        const expiry = Number(note.expiry);
        if (!Number.isSafeInteger(expiry) || expiry <= 0) {
            throw new Error('The finalized Solana note has an invalid expiry.');
        }
        return this.confirmDeposit({
            operationId: plan.operationId,
            secret: plan.secret,
            note_id: Number(plan.next_note_id),
            amount: Number(plan.amount),
            commitment: plan.commitment,
            expiry_ts: expiry,
            transactionHash: journal.stages.at(-1)?.signature || null
        });
    }

    async confirmSolanaWithdrawal() {
        await this.init();
        const plan = await this.currentPreparedWithdrawal();
        const journal = await this.currentSolanaOperationJournal('withdrawal');
        if (!plan || !journal || plan.operationId !== journal.operationId
            || !resumeSolanaOperationJournal(journal).completed) {
            throw new Error('The Solana withdrawal has not finalized every transaction stage.');
        }
        const noteId = Number(plan.noteId ?? plan.public_inputs?.note_id);
        const funding = this.config.funding;
        const operationState = await readFinalizedSolanaOperationState(
            funding,
            journal.operation,
            { noteId }
        );
        const finalBalance = BigInt(plan.public_inputs?.final_balance);
        const signature = journal.stages.at(-1)?.signature || null;
        const observedSlot = Number(operationState.slot);
        if (!Number.isSafeInteger(observedSlot) || observedSlot < 0
            || finalBalance < 0n || finalBalance > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error('The finalized Solana withdrawal has invalid accounting metadata.');
        }
        if (plan.mode === 'mutual') {
            // A close keeps the note's leaf: the note reads Closed, never pending.
            if (operationState.pending || (operationState.note && operationState.note.status !== 'closed')) {
                throw new Error('The finalized mutual close left unexpected Solana note state.');
            }
            const record = await this.detachClosedWithdrawal({
                mode: 'mutual',
                payoutVerified: true,
                noteId,
                destination: plan.destination,
                finalBalance: Number(finalBalance),
                transactionHash: signature,
                closeBlockNumber: observedSlot,
                lastObservedBlock: observedSlot,
                clearanceReserved: true
            });
            const finalized = await this.updateWithdrawal(record.recordId, {
                phase: 'closed',
                chainStatus: 'closed',
                state: null,
                preparedWithdrawal: null,
                finalizedBlockNumber: observedSlot,
                finalitySource: 'solana_finalized',
                error: null
            });
            return { status: 'closed', record: finalized, signature, slot: operationState.slot };
        }
        const note = operationState.note;
        const pending = operationState.pending;
        const terms = escapeTerms(plan);
        // A raise may already have lowered the payout; the state balance and
        // the successor nullifier are fixed by the proof.
        if (plan.mode !== 'escape' || !note || note.status !== 'pending_withdrawal' || !pending
            || pending.stage !== 'open'
            || pending.destination !== plan.destination
            || BigInt(pending.finalBalance) > finalBalance
            || BigInt(pending.stateBalance) !== terms.stateBalance
            || !sameFelt(pending.nextNullifier, plan.public_inputs?.next_nullifier)
            || !sameFelt(pending.nullifier, plan.withdrawalNullifier
                || plan.public_inputs?.withdrawal_nullifier)) {
            throw new Error('The finalized Solana escape does not match its prepared proof.');
        }
        const deadline = Number(pending.deadline);
        if (!Number.isSafeInteger(deadline) || deadline <= 0) {
            throw new Error('The finalized Solana escape has an invalid challenge deadline.');
        }
        const record = await this.detachEscapeWithdrawal({
            phase: 'pending',
            chainStatus: 'pending_withdrawal',
            noteId,
            destination: plan.destination,
            finalBalance: Number(pending.finalBalance),
            ...escapeRecordTerms(plan, pending.conceded),
            challengeDeadline: deadline,
            transactionHash: signature,
            startBlockNumber: observedSlot,
            lastObservedBlock: observedSlot
        });
        return { status: 'pending_withdrawal', record, signature, slot: operationState.slot };
    }

    // An escape's pending record is driven by one durable journal at a time
    // in the record's solanaFinalizeOperationId/solanaFinalizationJournal slot:
    // `finalize` after the challenge window, then `release` only when the
    // finalization parked the payout because the destination was not creditable.
    async currentSolanaFinalizationJournal(recordId) {
        const record = await this.currentWithdrawal(recordId);
        if (!record?.solanaFinalizationJournal) return null;
        assertSolanaOperationJournal(
            record.solanaFinalizationJournal,
            this.solanaJournalIdentity({ operationId: record.solanaFinalizeOperationId })
        );
        return record.solanaFinalizationJournal;
    }

    async beginSolanaFinalizationJournal(recordId, payer, operation, kind = 'finalize') {
        const record = await this.currentWithdrawal(recordId);
        const phases = kind === 'release'
            ? ['payout_parked', 'releasing']
            : ['pending', 'finalizing', 'awaiting_wallet'];
        if (!record || record.mode !== 'escape' || !phases.includes(record.phase)) {
            throw new Error(kind === 'release'
                ? 'There is no parked Solana escape payout to release.'
                : 'There is no pending Solana escape to finalize.');
        }
        const operationId = record.solanaFinalizeOperationId || uuid();
        const identity = this.solanaJournalIdentity({ operationId }, payer);
        const created = createSolanaOperationJournal({ kind, ...identity, operation });
        if (record.solanaFinalizationJournal) {
            assertSolanaOperationJournal(record.solanaFinalizationJournal, identity);
            if (record.solanaFinalizationJournal.kind !== kind
                || JSON.stringify(record.solanaFinalizationJournal.operation)
                    !== JSON.stringify(created.operation)) {
                throw new Error('A different Solana escape operation is already saved.');
            }
            return record.solanaFinalizationJournal;
        }
        const updated = await this.updateWithdrawal(recordId, {
            phase: kind === 'release' ? 'releasing' : 'finalizing',
            solanaFinalizeOperationId: operationId,
            solanaFinalizationJournal: created
        }, { expectedRevision: record.revision });
        return updated.solanaFinalizationJournal;
    }

    async updateSolanaFinalizationJournal(recordId, operationId, update) {
        const record = await this.currentWithdrawal(recordId);
        if (!record?.solanaFinalizationJournal
            || record.solanaFinalizeOperationId !== operationId) {
            throw new Error('The durable Solana finalization changed in another tab.');
        }
        const identity = this.solanaJournalIdentity({ operationId });
        assertSolanaOperationJournal(record.solanaFinalizationJournal, identity);
        const journal = update(record.solanaFinalizationJournal);
        assertSolanaOperationJournal(journal, identity);
        const updated = await this.updateWithdrawal(recordId, {
            phase: journal.kind === 'release' ? 'releasing' : 'finalizing',
            solanaFinalizationJournal: journal
        }, { expectedRevision: record.revision });
        return updated.solanaFinalizationJournal;
    }

    /** Finalize an unchallenged escape after its window; the payout may be parked. */
    submitSolanaFinalization(recordId, options = {}) {
        return this.submitSolanaPendingRecordOperation(recordId, 'finalize', options);
    }

    /** Pay a parked escape payout to its saved destination once that account is creditable. */
    submitSolanaEscapePayoutRelease(recordId, options = {}) {
        return this.submitSolanaPendingRecordOperation(recordId, 'release', options);
    }

    async submitSolanaPendingRecordOperation(recordId, kind, {
        wallet,
        account,
        signal = null,
        onProgress = () => {}
    } = {}) {
        await this.init();
        const funding = this.config.funding;
        if (!isUsdcFunding(funding)) {
            throw new Error('Solana escape finalization requires a Dagon USDC deployment.');
        }
        const payer = base58Encode(account?.publicKey);
        if (account?.address !== payer) {
            throw new Error('The Wallet Standard account address does not match its public key.');
        }
        let record = await this.currentWithdrawal(recordId);
        if (!record) throw new Error('The saved escape is no longer available.');
        let journal = record.solanaFinalizationJournal || null;
        if (journal && journal.kind !== kind) {
            throw new Error('A different Solana escape operation is still saved for this record.');
        }
        if (!journal) {
            const operation = kind === 'release'
                ? await this.prepareSolanaReleaseEscapePayoutOperation(payer, record.noteId)
                : await this.prepareSolanaFinalizeEscapeOperation(payer, record.noteId);
            journal = await this.beginSolanaFinalizationJournal(recordId, payer, operation, kind);
            record = await this.currentWithdrawal(recordId);
        }
        const identity = this.solanaJournalIdentity({ operationId: record.solanaFinalizeOperationId });
        assertSolanaOperationJournal(journal, { ...identity, payer });
        const resume = resumeSolanaOperationJournal(journal);
        if (!resume.completed) {
            await submitPreparedSolanaOperation({
                wallet,
                account,
                chain: funding.wallet_standard_chain,
                operation: resume.operation,
                programId: base58Decode(funding.program_id, 32, 'Solana program ID'),
                vaultState: base58Decode(funding.vault_state, 32, 'Solana vault state'),
                signedTransactions: resume.signedTransactions,
                startIndex: resume.startIndex,
                onSigned: event => this.updateSolanaFinalizationJournal(
                    recordId,
                    journal.operationId,
                    current => recordSolanaSignedStage(current, event)
                ),
                onSubmitted: event => this.updateSolanaFinalizationJournal(
                    recordId,
                    journal.operationId,
                    current => recordSolanaSubmittedStage(current, event)
                ),
                onConfirmed: event => this.updateSolanaFinalizationJournal(
                    recordId,
                    journal.operationId,
                    current => recordSolanaFinalizedStage(current, event)
                ),
                sendSignedTransaction: event => sendSignedSolanaTransaction(
                    funding,
                    event,
                    signal ? { signal } : undefined
                ),
                confirmTransaction: event => confirmFinalizedSolanaTransaction(
                    funding,
                    event,
                    signal ? { signal } : undefined
                ),
                onProgress
            });
        }
        record = await this.currentWithdrawal(recordId);
        journal = record.solanaFinalizationJournal;
        if (!resumeSolanaOperationJournal(journal).completed) {
            throw new Error('The Solana escape operation did not finalize every transaction stage.');
        }
        const operationState = await readFinalizedSolanaOperationState(
            funding,
            journal.operation,
            { noteId: Number(record.noteId) }
        );
        // Finalization closes the note but keeps its leaf (a release may
        // follow its retirement); no root changes.
        const { note, pending } = operationState;
        const parked = pending?.stage === 'payout_parked';
        if ((note && !['closed', 'retired'].includes(note.status))
            || pending?.stage === 'open' || (parked && kind === 'release')) {
            throw new Error('The finalized Solana escape still has live note state.');
        }
        const slot = Number(operationState.slot);
        if (!Number.isSafeInteger(slot) || slot < 0) {
            throw new Error('The finalized Solana escape has an invalid slot.');
        }
        const signature = journal.stages.at(-1)?.signature || null;
        // A parked payout leaves the pending record with the vault; this
        // record then waits for a release to the same saved destination.
        const finalized = await this.updateWithdrawal(recordId, {
            phase: parked ? 'payout_parked' : 'closed',
            chainStatus: parked ? 'payout_parked' : 'closed',
            payoutVerified: !parked,
            ...(kind === 'release'
                ? { releaseTransactionHash: signature }
                : { finalizeTransactionHash: signature }),
            finalizedBlockNumber: slot,
            finalitySource: 'solana_finalized',
            error: null
        }, { expectedRevision: record.revision, sanitize: true });
        return { status: parked ? 'payout_parked' : 'closed', record: finalized, signature,
            slot: operationState.slot };
    }

    async treePath(noteId, requireExisting = true, expectedActiveRoot = null) {
        return waitForExpectedActiveRoot(async () => {
            const snapshot = await this.remoteJson(`${this.config.funding.indexer_url}/v1/tree/snapshot`);
            return this.worker.call('treePath', { snapshot, noteId, requireExisting });
        }, expectedActiveRoot, { sleep: milliseconds => delay(milliseconds) });
    }

    async nextDepositPath(expectedActiveRoot = null) {
        return waitForExpectedActiveRoot(async () => {
            const snapshot = await this.remoteJson(`${this.config.funding.indexer_url}/v1/tree/snapshot`);
            return this.worker.call('treePath', {
                snapshot,
                noteId: Number(snapshot.next_note_id),
                requireExisting: false
            });
        }, expectedActiveRoot, { sleep: milliseconds => delay(milliseconds) });
    }

    // Only a never-journaled plan can be re-planned (new amount or vault
    // slot): once a Solana journal is saved, its signed transactions may
    // already be on the network.
    canReplanPendingDeposit(pending = this.runtime?.pendingDeposit) {
        return Boolean(pending && typeof pending.operationId === 'string' && pending.operationId
            && !pending.solanaJournal && (pending.phase || 'prepared') === 'prepared');
    }

    async prepareDeposit(amount) {
        await this.init();
        this.requireOnlineDeployment();
        const plan = await withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) throw new Error('This browser already has an active private note.');
            if (this.runtime.pendingDeposit) {
                const pending = this.runtime.pendingDeposit;
                if (Number(pending.amount) === Number(amount)) return pending;
                if (!this.canReplanPendingDeposit(pending)) {
                    throw new Error('A previous Solana deposit is unfinished. Recover it before changing the amount.');
                }
                await this.commit({ ...this.runtime, pendingDeposit: null });
                await this.reload();
            }
            const params = await this.worker.call('generateDeposit');
            const path = await this.nextDepositPath();
            const plan = {
                operationId: uuid(),
                createdAt: Date.now(),
                phase: 'prepared',
                amount: Number(amount),
                secret: params.secret,
                commitment: params.registration_commitment,
                next_note_id: path.note_id,
                active_root: path.active_root,
                zero_path: path.siblings
            };
            // Persist the note secret before any wallet prompt. If the tab is
            // closed after the transactions are signed, the deposit can still
            // be resumed from its journal and confirmed from finalized state.
            await this.commit({ ...this.runtime, pendingDeposit: plan });
            return plan;
        });
        // Start only after deposit preparation's small WASM calls have left the
        // worker. Wallet signing and Solana finality normally outlast the decode,
        // hiding it without creating a lease or disposable inference request.
        void this.prewarmRequestProver();
        return plan;
    }

    async refreshPendingDeposit(amount, expectedActiveRoot = null, { expectedOperationId = null } = {}) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) throw new Error('This browser already has an active private note.');
            const pending = this.runtime.pendingDeposit;
            if (!pending) throw new Error('The durable pending deposit is missing.');
            if (expectedOperationId && pending.operationId !== expectedOperationId) {
                throw new Error('The pending deposit changed in another tab. Check its status before continuing.');
            }
            if (Number(pending.amount) !== Number(amount)) {
                throw new Error('The prepared private note has a different deposit amount.');
            }
            if (!this.canReplanPendingDeposit(pending)) {
                throw new Error('This deposit already has signed Solana transactions. Resume it before refreshing the vault path.');
            }
            const path = await this.nextDepositPath(expectedActiveRoot);
            const refreshed = {
                ...pending,
                next_note_id: path.note_id,
                active_root: path.active_root,
                zero_path: path.siblings
            };
            // Keep the durable secret and commitment, but rebase their unused
            // note onto the latest append position before the wallet prompt.
            await this.commit({ ...this.runtime, pendingDeposit: refreshed });
            return refreshed;
        });
    }

    async pendingDeposit() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.runtime.pendingDeposit ? { ...this.runtime.pendingDeposit } : null;
        });
    }

    async confirmDeposit(args) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) throw new Error('This browser already has an active private note.');
            const pending = this.runtime.pendingDeposit;
            if (!pending || pending.secret !== args.secret
                || (args.operationId && pending.operationId !== args.operationId)
                || Number(pending.next_note_id) !== Number(args.note_id)
                || Number(pending.amount) !== Number(args.amount)
                || (args.commitment && !sameFelt(pending.commitment, args.commitment))) {
                throw new Error('The deposit secret does not match this browser’s durable pending deposit.');
            }
            const state = await this.worker.call('confirmDeposit', {
                config: this.config.wallet_core,
                args: {
                    secret: args.secret,
                    note_id: Number(args.note_id),
                    amount: Number(args.amount),
                    expiry_ts: Number(args.expiry_ts)
                }
            });
            await this.commit({
                ...this.runtime,
                state,
                journal: null,
                pendingDeposit: null,
                preparedWithdrawal: null
            }, {
                depositConfirmation: {
                    operationId: pending.operationId,
                    createdAt: pending.createdAt || null,
                    confirmedAt: Date.now(),
                    transactionHash: args.transactionHash || null
                }
            });
            // The atomic note/history write is the confirmation boundary.
            // A later worker status refresh must not turn this exact committed
            // deposit into a reported funding failure or authorize resubmission.
            return {
                status: 'confirmed',
                operationId: pending.operationId,
                noteId: Number(args.note_id),
                amount: Number(args.amount),
                transactionHash: args.transactionHash || null
            };
        });
    }

    // A lease's budget is its USD tier in USDC base units: one micro-USDC
    // per micro-USD, so no price conversion exists anywhere.
    leaseBudget(spendingLimitUsd, { checkBalance = false } = {}) {
        if (!CHAT_SPENDING_TIER_USD.includes(Number(spendingLimitUsd))) throw new Error('Invalid private-balance model budget configuration.');
        const amount = Number(usdcBaseUnits(String(spendingLimitUsd)));
        if (checkBalance) {
            const balance = Number(this.runtime.state.current_balance);
            if (!Number.isSafeInteger(balance) || balance < 0) throw new Error('Invalid private USDC balance.');
            if (amount < Number(this.config.request_charge_cap)) throw new Error('This model budget is below the deployment’s minimum private-chat budget.');
            if (balance < amount) {
                const error = new Error(`This model requires at least $${Number(spendingLimitUsd).toFixed(2)} in private balance for a new key. Choose a lower-cap model, or fund a larger balance.`);
                error.code = 'insufficient_chat_balance';
                error.required_credits = amount;
                error.required_balance_usd = Number(spendingLimitUsd);
                throw error;
            }
        }
        return amount;
    }

    async prepareLeaseRequest(onProgress = () => {}, signal = null, spendingLimitUsd = 1) {
        this.requireOnlineDeployment();
        throwIfAborted(signal);
        if (!this.runtime.state) throw new Error('Fund a private balance before starting a chat.');
        // C3: no request (new or re-sent) while an exit is prepared at this state.
        if (this.runtime.preparedWithdrawal) throw new Error('Finish the prepared withdrawal before sending another message.');
        const journal = this.runtime.journal;
        if (journal?.invalidSuccessor || journal?.withheldObservedAt) {
            throw new BrowserWalletHttpError(
                'The operator settled your last private request but has not delivered a valid balance update. Withdraw with the escape hatch: you recover your balance minus at most that request’s limit.',
                409,
                'successor_withheld'
            );
        }
        if (journal) return journal.prepared_request;
        onProgress('syncing', 'Checking your private balance…');
        const path = await this.treePath(this.runtime.state.note_id, true);
        throwIfAborted(signal);
        const now = Date.now();
        // C2: one bound per state. A request proof already left the device at
        // this state (then discarded as unaccepted), so any new proof here
        // must carry that same bound: a raise is capped by the largest bound
        // ever released at a state. issueLease settles a key of another
        // budget unused and proves the selected budget at the next state.
        const recordedBound = BigInt(this.runtime.state.bound_at_state ?? 0);
        const spendingLimitCredits = recordedBound > 0n
            ? Number(recordedBound)
            : this.leaseBudget(spendingLimitUsd, { checkBalance: true });
        onProgress('proving', 'Proving this chat is funded…');
        const prepared = await this.worker.call('prepareRequest', {
            config: {
                ...this.config.wallet_core,
                request_charge_cap: spendingLimitCredits,
                policy_charge_cap: this.config.policy_enabled
                    ? spendingLimitCredits
                    : this.config.wallet_core.policy_charge_cap
            },
            state: this.runtime.state,
            args: {
                payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1 }),
                active_root: path.active_root,
                merkle_siblings: path.siblings,
                client_request_id: uuid(),
                request_time: Math.floor(now / 1000),
                created_at_ms: now
            },
            provingKey: this.config.proving_keys.request
        });
        throwIfAborted(signal);
        if (!prepared.state || BigInt(prepared.state.bound_at_state ?? 0)
            !== BigInt(prepared.request?.public_inputs?.solvency_bound ?? -1)) {
            throw new Error('The private wallet did not record this request’s bound at its state.');
        }
        // The bound and the journal become durable together, before the proof
        // can leave the device.
        await this.commit({ ...this.runtime, state: prepared.state, journal: prepared.journal });
        return prepared.request;
    }

    async verifyLease(lease, expectedLimitCredits, expectedRequestId, onProgress = () => {}, signal = null) {
        throwIfAborted(signal);
        if (lease.status !== 'active'
            || lease.client_request_id !== expectedRequestId
            || !lease.api_key
            || Number(lease.expires_at) <= Math.floor(Date.now() / 1000)) {
            throw new Error('The zkAPI server returned an unusable OpenRouter lease.');
        }
        if (Number(lease.spending_limit_usd) !== leaseLimitUsd(expectedLimitCredits)) {
            throw new Error('The zkAPI server returned a child key with the wrong USD spending cap.');
        }
        exactTrustedUrl(lease.openrouter_api_base, this.config.openrouter.inference_base, 'OpenRouter inference origin');
        if (this.config.openrouter.require_oa_key_source && lease.key_source !== 'oa_org') {
            throw new Error('Client policy requires an OA verifier-backed ephemeral key.');
        }
        if (lease.key_source === 'oa_org') {
            onProgress('verifying', 'Verifying the new private key with OA…');
            const evidence = lease.verification;
            if (!evidence?.station_id || !evidence.station_signature || !evidence.org_signature) {
                throw new Error('The OA lease omitted its verification evidence.');
            }
            exactTrustedUrl(evidence.verifier_url, this.config.openrouter.verifier_url, 'OA verifier');
            if (Number(evidence.key_valid_till) < Number(lease.expires_at)
                || Number(evidence.key_valid_till) - Number(lease.expires_at) > 60) {
                throw new Error('The OA evidence expiry does not safely cover the lease.');
            }
            const verification = await this.remoteJson(`${this.config.openrouter.verifier_url}/submit_key`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                signal,
                body: JSON.stringify({
                    station_id: evidence.station_id,
                    api_key: lease.api_key,
                    key_valid_till: evidence.key_valid_till,
                    station_signature: evidence.station_signature,
                    org_signature: evidence.org_signature
                })
            });
            if (verification.status !== 'verified') throw new Error('The trusted OA verifier rejected the ephemeral key.');
        }
    }

    async requestLeaseWithRetry(request, onProgress = () => {}, signal = null, retryOptions = {}) {
        const maxWaitMs = retryOptions.maxWaitMs ?? LEASE_ISSUE_MAX_WAIT_MS;
        const maxAttempts = retryOptions.maxAttempts ?? LEASE_ISSUE_MAX_ATTEMPTS;
        const initialRetryMs = retryOptions.initialRetryMs ?? LEASE_ISSUE_INITIAL_RETRY_MS;
        const maxRetryMs = retryOptions.maxRetryMs ?? LEASE_ISSUE_MAX_RETRY_MS;
        const now = retryOptions.now || Date.now;
        const sleep = retryOptions.sleep || delay;
        const deadline = now() + maxWaitMs;
        const body = JSON.stringify(request);
        let attempt = 1;

        while (true) {
            throwIfAborted(signal);
            onProgress(
                'requesting',
                attempt === 1
                    ? 'Creating a temporary key for this chat…'
                    : 'Retrying temporary key creation…'
            );
            try {
                return await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    signal,
                    body
                });
            } catch (error) {
                throwIfAborted(signal);
                const backoffDelayMs = Math.min(
                    initialRetryMs * (2 ** Math.max(0, attempt - 1)),
                    maxRetryMs
                );
                const advertisedRetryMs = leaseRetryAfterMilliseconds(error);
                const retryDelayMs = Math.max(backoffDelayMs, advertisedRetryMs || 0);
                if (!isExplicitlyRetriableLeaseError(error)
                    || attempt >= maxAttempts
                    || now() + retryDelayMs > deadline) {
                    makeLeaseRateLimitActionable(error, advertisedRetryMs);
                    throw error;
                }

                const waitLabel = retryDelayMs < 1_000 ? 'a moment' : describeRetryDelay(retryDelayMs);
                onProgress(
                    'waiting',
                    isLeaseRateLimit(error)
                        ? `OA is briefly limiting new temporary keys. Retrying in ${waitLabel}…`
                        : `The temporary-key service is briefly unavailable. Retrying in ${waitLabel}…`
                );
                throwIfAborted(signal);
                await sleep(retryDelayMs, signal);
                attempt += 1;
            }
        }
    }

    async issueLease(sessionId, onProgress = () => {}, signal = null, spendingLimitUsd = 1) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            throwIfAborted(signal);
            await this.reload();
            throwIfAborted(signal);
            onProgress('checking', 'Checking for unfinished private activity…');
            const reportRecovery = (phase, message) => onProgress(phase, message, 'recovery');
            await this.recoverPendingLocked({
                retireLostKey: true,
                onProgress: reportRecovery,
                signal
            });
            let request = await this.prepareLeaseRequest(onProgress, signal, spendingLimitUsd);

            // A browser can restart with a durable proof made under an older
            // spending policy. Finish that byte-identical request safely, but
            // never expose its legacy-cap key to the host application. Settle it
            // unused, install the signed receipt, then prove the selected budget.
            const desiredLimitCredits = this.leaseBudget(spendingLimitUsd);
            if (Number(request.public_inputs.solvency_bound) !== desiredLimitCredits) {
                try {
                    this.legacyMigrationInProgress = true;
                    reportRecovery('settling', 'Updating an unfinished temporary key…');
                    const legacyLease = await this.requestLeaseWithRetry(request, reportRecovery, signal);
                    await this.verifyLease(
                        legacyLease,
                        request.public_inputs.solvency_bound,
                        request.client_request_id,
                        reportRecovery,
                        signal
                    );
                    // Persist recovery metadata, but deliberately never assign
                    // this legacy-cap key to activeLease. It cannot be returned
                    // to inference even if settlement needs a later retry.
                    await this.commit({
                        ...this.runtime,
                        lease: {
                            ownerId: this.ownerId,
                            sessionId,
                            client_request_id: legacyLease.client_request_id,
                            expires_at: Number(legacyLease.expires_at),
                            settle_after: Number(legacyLease.settle_after),
                            spending_limit_usd: Number(legacyLease.spending_limit_usd)
                        }
                    });
                    reportRecovery('usage', 'Closing the unfinished temporary key…');
                    const status = await this.retireRequest(
                        legacyLease.client_request_id,
                        request,
                        signal
                    );
                    if (status.status !== 'finalized') {
                        throw new Error(`Lease is still ${status.status}.`);
                    }
                    const installed = await this.installRecoveredResponse(
                        legacyLease.client_request_id,
                        reportRecovery
                    );
                    if (!installed) throw new Error('The legacy private-key receipt is not ready yet.');
                } finally {
                    this.legacyMigrationInProgress = false;
                }
                await this.reload();
                request = await this.prepareLeaseRequest(onProgress, signal, spendingLimitUsd);
            }
            let lease;
            try {
                lease = await this.requestLeaseWithRetry(request, onProgress, signal);
            } catch (error) {
                if (error.code === 'stale_root') {
                    await this.commit({ ...this.runtime, journal: null });
                }
                throw error;
            }
            await this.verifyLease(
                lease,
                request.public_inputs.solvency_bound,
                request.client_request_id,
                onProgress,
                signal
            );
            throwIfAborted(signal);
            const activeLease = {
                ...lease,
                sessionId,
                selectedSpendingLimitUsd: Number(spendingLimitUsd),
                inFlight: 0
            };
            await this.commit({
                ...this.runtime,
                lease: {
                    ownerId: this.ownerId,
                    sessionId,
                    client_request_id: lease.client_request_id,
                    expires_at: Number(lease.expires_at),
                    settle_after: Number(lease.settle_after),
                    spending_limit_usd: Number(lease.spending_limit_usd)
                }
            });
            this.activeLease = activeLease;
            this.dispatchEvent(new Event('change'));
            this.scheduleSettlement();
            onProgress('ready', 'Private chat ready.');
            return this.activeLease;
        });
    }

    addLeaseProgressListener(listener, { replay = true } = {}) {
        if (typeof listener !== 'function') return () => {};
        // Each registration gets a distinct token so two callers that happen
        // to pass the same callback can unsubscribe independently.
        const registration = (phase, message, kind) => listener(phase, message, kind);
        this.leaseProgressListeners.add(registration);
        if (replay && this.lastLeaseProgress) {
            const { phase, message, kind } = this.lastLeaseProgress;
            try {
                registration(phase, message, kind);
            } catch (error) {
                console.warn('A private-access progress listener failed.', error);
            }
        }
        return () => this.leaseProgressListeners.delete(registration);
    }

    reportLeaseProgress(phase, message, kind = 'access') {
        this.lastLeaseProgress = { phase, message, kind };
        for (const listener of this.leaseProgressListeners) {
            try {
                listener(phase, message, kind);
            } catch (error) {
                console.warn('A private-access progress listener failed.', error);
            }
        }
    }

    async waitForLeasePromise(normalizedSessionId, onProgress, signal, spendingLimitUsd = 1) {
        const leasePromise = this.leasePromise;
        if (!leasePromise) return null;
        if (this.leasePromiseSession !== normalizedSessionId) {
            throw new BrowserWalletHttpError(
                `Chat ${this.leasePromiseSession} is creating the current private key.`,
                409,
                'lease_session_conflict'
            );
        }

        if (this.leasePromiseSpendingLimitUsd !== spendingLimitUsd) {
            throw new BrowserWalletHttpError(
                'A different model budget is being prepared. Retry when the current request finishes.',
                409,
                'lease_budget_conflict'
            );
        }

        throwIfAborted(signal);
        const unsubscribe = this.addLeaseProgressListener(onProgress);
        this.leaseWaiterCount += 1;
        let abortHandler = null;
        try {
            if (!signal) return await leasePromise;
            const canceled = new Promise((_, reject) => {
                abortHandler = () => {
                    try {
                        throwIfAborted(signal);
                    } catch (error) {
                        reject(error);
                    }
                };
                signal.addEventListener('abort', abortHandler, { once: true });
            });
            return await Promise.race([leasePromise, canceled]);
        } finally {
            if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
            unsubscribe();
            this.leaseWaiterCount = Math.max(0, this.leaseWaiterCount - 1);
            if (signal?.aborted
                && this.leasePromise === leasePromise
                && this.leaseWaiterCount === 0) {
                this.leaseAbortController?.abort();
            }
        }
    }

    async ensureLease(sessionId, onProgress = () => {}, signal = null, spendingLimitUsd = 1) {
        throwIfAborted(signal);
        await this.init();
        this.requireOnlineDeployment();
        throwIfAborted(signal);
        const normalized = String(sessionId || 'default').slice(0, 160);
        spendingLimitUsd = Number(spendingLimitUsd);
        if (!CHAT_SPENDING_TIER_USD.includes(spendingLimitUsd)) throw new Error('Invalid private-balance model budget configuration.');
        if (this.leasePromise) {
            return this.waitForLeasePromise(normalized, onProgress, signal, spendingLimitUsd);
        }
        const now = Math.floor(Date.now() / 1000);
        const isSafeForNewRequest = this.activeLease
            && Number(this.activeLease.expires_at) > now + MIN_REQUEST_LEASE_REMAINING_SECONDS;
        const activeLeaseMatchesPolicy = this.activeLease?.selectedSpendingLimitUsd === spendingLimitUsd;
        if (this.activeLease
            && isSafeForNewRequest
            && activeLeaseMatchesPolicy
            && !this.activeLease.retiring
            && !this.activeLease.retired) {
            if (this.activeLease.sessionId !== normalized) {
                throw new BrowserWalletHttpError(
                    `Chat ${this.activeLease.sessionId} owns the current private key until it settles.`,
                    409,
                    'lease_session_conflict'
                );
            }
            onProgress('ready', 'Private chat ready.', 'access');
            return this.activeLease;
        }
        if (this.activeLease?.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the current requests to finish before renewing or changing the private key budget.',
                409,
                'lease_requests_in_flight'
            );
        }
        await this.reload();
        if (this.runtime.lease
            && Number(this.runtime.lease.settle_after || this.runtime.lease.expires_at) > now
            && this.runtime.lease.ownerId !== this.ownerId) {
            throw new BrowserWalletHttpError(
                `Another browser tab owns the current private key until ${new Date(Number(this.runtime.lease.settle_after || this.runtime.lease.expires_at) * 1000).toLocaleTimeString()}.`,
                409,
                'lease_tab_conflict'
            );
        }
        if (this.leasePromise) {
            return this.waitForLeasePromise(normalized, onProgress, signal, spendingLimitUsd);
        }
        this.leasePromiseSession = normalized;
        this.leasePromiseSpendingLimitUsd = spendingLimitUsd;
        this.lastLeaseProgress = null;
        const jobKind = this.activeLease ? 'renewal' : 'access';
        const controller = new AbortController();
        this.leaseAbortController = controller;
        let leasePromise;
        leasePromise = (async () => {
            if (this.activeLease) {
                await this.retireActiveLease(
                    (phase, message) => this.reportLeaseProgress(phase, message, 'renewal')
                );
            }
            return this.issueLease(
                normalized,
                (phase, message, kind = 'access') => this.reportLeaseProgress(
                    phase,
                    message,
                    kind === 'access' ? jobKind : kind
                ),
                controller.signal,
                spendingLimitUsd
            );
        })().finally(() => {
            if (this.leasePromise === leasePromise) {
                this.leasePromise = null;
                this.leasePromiseSession = null;
                this.leasePromiseSpendingLimitUsd = null;
                this.leaseAbortController = null;
                this.lastLeaseProgress = null;
            }
        });
        this.leasePromise = leasePromise;
        return this.waitForLeasePromise(normalized, onProgress, signal, spendingLimitUsd);
    }

    scheduleSettlement(delayOverrideMs = null) {
        if (!this.activeLease) return;
        if (this.settlementTimer) clearTimeout(this.settlementTimer);
        const delayMs = delayOverrideMs ?? Math.max(
            0,
            Number(this.activeLease.settle_after) * 1000 - Date.now() + 250
        );
        this.settlementTimer = setTimeout(() => {
            this.settlementTimer = null;
            if (!this.activeLease) return;
            if (this.activeLease.inFlight > 0) {
                this.scheduleSettlement(500);
                return;
            }
            void this.retireActiveLease().catch(() => {
                if (this.activeLease) this.scheduleSettlement(2_000);
            });
        }, Math.min(delayMs, 2_147_000_000));
    }

    async retireRequest(clientRequestId, request, signal, retryOptions = {}) {
        const now = retryOptions.now || Date.now;
        const sleep = retryOptions.sleep || delay;
        const maxWaitMs = retryOptions.maxWaitMs ?? MAX_RECOVERY_WAIT_MS;
        const deadline = now() + maxWaitMs;
        const body = JSON.stringify(request);
        let attempt = 1;
        while (true) {
            try {
                return await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(clientRequestId)}`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body,
                    signal
                });
            } catch (error) {
                const backoffDelayMs = Math.min(1_000 * (2 ** Math.max(0, attempt - 1)), 10_000);
                const advertisedRetryMs = leaseRetryAfterMilliseconds(error);
                const retryDelayMs = Math.max(backoffDelayMs, advertisedRetryMs || 0);
                if (!isExplicitlyRetriableLeaseRetirementError(error)
                    || now() + retryDelayMs > deadline) {
                    throw error;
                }
                await sleep(retryDelayMs, signal);
                attempt += 1;
            }
        }
    }

    async retireActiveLease(onProgress = () => {}) {
        if (this.retirementPromise) return this.retirementPromise;
        if (!this.activeLease || !this.runtime?.journal) return;
        if (this.activeLease.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the active model requests to finish before settling the private key.',
                409,
                'lease_requests_in_flight'
            );
        }
        const lease = this.activeLease;
        lease.retiring = true;
        onProgress('settling', 'Closing the temporary key from the previous chat…');
        const retireWithinLock = async () => {
            await this.reload();
            const request = this.runtime.journal?.prepared_request;
            if (!request || request.client_request_id !== lease.client_request_id) return;
            onProgress('usage', 'Confirming the previous chat’s usage…');
            const signal = AbortSignal.timeout(MAX_RECOVERY_WAIT_MS);
            const status = await this.retireRequest(lease.client_request_id, request, signal);
            if (status.status !== 'finalized') throw new Error(`Lease is still ${status.status}.`);
            // The remote key is now disabled. Make that transition
            // irreversible locally before receipt installation, which can
            // still fail independently and be retried from the durable journal.
            lease.retired = true;
            if (this.activeLease === lease) this.activeLease = null;
            if (this.settlementTimer) clearTimeout(this.settlementTimer);
            this.settlementTimer = null;
            this.dispatchEvent(new Event('change'));
            return this.installRecoveredResponse(lease.client_request_id, onProgress, { signal });
        };
        const retirement = (async () => {
            const installed = await withBrowserWalletLock(
                this.manifest.deployment_id,
                retireWithinLock
            );
            this.activeLease = null;
            if (this.settlementTimer) clearTimeout(this.settlementTimer);
            this.settlementTimer = null;
            // installRecoveredResponse commits and notifies. Only publish here
            // when there was no recovered response (and therefore no commit).
            if (!installed) this.dispatchEvent(new Event('change'));
            return installed;
        })();
        this.retirementPromise = retirement;
        try {
            return await retirement;
        } finally {
            if (this.activeLease === lease) lease.retiring = false;
            if (this.retirementPromise === retirement) this.retirementPromise = null;
        }
    }

    /**
     * Retire the active key and install its successor. `allowUnresolved` is
     * the escape path: a request whose successor is withheld (or still
     * settling) stays journaled, since the escape's concession covers it.
     */
    async settleActiveLease(onProgress = () => {}, { allowUnresolved = false } = {}) {
        await this.init();
        if (this.retirementPromise) {
            try {
                await this.retirementPromise;
            } catch {
                // The durable journal remains recoverable below even if the
                // first receipt-installation attempt failed.
            }
        }
        if (this.legacyMigrationInProgress) {
            throw new BrowserWalletHttpError(
                'An unfinished private key is already being updated. Try settling again in a moment.',
                409,
                'lease_pending'
            );
        }
        if (this.activeLease?.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the active model requests to finish before settling the private key.',
                409,
                'lease_requests_in_flight'
            );
        }
        try {
            if (this.activeLease) {
                await this.retireActiveLease(onProgress);
            } else {
                await this.reload();
                await this.recoverPending({ retireLostKey: true, onProgress });
            }
        } catch (error) {
            // Escape must not depend on any operator response (including an
            // outage, refusal, or malformed receipt). Keep the durable journal
            // and its bound; the exit policy below accounts for this request.
            if (!allowUnresolved) throw error;
        }
        await this.reload();
        if (this.runtime.journal && !allowUnresolved) {
            throw new BrowserWalletHttpError(
                'The private key usage receipt is still being finalized. Try settling again shortly.',
                409,
                'lease_pending'
            );
        }
        this.activeLease = null;
        return this.walletStatus();
    }

    async settleSessionLease(sessionId, onProgress = () => {}) {
        await this.init();
        if (this.activeLease?.sessionId === sessionId) {
            // retireActiveLease captures the exact request and checks it again
            // under the wallet lock before publishing its settlement.
            await this.retireActiveLease(onProgress);
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            // A different tab may have opened a key after our first owner read.
            // Recovery must never retire that tab's new lease.
            if (this.runtime?.lease?.sessionId !== sessionId) return;
            await this.recoverPendingLocked({ retireLostKey: true, onProgress });
            if (this.runtime?.journal && this.runtime?.lease?.sessionId === sessionId) {
                throw new BrowserWalletHttpError('This chat’s private key is still being finalized. Try again shortly.',
                    409, 'lease_pending');
            }
        });
    }

    /** Finalized block time from the host-pinned RPC (never the operator), for the exit freeze. */
    readFinalizedChainTime() {
        return readFinalizedSolanaTime(this.config.funding);
    }

    /**
     * Install the signed successor of the journal's request. `settled` says the
     * server already reported the request finalized: a missing successor is
     * then withheld, and a signed successor that fails the wallet's S3-S5
     * checks is treated exactly like a withheld one (design §6.1). Either way
     * the journal stays, the balance accepts no new request, and an escape
     * concedes at most the request's bound.
     */
    async installRecoveredResponse(clientRequestId, onProgress = () => {}, { settled = false, signal = null } = {}) {
        onProgress('applying', 'Updating your private balance…');
        const recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/requests/${encodeURIComponent(clientRequestId)}`, { signal });
        if (!recovery.request_response) {
            if (settled && !this.runtime.journal?.withheldObservedAt) {
                await this.commit({ ...this.runtime, journal: { ...this.runtime.journal, withheldObservedAt: Date.now() } });
            }
            return false;
        }
        // E4.6: a successor that arrives after an exit proof left the device
        // is not installed while that proof can still land.
        if (await exitProofStillLive(this.runtime.preparedWithdrawal?.releasedValidUntil ?? null,
            () => this.readFinalizedChainTime())) return false;
        let state;
        try {
            state = await this.worker.call('completeResponse', {
                config: this.config.wallet_core,
                args: {
                    state: this.runtime.state,
                    journal: this.runtime.journal,
                    response: recovery.request_response
                }
            });
        } catch (error) {
            if (!/invalid_successor/.test(error?.message || '')) throw error;
            const charge = recovery.request_response.charge_applied;
            await this.commit({ ...this.runtime, journal: { ...this.runtime.journal, invalidSuccessor: {
                reason: String(error.message),
                charge: charge == null ? null : String(charge),
                observedAt: Date.now()
            } } });
            throw new BrowserWalletHttpError(
                'The operator returned an invalid balance update for your last private request. This balance accepts no new requests; withdraw with the escape hatch.',
                409,
                'successor_withheld'
            );
        }
        await this.commit({ ...this.runtime, state, journal: null, lease: null });
        return true;
    }

    // E3: the settlement deadline the server reported for the journal's
    // request, kept for the escape timing even when the server goes away.
    async rememberRequestSettlement(status) {
        const settleAfter = Number(status?.settle_after);
        const journal = this.runtime?.journal;
        if (!journal || !Number.isSafeInteger(settleAfter) || settleAfter <= 0
            || Number(journal.settleAfter) === settleAfter) return;
        await this.commit({ ...this.runtime, journal: { ...journal, settleAfter } });
    }

    async recoverPending(options = {}) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.recoverPendingLocked(options);
        });
    }

    async recoverPendingLocked({ quiet = false, ...options } = {}) {
        try {
            return await this.recoverPendingRequest(options);
        } catch (error) {
            if (!quiet) throw error;
            return false;
        }
    }

    async recoverPendingRequest({ retireLostKey = false, onProgress = () => {}, signal = AbortSignal.timeout(MAX_RECOVERY_WAIT_MS) } = {}) {
        throwIfAborted(signal);
        if (!this.runtime?.journal || this.activeLease) return false;
        const request = this.runtime.journal.prepared_request;
        try {
            const status = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(request.client_request_id)}`, { signal });
            await this.rememberRequestSettlement(status);
            if (status.status === 'active' && retireLostKey) {
                const ownershipDeadline = Number(
                    this.runtime.lease?.settle_after || this.runtime.lease?.expires_at
                );
                if (this.runtime.lease && ownershipDeadline > Math.floor(Date.now() / 1000)
                    && this.runtime.lease.ownerId !== this.ownerId) {
                    return false;
                }
                onProgress('settling', 'Finishing an interrupted private chat…');
                const retired = await this.retireRequest(request.client_request_id, request, signal);
                if (retired.status !== 'finalized') return false;
            } else if (status.status !== 'finalized') {
                return false;
            }
            return this.installRecoveredResponse(request.client_request_id, onProgress, { settled: true, signal });
        } catch (error) {
            if (error.status === 404) {
                const recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/nullifiers/${encodeURIComponent(this.runtime.journal.nullifier)}`, { signal });
                if (recovery.request_response) return this.installRecoveredResponse(request.client_request_id, onProgress, { signal });
                if (recovery.status === 'not_found'
                    && recovery.nullifier_status === 'unknown' && !recovery.request_response) {
                    // Never accepted: the journal's byte-identical request is
                    // simply sent again by the next lease attempt.
                    return false;
                }
                if (recovery.nullifier_status === 'clearance_reserved') {
                    // Mutual-close preparation owns this deterministic state
                    // nullifier. The lease was never accepted, so discard only
                    // its orphaned request journal and keep the withdrawal-only
                    // note/intent intact.
                    await this.commit({
                        ...this.runtime,
                        journal: null,
                        lease: null,
                        preparedWithdrawal: this.runtime.preparedWithdrawal || {
                            phase: 'reserving',
                            mode: 'mutual',
                            noteId: Number(this.runtime.state?.note_id),
                            destination: null,
                            withdrawalNullifier: this.runtime.journal.nullifier,
                            clearanceReserved: true,
                            createdAt: Date.now()
                        }
                    });
                    return true;
                }
            }
            throw error;
        }
    }

    async acquireEphemeralKey(sessionId, onProgress = () => {}, options = {}) {
        const signal = options.signal || null;
        const lease = await this.ensureLease(sessionId, onProgress, signal, options.spendingLimitUsd);
        throwIfAborted(signal);
        // Rotation may have started between ensureLease resolving and this
        // continuation. Retirement marks the old key synchronously, so check
        // ownership before checking it out and exposing its credential.
        if (this.activeLease !== lease || lease.retiring || lease.retired) {
            throw new BrowserWalletHttpError(
                'The previous private key is closing. Retry when its balance update finishes.',
                409,
                'lease_pending'
            );
        }
        lease.inFlight += 1;
        let released = false;
        return {
            mode: 'ephemeral-key',
            apiKey: lease.api_key,
            baseUrl: normalizeUrl(lease.openrouter_api_base),
            spendingLimitUsd: Number(lease.spending_limit_usd),
            headers: {
                authorization: `Bearer ${lease.api_key}`,
                'content-type': 'application/json',
                'http-referer': location.origin,
                'x-title': 'zkAPI'
            },
            release: () => {
                if (released) return;
                released = true;
                // A fetch resolves when headers arrive, not when an SSE body is
                // finished. Keep the lease checked out for the entire stream.
                lease.inFlight = Math.max(0, lease.inFlight - 1);
                if (lease.inFlight === 0
                    && Number(lease.settle_after) * 1000 <= Date.now()) {
                    this.scheduleSettlement(0);
                }
                this.dispatchEvent(new Event('change'));
            }
        };
    }

    /**
     * Prove a leaf-bound exit from the newest installed state. A mutual close
     * needs the server's clearance and a settled state. An escape concedes c
     * chosen by the exit rules (zkapiExitPolicy.chooseEscapeConcession): 0 from
     * a fresh state, and at most the state's single bound b when a request
     * made at it is in flight or its successor was withheld. `earlyConcession`
     * ('zero' | 'bound') forces an escape before the settlement window ends.
     */
    async prepareWithdrawal(mode, destination, { earlyConcession = null } = {}) {
        await this.init();
        await this.settleActiveLease(() => {}, { allowUnresolved: mode === 'escape' });
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (!this.runtime.state) throw new Error('There is no active private note to withdraw.');
            const validateExisting = (prepared) => {
                if (!prepared) return;
                if (Number(prepared.noteId ?? prepared.note_id ?? prepared.public_inputs?.note_id)
                    !== Number(this.runtime.state.note_id)) {
                    throw new Error('The prepared withdrawal belongs to a different private balance.');
                }
                const existingDestination = prepared.destination;
                const safeModeSwitch = !prepared.solanaJournal && (
                    (prepared.mode === 'mutual' && mode === 'escape')
                    || (prepared.mode === 'escape' && mode === 'mutual'
                        && prepared.clearanceReserved === true)
                );
                if (existingDestination
                    && (prepared.mode !== mode || existingDestination !== destination)
                    && !(safeModeSwitch && existingDestination === destination)) {
                    throw new Error('A different withdrawal is already prepared in this browser.');
                }
            };
            let existing = this.runtime.preparedWithdrawal;
            validateExisting(existing);
            try {
                await this.recoverPendingLocked({ retireLostKey: true });
            } catch (error) {
                // Recovery is advisory for escape, never an authorization
                // gate. Reload persisted state and retain an unresolved
                // journal so local timing and its bound choose the concession.
                if (mode !== 'escape') throw error;
            }
            await this.reload();
            if (!this.runtime.state) throw new Error('There is no active private note to withdraw.');
            // Recovery can discover that a pre-crash request nullifier was
            // already reserved for mutual close. Re-read that marker before
            // choosing whether this note is still usable.
            existing = this.runtime.preparedWithdrawal;
            validateExisting(existing);
            const state = this.runtime.state;
            const journal = this.runtime.journal;
            if ((mode === 'mutual' && (journal || this.runtime.lease)) || (!journal && this.runtime.lease)) {
                throw new BrowserWalletHttpError(
                    mode === 'mutual'
                        ? 'A private request from this balance is still unsettled. Wait for its balance update, or withdraw with the escape hatch.'
                        : 'A private chat started in another tab while withdrawal was opening. Finish that chat and try again.',
                    409,
                    'lease_pending'
                );
            }
            // Signed Solana transactions may already be on the network: the
            // journaled plan is resumed, never re-proved.
            if (existing?.solanaJournal) {
                if (!existing.public_inputs || !existing.proof) {
                    throw new Error('The submitted withdrawal proof is missing from this browser.');
                }
                return existing;
            }
            let concession = { conceded: 0n, rule: 'mutual' };
            if (mode === 'escape') {
                const lease = this.runtime.lease;
                concession = chooseEscapeConcession({
                    now: nowSeconds(),
                    expiryTs: Number(state.expiry_ts),
                    boundAtState: state.bound_at_state ?? 0,
                    inFlight: journal ? {
                        createdAt: Math.floor(Number(journal.created_at_ms) / 1000),
                        settleAfter: journal.settleAfter
                            ?? (lease?.client_request_id === journal.prepared_request?.client_request_id
                                ? lease.settle_after : null),
                        invalidSuccessorCharge: journal.invalidSuccessor?.charge ?? null
                    } : null,
                    earlyConcession
                });
                if (concession.action === 'wait') {
                    const error = new BrowserWalletHttpError(
                        `Your last private request may still be settling. From ${new Date(concession.escapeAt * 1000).toISOString()} the escape concedes at most that request’s limit; you can also force the escape now.`,
                        409,
                        'escape_wait'
                    );
                    error.escapeAt = concession.escapeAt;
                    throw error;
                }
            }
            const now = nowSeconds();
            // Exits are leaf-bound and root-free, so a never-released plan stays
            // reusable for the same state, concession and destination until it
            // nears its validity deadline.
            if (existing?.mode === mode && existing.public_inputs
                && existing.destination === destination
                && sameFelt(existing.stateAnchor, state.current_anchor)
                && BigInt(existing.public_inputs.conceded ?? -1) === concession.conceded
                && reusableExitProof(existing.public_inputs.valid_until, now)) {
                return existing;
            }
            let clearance = null;
            let withdrawalNullifier = existing?.withdrawalNullifier
                || existing?.public_inputs?.withdrawal_nullifier
                || null;
            const clearanceReserved = existing?.clearanceReserved === true
                || existing?.mode === 'mutual';
            if (mode === 'mutual') {
                withdrawalNullifier = withdrawalNullifier
                    || await this.worker.call('withdrawalNullifier', { state: this.runtime.state });
                // The server's mutual-close clearance reservation is
                // deliberately irreversible for this note state. Persist the
                // intent before crossing that boundary so closing the tab can
                // never leave an apparently usable but server-rejected note.
                await this.commit({
                    ...this.runtime,
                    preparedWithdrawal: {
                        phase: 'reserving',
                        mode,
                        operationId: existing?.operationId || uuid(),
                        noteId: Number(this.runtime.state.note_id),
                        destination,
                        withdrawalNullifier,
                        clearanceReserved: true,
                        releasedValidUntil: existing?.releasedValidUntil ?? null,
                        createdAt: Number(existing?.createdAt || Date.now())
                    }
                });
                clearance = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/withdraw/clearance`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({ withdrawal_nullifier: withdrawalNullifier })
                });
            }
            const validUntil = exitProofValidUntil(now);
            const plan = await this.worker.call('prepareWithdrawal', {
                config: this.config.wallet_core,
                state: this.runtime.state,
                args: {
                    mode,
                    destination,
                    clearance,
                    conceded: String(concession.conceded),
                    valid_until: String(validUntil)
                },
                provingKey: this.config.proving_keys.withdrawal
            });
            if (BigInt(plan.public_inputs?.conceded ?? -1) !== concession.conceded
                || Number(plan.public_inputs?.valid_until) !== validUntil
                || Boolean(plan.public_inputs?.has_clearance) !== (mode === 'mutual')) {
                throw new Error('The private wallet returned a withdrawal with different exit terms.');
            }
            plan.destination = destination;
            plan.phase = 'prepared';
            plan.operationId = existing?.operationId || uuid();
            plan.noteId = Number(this.runtime.state.note_id);
            plan.withdrawalNullifier = withdrawalNullifier
                || plan.public_inputs?.withdrawal_nullifier
                || null;
            plan.clearanceReserved = mode === 'mutual' || clearanceReserved;
            plan.stateAnchor = state.current_anchor;
            plan.boundAtState = String(state.bound_at_state ?? 0);
            plan.concessionRule = concession.rule;
            // A re-proof never thaws a state an earlier released proof froze.
            plan.releasedValidUntil = existing?.releasedValidUntil ?? null;
            plan.createdAt = Number(existing?.createdAt || Date.now());
            await this.commit({ ...this.runtime, preparedWithdrawal: plan });
            return plan;
        });
    }

    async clearPreparedWithdrawal({ expectedNoteId = null } = {}) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            if (expectedNoteId != null
                && Number(prepared.noteId ?? prepared.public_inputs?.note_id) !== Number(expectedNoteId)) {
                throw new Error('The selected withdrawal changed before it could be cleared.');
            }
            if (prepared.mode === 'mutual' || prepared.clearanceReserved === true) {
                throw new Error('This balance already has a mutual-close authorization and must remain withdrawal-only.');
            }
            if (prepared.solanaJournal?.stages?.some(stage => stage.phase === 'finalized')) {
                throw new Error('This withdrawal already finalized on Solana. Resume it to record the result.');
            }
            if (await exitProofStillLive(prepared.releasedValidUntil ?? null,
                () => this.readFinalizedChainTime())) {
                throw exitProofFrozenError(prepared);
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: null });
            return null;
        });
    }

    withdrawalRecordId(noteId) {
        return [
            this.manifest.deployment_id,
            canonicalChainId(this.config?.funding?.chain_id),
            String(this.config?.funding?.contract_address || '').toLowerCase(),
            Number(noteId)
        ].join(':');
    }

    async detachEscapeWithdrawal(details) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const noteId = Number(details.noteId);
            const result = await detachBrowserEscapeWithdrawal({
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: canonicalChainId(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: 'escape',
                phase: 'pending',
                chainStatus: 'pending_withdrawal',
                noteId,
                destination: details.destination,
                finalBalance: Number(details.finalBalance),
                ...concessionRecordFields(details),
                challengeDeadline: Number(details.challengeDeadline),
                transactionHash: details.transactionHash || null,
                startBlockNumber: Number(details.startBlockNumber || 0),
                lastObservedBlock: Number(details.lastObservedBlock || 0),
                createdAt: Number(details.createdAt || Date.now())
            });
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.activeLease = null;
            this.notify();
            return result.withdrawal;
        });
    }

    async detachClosedWithdrawal(details) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const noteId = Number(details.noteId);
            const result = await detachBrowserClosedWithdrawal({
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: canonicalChainId(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: details.mode,
                noteId,
                destination: details.destination,
                finalBalance: Number(details.finalBalance),
                transactionHash: details.transactionHash || null,
                closeBlockNumber: Number(details.closeBlockNumber || 0),
                payoutVerified: details.payoutVerified === true,
                lastObservedBlock: Number(details.lastObservedBlock || 0),
                clearanceReserved: details.clearanceReserved === true,
                createdAt: Number(details.createdAt || Date.now()),
                closedAt: Date.now()
            });
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.activeLease = null;
            this.notify();
            return result.withdrawal;
        });
    }

    async updateWithdrawal(recordId, changes = {}, options = {}) {
        await this.init();
        const updated = await updateBrowserWithdrawal(recordId, changes, options);
        await this.reload();
        this.notify();
        return updated;
    }

    async currentPreparedWithdrawal() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.runtime.preparedWithdrawal
                ? structuredClone(this.runtime.preparedWithdrawal)
                : null;
        });
    }

    async currentWithdrawal(recordId) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const record = this.withdrawals.find(entry => entry.recordId === recordId);
            return record ? structuredClone(record) : null;
        });
    }
}

const browserWalletRuntime = new BrowserWalletRuntime();
export { BrowserWalletHttpError, BrowserWalletRuntime };
export default browserWalletRuntime;
