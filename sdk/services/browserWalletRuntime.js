import { browserSdkOptions, beginBrowserSdkInitialization, browserSdkTransport } from '../configure.js';
import { assertNativeVault, isNativeSolFunding, validateNativeFunding, validateNativeQuote, readNativeQuote, nativeUnitsForUsd, nativeUsdMicros, sameNativeQuote, requestBillingQuote, readFinalizedChainTime } from './zkapiNativeBilling.mjs';
import { CHAT_SPENDING_TIER_USD } from './zkapiRequestCompat.mjs';
import { TestnetPasswordAuth, testnetPasswordRequired } from './testnetPasswordAuth.mjs';
import { sameFelt, waitForExpectedActiveRoot } from './zkapiActiveRoot.mjs';
import { chooseEscapeConcession, exitProofLive, exitProofLiveUntil, exitProofValidUntil, reusableExitProof }
    from './zkapiExitPolicy.mjs';
import { isUnsubmittedParkedMutualWithdrawal } from './zkapiWithdrawalRecovery.mjs';
import { canonicalChainId, losslessChainId, sameChainId } from './zkapiLedgerIdentity.mjs';
import { confirmFinalizedSolanaTransaction, readFinalizedSolanaOperationState,
    sendSignedSolanaTransaction }
    from './zkapiNativeSol.mjs';
import { base58Decode, base58Encode, submitPreparedSolanaOperation }
    from './zkapiSolanaTransport.mjs';
import { prepareLocalSolanaExit } from './zkapiSolanaExit.mjs';
import {
    assertSolanaOperationJournal,
    createSolanaOperationJournal,
    recordSolanaFinalizedStage,
    recordSolanaSignedStage,
    recordSolanaSubmittedStage,
    resumeSolanaOperationJournal
} from './zkapiSolanaJournal.mjs';
import {
    archiveBrowserWallet,
    assertBrowserBackgroundWithdrawalAvailable,
    authorizeBrowserWithdrawalFinalizationRetry,
    claimBrowserWithdrawalStartReplacement,
    claimBrowserBackgroundWithdrawalSubmission,
    claimBrowserWithdrawalFinalization,
    claimBrowserWithdrawalFinalizationReplacement,
    createWalletChannel,
    detachBrowserClosedWithdrawal,
    detachBrowserEscapeWithdrawal,
    listBrowserWithdrawals,
    isBrowserBackgroundWithdrawalPreparationCancelable,
    markBrowserWithdrawalFinalizationAmbiguous,
    markBrowserBackgroundWithdrawalAmbiguous,
    markBrowserWithdrawalFinalizationMissingReceipts,
    parkBrowserWithdrawal,
    projectBrowserDeposits,
    readBrowserWalletSnapshot,
    recordBrowserExpiryClaims,
    releaseBrowserWithdrawalFinalization,
    releaseBrowserWithdrawalFinalizationReplacementClaim,
    releaseBrowserWithdrawalStartSubmission,
    releaseBrowserBackgroundWithdrawalSubmission,
    rememberBrowserBackgroundWithdrawalMetadata,
    rememberBrowserBackgroundWithdrawalTransaction,
    rememberBrowserWithdrawalFinalization,
    rememberBrowserWithdrawalFinalizationSubmissionMetadata,
    requestPersistentStorage,
    repairBrowserUnsubmittedBackgroundWithdrawal,
    resolveBrowserBackgroundWithdrawalForRetry,
    resolveBrowserChallengedFinalization,
    restoreBrowserWithdrawal,
    saveBrowserBackgroundWithdrawalPlan,
    transferBrowserLateWithdrawalAttempt,
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
const LATE_WITHDRAWAL_TERMINAL_STATUSES = new Set([
    'closed',
    'detached',
    'reverted',
    'challenged',
    'superseded',
    'quarantined'
]);
const LATE_DEPOSIT_TERMINAL_STATUSES = new Set(['confirmed', 'reverted', 'superseded']);

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
        && !['stale_root', 'native_quote_expired', 'native_quote_superseded', 'lease_pending', 'lease_settlement_pending'].includes(error?.code);
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

function retainAttemptHistory(attempts, terminalStatuses, terminalLimit = 32) {
    const unresolved = attempts.filter(attempt => !terminalStatuses.has(attempt.status));
    const terminal = attempts
        .filter(attempt => terminalStatuses.has(attempt.status))
        .slice(-terminalLimit);
    // An unresolved transaction is a recovery capability, not log history. It
    // must never be evicted merely because more wallet attempts were made.
    return [...terminal, ...unresolved];
}

function unresolvedLateWithdrawalForNote(runtime, noteId) {
    return (runtime?.lateWithdrawalAttempts || []).find(attempt =>
        Number(attempt.noteId) === Number(noteId)
        && !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status)) || null;
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
        this.testnetAuth = new TestnetPasswordAuth({
            funding: this.config.funding,
            fetch: (url, init) => this.remoteFetchRaw(url, init),
            requestPassword: browserSdkOptions().requestTestnetPassword
        });
        await assertNativeVault(this.config.funding);
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
                    billingAsset: this.manifest.billing_asset || 'native_eth'
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
        const solana = isNativeSolFunding(manifest);
        if (solana ? !/^0x[0-9a-fA-F]{64}$/.test(manifest.contract_address)
            : !/^0x[0-9a-fA-F]{40}$/.test(manifest.contract_address)) {
            throw new Error(`The deployment manifest contains an invalid ${solana ? 'protocol binding' : 'contract address'}.`);
        }
        validateNativeFunding(manifest);
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
        if (this.browserConfig.deployment_status === 'migration_required') {
            throw new Error('This application still pins a legacy vault. Configure a newly deployed note-bound vault before funding.');
        }
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
        requireEqual(manifest.contract_address, trusted.contract_address,
            isNativeSolFunding(manifest) ? 'deployment binding' : 'vault address', lowercase);
        validateNativeFunding(manifest);
        validateNativeFunding(trusted);
        requireEqual(manifest.billing_asset, trusted.billing_asset, 'billing asset');
        requireEqual(manifest.billing_unit, trusted.billing_unit, 'billing unit');
        if (isNativeSolFunding(manifest)) {
            for (const [field, label, normalize] of [
                ['ledger_backend', 'ledger backend', String],
                ['network', 'Solana network', String],
                ['program_id', 'Solana program', String],
                ['vault_state', 'Solana vault state', String],
                ['genesis_hash', 'Solana genesis hash', String],
                ['wallet_standard_chain', 'wallet-standard chain', String],
                ['base_units_per_asset', 'SOL asset scale', String],
                ['pyth_receiver_program', 'Pyth receiver program', String],
                ['pyth_price_account', 'Pyth price account', String],
                ['pyth_feed_id', 'Pyth feed', lowercase],
                ['pyth_max_age_seconds', 'Pyth freshness', Number],
                ['pyth_max_confidence_bps', 'Pyth confidence bound', Number]
            ]) requireEqual(manifest[field], trusted[field], label, normalize);
        } else {
            requireEqual(manifest.native_asset_wei_per_unit, trusted.native_asset_wei_per_unit, 'native asset scale');
            requireEqual(manifest.native_price_feed_address, trusted.native_price_feed_address, 'ETH price feed', lowercase);
            requireEqual(manifest.native_price_feed_decimals, trusted.native_price_feed_decimals, 'ETH price decimals', Number);
            requireEqual(manifest.native_price_max_age_seconds, trusted.native_price_max_age_seconds, 'ETH price freshness', Number);
        }
        requireEqual(manifest.rpc_url, trusted.rpc_url, 'native asset RPC', normalizedUrl);
        requireEqual(manifest.protocol_server_url, trusted.protocol_server_url, 'protocol server', normalizedUrl);
        requireEqual(manifest.indexer_url, trusted.indexer_url, 'indexer', normalizedUrl);
        requireEqual(manifest.request_charge_cap, trusted.request_charge_cap, 'request charge cap', Number);
        for (const keyName of ['state_signing_key', 'clearance_signing_key']) {
            for (const coordinate of ['x', 'y']) {
                requireEqual(
                    manifest[keyName]?.[coordinate],
                    trusted[keyName]?.[coordinate],
                    `${keyName}.${coordinate}`,
                    lowercase
                );
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
        requireEqual(
            manifest.privacy_mode?.verifier_url,
            trusted.verifier_url,
            'OA verifier',
            normalizedUrl
        );
    }

    buildClientConfig(manifest, browserConfig) {
        const keyBase = new URL(browserConfig.proving_keys_base_url || './proofs/', browserConfigUrl());
        const requestKey = new URL('request.pk', keyBase).href;
        const withdrawalKey = new URL('withdrawal.pk', keyBase).href;
        const requestCap = Number(manifest.request_charge_cap);
        validateNativeFunding(manifest);
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
                ledger_backend: manifest.ledger_backend || 'evm.groth16.v1',
                chain_id: losslessChainId(manifest.chain_id),
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
                verifier_url: normalizeUrl(manifest.privacy_mode.verifier_url),
                require_oa_key_source: browserConfig.require_oa_key_source !== false
            },
            funding: {
                ledger_backend: manifest.ledger_backend || 'evm.groth16.v1',
                contract_address: manifest.contract_address,
                chain_id: losslessChainId(manifest.chain_id),
                indexer_url: normalizeUrl(manifest.indexer_url),
                protocol_server_url: normalizeUrl(manifest.protocol_server_url),
                models: manifest.models || [],
                suggested_deposit_amount: Number(browserConfig.suggested_deposit_amount || requestCap * 100),
                demo_rpc_url: manifest.rpc_url || null,
                billing_token_symbol: isNativeSolFunding(manifest) ? 'SOL' : 'ETH',
                billing_token_decimals: 9,
                billing_asset: manifest.billing_asset,
                billing_unit: manifest.billing_unit,
                native_asset_wei_per_unit: manifest.native_asset_wei_per_unit,
                native_price_feed_address: manifest.native_price_feed_address,
                native_price_feed_decimals: manifest.native_price_feed_decimals,
                native_price_max_age_seconds: manifest.native_price_max_age_seconds,
                base_units_per_asset: manifest.base_units_per_asset,
                network: manifest.network,
                program_id: manifest.program_id,
                vault_state: manifest.vault_state,
                genesis_hash: manifest.genesis_hash,
                wallet_standard_chain: manifest.wallet_standard_chain,
                pyth_receiver_program: manifest.pyth_receiver_program,
                pyth_price_account: manifest.pyth_price_account,
                pyth_feed_id: manifest.pyth_feed_id,
                pyth_max_age_seconds: manifest.pyth_max_age_seconds,
                pyth_max_confidence_bps: manifest.pyth_max_confidence_bps,
                demo_note_ttl_seconds: Number(manifest.note_ttl_seconds || 0) || null
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
        const preparedHashes = new Set((Array.isArray(prepared?.transactionHashes)
            ? prepared.transactionHashes
            : prepared?.transactionHash ? [prepared.transactionHash] : [])
            .map(hash => String(hash).toLowerCase()));
        const replacementIdentities = new Set((prepared?.transactionAttempts || [])
            .filter(attempt => preparedHashes.has(String(attempt.hash || '').toLowerCase())
                && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                && Number.isSafeInteger(Number(attempt.nonce))
                && Number(attempt.nonce) >= 0)
            .map(attempt => `${attempt.from.toLowerCase()}:${Number(attempt.nonce)}`));
        const pendingDepositHashes = new Set((Array.isArray(pendingDeposit?.transactionHashes)
            ? pendingDeposit.transactionHashes
            : pendingDeposit?.transactionHash ? [pendingDeposit.transactionHash] : [])
            .map(hash => String(hash).toLowerCase()));
        const depositReplacementIdentities = new Set((pendingDeposit?.transactionAttempts || [])
            .filter(attempt => pendingDepositHashes.has(String(attempt.hash || '').toLowerCase())
                && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                && Number.isSafeInteger(Number(attempt.nonce))
                && Number(attempt.nonce) >= 0)
            .map(attempt => `${attempt.from.toLowerCase()}:${Number(attempt.nonce)}`));
        const config = this.config ? {
            exit_only: this.exitOnly === true,
            ...this.config,
            active_lease: active,
            late_withdrawal_attempts: (this.runtime?.lateWithdrawalAttempts || [])
                .filter(attempt => !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status))
                .map(attempt => ({
                    operation_id: attempt.operationId,
                    note_id: Number(attempt.noteId),
                    mode: attempt.mode,
                    destination: attempt.destination,
                    transaction_hash: attempt.transactionHash,
                    status: attempt.status,
                    error: attempt.error || null
                })),
            late_deposit_attempts: (this.runtime?.lateDepositAttempts || [])
                .filter(attempt => !LATE_DEPOSIT_TERMINAL_STATUSES.has(attempt.status))
                .map(attempt => ({
                    operation_id: attempt.operationId,
                    note_id: Number(attempt.noteId),
                    amount: Number(attempt.amount),
                    transaction_hash: attempt.transactionHash,
                    status: attempt.status
                })),
            pending_deposit: pendingDeposit ? {
                operation_id: pendingDeposit.operationId || null,
                phase: pendingDeposit.phase || (pendingDeposit.transactionHash ? 'submitted' : 'ambiguous'),
                amount: Number(pendingDeposit.amount),
                funding_quote_available: Boolean(this.config?.funding)
                    && this.canQuotePendingDeposit(pendingDeposit),
                next_note_id: Number(pendingDeposit.next_note_id),
                transaction_hash: pendingDeposit.transactionHash || null,
                transaction_hashes: Array.isArray(pendingDeposit.transactionHashes)
                    ? [...pendingDeposit.transactionHashes]
                    : pendingDeposit.transactionHash ? [pendingDeposit.transactionHash] : [],
                replacement_available: pendingDeposit.phase === 'dropped_or_pending'
                    && depositReplacementIdentities.size === 1
            } : null,
            prepared_withdrawal: prepared ? {
                mode: prepared.mode,
                phase: prepared.phase || (prepared.transactionHash ? 'submitted' : 'prepared'),
                note_id: prepared.public_inputs?.note_id ?? prepared.noteId ?? prepared.note_id,
                destination: Array.isArray(prepared.public_inputs?.destination)
                    ? `0x${prepared.public_inputs.destination.map(byte => Number(byte).toString(16).padStart(2, '0')).join('')}`
                    : prepared.destination,
                transaction_hash: prepared.transactionHash || null,
                clearance_reserved: prepared.clearanceReserved === true || prepared.mode === 'mutual',
                conceded: prepared.public_inputs?.conceded != null ? String(prepared.public_inputs.conceded) : null,
                concession_rule: prepared.concessionRule || null,
                valid_until: prepared.public_inputs?.valid_until != null ? Number(prepared.public_inputs.valid_until) : null,
                exit_proof_live_until: exitProofLiveUntil(prepared.releasedValidUntil ?? null),
                replacement_available: prepared.phase === 'dropped_or_pending'
                    && replacementIdentities.size === 1
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
            deposits: this.deposits.map(record => ({ ...record,
                ...(record.expiryClaim ? { expiryClaim: { ...record.expiryClaim } } : {}) })),
            withdrawals: this.withdrawals.map(record => {
                const {
                    state: _state,
                    preparedWithdrawal: _prepared,
                    proof: _proof,
                    withdrawalNullifier: _nullifier,
                    inFlightJournal: _journal,
                    ...summary
                } = record;
                return { ...summary, backgroundWithdrawalReady: isUnsubmittedParkedMutualWithdrawal(
                    record, this.runtime?.lateWithdrawalAttempts || []
                ), backgroundPreparationCancelable: Boolean(this.config && this.manifest)
                    && isBrowserBackgroundWithdrawalPreparationCancelable(
                        record, this.runtime, this.backgroundWithdrawalIdentity(record)
                    ) };
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
            || storedRuntime.depositQuote
            || storedRuntime.preparedWithdrawal
            || storedRuntime.lease
            || (Array.isArray(storedRuntime.lateWithdrawalAttempts)
                && storedRuntime.lateWithdrawalAttempts.some(attempt =>
                    !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status)))
            || (Array.isArray(storedRuntime.lateDepositAttempts)
                && storedRuntime.lateDepositAttempts.some(attempt =>
                    !LATE_DEPOSIT_TERMINAL_STATUSES.has(attempt.status)))
        );
        if (this.manifest && hasDurableState
            && (!storedRuntime.deploymentId || storedRuntime.deploymentId !== this.manifest.deployment_id
                || (storedRuntime.billingAsset != null
                    && storedRuntime.billingAsset
                        !== (this.manifest.billing_asset || 'native_eth')))) {
            throw new Error(`This browser contains a wallet for ${storedRuntime.deploymentId || 'an unidentified legacy deployment'}. Switch back to that deployment before using or withdrawing it.`);
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
            billingAsset: this.manifest.billing_asset || 'native_eth'
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

    async rememberExpiryClaims(claims) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const updated = await recordBrowserExpiryClaims(this.manifest.deployment_id, claims);
            await this.reload();
            if (updated.length) this.notify();
            return updated;
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
        return this.testnetAuth ? this.testnetAuth.fetch(url, init) : this.remoteFetchRaw(url, init);
    }

    async remoteFetchRaw(url, init = {}) {
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
        if (response.status === 401 && this.testnetAuth?.protects(url)) throw testnetPasswordRequired();
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
        if (!isNativeSolFunding(funding)) {
            throw new Error('Prepared Solana operations require a Dagon native-SOL deployment.');
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
        return prepared.operation;
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

    solanaJournalPlan(scope) {
        if (scope === 'deposit') return this.runtime?.pendingDeposit || null;
        if (scope === 'withdrawal') return this.runtime?.preparedWithdrawal || null;
        throw new Error('Unknown durable Solana operation scope.');
    }

    solanaJournalIdentity(plan, payer = null) {
        const funding = this.config?.funding;
        if (!isNativeSolFunding(funding) || !plan?.operationId) {
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
        if (!isNativeSolFunding(funding)) {
            throw new Error('Solana wallet submission requires a Dagon native-SOL deployment.');
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
            || note.commitment.toLowerCase() !== String(plan.commitment).toLowerCase()
            || BigInt(note.amount) !== BigInt(plan.amount)) {
            throw new Error('The finalized Solana note does not match this browser’s deposit.');
        }
        const vault = await assertNativeVault(funding);
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
            expiry_ts: expiry
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

    async currentSolanaFinalizationJournal(recordId) {
        const record = await this.currentWithdrawal(recordId);
        if (!record?.solanaFinalizationJournal) return null;
        assertSolanaOperationJournal(
            record.solanaFinalizationJournal,
            this.solanaJournalIdentity({ operationId: record.solanaFinalizeOperationId })
        );
        return record.solanaFinalizationJournal;
    }

    async beginSolanaFinalizationJournal(recordId, payer, operation) {
        const record = await this.currentWithdrawal(recordId);
        if (!record || record.mode !== 'escape'
            || !['pending', 'finalizing', 'awaiting_wallet'].includes(record.phase)) {
            throw new Error('There is no pending Solana escape to finalize.');
        }
        const operationId = record.solanaFinalizeOperationId || uuid();
        const identity = this.solanaJournalIdentity({ operationId }, payer);
        const created = createSolanaOperationJournal({ kind: 'finalize', ...identity, operation });
        if (record.solanaFinalizationJournal) {
            assertSolanaOperationJournal(record.solanaFinalizationJournal, identity);
            if (JSON.stringify(record.solanaFinalizationJournal.operation)
                !== JSON.stringify(created.operation)) {
                throw new Error('A different Solana finalization plan is already saved.');
            }
            return record.solanaFinalizationJournal;
        }
        const updated = await this.updateWithdrawal(recordId, {
            phase: 'finalizing',
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
            phase: 'finalizing',
            solanaFinalizationJournal: journal
        }, { expectedRevision: record.revision });
        return updated.solanaFinalizationJournal;
    }

    async submitSolanaFinalization(recordId, {
        wallet,
        account,
        signal = null,
        onProgress = () => {}
    } = {}) {
        await this.init();
        const funding = this.config.funding;
        if (!isNativeSolFunding(funding)) {
            throw new Error('Solana finalization requires a Dagon native-SOL deployment.');
        }
        const payer = base58Encode(account?.publicKey);
        if (account?.address !== payer) {
            throw new Error('The Wallet Standard account address does not match its public key.');
        }
        let record = await this.currentWithdrawal(recordId);
        if (!record) throw new Error('The saved escape is no longer available.');
        let journal = record.solanaFinalizationJournal || null;
        if (!journal) {
            const operation = await this.prepareSolanaFinalizeEscapeOperation(payer, record.noteId);
            journal = await this.beginSolanaFinalizationJournal(recordId, payer, operation);
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
            throw new Error('The Solana finalization did not finalize every transaction stage.');
        }
        const operationState = await readFinalizedSolanaOperationState(
            funding,
            journal.operation,
            { noteId: Number(record.noteId) }
        );
        // Finalization closes the note but keeps its leaf; no root changes.
        if (operationState.pending || (operationState.note && operationState.note.status !== 'closed')) {
            throw new Error('The finalized Solana escape still has live note state.');
        }
        const slot = Number(operationState.slot);
        if (!Number.isSafeInteger(slot) || slot < 0) {
            throw new Error('The finalized Solana escape has an invalid slot.');
        }
        const finalized = await this.updateWithdrawal(recordId, {
            phase: 'closed',
            chainStatus: 'closed',
            payoutVerified: true,
            finalizeTransactionHash: journal.stages.at(-1)?.signature || null,
            finalizedBlockNumber: slot,
            finalitySource: 'solana_finalized',
            error: null
        }, { expectedRevision: record.revision, sanitize: true });
        return { status: 'closed', record: finalized,
            signature: journal.stages.at(-1)?.signature || null, slot: operationState.slot };
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

    canQuotePendingDeposit(pending = this.runtime?.pendingDeposit) {
        const noActiveAttempt = pending && typeof pending.operationId === 'string' && pending.operationId
            && !pending.submissionId && !pending.transactionHash
            && !pending.transactionHashes?.length && !pending.transactionAttempts?.length
            && !pending.submissionFrom && pending.submissionNonce == null
            && !(this.runtime?.lateDepositAttempts || []).some(attempt =>
                attempt.operationId === pending.operationId
                && !LATE_DEPOSIT_TERMINAL_STATUSES.has(attempt.status));
        if (!noActiveAttempt) return false;
        if (pending.phase === 'retry_exact') {
            return pending.fundingQuoteRetryAuthorized === true && Boolean(pending.ambiguousSubmissions?.length);
        }
        return pending.phase === 'prepared' && !pending.legacyRecovery
            && !(pending.ambiguousSubmissions || []).some(attempt =>
                !(pending.resolvedAmbiguousSubmissionIds || []).includes(attempt.submissionId));
    }

    async prepareDepositQuote(amount, expectedActiveRoot) {
        await this.init();
        this.requireOnlineDeployment();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (this.runtime.state || (pending && !this.canQuotePendingDeposit(pending))) {
                throw new Error('Recover the existing private balance or deposit before preparing another quote.');
            }
            if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('Invalid deposit amount.');
            if (pending && pending.amount !== amount) {
                throw new Error('The prepared deposit amount is fixed. Refresh its existing funding quote.');
            }
            if (pending?.phase === 'retry_exact') {
                // An explicit retry may coexist with an unknown old send. Its
                // exact calldata must remain fixed until chain recovery proves
                // the old slot cannot execute; quoting never rebases it.
                return { ...pending };
            }
            const previous = pending || this.runtime.depositQuote;
            const params = previous?.amount === amount ? previous
                : await this.worker.call('generateDeposit');
            const path = await this.nextDepositPath(expectedActiveRoot);
            const draft = {
                ...(pending || {}),
                operationId: previous?.amount === amount ? previous.operationId : uuid(),
                createdAt: previous?.amount === amount ? previous.createdAt : Date.now(),
                amount,
                secret: params.secret,
                commitment: params.commitment || params.registration_commitment,
                next_note_id: path.note_id,
                active_root: path.active_root,
                zero_path: path.siblings
            };
            // A new quote is only a draft. A rejected-before-broadcast pending
            // plan can be requoted, but only for its original amount and identity.
            // Neither path creates a claim, history entry or transaction.
            await this.commit(pending
                ? { ...this.runtime, depositQuote: null, pendingDeposit: draft }
                : { ...this.runtime, depositQuote: draft });
            return draft;
        });
    }

    async prepareDeposit(amount, { preparedOperationId = null } = {}) {
        await this.init();
        this.requireOnlineDeployment();
        const plan = await withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) throw new Error('This browser already has an active private note.');
            if (preparedOperationId && this.runtime.pendingDeposit?.operationId === preparedOperationId
                && this.runtime.pendingDeposit.amount !== amount) {
                throw new Error('The prepared deposit amount does not match the selected quote.');
            }
            if (preparedOperationId && this.runtime.pendingDeposit?.operationId !== preparedOperationId) {
                const draft = this.runtime.depositQuote;
                if (this.runtime.pendingDeposit || !draft || draft.operationId !== preparedOperationId
                    || draft.amount !== amount) {
                    throw new Error('The deposit quote changed in another tab. Refresh the quote before continuing.');
                }
                const promoted = { ...draft, phase: 'prepared' };
                // Promotion is the explicit deposit action, atomic with the
                // stale-quote check under the same cross-tab wallet lock.
                await this.commit({ ...this.runtime, depositQuote: null, pendingDeposit: promoted });
                return promoted;
            }
            if (this.runtime.pendingDeposit) {
                let pending = this.runtime.pendingDeposit;
                if (!pending.operationId || !pending.phase) {
                    // Legacy clients opened MetaMask without a durable claim.
                    // A missing hash is not proof that nothing was broadcast.
                    pending = {
                        ...pending,
                        operationId: pending.operationId || uuid(),
                        phase: pending.transactionHash ? 'submitted' : 'ambiguous',
                        legacyRecovery: true
                    };
                    await this.commit({ ...this.runtime, pendingDeposit: pending });
                }
                if (Number(pending.amount) !== Number(amount)) {
                    if (pending.phase !== 'prepared' || pending.submissionId
                        || pending.transactionHash || pending.transactionHashes?.length) {
                        throw new Error('A previous deposit may already be in MetaMask. Recover it before changing the amount.');
                    }
                    await this.commit({ ...this.runtime, pendingDeposit: null });
                    await this.reload();
                } else {
                    return pending;
                }
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
            // Persist the note secret before MetaMask is opened. If the tab is
            // closed after the transaction is submitted, the deposit can still
            // be confirmed from its on-chain receipt without losing funds.
            await this.commit({ ...this.runtime, depositQuote: null, pendingDeposit: plan });
            return plan;
        });
        // Start only after deposit preparation's small WASM calls have left the
        // worker. MetaMask/on-chain confirmation normally outlasts the decode,
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
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (pending.phase !== 'prepared' || pending.submissionId || hashes.length) {
                throw new Error('This deposit already has a wallet attempt. Check it before refreshing the vault path.');
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

    async claimPendingDepositSubmission(expectedOperationId = null) {
        await this.init();
        this.requireOnlineDeployment();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) throw new Error('The durable pending deposit is missing.');
            if (expectedOperationId && pending.operationId !== expectedOperationId) {
                throw new Error('The pending deposit changed in another tab. Check its status before continuing.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (hashes.length) {
                return {
                    status: 'submitted',
                    transactionHash: hashes[0],
                    operationId: pending.operationId,
                    submissionId: pending.submissionId || null,
                    noteId: Number(pending.next_note_id),
                    amount: Number(pending.amount),
                    commitment: pending.commitment,
                    secret: pending.secret,
                    deploymentId: this.manifest.deployment_id,
                    chainId: losslessChainId(this.config.funding.chain_id),
                    contractAddress: this.config.funding.contract_address
                };
            }
            if (pending.phase === 'ambiguous') {
                throw new BrowserWalletHttpError(
                    'The previous deposit has an unknown result. Check it before explicitly retrying.',
                    409,
                    'deposit_submission_ambiguous'
                );
            }
            if (pending.submissionId) {
                throw new BrowserWalletHttpError(
                    'This deposit is already awaiting MetaMask in this or another tab.',
                    409,
                    'deposit_wallet_pending'
                );
            }
            if (!['prepared', 'retry_exact'].includes(pending.phase)) {
                throw new Error('This deposit is not ready for a wallet request.');
            }
            const submissionId = uuid();
            const next = {
                ...pending,
                phase: 'awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return {
                status: 'claimed',
                plan: { ...next },
                transactionHash: null,
                operationId: next.operationId,
                submissionId,
                noteId: Number(next.next_note_id),
                amount: Number(next.amount),
                commitment: next.commitment,
                secret: next.secret,
                deploymentId: this.manifest.deployment_id,
                chainId: losslessChainId(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address
            };
        });
    }

    async claimPendingDepositReplacement(expectedFrom) {
        await this.init();
        this.requireOnlineDeployment();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending || pending.phase !== 'dropped_or_pending') {
                throw new Error('Check the submitted deposit before replacing it.');
            }
            if (pending.submissionId) {
                throw new Error('A deposit replacement request is already open in MetaMask.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            const hashSet = new Set(hashes.map(hash => String(hash).toLowerCase()));
            const identities = [...new Map((pending.transactionAttempts || [])
                .filter(attempt => hashSet.has(String(attempt.hash || '').toLowerCase())
                    && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                    && Number.isSafeInteger(Number(attempt.nonce))
                    && Number(attempt.nonce) >= 0)
                .map(attempt => {
                    const identity = {
                        from: attempt.from.toLowerCase(),
                        nonce: Number(attempt.nonce)
                    };
                    return [`${identity.from}:${identity.nonce}`, identity];
                })).values()];
            if (identities.length !== 1) {
                throw new Error(identities.length
                    ? 'The saved deposit has more than one wallet nonce. Use MetaMask to cancel or speed up the pending transactions, then check again.'
                    : 'The saved deposit has no replacement nonce. Use MetaMask to cancel or speed up the pending transaction, then check again.');
            }
            const [{ from, nonce }] = identities;
            if (!/^0x[0-9a-fA-F]{40}$/.test(expectedFrom || '')
                || from !== expectedFrom.toLowerCase()) {
                throw new Error(`Connect the MetaMask account ${from} that submitted this deposit.`);
            }
            const submissionId = uuid();
            const next = {
                ...pending,
                phase: 'awaiting_wallet',
                submissionOutcome: 'replacement_awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now(),
                submissionFrom: from,
                submissionNonce: nonce,
                replacementOf: [...hashSet]
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return {
                status: 'claimed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.next_note_id),
                amount: Number(next.amount),
                commitment: next.commitment,
                secret: next.secret,
                deploymentId: this.manifest.deployment_id,
                chainId: losslessChainId(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                replacementFrom: from,
                replacementNonce: nonce,
                plan: structuredClone(next)
            };
        });
    }

    async rememberPendingDepositSubmissionMetadata(submission, metadata) {
        await this.init();
        const from = metadata?.from;
        const nonce = Number(metadata?.nonce);
        if (!/^0x[0-9a-fA-F]{40}$/.test(from || '')
            || !Number.isSafeInteger(nonce) || nonce < 0) {
            throw new Error('The deposit transaction metadata is invalid.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!this.depositSubmissionMatches(pending, submission)
                || pending.submissionId !== submission.submissionId) {
                throw new Error('The deposit wallet claim changed before its nonce was saved.');
            }
            const next = {
                ...pending,
                submissionFrom: from.toLowerCase(),
                submissionNonce: nonce
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    depositSubmissionMatches(pending, reference) {
        return Boolean(reference?.operationId && reference?.submissionId
            && pending?.operationId === reference.operationId
            && Number(pending.next_note_id) === Number(reference.noteId)
            && Number(pending.amount) === Number(reference.amount)
            && sameFelt(pending.commitment, reference.commitment)
            && reference.deploymentId === this.manifest.deployment_id
            && sameChainId(reference.chainId, this.config.funding.chain_id)
            && String(reference.contractAddress || '').toLowerCase()
                === String(this.config.funding.contract_address || '').toLowerCase());
    }

    async rememberPendingDepositTransaction(
        transactionHash,
        submission,
        transactionMetadata = null
    ) {
        await this.init();
        if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash || '')) {
            throw new Error('MetaMask returned an invalid deposit transaction hash.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) {
                throw new Error('The durable pending deposit is missing.');
            }
            if (!this.depositSubmissionMatches(pending, submission)) {
                const attempts = Array.isArray(this.runtime.lateDepositAttempts)
                    ? this.runtime.lateDepositAttempts
                    : [];
                const lateAttempt = {
                    operationId: submission?.operationId || null,
                    submissionId: submission?.submissionId || null,
                    noteId: Number(submission?.noteId),
                    amount: Number(submission?.amount),
                    commitment: submission?.commitment || null,
                    secret: submission?.secret || null,
                    deploymentId: submission?.deploymentId || null,
                    chainId: losslessChainId(submission?.chainId),
                    contractAddress: submission?.contractAddress || null,
                    transactionHash: transactionHash.toLowerCase(),
                    from: /^0x[0-9a-fA-F]{40}$/.test(transactionMetadata?.from || '')
                        ? transactionMetadata.from.toLowerCase()
                        : null,
                    nonce: Number.isSafeInteger(Number(transactionMetadata?.nonce))
                        ? Number(transactionMetadata.nonce)
                        : null,
                    status: 'submitted_late',
                    observedAt: Date.now()
                };
                await this.commit({
                    ...this.runtime,
                    lateDepositAttempts: retainAttemptHistory([...attempts.filter(attempt => !(
                        attempt.operationId === lateAttempt.operationId
                        && attempt.transactionHash === lateAttempt.transactionHash
                    )), lateAttempt], new Set(['confirmed', 'reverted', 'superseded']))
                });
                return { late: true, ...lateAttempt };
            }
            const normalizedHash = transactionHash.toLowerCase();
            const hashes = [...new Set([
                ...(Array.isArray(pending.transactionHashes)
                    ? pending.transactionHashes
                    : pending.transactionHash ? [pending.transactionHash] : []),
                normalizedHash
            ].map(value => value.toLowerCase()))];
            const pendingDeposit = {
                ...pending,
                phase: 'submitted',
                transactionHash: hashes[0],
                transactionHashes: hashes,
                transactionAttempts: [
                    ...(Array.isArray(pending.transactionAttempts)
                        ? pending.transactionAttempts.filter(attempt => attempt.hash !== normalizedHash)
                        : []),
                    {
                        hash: normalizedHash,
                        submissionId: submission.submissionId,
                        operationId: submission.operationId,
                        from: /^0x[0-9a-fA-F]{40}$/.test(
                            transactionMetadata?.from || pending.submissionFrom || ''
                        )
                            ? (transactionMetadata?.from || pending.submissionFrom).toLowerCase()
                            : null,
                        nonce: Number.isSafeInteger(Number(
                            transactionMetadata?.nonce ?? pending.submissionNonce
                        ))
                            ? Number(transactionMetadata?.nonce ?? pending.submissionNonce)
                            : null,
                        observedAt: Date.now()
                    }
                ]
            };
            if (pending.submissionId === submission.submissionId) {
                delete pendingDeposit.submissionId;
                delete pendingDeposit.submissionOwner;
                delete pendingDeposit.submissionStartedAt;
                delete pendingDeposit.submissionFrom;
                delete pendingDeposit.submissionNonce;
            }
            await this.commit({ ...this.runtime, pendingDeposit });
            return { ...pendingDeposit };
        });
    }

    async markPendingDepositRetryable(expectedTransactionHash = null, submission = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) return null;
            if (!expectedTransactionHash && !this.depositSubmissionMatches(pending, submission)) {
                throw new Error('The deposit operation changed while MetaMask was open.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (expectedTransactionHash
                && !hashes.some(hash => hash.toLowerCase() === expectedTransactionHash.toLowerCase())) {
                throw new Error('The deposit transaction changed while its receipt was checked.');
            }
            const remaining = expectedTransactionHash
                ? hashes.filter(hash => hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                : hashes;
            const releasesClaim = !expectedTransactionHash
                && pending.submissionId === submission?.submissionId;
            const next = {
                ...pending,
                phase: remaining.length
                    ? 'submitted'
                    : pending.submissionId && !releasesClaim
                        ? (pending.phase === 'ambiguous' ? 'ambiguous' : 'awaiting_wallet')
                        : pending.fundingQuoteRetryAuthorized === true && pending.ambiguousSubmissions?.length
                            ? 'retry_exact' : 'prepared',
                transactionHashes: remaining,
                transactionAttempts: Array.isArray(pending.transactionAttempts)
                    ? pending.transactionAttempts.filter(attempt => !expectedTransactionHash
                        || attempt.hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                    : []
            };
            if (remaining.length) next.transactionHash = remaining[0];
            else {
                delete next.transactionHash;
                delete next.transactionHashes;
            }
            if (releasesClaim) {
                delete next.submissionId;
                delete next.submissionOwner;
                delete next.submissionStartedAt;
                delete next.submissionFrom;
                delete next.submissionNonce;
            }
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async markPendingDepositMissingReceipts(expectedTransactionHashes) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) return null;
            const normalize = values => [...values]
                .map(value => String(value).toLowerCase())
                .sort();
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (JSON.stringify(normalize(hashes))
                !== JSON.stringify(normalize(expectedTransactionHashes || []))) {
                throw new Error('The deposit transactions changed while their receipts were checked.');
            }
            if (pending.submissionId) return pending;
            if (pending.phase === 'dropped_or_pending') return pending;
            const next = {
                ...pending,
                phase: 'dropped_or_pending',
                submissionOutcome: 'receipt_missing',
                missingReceiptCheckedAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async releasePendingDepositReplacementClaim(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending || pending.submissionId !== submission?.submissionId
                || pending.operationId !== submission?.operationId
                || !Number.isSafeInteger(Number(submission?.replacementNonce))) {
                throw new Error('The deposit replacement request changed before it could be released.');
            }
            const history = Array.isArray(pending.ambiguousReplacements)
                ? pending.ambiguousReplacements
                : [];
            const next = {
                ...pending,
                phase: 'dropped_or_pending',
                submissionOutcome: 'replacement_result_unknown',
                ambiguousReplacements: [...history, {
                    submissionId: pending.submissionId,
                    nonce: Number(submission.replacementNonce),
                    startedAt: pending.submissionStartedAt,
                    releasedAt: Date.now(),
                    message: message || 'The wallet did not return a deposit replacement transaction ID.'
                }].slice(-8),
                missingReceiptCheckedAt: Date.now()
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionError;
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async markPendingDepositAmbiguous(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!this.depositSubmissionMatches(pending, submission)
                || pending.submissionId !== submission.submissionId) {
                throw new Error('The deposit operation changed before its unknown result could be saved.');
            }
            const next = {
                ...pending,
                phase: 'ambiguous',
                submissionError: message || 'MetaMask did not return a transaction ID.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async markPendingDepositUnknown() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending?.submissionId) throw new Error('There is no deposit wallet prompt to recover.');
            if (pending.phase === 'ambiguous') return pending;
            const next = {
                ...pending,
                phase: 'ambiguous',
                submissionError: 'The wallet prompt was closed before a transaction ID was saved.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async authorizePendingDepositRetry({ forFundingQuote = false } = {}) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            const hashes = Array.isArray(pending?.transactionHashes)
                ? pending.transactionHashes
                : pending?.transactionHash ? [pending.transactionHash] : [];
            if (forFundingQuote && pending?.phase === 'retry_exact' && !pending.submissionId
                && !hashes.length && !pending.transactionAttempts?.length && pending.ambiguousSubmissions?.length) {
                const authorized = { ...pending, fundingQuoteRetryAuthorized: true };
                if (!this.canQuotePendingDeposit(authorized)) {
                    throw new Error('Check the unresolved deposit transaction before reviewing retry fees.');
                }
                await this.commit({ ...this.runtime, pendingDeposit: authorized });
                return authorized;
            }
            if (!pending || pending.phase !== 'ambiguous' || !pending.submissionId || hashes.length) {
                throw new Error('There is no unknown deposit request to retry.');
            }
            const history = Array.isArray(pending.ambiguousSubmissions)
                ? pending.ambiguousSubmissions
                : [];
            const next = {
                ...pending,
                phase: 'retry_exact',
                fundingQuoteRetryAuthorized: forFundingQuote,
                ambiguousSubmissions: [...history, {
                    submissionId: pending.submissionId,
                    startedAt: pending.submissionStartedAt,
                    authorizedAt: Date.now()
                }].slice(-8)
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionError;
            if (forFundingQuote && !this.canQuotePendingDeposit(next)) {
                throw new Error('Check the unresolved deposit transaction before reviewing retry fees.');
            }
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async resolvePendingDepositSlotConflict(expected) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) return null;
            const normalizeHashes = value => [...new Set((Array.isArray(value)
                ? value
                : value ? [value] : [])
                .map(hash => String(hash).toLowerCase()))].sort();
            const pendingHashes = normalizeHashes(
                pending.transactionHashes || pending.transactionHash
            );
            const expectedHashes = normalizeHashes(
                expected?.transactionHashes || expected?.transactionHash
            );
            if (!expected?.operationId
                || pending.operationId !== expected.operationId
                || Number(pending.next_note_id) !== Number(expected.noteId)
                || Number(pending.amount) !== Number(expected.amount)
                || !sameFelt(pending.commitment, expected.commitment)
                || (pending.phase || null) !== (expected.phase || null)
                || (pending.submissionId || null) !== (expected.submissionId || null)
                || JSON.stringify(pendingHashes) !== JSON.stringify(expectedHashes)) {
                throw new Error('The pending deposit changed while its vault slot was being checked. Check it again before retrying.');
            }
            const next = {
                ...pending,
                phase: 'prepared',
                previousSlot: Number(pending.next_note_id),
                // Finalized occupation by another commitment proves every old
                // ambiguous call for this append slot can no longer succeed.
                // Retain those claims for late recovery, while recording exactly
                // which ambiguity was resolved before allowing a fresh quote.
                resolvedAmbiguousSubmissionIds: (pending.ambiguousSubmissions || []).map(attempt => attempt.submissionId),
                legacyRecovery: false,
                fundingQuoteRetryAuthorized: false
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.transactionHash;
            delete next.transactionHashes;
            delete next.transactionAttempts;
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
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
                    createdAt: pending.createdAt || pending.submissionStartedAt || null,
                    confirmedAt: Date.now(),
                    // A saved attempt may have been replaced. Only the receipt
                    // caller identifies the actual mined transaction; recovery
                    // from the vault alone intentionally leaves it unknown.
                    transactionHash: args.transactionHash || null,
                    ...(args.receiptMetadata || {})
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

    async nativeBillingQuote(signal) {
        const funding = this.config.funding;
        const quoted = await this.remoteJson(`${funding.protocol_server_url}/v2/billing/quote`, { signal });
        validateNativeQuote(quoted, funding);
        const verified = await readNativeQuote(funding, { expected: quoted, signal });
        this.ethUsdQuote = verified;
        return verified;
    }

    leaseBudget(spendingLimitUsd, quote = null, { checkBalance = false } = {}) {
        if (!CHAT_SPENDING_TIER_USD.includes(Number(spendingLimitUsd))) throw new Error('Invalid private-balance model budget configuration.');
        validateNativeQuote(quote, this.config.funding, { allowExpired: true });
        const amount = Number(nativeUnitsForUsd(spendingLimitUsd, quote));
        if (checkBalance) {
            const balance = Number(this.runtime.state.current_balance);
            if (!Number.isSafeInteger(balance) || balance < 0) throw new Error('Invalid native ETH wallet balance.');
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
        if (unresolvedLateWithdrawalForNote(this.runtime, this.runtime.state.note_id)) {
            throw new BrowserWalletHttpError(
                'A withdrawal from another tab may already be on-chain. Check its status before using this balance.',
                409,
                'late_withdrawal_pending'
            );
        }
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
        const quote = await this.nativeBillingQuote(signal);
        throwIfAborted(signal);
        // C2: one bound per state. A request proof already left the device at
        // this state (then discarded as unaccepted), so any new proof here
        // must carry that same bound: a raise is capped by the largest bound
        // ever released at a state. issueLease settles a key of another
        // budget unused and proves the selected budget at the next state.
        const recordedBound = BigInt(this.runtime.state.bound_at_state ?? 0);
        const spendingLimitCredits = recordedBound > 0n
            ? Number(recordedBound)
            : this.leaseBudget(spendingLimitUsd, quote, { checkBalance: true });
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
                payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: quote }),
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

    async verifyLease(lease, expectedLimitCredits, expectedRequestId, onProgress = () => {}, signal = null, expectedQuote = null) {
        throwIfAborted(signal);
        if (lease.status !== 'active'
            || lease.client_request_id !== expectedRequestId
            || !lease.api_key
            || Number(lease.expires_at) <= Math.floor(Date.now() / 1000)) {
            throw new Error('The zkAPI server returned an unusable OpenRouter lease.');
        }
        validateNativeQuote(expectedQuote, this.config.funding, { allowExpired: true });
        if (!sameNativeQuote(lease.billing_quote, expectedQuote)
            || Number(lease.spending_limit_usd) !== Number(nativeUsdMicros(expectedLimitCredits, expectedQuote)) / 1_000_000) {
            throw new Error('The zkAPI server returned a child key with the wrong native ETH spending cap or quote.');
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

    async requestLeaseWithQuoteRecovery(request, onProgress, signal) {
        try {
            return await this.requestLeaseWithRetry(request, onProgress, signal);
        } catch (error) {
            if (['native_quote_expired', 'native_quote_superseded'].includes(error?.code)) {
                await this.recoverUnacceptedNativeQuote(request, signal);
            }
            throw error;
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
            const desiredLimitCredits = this.leaseBudget(spendingLimitUsd, requestBillingQuote(request));
            if (Number(request.public_inputs.solvency_bound) !== desiredLimitCredits) {
                try {
                    this.legacyMigrationInProgress = true;
                    reportRecovery('settling', 'Updating an unfinished temporary key…');
                    const legacyLease = await this.requestLeaseWithQuoteRecovery(request, reportRecovery, signal);
                    await this.verifyLease(
                        legacyLease,
                        request.public_inputs.solvency_bound,
                        request.client_request_id,
                        reportRecovery,
                        signal,
                        requestBillingQuote(request)
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
                lease = await this.requestLeaseWithQuoteRecovery(request, onProgress, signal);
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
                signal,
                requestBillingQuote(request)
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
        return readFinalizedChainTime(this.config.funding);
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
        const quote = requestBillingQuote(this.runtime.journal?.prepared_request);
        validateNativeQuote(quote, this.config.funding, { allowExpired: true });
        let payload;
        try { payload = JSON.parse(recovery.request_response.response_payload); } catch { /* Reject below. */ }
        if (!sameNativeQuote(payload?.billing_quote, quote)) throw new Error('The settlement receipt changed the authorized ETH/USD quote.');
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

    async recoverUnacceptedNativeQuote(request, signal = null) {
        const journal = this.runtime?.journal;
        const body = JSON.stringify(request);
        if (!request?.client_request_id || request.payload_hash == null
            || request.public_inputs?.request_nullifier == null
            || !sameFelt(journal?.nullifier, request.public_inputs.request_nullifier)
            || body !== JSON.stringify(journal?.prepared_request)) return false;
        validateNativeQuote(requestBillingQuote(request), this.config.funding, { allowExpired: true });
        // This endpoint only observes quote validity and acceptance under the server's
        // issuance lock. Neither local time nor an unknown nullifier proves an
        // older in-flight request can no longer reserve the note.
        let recovery;
        try {
            recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(request.client_request_id)}/expire`, {
                method: 'POST', headers: { 'content-type': 'application/json' }, signal, body
            });
        } catch (error) {
            if (error?.code === 'lease_pending') return false;
            throw error;
        }
        if (!['expired_unaccepted', 'superseded_unaccepted'].includes(recovery?.status)) return false;
        if (recovery.client_request_id !== request.client_request_id
            || recovery.request_nullifier == null || recovery.payload_hash == null
            || !sameFelt(recovery.request_nullifier, request.public_inputs.request_nullifier)
            || !sameFelt(recovery.payload_hash, request.payload_hash)) {
            throw new Error('The quote recovery response does not match the saved private request.');
        }
        if (body !== JSON.stringify(this.runtime?.journal?.prepared_request)
            || !sameFelt(this.runtime.journal.nullifier, request.public_inputs.request_nullifier)) return false;
        await this.commit({ ...this.runtime, journal: null, lease: null });
        return true;
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
                    return this.recoverUnacceptedNativeQuote(request, signal);
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
            if (unresolvedLateWithdrawalForNote(this.runtime, this.runtime.state.note_id)) {
                throw new BrowserWalletHttpError(
                    'A withdrawal from another tab may already be on-chain. Check its status before starting another withdrawal.',
                    409,
                    'late_withdrawal_pending'
                );
            }
            const validateExisting = (prepared) => {
                if (!prepared) return;
                if (Number(prepared.noteId ?? prepared.note_id ?? prepared.public_inputs?.note_id)
                    !== Number(this.runtime.state.note_id)) {
                    throw new Error('The prepared withdrawal belongs to a different private balance.');
                }
                const existingDestination = prepared.destination?.toLowerCase();
                const existingHashes = Array.isArray(prepared.transactionHashes)
                    ? prepared.transactionHashes
                    : prepared.transactionHash ? [prepared.transactionHash] : [];
                const hasSubmission = Boolean(prepared.submissionId || existingHashes.length);
                const safeModeSwitch = !hasSubmission && (
                    (prepared.mode === 'mutual' && mode === 'escape')
                    || (prepared.mode === 'escape' && mode === 'mutual'
                        && prepared.clearanceReserved === true)
                );
                if (existingDestination
                    && (prepared.mode !== mode || existingDestination !== destination.toLowerCase())
                    && !(safeModeSwitch && existingDestination === destination.toLowerCase())) {
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
            const existingHashes = Array.isArray(existing?.transactionHashes)
                ? existing.transactionHashes
                : existing?.transactionHash ? [existing.transactionHash] : [];
            if (existing?.submissionId && !existingHashes.length) {
                throw new BrowserWalletHttpError(
                    existing.phase === 'ambiguous'
                        ? 'MetaMask did not return a transaction ID. Check the chain, then explicitly retry if this balance is still active.'
                        : 'This withdrawal is awaiting MetaMask in this or another tab.',
                    409,
                    existing.phase === 'ambiguous'
                        ? 'withdrawal_submission_ambiguous'
                        : 'withdrawal_wallet_pending'
                );
            }
            if (existingHashes.length) {
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
                && existing.destination?.toLowerCase() === destination.toLowerCase()
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

    async claimPreparedWithdrawalSubmission() {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            let prepared = this.runtime.preparedWithdrawal;
            if (!prepared) throw new Error('The durable prepared withdrawal is missing.');
            if (!prepared.operationId) {
                prepared = { ...prepared, operationId: uuid() };
                await this.commit({ ...this.runtime, preparedWithdrawal: prepared });
            }
            const knownHashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (knownHashes.length) {
                return {
                    status: 'submitted',
                    transactionHash: knownHashes[0],
                    submissionId: prepared.submissionId || null,
                    operationId: prepared.operationId,
                    noteId: Number(prepared.noteId ?? prepared.public_inputs?.note_id),
                    mode: prepared.mode,
                    destination: prepared.destination,
                    finalBalance: Number(prepared.public_inputs?.final_balance
                        ?? this.runtime.state?.current_balance),
                    clearanceReserved: prepared.clearanceReserved === true
                        || prepared.mode === 'mutual',
                    withdrawalNullifier: prepared.withdrawalNullifier
                        || prepared.public_inputs?.withdrawal_nullifier
                        || null,
                    deploymentId: this.manifest.deployment_id,
                    chainId: losslessChainId(this.config.funding.chain_id),
                    contractAddress: this.config.funding.contract_address
                };
            }
            if (prepared.submissionId) {
                throw new BrowserWalletHttpError(
                    prepared.phase === 'ambiguous'
                        ? 'The previous wallet request has no transaction ID. Check its status before retrying.'
                        : 'This withdrawal is already awaiting MetaMask in this or another tab.',
                    409,
                    prepared.phase === 'ambiguous'
                        ? 'withdrawal_submission_ambiguous'
                        : 'withdrawal_wallet_pending'
                );
            }
            const now = Date.now();
            const submissionId = uuid();
            // C3: from here the proof can leave the device, so its state stays
            // frozen until the proof's valid_until has passed.
            const validUntil = Number(prepared.public_inputs?.valid_until ?? 0);
            const next = {
                ...prepared,
                phase: 'awaiting_wallet',
                submissionOutcome: 'awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: now,
                submissionNonceJournalRequired: true,
                releasedValidUntil: Math.max(Number(prepared.releasedValidUntil || 0), validUntil) || null
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return {
                status: 'claimed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.noteId ?? next.public_inputs?.note_id),
                mode: next.mode,
                destination: next.destination,
                finalBalance: Number(next.public_inputs?.final_balance
                    ?? this.runtime.state?.current_balance),
                clearanceReserved: next.clearanceReserved === true
                    || next.mode === 'mutual',
                withdrawalNullifier: next.withdrawalNullifier
                    || next.public_inputs?.withdrawal_nullifier
                    || null,
                deploymentId: this.manifest.deployment_id,
                chainId: losslessChainId(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address
            };
        });
    }

    async rememberPreparedWithdrawalSubmissionMetadata(submission, metadata) {
        const from = metadata?.from;
        const nonce = Number(metadata?.nonce);
        if (!/^0x[0-9a-fA-F]{40}$/.test(from || '')
            || !Number.isSafeInteger(nonce) || nonce < 0) {
            throw new Error('The withdrawal transaction metadata is invalid.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const reference = submission && typeof submission === 'object' ? submission : null;
            const matches = prepared
                && reference?.operationId === prepared.operationId
                && reference?.submissionId === prepared.submissionId
                && Number(reference.noteId) === Number(
                    prepared.noteId ?? prepared.public_inputs?.note_id
                )
                && reference.mode === prepared.mode
                && String(reference.destination || '').toLowerCase()
                    === String(prepared.destination || '').toLowerCase()
                && reference.deploymentId === this.manifest.deployment_id
                && sameChainId(reference.chainId, this.config.funding.chain_id)
                && String(reference.contractAddress || '').toLowerCase()
                    === String(this.config.funding.contract_address || '').toLowerCase();
            if (!matches) {
                throw new Error('The withdrawal wallet claim changed before its nonce was saved.');
            }
            const next = {
                ...prepared,
                submissionFrom: from.toLowerCase(),
                submissionNonce: nonce
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async claimPreparedWithdrawalReplacement(expectedFrom) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.phase !== 'dropped_or_pending') {
                throw new Error('Check the submitted withdrawal before replacing it.');
            }
            if (prepared.submissionId) {
                throw new Error('A replacement request is already open in MetaMask.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            const hashSet = new Set(hashes.map(hash => String(hash).toLowerCase()));
            const identities = [...new Map((prepared.transactionAttempts || [])
                .filter(attempt => hashSet.has(String(attempt.hash || '').toLowerCase())
                    && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                    && Number.isSafeInteger(Number(attempt.nonce))
                    && Number(attempt.nonce) >= 0)
                .map(attempt => {
                    const identity = {
                        from: attempt.from.toLowerCase(),
                        nonce: Number(attempt.nonce)
                    };
                    return [`${identity.from}:${identity.nonce}`, identity];
                })).values()];
            if (identities.length !== 1) {
                throw new Error(identities.length
                    ? 'The saved withdrawal has more than one wallet nonce. Use MetaMask to cancel or speed up the pending transactions, then check again.'
                    : 'The saved withdrawal has no replacement nonce. Use MetaMask to cancel or speed up the pending transaction, then check again.');
            }
            const [{ from, nonce }] = identities;
            if (!/^0x[0-9a-fA-F]{40}$/.test(expectedFrom || '')
                || from !== expectedFrom.toLowerCase()) {
                throw new Error(`Connect the MetaMask account ${from} that submitted this withdrawal.`);
            }
            const submissionId = uuid();
            const next = {
                ...prepared,
                phase: 'awaiting_wallet',
                submissionOutcome: 'replacement_awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now(),
                submissionFrom: from,
                submissionNonce: nonce,
                submissionNonceJournalRequired: true,
                replacementOf: [...hashSet]
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return {
                status: 'claimed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.noteId ?? next.public_inputs?.note_id),
                mode: next.mode,
                destination: next.destination,
                finalBalance: Number(next.public_inputs?.final_balance
                    ?? this.runtime.state?.current_balance),
                clearanceReserved: next.clearanceReserved === true
                    || next.mode === 'mutual',
                withdrawalNullifier: next.withdrawalNullifier
                    || next.public_inputs?.withdrawal_nullifier
                    || null,
                deploymentId: this.manifest.deployment_id,
                chainId: losslessChainId(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                replacementFrom: from,
                replacementNonce: nonce,
                plan: structuredClone(next)
            };
        });
    }

    async rememberPreparedWithdrawalTransaction(
        transactionHash,
        submission = null,
        transactionMetadata = null
    ) {
        if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash || '')) {
            throw new Error('MetaMask returned an invalid withdrawal transaction hash.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const reference = submission && typeof submission === 'object' ? submission : null;
            if (!reference?.operationId || !reference.submissionId
                || reference.deploymentId !== this.manifest.deployment_id
                || !sameChainId(reference.chainId, this.config.funding.chain_id)
                || String(reference.contractAddress || '').toLowerCase()
                    !== String(this.config.funding.contract_address || '').toLowerCase()) {
                throw new Error('The withdrawal transaction is missing its durable operation identity.');
            }
            const sameOperation = prepared && (
                prepared.operationId === reference.operationId
                    && Number(prepared.noteId ?? prepared.public_inputs?.note_id) === Number(reference.noteId)
                    && prepared.mode === reference.mode
                    && prepared.destination?.toLowerCase() === reference.destination?.toLowerCase()
            );
            if (!sameOperation) {
                const attempts = Array.isArray(this.runtime.lateWithdrawalAttempts)
                    ? this.runtime.lateWithdrawalAttempts
                    : [];
                const lateAttempt = {
                    operationId: reference.operationId || null,
                    submissionId: reference.submissionId || null,
                    noteId: Number(reference.noteId),
                    mode: reference.mode || null,
                    destination: reference.destination || null,
                    finalBalance: Number(reference.finalBalance),
                    clearanceReserved: reference.clearanceReserved === true
                        || reference.mode === 'mutual',
                    withdrawalNullifier: reference.withdrawalNullifier || null,
                    deploymentId: reference.deploymentId,
                    chainId: losslessChainId(reference.chainId),
                    contractAddress: reference.contractAddress,
                    transactionHash: transactionHash.toLowerCase(),
                    from: /^0x[0-9a-fA-F]{40}$/.test(
                        transactionMetadata?.from || prepared?.submissionFrom || ''
                    )
                        ? (transactionMetadata?.from || prepared?.submissionFrom).toLowerCase()
                        : null,
                    nonce: Number.isSafeInteger(Number(
                        transactionMetadata?.nonce ?? prepared?.submissionNonce
                    ))
                        ? Number(transactionMetadata?.nonce ?? prepared?.submissionNonce)
                        : null,
                    observedAt: Date.now(),
                    status: 'submitted_late'
                };
                const deduplicated = attempts.filter(attempt => !(
                    attempt.operationId === lateAttempt.operationId
                    && attempt.transactionHash === lateAttempt.transactionHash
                ));
                await this.commit({
                    ...this.runtime,
                    lateWithdrawalAttempts: retainAttemptHistory(
                        [...deduplicated, lateAttempt],
                        LATE_WITHDRAWAL_TERMINAL_STATUSES
                    )
                });
                return { late: true, ...lateAttempt };
            }
            // A wallet prompt can outlive its cross-tab ownership claim. Never
            // reject a late valid hash: retaining every broadcast is the only
            // safe way to reconcile a takeover without losing an on-chain tx.
            const transactionHashes = [...new Set([
                ...(Array.isArray(prepared.transactionHashes)
                    ? prepared.transactionHashes
                    : prepared.transactionHash ? [prepared.transactionHash] : []),
                transactionHash
            ].map(value => value.toLowerCase()))];
            const transactionAttempts = [
                ...(Array.isArray(prepared.transactionAttempts)
                    ? prepared.transactionAttempts.filter(attempt => attempt.hash !== transactionHash.toLowerCase())
                    : []),
                {
                    hash: transactionHash.toLowerCase(),
                    submissionId: reference.submissionId || null,
                    operationId: prepared.operationId,
                    from: /^0x[0-9a-fA-F]{40}$/.test(
                        transactionMetadata?.from || prepared.submissionFrom || ''
                    )
                        ? (transactionMetadata?.from || prepared.submissionFrom).toLowerCase()
                        : null,
                    nonce: Number.isSafeInteger(Number(
                        transactionMetadata?.nonce ?? prepared.submissionNonce
                    ))
                        ? Number(transactionMetadata?.nonce ?? prepared.submissionNonce)
                        : null,
                    observedAt: Date.now()
                }
            ];
            const next = {
                ...prepared,
                phase: 'submitted',
                transactionHash: transactionHashes[0],
                transactionHashes,
                transactionAttempts,
                submissionOutcome: 'submitted',
                ...(reference.submissionId && prepared.submissionId !== reference.submissionId
                    ? { concurrentSubmissionObserved: true }
                    : {})
            };
            if (reference.submissionId && prepared.submissionId === reference.submissionId) {
                delete next.submissionId;
                delete next.submissionOwner;
                delete next.submissionStartedAt;
                delete next.submissionFrom;
                delete next.submissionNonce;
                delete next.submissionNonceJournalRequired;
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async currentLateWithdrawalAttempts() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return (this.runtime.lateWithdrawalAttempts || []).map(attempt => ({ ...attempt }));
        });
    }

    async updateLateWithdrawalAttempt(operationId, transactionHash, changes = {}, {
        expectedStatus = null
    } = {}) {
        await this.init();
        const normalizedHash = String(transactionHash || '').toLowerCase();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const attempts = Array.isArray(this.runtime.lateWithdrawalAttempts)
                ? this.runtime.lateWithdrawalAttempts
                : [];
            const index = attempts.findIndex(attempt =>
                attempt.operationId === operationId
                && String(attempt.transactionHash || '').toLowerCase() === normalizedHash);
            if (index < 0) return null;
            const current = attempts[index];
            if (expectedStatus != null && current.status !== expectedStatus) {
                throw new Error('The late withdrawal attempt changed while its receipt was being checked.');
            }
            if (LATE_WITHDRAWAL_TERMINAL_STATUSES.has(current.status)
                && changes.status && changes.status !== current.status) {
                return { ...current };
            }
            const nextAttempt = {
                ...current,
                ...changes,
                updatedAt: Date.now()
            };
            const nextAttempts = [...attempts];
            nextAttempts[index] = nextAttempt;
            await this.commit({
                ...this.runtime,
                lateWithdrawalAttempts: retainAttemptHistory(
                    nextAttempts,
                    LATE_WITHDRAWAL_TERMINAL_STATUSES
                )
            });
            return { ...nextAttempt };
        });
    }

    async transferLateWithdrawalAttempt(attempt, record) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const detachesSelectedNote = this.runtime.deploymentId === attempt.deploymentId
                && this.runtime.state
                && Number(this.runtime.state.note_id) === Number(attempt.noteId);
            const result = await transferBrowserLateWithdrawalAttempt({
                operationId: attempt.operationId,
                transactionHash: attempt.transactionHash,
                deploymentId: attempt.deploymentId,
                chainId: losslessChainId(attempt.chainId),
                contractAddress: attempt.contractAddress,
                noteId: Number(attempt.noteId)
            }, record);
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            if (detachesSelectedNote) this.activeLease = null;
            this.notify();
            return result;
        });
    }

    async releaseBackgroundWithdrawalStartSubmission(submission, options = {}) {
        await this.init();
        const recordId = this.withdrawalRecordId(submission?.noteId);
        let result = await releaseBrowserWithdrawalStartSubmission(
            recordId,
            submission,
            options
        );
        // Test adapters and older embedders may provide a runtime persistence
        // layer without the shared IndexedDB stores. The production path above
        // atomically checks both owners; this fallback preserves that adapter
        // contract without creating a gap between production ownership checks.
        if (!result) {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (prepared?.submissionId === submission?.submissionId
                && prepared.operationId === submission?.operationId) {
                const released = options.replacementUnknown
                    ? await this.releasePreparedWithdrawalReplacementClaim(
                        submission,
                        options.message || null
                    )
                    : await this.markPreparedWithdrawalRetryable(null, submission);
                result = released ? { location: 'selected', runtime: this.runtime } : null;
            }
        }
        await this.reload();
        this.notify();
        return result;
    }

    async resolveLateChallengedWithdrawalAttempt(attempt) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const attempts = Array.isArray(this.runtime.lateWithdrawalAttempts)
                ? this.runtime.lateWithdrawalAttempts
                : [];
            const index = attempts.findIndex(entry =>
                entry.operationId === attempt.operationId
                && String(entry.transactionHash || '').toLowerCase()
                    === String(attempt.transactionHash || '').toLowerCase()
                && Number(entry.noteId) === Number(attempt.noteId));
            if (index < 0) throw new Error('The challenged withdrawal attempt is no longer available.');
            const currentAttempt = attempts[index];
            if (LATE_WITHDRAWAL_TERMINAL_STATUSES.has(currentAttempt.status)) {
                return { ...currentAttempt };
            }
            const selectedOwns = Number(this.runtime.state?.note_id) === Number(attempt.noteId);
            const backgroundOwns = this.withdrawals.some(record =>
                Number(record.noteId) === Number(attempt.noteId) && record.state);
            if (!selectedOwns && !backgroundOwns) {
                throw new Error('The challenged withdrawal has no recoverable private note.');
            }
            const clearanceReserved = currentAttempt.clearanceReserved === true
                || currentAttempt.mode === 'mutual';
            const preparedWithdrawal = selectedOwns && clearanceReserved
                ? this.runtime.preparedWithdrawal || {
                    phase: 'prepared',
                    mode: currentAttempt.mode === 'mutual' ? 'mutual' : 'escape',
                    operationId: currentAttempt.operationId,
                    noteId: Number(currentAttempt.noteId),
                    destination: currentAttempt.destination,
                    withdrawalNullifier: currentAttempt.withdrawalNullifier || null,
                    clearanceReserved: true,
                    submissionOutcome: 'challenged',
                    createdAt: Number(currentAttempt.observedAt || Date.now())
                }
                : this.runtime.preparedWithdrawal;
            const nextAttempt = {
                ...currentAttempt,
                status: 'challenged',
                resolvedAt: Date.now(),
                error: null
            };
            const nextAttempts = attempts.map((entry, entryIndex) => {
                if (entryIndex === index) return nextAttempt;
                return Number(entry.noteId) === Number(currentAttempt.noteId)
                    && entry.deploymentId === currentAttempt.deploymentId
                    && !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(entry.status)
                    ? {
                        ...entry,
                        status: 'superseded',
                        supersededBy: currentAttempt.transactionHash,
                        resolvedAt: Date.now(),
                        error: null
                    }
                    : entry;
            });
            await this.commit({
                ...this.runtime,
                preparedWithdrawal,
                lateWithdrawalAttempts: retainAttemptHistory(
                    nextAttempts,
                    LATE_WITHDRAWAL_TERMINAL_STATUSES
                )
            });
            return { ...nextAttempt };
        });
    }

    async markPreparedWithdrawalRetryable(expectedTransactionHash = null, submission = null) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            const reference = submission && typeof submission === 'object' ? submission : null;
            if (!expectedTransactionHash && (!reference?.operationId || !reference.submissionId)) {
                throw new Error('The withdrawal retry is missing its durable operation identity.');
            }
            if (reference?.operationId && prepared.operationId !== reference.operationId) {
                throw new Error('The withdrawal operation changed while MetaMask was open.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (expectedTransactionHash
                && !hashes.some(hash => hash.toLowerCase() === expectedTransactionHash.toLowerCase())) {
                throw new Error('The withdrawal transaction changed while its receipt was being checked.');
            }
            if (!expectedTransactionHash && reference.submissionId
                && prepared.submissionId !== reference.submissionId) {
                throw new Error('The withdrawal submission changed while MetaMask was open.');
            }
            const remainingHashes = expectedTransactionHash
                ? hashes.filter(hash => hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                : hashes;
            const remainingAttempts = Array.isArray(prepared.transactionAttempts)
                ? prepared.transactionAttempts.filter(attempt => !expectedTransactionHash
                    || attempt.hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                : [];
            const releasesClaim = !expectedTransactionHash
                && reference?.submissionId
                && prepared.submissionId === reference.submissionId;
            const survivingClaimPhase = prepared.submissionId && !releasesClaim
                ? (prepared.submissionOutcome === 'ambiguous' || prepared.phase === 'ambiguous'
                    ? 'ambiguous'
                    : 'awaiting_wallet')
                : 'prepared';
            const next = {
                ...prepared,
                phase: remainingHashes.length
                    ? 'submitted'
                    : survivingClaimPhase,
                transactionHashes: remainingHashes,
                transactionAttempts: remainingAttempts,
                submissionOutcome: remainingHashes.length
                    ? 'submitted'
                    : releasesClaim
                        ? 'explicitly_rejected'
                        : prepared.submissionId
                            ? prepared.submissionOutcome
                            : expectedTransactionHash ? 'reverted' : prepared.submissionOutcome
            };
            if (remainingHashes.length) {
                next.transactionHash = remainingHashes[0];
            } else {
                delete next.transactionHash;
                delete next.transactionHashes;
            }
            if (releasesClaim) {
                delete next.submissionId;
                delete next.submissionOwner;
                delete next.submissionStartedAt;
                delete next.submissionFrom;
                delete next.submissionNonce;
                delete next.submissionNonceJournalRequired;
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async markPreparedWithdrawalMissingReceipts(expectedTransactionHashes) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            const normalize = values => [...values]
                .map(value => String(value).toLowerCase())
                .sort();
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (JSON.stringify(normalize(hashes))
                !== JSON.stringify(normalize(expectedTransactionHashes || []))) {
                throw new Error('The withdrawal transactions changed while their receipts were checked.');
            }
            // A second tab may already be replacing this transaction. Preserve
            // that live claim rather than regressing its UI/state phase.
            if (prepared.submissionId) return prepared;
            const next = {
                ...prepared,
                phase: 'dropped_or_pending',
                submissionOutcome: 'receipt_missing',
                missingReceiptCheckedAt: Date.now()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async markPreparedWithdrawalAmbiguous(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const reference = submission && typeof submission === 'object' ? submission : null;
            if (!prepared || !reference?.submissionId || !reference.operationId
                || prepared.submissionId !== reference.submissionId
                || prepared.operationId !== reference.operationId) {
                throw new Error('The withdrawal operation changed before its ambiguous result could be saved.');
            }
            const next = {
                ...prepared,
                phase: 'ambiguous',
                submissionOutcome: 'ambiguous',
                submissionError: message || 'MetaMask did not return a transaction ID.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async releasePreparedWithdrawalReplacementClaim(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.submissionId !== submission?.submissionId
                || prepared.operationId !== submission?.operationId
                || !Number.isSafeInteger(Number(submission?.replacementNonce))) {
                throw new Error('The replacement wallet request changed before it could be released.');
            }
            const history = Array.isArray(prepared.ambiguousReplacements)
                ? prepared.ambiguousReplacements
                : [];
            const next = {
                ...prepared,
                phase: 'dropped_or_pending',
                submissionOutcome: 'replacement_result_unknown',
                ambiguousReplacements: [...history, {
                    submissionId: prepared.submissionId,
                    nonce: Number(submission.replacementNonce),
                    startedAt: prepared.submissionStartedAt,
                    releasedAt: Date.now(),
                    message: message || 'The wallet did not return a replacement transaction ID.'
                }].slice(-8),
                missingReceiptCheckedAt: Date.now()
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionNonceJournalRequired;
            delete next.submissionError;
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async authorizePreparedWithdrawalRetry() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.phase !== 'ambiguous' || !prepared.submissionId) {
                throw new Error('There is no ambiguous wallet request to retry.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (hashes.length) throw new Error('Check the submitted transaction before retrying.');
            const history = Array.isArray(prepared.ambiguousSubmissions)
                ? prepared.ambiguousSubmissions
                : [];
            const next = {
                ...prepared,
                phase: 'prepared',
                submissionOutcome: 'retry_authorized',
                ambiguousSubmissions: [...history, {
                    submissionId: prepared.submissionId,
                    startedAt: prepared.submissionStartedAt,
                    authorizedAt: Date.now()
                }].slice(-8)
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionNonceJournalRequired;
            delete next.submissionError;
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async clearPreparedWithdrawal({
        force = false,
        expectedNoteId = null,
        expectedTransactionHashes = null
    } = {}) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            if (expectedNoteId != null
                && Number(prepared.noteId ?? prepared.public_inputs?.note_id) !== Number(expectedNoteId)) {
                throw new Error('The selected withdrawal changed before it could be cleared.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (expectedTransactionHashes) {
                const normalize = values => [...values].map(value => value.toLowerCase()).sort();
                if (JSON.stringify(normalize(hashes))
                    !== JSON.stringify(normalize(expectedTransactionHashes))) {
                    throw new Error('The withdrawal transactions changed before recovery completed.');
                }
            }
            if (!force && (prepared.mode === 'mutual' || prepared.clearanceReserved === true)) {
                throw new Error('This balance already has a mutual-close authorization and must remain withdrawal-only.');
            }
            // Even force recovery must preserve a hashless MetaMask claim: its
            // delayed callback still needs a durable owner in this exact note.
            if (prepared.submissionId) {
                throw new Error('A MetaMask withdrawal request is still unresolved. Close or finish that prompt before clearing this balance.');
            }
            if (!force && hashes.length) {
                throw new Error('This withdrawal may already be in MetaMask. Check its transaction status before canceling it.');
            }
            if (!force && await exitProofStillLive(prepared.releasedValidUntil ?? null,
                () => this.readFinalizedChainTime())) {
                throw exitProofFrozenError(prepared);
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: null });
            return null;
        });
    }

    async recoverPreparedWithdrawalSubmissionClaim() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared?.submissionId) return prepared || null;
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (hashes.length) return prepared;
            // A reload cannot prove whether another tab still has MetaMask
            // open. Preserve the claim until the provider returns a definite
            // rejection or the user explicitly starts recovery.
            return prepared;
        });
    }

    async markPreparedWithdrawalUnknown(message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared?.submissionId) {
                throw new Error('There is no wallet request waiting to be recovered.');
            }
            if (prepared.phase === 'ambiguous') return prepared;
            const next = {
                ...prepared,
                phase: 'ambiguous',
                submissionOutcome: 'ambiguous',
                submissionError: message || 'The wallet prompt was closed before a transaction ID was saved.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async resolveChallengedPreparedEscape(noteId, expectedTransactionHashes = []) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.mode !== 'escape' || prepared.clearanceReserved !== true
                || Number(prepared.noteId ?? prepared.public_inputs?.note_id) !== Number(noteId)) {
                throw new Error('The challenged escape no longer matches the selected balance.');
            }
            if (prepared.submissionId) {
                throw new Error('A wallet request is still unresolved for this balance.');
            }
            const normalize = values => [...values].map(value => value.toLowerCase()).sort();
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (JSON.stringify(normalize(hashes)) !== JSON.stringify(normalize(expectedTransactionHashes))) {
                throw new Error('The withdrawal transactions changed while the challenge was being checked.');
            }
            const next = {
                phase: 'prepared',
                mode: 'escape',
                operationId: prepared.operationId,
                noteId: Number(noteId),
                destination: prepared.destination,
                withdrawalNullifier: prepared.withdrawalNullifier
                    || prepared.public_inputs?.withdrawal_nullifier
                    || null,
                clearanceReserved: true,
                submissionOutcome: 'challenged',
                createdAt: Number(prepared.createdAt || Date.now())
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
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
            const phase = details.phase === 'challenged_unconfirmed'
                ? 'challenged_unconfirmed'
                : 'pending';
            const result = await detachBrowserEscapeWithdrawal({
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: losslessChainId(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: 'escape',
                phase,
                chainStatus: details.chainStatus
                    || (phase === 'challenged_unconfirmed' ? 'active' : 'pending_withdrawal'),
                noteId,
                destination: details.destination,
                finalBalance: Number(details.finalBalance),
                ...concessionRecordFields(details),
                challengeDeadline: Number(details.challengeDeadline),
                transactionHash: details.transactionHash || null,
                startBlockNumber: Number(details.startBlockNumber || 0),
                challengeObservedBlock: Number(details.challengeObservedBlock || 0),
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
                chainId: losslessChainId(this.config.funding.chain_id),
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

    backgroundWithdrawalIdentity(record) {
        return { recordId: record?.recordId, deploymentId: this.manifest.deployment_id,
            chainId: losslessChainId(this.config.funding.chain_id), contractAddress: this.config.funding.contract_address,
            noteId: Number(record?.noteId), mode: record?.mode, destination: record?.destination };
    }

    async repairUnsubmittedBackgroundWithdrawal(recordId, observedBlock, expectedRevision) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record) return null;
        const result = await repairBrowserUnsubmittedBackgroundWithdrawal(
            this.backgroundWithdrawalIdentity(record), Number(observedBlock), expectedRevision);
        await this.reload();
        if (result && Number(result.revision) !== Number(expectedRevision)) this.notify();
        return result;
    }

    async resolveBackgroundWithdrawalForRetry(recordId, evidence) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        const result = await resolveBrowserBackgroundWithdrawalForRetry(
            this.backgroundWithdrawalIdentity(record), evidence);
        await this.reload();
        this.notify();
        return result;
    }

    async prepareBackgroundWithdrawal(recordId) {
        await this.init();
        await this.reload();
        const record = structuredClone(this.withdrawals.find(entry => entry.recordId === recordId));
        const identity = this.backgroundWithdrawalIdentity(record);
        assertBrowserBackgroundWithdrawalAvailable(record, this.runtime, identity);
        const state = record.state;
        const config = this.config;
        if (!sameChainId(state.chain_id, identity.chainId) || !sameFelt(state.contract_address, identity.contractAddress)) {
            throw new Error('The saved private state belongs to a different vault.');
        }
        const nullifier = await this.worker.call('withdrawalNullifier', { state });
        const savedNullifiers = [record.withdrawalNullifier, record.preparedWithdrawal?.withdrawalNullifier,
            record.preparedWithdrawal?.public_inputs?.withdrawal_nullifier].filter(value => value != null);
        if (savedNullifiers.some(value => !sameFelt(value, nullifier))) {
            throw new Error('The saved withdrawal authorization does not match its private balance.');
        }
        // Deliberately outside the global wallet lock: a proof must not stall
        // unrelated deposits, requests, or settlement in another tab.
        const clearance = await this.remoteJson(`${config.funding.protocol_server_url}/v2/withdraw/clearance`, {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ withdrawal_nullifier: nullifier })
        });
        const validUntil = exitProofValidUntil(nowSeconds());
        const plan = await this.worker.call('prepareWithdrawal', {
            config: config.wallet_core, state,
            args: { mode: 'mutual', destination: identity.destination, clearance, conceded: '0',
                valid_until: String(validUntil) }, provingKey: config.proving_keys.withdrawal
        });
        const inputs = plan.public_inputs;
        const encodedDestination = Array.isArray(inputs?.destination)
            ? `0x${inputs.destination.map(value => Number(value).toString(16).padStart(2, '0')).join('')}`
            : inputs?.destination;
        if (!plan.proof || Number(inputs?.note_id) !== identity.noteId
            || !sameChainId(inputs?.chain_id, identity.chainId)
            || !sameFelt(inputs?.contract_address, identity.contractAddress)
            || Number(inputs?.valid_until) !== validUntil
            || BigInt(inputs?.conceded ?? -1) !== 0n || !sameFelt(inputs?.next_nullifier ?? -1, 0)
            || !sameFelt(inputs?.withdrawal_nullifier, nullifier)
            || !sameFelt(inputs?.final_balance, state.current_balance)
            || String(encodedDestination || '').toLowerCase() !== identity.destination.toLowerCase()
            || inputs?.has_clearance !== true) {
            throw new Error('The generated withdrawal proof does not match its saved balance and vault.');
        }
        Object.assign(plan, { destination: identity.destination, mode: 'mutual', phase: 'prepared',
            operationId: uuid(), noteId: identity.noteId, withdrawalNullifier: nullifier,
            clearanceReserved: true, stateAnchor: state.current_anchor,
            releasedValidUntil: record.preparedWithdrawal?.releasedValidUntil ?? null,
            createdAt: Number(record.createdAt || Date.now()) });
        await saveBrowserBackgroundWithdrawalPlan(identity, record, plan);
        await this.reload();
        this.notify();
        return plan;
    }

    async claimBackgroundWithdrawalSubmission(recordId, expectedOperationId) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        const result = await claimBrowserBackgroundWithdrawalSubmission(
            this.backgroundWithdrawalIdentity(record), expectedOperationId, this.ownerId);
        await this.reload();
        this.notify();
        return result;
    }

    async rememberBackgroundWithdrawalSubmissionMetadata(submission, metadata) {
        const result = await rememberBrowserBackgroundWithdrawalMetadata(submission, metadata);
        await this.reload();
        this.notify();
        return result;
    }

    async markBackgroundWithdrawalAmbiguous(submission, message) {
        const result = await markBrowserBackgroundWithdrawalAmbiguous(submission, message);
        await this.reload();
        this.notify();
        return result;
    }

    async releaseBackgroundWithdrawalSubmission(submission) {
        const result = await releaseBrowserBackgroundWithdrawalSubmission(submission);
        await this.reload();
        this.notify();
        return result;
    }

    async cancelBackgroundWithdrawalPreparation(recordId) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record) throw new Error('This saved withdrawal is no longer available.');
        const submission = { ...this.backgroundWithdrawalIdentity(record),
            submissionId: record.startSubmissionId, operationId: record.startOperationId };
        const result = await releaseBrowserBackgroundWithdrawalSubmission(submission, { requireNoNonce: true });
        await this.reload();
        this.notify();
        return result;
    }

    async rememberBackgroundWithdrawalTransaction(hash, submission, metadata = null) {
        const result = await rememberBrowserBackgroundWithdrawalTransaction(hash, submission, metadata);
        await this.reload();
        this.notify();
        return result;
    }

    async parkPreparedWithdrawal() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const noteId = Number(this.runtime.state?.note_id);
            if (!prepared || (prepared.mode !== 'mutual' && prepared.clearanceReserved !== true)
                || !Number.isFinite(noteId)) {
                throw new Error('There is no withdrawal-only balance to set aside.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (!['reserving', 'prepared'].includes(prepared.phase || 'prepared')
                || prepared.submissionId || hashes.length) {
                throw new Error('Check the submitted withdrawal before setting this balance aside.');
            }
            const result = await parkBrowserWithdrawal({
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: losslessChainId(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: prepared.mode,
                phase: 'parked',
                noteId,
                destination: prepared.destination,
                finalBalance: Number(prepared.public_inputs?.final_balance
                    ?? this.runtime.state.current_balance),
                createdAt: Number(prepared.createdAt || Date.now())
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

    async claimBackgroundWithdrawalStartReplacement(recordId, expectedFrom) {
        await this.init();
        const result = await claimBrowserWithdrawalStartReplacement(
            recordId,
            this.ownerId,
            expectedFrom
        );
        await this.reload();
        this.notify();
        return result;
    }

    async claimWithdrawalFinalization(recordId) {
        await this.init();
        const result = await claimBrowserWithdrawalFinalization(
            recordId,
            this.ownerId
        );
        await this.reload();
        this.notify();
        return result;
    }

    async claimWithdrawalFinalizationReplacement(recordId, expectedFrom) {
        await this.init();
        const result = await claimBrowserWithdrawalFinalizationReplacement(
            recordId,
            this.ownerId,
            expectedFrom
        );
        await this.reload();
        this.notify();
        return result;
    }

    async rememberWithdrawalFinalization(
        recordId,
        transactionHash,
        submission = null,
        transactionMetadata = null
    ) {
        await this.init();
        const result = await rememberBrowserWithdrawalFinalization(
            recordId,
            transactionHash,
            submission,
            transactionMetadata
        );
        await this.reload();
        this.notify();
        return result;
    }

    async rememberWithdrawalFinalizationSubmissionMetadata(
        recordId,
        submission,
        transactionMetadata
    ) {
        await this.init();
        const result = await rememberBrowserWithdrawalFinalizationSubmissionMetadata(
            recordId,
            submission,
            transactionMetadata
        );
        await this.reload();
        this.notify();
        return result;
    }

    async releaseWithdrawalFinalization(recordId, options = {}) {
        await this.init();
        const result = await releaseBrowserWithdrawalFinalization(recordId, options);
        await this.reload();
        this.notify();
        return result;
    }

    async markWithdrawalFinalizationMissingReceipts(recordId, expectedTransactionHashes) {
        await this.init();
        const result = await markBrowserWithdrawalFinalizationMissingReceipts(
            recordId,
            expectedTransactionHashes
        );
        await this.reload();
        this.notify();
        return result;
    }

    async releaseWithdrawalFinalizationReplacementClaim(
        recordId,
        submission,
        message = null
    ) {
        await this.init();
        const result = await releaseBrowserWithdrawalFinalizationReplacementClaim(
            recordId,
            submission,
            message
        );
        await this.reload();
        this.notify();
        return result;
    }

    async markWithdrawalFinalizationAmbiguous(recordId, submission, message = null) {
        await this.init();
        const result = await markBrowserWithdrawalFinalizationAmbiguous(
            recordId,
            submission,
            message
        );
        await this.reload();
        this.notify();
        return result;
    }

    async markWithdrawalFinalizationUnknown(recordId) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record?.finalizeSubmissionId || !record.finalizeOperationId) {
            throw new Error('There is no finalization wallet request waiting to be recovered.');
        }
        if (record.phase === 'ambiguous') return record;
        return this.markWithdrawalFinalizationAmbiguous(recordId, {
            recordId,
            submissionId: record.finalizeSubmissionId,
            operationId: record.finalizeOperationId,
            generation: Number(record.finalizeGeneration || 0),
            deploymentId: record.deploymentId,
            chainId: losslessChainId(record.chainId),
            contractAddress: record.contractAddress,
            noteId: Number(record.noteId),
            destination: record.destination
        }, 'The wallet prompt was closed before a transaction ID was saved.');
    }

    async resolveChallengedWithdrawalFinalization(recordId, {
        expectedRevision = null,
        observedBlock = null
    } = {}) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record?.finalizeSubmissionId || !record.finalizeOperationId) {
            throw new Error('There is no challenged wallet prompt to release.');
        }
        const result = await resolveBrowserChallengedFinalization(recordId, {
            recordId,
            submissionId: record.finalizeSubmissionId,
            operationId: record.finalizeOperationId,
            generation: Number(record.finalizeGeneration || 0),
            deploymentId: record.deploymentId,
            chainId: losslessChainId(record.chainId),
            contractAddress: record.contractAddress,
            noteId: Number(record.noteId),
            destination: record.destination
        }, { expectedRevision, observedBlock });
        await this.reload();
        this.notify();
        return result;
    }

    async authorizeWithdrawalFinalizationRetry(recordId) {
        await this.init();
        const result = await authorizeBrowserWithdrawalFinalizationRetry(recordId);
        await this.reload();
        this.notify();
        return result;
    }

    async restoreWithdrawal(recordId, {
        expectedRevision = null,
        observedBlock = null
    } = {}) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const record = this.withdrawals.find(entry => entry.recordId === recordId);
            if (!record) throw new Error('The recoverable private balance is no longer available.');
            if (expectedRevision == null || Number(record.revision) !== Number(expectedRevision)) {
                throw new Error('The withdrawal changed after its on-chain status was checked. Check it again before selecting this balance.');
            }
            const chainFloor = Math.max(
                Number(record.startBlockNumber || 0),
                Number(record.lastObservedBlock || 0)
            );
            if (observedBlock == null || Number(observedBlock) < chainFloor) {
                throw new Error('The connected RPC has not caught up to this withdrawal. Check it again before selecting this balance.');
            }
            // C3: a balance whose exit proof can still land is never selected
            // for requests again until that proof is dead.
            if (await exitProofStillLive(record.preparedWithdrawal?.releasedValidUntil ?? null,
                () => this.readFinalizedChainTime())) {
                throw exitProofFrozenError(record.preparedWithdrawal);
            }
            const runtime = await restoreBrowserWithdrawal(recordId, {
                deploymentId: this.manifest.deployment_id,
                chainId: losslessChainId(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address
            }, expectedRevision);
            this.runtime = runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.notify();
            return this.walletStatus();
        });
    }

    async archiveNote(reason = 'closed', expectedNoteId = null) {
        await this.init();
        if (expectedNoteId == null) {
            throw new Error('Archiving a private note requires its exact note identity.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const noteId = expectedNoteId ?? this.runtime.state?.note_id;
            if (reason === 'expiry-claimed' && this.activeLease?.inFlight > 0) {
                throw new Error('Finish the current response before starting a new private balance.');
            }
            this.runtime = await archiveBrowserWallet(reason, noteId);
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            if (reason === 'expiry-claimed' && this.settlementTimer) {
                clearTimeout(this.settlementTimer);
                this.settlementTimer = null;
            }
            this.activeLease = null;
            this.notify();
            return this.walletStatus();
        });
    }
}

const browserWalletRuntime = new BrowserWalletRuntime();
export { BrowserWalletHttpError, BrowserWalletRuntime };
export default browserWalletRuntime;
