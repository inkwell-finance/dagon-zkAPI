import { beginBrowserSdkInitialization } from '../configure.js';
import browserWalletRuntime from './browserWalletRuntime.js';
import { assertSolanaDepositsOpen, assertSolanaVault, formatUnits, MICRO_USDC_PER_USDC, readUsdcTokenAccount,
    solanaRpc, usdcAssociatedTokenAddress, usdcBaseUnits, USDC_DECIMALS, validateSolanaFunding,
    vaultTokenAddress } from './zkapiUsdc.mjs';
import { base58Decode, base58Encode } from './zkapiSolanaTransport.mjs';
import { walletErrorMessage } from './zkapiWalletError.mjs';
import { deriveExpiryRecords } from './zkapiExpiryHistory.mjs';

const WITHDRAWAL_STORAGE_KEY = 'zkapi-withdrawal-v2';
const DEFAULT_CHALLENGE_PERIOD_SECONDS = 24 * 60 * 60;

// The Wallet Standard wallet and account the host selected. Kept outside the
// instance so snapshots never serialize a wallet object.
const solanaWalletProviders = new WeakMap();

function readStoredWithdrawal() {
    if (typeof window === 'undefined' || typeof localStorage === 'undefined'
        || typeof localStorage.getItem !== 'function') return null;
    try {
        const stored = JSON.parse(localStorage.getItem(WITHDRAWAL_STORAGE_KEY) || 'null');
        return stored?.noteId != null && ['prepared', 'submitting', 'pending'].includes(stored.phase)
            ? stored
            : null;
    } catch {
        localStorage.removeItem?.(WITHDRAWAL_STORAGE_KEY);
        return null;
    }
}

// A withdrawal pays a USDC token account (any owner), never a wallet
// address: the proof binds this exact account.
function normalizeWithdrawalDestination(destination, funding) {
    if (destination === undefined) return null;
    const normalized = base58Encode(base58Decode(destination, 32, 'USDC payout token account'));
    if (normalized === funding?.vault_state
        || (funding && normalized === vaultTokenAddress(funding.program_id, funding.vault_state))) {
        throw new TypeError('The withdrawal destination cannot be a Dagon vault account.');
    }
    return normalized;
}

function normalizedEscapePeriod(seconds) {
    return Math.max(1, Number(seconds) || DEFAULT_CHALLENGE_PERIOD_SECONDS);
}

function escapePeriodLabel(seconds) {
    const value = normalizedEscapePeriod(seconds);
    if (value % 86_400 === 0) return `${value / 86_400}-day`;
    if (value % 3_600 === 0) return `${value / 3_600}-hour`;
    if (value % 60 === 0) return `${value / 60}-minute`;
    return `${value}-second`;
}

function escapePeriodPhrase(seconds) {
    const value = normalizedEscapePeriod(seconds);
    if (value % 86_400 === 0) {
        const days = value / 86_400;
        return `${days} ${days === 1 ? 'day' : 'days'}`;
    }
    if (value % 3_600 === 0) {
        const hours = value / 3_600;
        return `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
    }
    if (value % 60 === 0) {
        const minutes = value / 60;
        return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`;
    }
    return `${value} ${value === 1 ? 'second' : 'seconds'}`;
}

function escapePeriodBadge(seconds) {
    const value = normalizedEscapePeriod(seconds);
    if (value >= 3_600) return `${Math.round(value / 3_600)}h`;
    if (value >= 60) return `${Math.round(value / 60)}m`;
    return `${value}s`;
}

function solanaProgressMessage(progress, subject) {
    const action = {
        signing: 'Confirm',
        resuming: 'Resuming',
        submitting: 'Submitting',
        confirming: 'Finalizing'
    }[progress.phase] || 'Processing';
    return progress.total > 1
        ? `${action} ${subject} ${progress.index + 1} of ${progress.total}…`
        : `${action} ${subject}…`;
}

class ZkapiClient extends EventTarget {
    constructor() {
        super();
        solanaWalletProviders.set(this, { wallet: null, account: null });
        this.config = null;
        this.wallet = null;
        this.walletAddress = null;
        this.withdrawal = readStoredWithdrawal();
        this.withdrawals = [];
        this.deposits = [];
        this.challengePeriodSeconds = DEFAULT_CHALLENGE_PERIOD_SECONDS;
        this.loading = false;
        this.lastError = null;
        this.initialized = false;
        this.initPromise = null;
        this.refreshTimer = null;
        this.clockTimer = null;
        this.browserMode = true;
        this.activities = [];
        this.activitySequence = 0;
        this.withdrawPromise = null;
        this.withdrawPromiseKey = null;
        this.finalizePromise = null;
        this.finalizePromiseKey = null;
        this.releasePromise = null;
        this.releasePromiseKey = null;
        this.depositPromise = null;
        this.depositPromiseKey = null;
        this.backgroundRefreshPromise = null;
        this.visibilityHandler = null;
    }

    async init() {
        beginBrowserSdkInitialization();
        if (this.initPromise) return this.initPromise;
        this.initPromise = (async () => {
            await this.enableBrowserMode();
            await this.refresh();
            this.refreshTimer = window.setInterval(() => void this.refreshInBackground(), 15_000);
            if (typeof document !== 'undefined' && !this.visibilityHandler) {
                this.visibilityHandler = () => {
                    if (document.visibilityState !== 'hidden') void this.refreshInBackground();
                };
                document.addEventListener('visibilitychange', this.visibilityHandler);
                window.addEventListener?.('focus', this.visibilityHandler);
            }
            // Time-only ticks have their own channel. Publishing them as a
            // semantic state change caused every subscriber to rebuild UI once
            // per second, disconnecting animated nodes and resetting focus.
            this.clockTimer = window.setInterval(() => this.emitClock(), 1_000);
            this.initialized = true;
            return this.snapshot();
        })().catch((error) => {
            this.lastError = error;
            this.loading = false;
            this.emitChange('error');
            throw error;
        });
        return this.initPromise;
    }

    async enableBrowserMode() {
        await browserWalletRuntime.init();
        if (!this.browserRuntimeListener) {
            this.browserRuntimeListener = () => void this.refresh({ quiet: true });
            browserWalletRuntime.addEventListener('change', this.browserRuntimeListener);
        }
    }

    /**
     * Re-read durable wallet state. Every Solana operation is resumed from its
     * journal by an explicit user action, so background work never opens a
     * wallet or signs anything.
     */
    refreshInBackground() {
        if (this.backgroundRefreshPromise) return this.backgroundRefreshPromise;
        const operation = this.refresh({ quiet: true })
            .then(() => true)
            .catch(error => {
                console.warn('Unable to refresh the browser wallet in the background.', error);
                return false;
            })
            .finally(() => {
                if (this.backgroundRefreshPromise === operation) this.backgroundRefreshPromise = null;
            });
        this.backgroundRefreshPromise = operation;
        return operation;
    }

    get solanaWallet() {
        return solanaWalletProviders.get(this)?.wallet || null;
    }

    get solanaAccount() {
        return solanaWalletProviders.get(this)?.account || null;
    }

    get walletProviderBusy() {
        return Boolean(this.depositPromise || this.withdrawPromise || this.finalizePromise || this.releasePromise);
    }

    setSolanaWallet(wallet = null, account = null) {
        if (wallet !== null && (typeof wallet !== 'object' || !wallet.features)) {
            throw new TypeError('The Solana wallet must implement Wallet Standard features.');
        }
        if (account !== null && (!account?.address || !account?.publicKey)) {
            throw new TypeError('The Solana wallet account is invalid.');
        }
        if (this.walletProviderBusy) {
            const error = new Error('Wait for the current wallet action to finish before changing wallets.');
            error.code = 'wallet_provider_busy';
            throw error;
        }
        solanaWalletProviders.set(this, { wallet, account });
        this.walletAddress = account?.address || null;
        this.emitChange('wallet-provider');
        return wallet;
    }

    snapshot() {
        return {
            config: this.config,
            wallet: this.wallet,
            walletAddress: this.walletAddress,
            withdrawal: this.withdrawal,
            withdrawals: this.withdrawals.map(record => ({ ...record })),
            deposits: this.deposits.map(record => ({ ...record })),
            challengePeriodSeconds: this.challengePeriodSeconds,
            loading: this.loading,
            lastError: this.lastError,
            initialized: this.initialized,
            activities: this.activities.map(activity => ({ ...activity }))
        };
    }

    runtimeStateSignature() {
        const error = this.lastError ? {
            name: this.lastError.name || null,
            code: this.lastError.code || null,
            status: this.lastError.status || null,
            message: walletErrorMessage(this.lastError)
        } : null;
        return JSON.stringify({
            config: this.config,
            wallet: this.wallet,
            withdrawal: this.withdrawal,
            withdrawals: this.withdrawals,
            deposits: this.deposits,
            error
        });
    }

    beginActivity(kind, details = {}) {
        const now = Date.now();
        const activity = {
            id: `zkapi-${now}-${++this.activitySequence}`,
            kind,
            phase: details.phase || 'starting',
            title: details.title || null,
            message: details.message || null,
            status: 'running',
            blocksSend: Boolean(details.blocksSend),
            sessionId: details.sessionId || null,
            startedAt: now,
            updatedAt: now,
            finishedAt: null,
            error: null
        };
        this.activities.push(activity);
        if (this.activities.length > 16) this.activities.splice(0, this.activities.length - 16);
        this.emitChange('activity-start');
        return activity.id;
    }

    updateActivity(id, changes = {}) {
        const activity = this.activities.find(entry => entry.id === id);
        if (!activity) return null;
        Object.assign(activity, changes, { updatedAt: Date.now() });
        this.emitChange('activity-update');
        return { ...activity };
    }

    completeActivity(id, changes = {}) {
        return this.updateActivity(id, {
            ...changes,
            status: 'success',
            phase: changes.phase || 'complete',
            finishedAt: Date.now(),
            blocksSend: false,
            error: null
        });
    }

    failActivity(id, error, changes = {}) {
        const message = walletErrorMessage(error);
        return this.updateActivity(id, {
            ...changes,
            status: 'error',
            phase: 'error',
            finishedAt: Date.now(),
            blocksSend: Boolean(changes.blocksSend),
            error: message
        });
    }

    cancelActivity(id, message = 'Canceled. No changes were made.') {
        return this.updateActivity(id, {
            status: 'canceled',
            phase: 'canceled',
            message,
            finishedAt: Date.now(),
            blocksSend: false,
            error: null
        });
    }

    subscribe(listener) {
        const handler = (event) => listener(this.snapshot(), event.detail);
        this.addEventListener('change', handler);
        return () => this.removeEventListener('change', handler);
    }

    subscribeClock(listener) {
        const handler = (event) => listener(event.detail);
        this.addEventListener('clock', handler);
        return () => this.removeEventListener('clock', handler);
    }

    emitClock() {
        this.dispatchEvent(new CustomEvent('clock', {
            detail: { now: Date.now() }
        }));
    }

    emitChange(reason = 'update') {
        this.dispatchEvent(new CustomEvent('change', { detail: { reason } }));
        window.dispatchEvent(new CustomEvent('zkapi-state-changed', {
            detail: { reason, snapshot: this.snapshot() }
        }));
    }

    rememberWithdrawal(value, { emit = true } = {}) {
        this.withdrawal = value;
        if (value) localStorage.setItem(WITHDRAWAL_STORAGE_KEY, JSON.stringify(value));
        else localStorage.removeItem(WITHDRAWAL_STORAGE_KEY);
        if (emit) this.emitChange('withdrawal');
    }

    async refresh({ quiet = false } = {}) {
        const stateBeforeRefresh = this.runtimeStateSignature();
        if (!quiet) {
            this.loading = true;
            this.emitChange('loading');
        }
        try {
            const wallet = await browserWalletRuntime.walletStatus();
            const browserSnapshot = browserWalletRuntime.snapshot();
            validateSolanaFunding(browserSnapshot.config?.funding);
            this.config = browserSnapshot.config;
            this.wallet = wallet;
            this.withdrawals = browserSnapshot.withdrawals || [];
            this.deposits = browserSnapshot.deposits || [];
            const challengePeriod = Number(browserWalletRuntime.vaultState?.challengePeriod);
            if (Number.isSafeInteger(challengePeriod) && challengePeriod > 0) {
                this.challengePeriodSeconds = challengePeriod;
            }
            this.lastError = null;

            const prepared = this.config?.prepared_withdrawal;
            if (prepared) {
                const mirror = {
                    phase: prepared.phase,
                    mode: prepared.mode,
                    noteId: prepared.note_id,
                    destination: prepared.destination,
                    clearanceReserved: prepared.clearance_reserved === true || prepared.mode === 'mutual'
                };
                if (JSON.stringify(this.withdrawal) !== JSON.stringify(mirror)) {
                    this.rememberWithdrawal(mirror, { emit: false });
                }
            } else if (this.withdrawal) {
                // IndexedDB is authoritative in browser mode. localStorage is
                // only a presentation mirror and must never resurrect a
                // canceled/prepared marker after the durable plan is cleared.
                this.rememberWithdrawal(null, { emit: false });
            }
        } catch (error) {
            this.lastError = error;
            if (!quiet) throw error;
        } finally {
            this.loading = false;
            // Periodic/browser-runtime refreshes often return byte-for-byte
            // equivalent state. Do not fan those out as semantic UI changes;
            // full panel/modal renders would otherwise replay animations even
            // though nothing users can act on changed.
            if (!quiet || stateBeforeRefresh !== this.runtimeStateSignature()) {
                this.emitChange(this.lastError ? 'error' : 'runtime');
            }
        }
        return this.snapshot();
    }

    /** Billing is exact: one USDC base unit is one micro-USD. */
    get creditsPerUsd() {
        return Number(MICRO_USDC_PER_USDC);
    }

    get hasNote() {
        return !!this.wallet?.has_note && !!this.wallet?.note;
    }

    async acquireInferenceAccess(sessionId, options = {}) {
        const signal = options.signal || null;
        const throwIfCancelled = () => {
            if (!signal?.aborted) return;
            const error = new DOMException('The operation was aborted.', 'AbortError');
            error.isCancelled = true;
            throw error;
        };
        throwIfCancelled();
        if (!this.initialized) await this.init();
        throwIfCancelled();
        const activityId = this.beginActivity('access', {
            phase: 'checking',
            title: 'Starting private chat',
            message: 'Checking your private balance…',
            progressKind: 'access',
            sessionId,
            blocksSend: true
        });
        let lastProgressPhase = 'checking';
        let lastProgressKind = 'access';
        const notifyProgress = (phase, message, kind = 'access', metadata = {}) => {
            try {
                options.onProgress?.({
                    kind,
                    phase,
                    message,
                    sessionId,
                    ...metadata
                });
            } catch (error) {
                console.warn('The assistant private-access trace could not update.', error);
            }
        };
        const reportProgress = (phase, message, kind = 'access') => {
            lastProgressPhase = phase;
            lastProgressKind = kind;
            this.updateActivity(activityId, { phase, message, progressKind: kind });
            notifyProgress(phase, message, kind);
        };
        notifyProgress('checking', 'Checking your private balance…');
        try {
            const access = await browserWalletRuntime.acquireEphemeralKey(
                sessionId,
                reportProgress,
                { signal, spendingLimitUsd: options.spendingLimitUsd }
            );
            if (signal?.aborted) {
                access.release?.();
                throwIfCancelled();
            }
            if (lastProgressPhase !== 'ready') {
                reportProgress('ready', 'Private chat ready.', lastProgressKind);
            }
            this.completeActivity(activityId, {
                phase: 'ready',
                message: 'Private chat ready.',
                progressKind: lastProgressKind
            });
            return access;
        } catch (error) {
            if (signal?.aborted) error.isCancelled = true;
            this.failActivity(activityId, error, { blocksSend: true });
            notifyProgress(
                error?.isCancelled ? 'canceled' : 'error',
                'Private access was not created.',
                lastProgressKind,
                { failedPhase: lastProgressPhase }
            );
            throw error;
        }
    }

    get note() {
        return this.wallet?.note || null;
    }

    get expiryHistory() {
        return deriveExpiryRecords(this.deposits, this.withdrawals);
    }

    get requestMode() {
        return 'direct_openrouter';
    }

    get isDirectMode() {
        return this.requestMode === 'direct_openrouter';
    }

    get suggestedDeposit() {
        return 5;
    }

    get billingTokenSymbol() {
        return 'USDC';
    }

    get isMainnetFunding() {
        return this.config?.funding?.network === 'mainnet-beta';
    }

    get activeLease() {
        const lease = this.config?.active_lease;
        return lease && Number(lease.expires_at) * 1000 > Date.now() ? lease : null;
    }

    get withdrawalBlocksChat() {
        return !!this.config?.prepared_withdrawal
            || ['prepared', 'submitting', 'pending'].includes(this.withdrawal?.phase);
    }

    get activeWithdrawal() {
        return this.config?.prepared_withdrawal || this.withdrawal || null;
    }

    get openWithdrawals() {
        return this.withdrawals.filter(record => record.phase !== 'closed');
    }

    get withdrawalRecoveryCount() {
        return this.openWithdrawals.length;
    }

    formatMoney(credits) {
        if (credits == null) return '—';
        const value = Number(credits) / Number(MICRO_USDC_PER_USDC);
        const digits = value > 0 && value < 0.01 ? 6 : 2;
        return new Intl.NumberFormat(undefined, {
            style: 'currency',
            currency: 'USD',
            minimumFractionDigits: 2,
            maximumFractionDigits: digits
        }).format(value);
    }

    formatBillingAmount(credits) {
        return formatUnits(credits || 0, USDC_DECIMALS);
    }

    formatExpiry(timestamp) {
        if (!timestamp) return '—';
        const remaining = Number(timestamp) * 1000 - Date.now();
        if (remaining <= 0) return 'expired';
        const days = Math.floor(remaining / 86_400_000);
        if (days > 1) return `${days} days`;
        const hours = Math.floor(remaining / 3_600_000);
        if (hours > 0) return `${hours}h`;
        return `${Math.max(1, Math.ceil(remaining / 60_000))}m`;
    }

    compact(value, width = 7) {
        if (!value) return '—';
        const text = String(value);
        return text.length > width * 2 + 2
            ? `${text.slice(0, width)}…${text.slice(-width)}`
            : text;
    }

    networkName(network = this.config?.funding?.network) {
        return network ? `Solana ${network}` : 'Solana';
    }

    async connectSolanaWallet() {
        const state = solanaWalletProviders.get(this);
        const wallet = state?.wallet;
        if (!wallet) {
            throw new Error('Choose a Solana wallet before continuing.');
        }
        const connect = wallet.features?.['standard:connect'];
        if (!connect || typeof connect.connect !== 'function') {
            throw new Error('The selected Solana wallet cannot connect through Wallet Standard.');
        }
        await connect.connect();
        const chain = this.config.funding.wallet_standard_chain;
        const accounts = Array.isArray(wallet.accounts) ? wallet.accounts : [];
        const selected = (state.account && accounts.find(account => account.address === state.account.address))
            || accounts.find(account => account.chains?.includes?.(chain)
                && account.features?.includes?.('solana:signTransaction'));
        if (!selected) {
            throw new Error(`The selected wallet has no account that can sign on ${chain}.`);
        }
        const publicKey = selected.publicKey instanceof Uint8Array
            ? selected.publicKey : Uint8Array.from(selected.publicKey || []);
        base58Decode(selected.address, 32, 'Solana wallet address');
        if (base58Encode(publicKey) !== selected.address) {
            throw new Error('The Solana wallet address does not match its public key.');
        }
        state.account = selected;
        this.walletAddress = selected.address;
        this.emitChange('wallet-connected');
        return { wallet, account: selected, address: selected.address };
    }

    async deposit(amountInput, onStatus = () => {}) {
        const key = String(amountInput).trim();
        if (this.depositPromise) {
            if (this.depositPromiseKey === key) return this.depositPromise;
            throw new Error('A different deposit action is already running.');
        }
        const operation = this.performDeposit(amountInput, onStatus);
        this.depositPromise = operation;
        this.depositPromiseKey = key;
        try {
            return await operation;
        } finally {
            if (this.depositPromise === operation) {
                this.depositPromise = null;
                this.depositPromiseKey = null;
            }
        }
    }

    /**
     * A new deposit moves USDC out of the wallet's canonical USDC account; the
     * wallet also pays network fees and the note/operation rent in SOL.
     */
    async assertDepositFunds(address, amount) {
        const funding = this.config.funding;
        const source = await readUsdcTokenAccount(funding, usdcAssociatedTokenAddress(address));
        if (!source) throw new Error('This wallet has no USDC account yet. Fund it with USDC before depositing.');
        if (!source.creditable) throw new Error('This wallet’s USDC account is frozen and cannot fund a deposit.');
        if (BigInt(source.amount) < amount) {
            throw new Error('Your wallet’s USDC balance is below this deposit amount.');
        }
        const fees = await solanaRpc(funding, 'getBalance', [address, {
            commitment: 'confirmed'
        }], AbortSignal.timeout(20_000));
        if (!Number.isSafeInteger(fees?.value) || fees.value < 0) {
            throw new Error('The Solana RPC returned an invalid wallet balance.');
        }
        if (fees.value === 0) {
            throw new Error('Your Solana wallet needs a little SOL for network fees and account rent besides the USDC deposit.');
        }
    }

    async performDeposit(amountInput, onStatus = () => {}) {
        if (this.hasNote) throw new Error('This client already has an active private note.');
        const funding = this.config?.funding;
        validateSolanaFunding(funding);
        const amount = usdcBaseUnits(amountInput);
        onStatus('Checking the finalized Dagon vault…');
        await assertSolanaVault(funding);
        onStatus('Connecting to your Solana wallet…');
        const { wallet, account, address } = await this.connectSolanaWallet();

        let plan = await browserWalletRuntime.pendingDeposit();
        if (plan) {
            if (Number(plan.amount) !== Number(amount)) {
                throw new Error('A previous Solana deposit is unfinished. Recover it before changing the amount.');
            }
            const journal = await browserWalletRuntime.currentSolanaOperationJournal('deposit');
            if (journal && journal.operationId !== plan.operationId) {
                throw new Error('The saved Solana deposit journal belongs to a different operation.');
            }
            if (journal && (await browserWalletRuntime.resumeSolanaOperation('deposit')).completed) {
                onStatus('Every Solana stage finalized. Verifying the private note…');
                const confirmed = await browserWalletRuntime.confirmSolanaDeposit();
                await this.refresh({ quiet: true });
                onStatus('Private USDC balance is ready.');
                return confirmed;
            }
        }

        if (!await browserWalletRuntime.currentSolanaOperationJournal('deposit')) {
            // Only a deposit with no signed transaction can still spend the
            // wallet's USDC; a resumed one already moved it.
            onStatus('Checking your wallet’s USDC balance…');
            await this.assertDepositFunds(address, amount);
            if (!plan) {
                onStatus('Generating the private note commitment locally…');
                plan = await browserWalletRuntime.prepareDeposit(Number(amount));
            }
            // Freeze a path against the finalized vault root before asking the
            // server to prepare any transaction bytes.
            const vault = assertSolanaDepositsOpen(await assertSolanaVault(funding));
            plan = await browserWalletRuntime.refreshPendingDeposit(
                Number(amount),
                vault.root,
                { expectedOperationId: plan.operationId }
            );
        }

        onStatus('Signing and finalizing the ordered Solana vault transactions…');
        await browserWalletRuntime.submitSolanaOperation('deposit', {
            wallet,
            account,
            onProgress: progress => onStatus(solanaProgressMessage(progress, 'Solana transaction'))
        });
        onStatus('Verifying the finalized Solana note and Merkle root…');
        const confirmed = await browserWalletRuntime.confirmSolanaDeposit();
        await this.refresh({ quiet: true });
        onStatus('Private USDC balance is ready.');
        return confirmed;
    }

    /**
     * Withdraw the selected balance. `mode` 'mutual' closes cooperatively;
     * 'escape' exits unilaterally, conceding what the exit rules choose (0
     * from a fresh state, at most the last request's bound otherwise).
     * `earlyConcession` ('zero' | 'bound') forces an escape while that request
     * may still be settling. The payout goes to the USDC token account
     * `destination` (any owner), or to the connected wallet's canonical USDC
     * account when omitted; that account is created first when missing.
     */
    async withdraw(mode, onStatus = () => {}, { destination, earlyConcession = null } = {}) {
        const requestedDestination = normalizeWithdrawalDestination(destination, this.config?.funding);
        const operationKey = `${mode}:${requestedDestination || ''}:${earlyConcession || ''}`;
        if (this.withdrawPromise) {
            if (this.withdrawPromiseKey === operationKey) return this.withdrawPromise;
            throw new Error('A different withdrawal action is already running.');
        }
        const operation = this.performWithdrawal(mode, onStatus, {
            destination: requestedDestination,
            earlyConcession
        });
        this.withdrawPromise = operation;
        this.withdrawPromiseKey = operationKey;
        try {
            return await operation;
        } finally {
            if (this.withdrawPromise === operation) {
                this.withdrawPromise = null;
                this.withdrawPromiseKey = null;
            }
        }
    }

    async performWithdrawal(mode, onStatus = () => {}, { destination: requested = null, earlyConcession = null } = {}) {
        const note = this.note;
        if (!note) throw new Error('There is no active private note to withdraw.');
        if (!['mutual', 'escape'].includes(mode)) throw new Error('Choose a valid withdrawal mode.');
        const noteId = Number(note.note_id);

        await this.settleActiveLease(onStatus, { allowUnresolved: mode === 'escape' });

        let plan = await browserWalletRuntime.currentPreparedWithdrawal();
        if (plan && Number(plan.noteId ?? plan.public_inputs?.note_id) !== noteId) {
            throw new Error('The prepared Solana withdrawal belongs to a different private balance.');
        }
        if (requested && plan?.destination && requested !== plan.destination) {
            throw new Error('This withdrawal is already bound to a different USDC payout account.');
        }
        const savedJournal = await browserWalletRuntime.currentSolanaOperationJournal('withdrawal');
        if (savedJournal && (await browserWalletRuntime.resumeSolanaOperation('withdrawal')).completed) {
            onStatus('Every Solana stage finalized. Verifying the withdrawal state…');
            const result = await browserWalletRuntime.confirmSolanaWithdrawal();
            await this.refresh({ quiet: true });
            return result;
        }

        onStatus('Connecting to your Solana wallet…');
        const { wallet, account, address } = await this.connectSolanaWallet();
        const destination = plan?.destination || requested || usdcAssociatedTokenAddress(address);
        if (!savedJournal) {
            // The proof binds the payout account, and the vault pays only a
            // creditable USDC account: make it exist before proving.
            onStatus('Checking the USDC payout account…');
            await browserWalletRuntime.ensureUsdcPayoutAccount(destination, {
                wallet,
                account,
                onProgress: progress => onStatus(solanaProgressMessage(progress, 'the USDC account creation'))
            });
            onStatus(mode === 'mutual'
                ? 'Requesting clearance and generating the withdrawal proof…'
                : 'Generating the unilateral escape proof locally…');
            plan = await browserWalletRuntime.prepareWithdrawal(mode, destination, { earlyConcession });
        }
        onStatus('Signing and finalizing the ordered Solana withdrawal transactions…');
        await browserWalletRuntime.submitSolanaOperation('withdrawal', {
            wallet,
            account,
            onProgress: progress => onStatus(solanaProgressMessage(progress, 'Solana transaction'))
        });
        onStatus('Verifying the finalized Solana vault and payout state…');
        const result = await browserWalletRuntime.confirmSolanaWithdrawal();
        await this.refresh({ quiet: true });
        onStatus(result.status === 'closed'
            ? 'The private USDC balance was returned.'
            : 'Escape started. The balance is secured for finalization after its challenge window.');
        return result;
    }

    async settleActiveLease(onStatus = () => {}, { sessionId = null, allowUnresolved = false } = {}) {
        const hasPendingRequest = Boolean(this.activeLease || this.wallet?.pending_request);
        const activityId = hasPendingRequest ? this.beginActivity('settlement', {
            phase: 'settling',
            title: 'Finishing previous chat',
            message: 'Closing its temporary key…',
            sessionId: this.activeLease?.session_id || null,
            blocksSend: true
        }) : null;
        const report = (phase, message) => {
            if (activityId) this.updateActivity(activityId, { phase, message });
            onStatus(message);
        };
        if (hasPendingRequest) {
            report('settling', 'Finishing the active chat and confirming its usage…');
        }
        try {
            const settled = sessionId
                ? await browserWalletRuntime.settleSessionLease(sessionId, report)
                : await browserWalletRuntime.settleActiveLease(report, { allowUnresolved });
            await this.refresh({ quiet: true });
            if (sessionId ? await this.getPendingLeaseOwner() === sessionId
                : this.activeLease || (this.wallet?.pending_request && !allowUnresolved)) {
                throw new Error('The private key usage is still settling. Try again shortly.');
            }
            if (hasPendingRequest) {
                report('complete', 'Previous chat finished. Balance updated.');
                this.completeActivity(activityId, { message: 'Previous chat finished. Balance updated.' });
            }
            return settled;
        } catch (error) {
            if (activityId) this.failActivity(activityId, error, { blocksSend: true });
            throw error;
        }
    }

    async hasPendingLease() {
        if (!this.initialized) await this.init();
        return browserWalletRuntime.hasPendingLease();
    }

    async getPendingLeaseOwner() {
        await this.init();
        return browserWalletRuntime.getPendingLeaseOwner();
    }

    async cancelPreparedWithdrawal(onStatus = () => {}) {
        const prepared = this.config?.prepared_withdrawal;
        if (!prepared) return false;
        if (prepared.mode === 'mutual' || prepared.clearance_reserved === true) {
            throw new Error('This balance already has a mutual-close authorization. Finish it or use the escape hatch.');
        }
        await browserWalletRuntime.clearPreparedWithdrawal({ expectedNoteId: prepared.note_id });
        this.rememberWithdrawal(null);
        await this.refresh();
        onStatus('Withdrawal canceled. Your private balance is ready to use.');
        return true;
    }

    async finalizeEscape(recordIdOrStatus = null, maybeStatus = () => {}) {
        const key = typeof recordIdOrStatus === 'string' ? recordIdOrStatus : 'selected';
        if (this.finalizePromise) {
            if (this.finalizePromiseKey === key) return this.finalizePromise;
            throw new Error('A different escape finalization is already running.');
        }
        const operation = this.performFinalizeEscape(recordIdOrStatus, maybeStatus);
        this.finalizePromise = operation;
        this.finalizePromiseKey = key;
        try {
            return await operation;
        } finally {
            if (this.finalizePromise === operation) {
                this.finalizePromise = null;
                this.finalizePromiseKey = null;
            }
        }
    }

    async performFinalizeEscape(recordIdOrStatus = null, maybeStatus = () => {}) {
        const hasRecordId = typeof recordIdOrStatus === 'string';
        const onStatus = typeof recordIdOrStatus === 'function' ? recordIdOrStatus : maybeStatus;
        let withdrawal = hasRecordId
            ? this.withdrawals.find(record => record.recordId === recordIdOrStatus)
            : this.withdrawals.find(record => record.mode === 'escape' && ['pending', 'finalizing'].includes(record.phase));
        if (withdrawal?.recordId) {
            withdrawal = await browserWalletRuntime.currentWithdrawal(withdrawal.recordId);
        }
        if (!['pending', 'finalizing'].includes(withdrawal?.phase)) {
            throw new Error('There is no pending escape withdrawal.');
        }
        if (Date.now() < Number(withdrawal.challengeDeadline) * 1000) {
            throw new Error(`The safety window has ${this.formatExpiry(withdrawal.challengeDeadline)} remaining.`);
        }
        onStatus('Connecting to your Solana wallet for finalization…');
        const { wallet, account } = await this.connectSolanaWallet();
        const result = await browserWalletRuntime.submitSolanaFinalization(withdrawal.recordId, {
            wallet,
            account,
            onProgress: progress => onStatus(solanaProgressMessage(progress, 'the Solana escape finalization'))
        });
        await this.refresh({ quiet: true });
        this.rememberWithdrawal(null);
        onStatus(result.status === 'payout_parked'
            ? 'Escape finalized, but its USDC payout account cannot receive funds. The payout is parked in the vault until it is released to that account.'
            : 'Escape finalized. The private USDC balance was returned.');
        return result;
    }

    async releaseEscapePayout(recordIdOrStatus = null, maybeStatus = () => {}) {
        const key = typeof recordIdOrStatus === 'string' ? recordIdOrStatus : 'selected';
        if (this.releasePromise) {
            if (this.releasePromiseKey === key) return this.releasePromise;
            throw new Error('A different escape payout release is already running.');
        }
        const operation = this.performReleaseEscapePayout(recordIdOrStatus, maybeStatus);
        this.releasePromise = operation;
        this.releasePromiseKey = key;
        try {
            return await operation;
        } finally {
            if (this.releasePromise === operation) {
                this.releasePromise = null;
                this.releasePromiseKey = null;
            }
        }
    }

    /**
     * Pay a parked escape payout to its proof-bound USDC account. The wallet's
     * own canonical USDC account is recreated first when it was closed; any
     * other payout account must be made creditable by its owner.
     */
    async performReleaseEscapePayout(recordIdOrStatus = null, maybeStatus = () => {}) {
        const hasRecordId = typeof recordIdOrStatus === 'string';
        const onStatus = typeof recordIdOrStatus === 'function' ? recordIdOrStatus : maybeStatus;
        let withdrawal = hasRecordId
            ? this.withdrawals.find(record => record.recordId === recordIdOrStatus)
            : this.withdrawals.find(record => record.mode === 'escape'
                && ['payout_parked', 'releasing'].includes(record.phase));
        if (withdrawal?.recordId) {
            withdrawal = await browserWalletRuntime.currentWithdrawal(withdrawal.recordId);
        }
        if (!['payout_parked', 'releasing'].includes(withdrawal?.phase)) {
            throw new Error('There is no parked escape payout.');
        }
        onStatus('Connecting to your Solana wallet to release the payout…');
        const { wallet, account } = await this.connectSolanaWallet();
        if (withdrawal.phase === 'payout_parked') {
            onStatus('Checking the USDC payout account…');
            await browserWalletRuntime.ensureUsdcPayoutAccount(withdrawal.destination, {
                wallet,
                account,
                onProgress: progress => onStatus(solanaProgressMessage(progress, 'the USDC account creation'))
            });
        }
        const result = await browserWalletRuntime.submitSolanaEscapePayoutRelease(withdrawal.recordId, {
            wallet,
            account,
            onProgress: progress => onStatus(solanaProgressMessage(progress, 'the Solana payout release'))
        });
        await this.refresh({ quiet: true });
        onStatus('The parked USDC payout was released.');
        return result;
    }

    escapePeriodLabel() {
        return escapePeriodLabel(this.challengePeriodSeconds);
    }

    escapePeriodPhrase() {
        return escapePeriodPhrase(this.challengePeriodSeconds);
    }

    escapePeriodBadge() {
        return escapePeriodBadge(this.challengePeriodSeconds);
    }
}

const zkapiClient = new ZkapiClient();
globalThis.zkapiClient = zkapiClient;

export { ZkapiClient };
export default zkapiClient;
