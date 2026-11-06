import * as eth from './zkapiNativeEth.mjs';
import * as sol from './zkapiNativeSol.mjs';

export const isNativeEthFunding = eth.isNativeEthFunding;
export const isNativeSolFunding = sol.isNativeSolFunding;
export const parseUnits = eth.parseUnits;
export const formatUnits = eth.formatUnits;
export const nativeDepositValue = eth.nativeDepositValue;

export function validateNativeFunding(funding) {
    return sol.isNativeSolFunding(funding)
        ? sol.validateSolanaFunding(funding)
        : eth.validateNativeFunding(funding);
}

export function validateNativeQuote(quote, funding, options) {
    return sol.isNativeSolFunding(funding)
        ? sol.validateSolanaQuote(quote, funding, options)
        : eth.validateNativeQuote(quote, funding, options);
}

export function nativeUnitsForUsd(usd, quote) {
    return quote?.asset === 'native_sol'
        ? sol.solanaUnitsForUsd(usd, quote)
        : eth.nativeUnitsForUsd(usd, quote);
}

export function nativeUsdMicros(amount, quote) {
    return quote?.asset === 'native_sol'
        ? sol.solanaUsdMicros(amount, quote)
        : eth.nativeUsdMicros(amount, quote);
}

export function sameNativeQuote(left, right) {
    return left?.asset === 'native_sol' || right?.asset === 'native_sol'
        ? sol.sameSolanaQuote(left, right)
        : eth.sameNativeQuote(left, right);
}

export function assertNativeVault(funding, options) {
    return sol.isNativeSolFunding(funding)
        ? sol.assertSolanaVault(funding, options)
        : eth.assertNativeVault(funding, options);
}

/** Finalized block time (seconds) from the host-pinned RPC; never the operator. */
export function readFinalizedChainTime(funding, options) {
    return sol.isNativeSolFunding(funding)
        ? sol.readFinalizedSolanaTime(funding, options)
        : eth.readFinalizedChainTime(funding, options);
}

export function readNativeQuote(funding, options) {
    return sol.isNativeSolFunding(funding)
        ? sol.readSolanaQuote(funding, options)
        : eth.readNativeQuote(funding, options);
}

export const requestBillingQuote = eth.requestBillingQuote;
