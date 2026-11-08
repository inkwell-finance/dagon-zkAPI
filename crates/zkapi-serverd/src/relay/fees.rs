//! Relay fee quotes and the SDK's fee caps.
//!
//! `fee_usdc = ceil(cost_lamports × sol_usd_micros / 1e9 × (10000 + margin_bps) / 10000)`
//! where one USDC base unit is one micro-USD. Relay transactions carry no
//! compute-unit price, so the cost is rent plus 5,000 lamports per signature.

use serde::Serialize;

/// Base fee per transaction signature.
pub const SIGNATURE_LAMPORTS: u64 = 5_000;

/// The relay operations that are priced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayKind {
    Deposit,
    Receive,
    Close,
    Escape,
    Burn,
    Sweep,
}

impl RelayKind {
    pub const ALL: [RelayKind; 6] = [
        RelayKind::Deposit,
        RelayKind::Receive,
        RelayKind::Close,
        RelayKind::Escape,
        RelayKind::Burn,
        RelayKind::Sweep,
    ];

    /// Hard per-kind cap (USDC base units), enforced independently of the
    /// caller's ceiling. A fallback receive is free.
    pub const fn sdk_cap(self) -> u64 {
        match self {
            RelayKind::Deposit => 400_000,
            RelayKind::Receive => 0,
            RelayKind::Close => 750_000,
            RelayKind::Escape => 750_000,
            RelayKind::Burn | RelayKind::Sweep => 50_000,
        }
    }
}

/// Rent-exempt minimums (lamports) read from the cluster at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RentTable {
    pub note: u64,
    pub used_nullifier: u64,
    pub token_account: u64,
    pub used_nonce: u64,
}

/// The user-priced lamports of one operation. Event rent is relay float,
/// not charged to the user; the durable outstanding-rent limit bounds it.
///
/// * deposit: NoteState rent + one atomic transaction (2 signatures);
///   the ek-owned operation buffer rent is advanced and refunded atomically;
/// * receive: `used_nonce` rent + 1 sig, **not charged**: with the 312-byte
///   D2 hook no ek fee transfer fits the packet, so a fallback receive is a
///   bounded subsidy into a never-closable account (`ATA(ek)` must exist);
/// * close: UsedNullifier rent + ATA rent if absent + 2 sigs;
/// * escape: 2 × UsedNullifier rent + escape (2 sigs) + the relayer-paid
///   finalize (1 sig); the pending rent is refunded to the relayer;
/// * burn: 3 burn signatures + 1 reclaim signature; event rent remains relay float;
/// * sweep: 2 signatures.
pub fn cost_lamports(kind: RelayKind, rent: &RentTable, creates_ata: bool) -> u64 {
    let ata = if creates_ata { rent.token_account } else { 0 };
    match kind {
        RelayKind::Deposit => rent.note + 2 * SIGNATURE_LAMPORTS,
        RelayKind::Receive => rent.used_nonce + SIGNATURE_LAMPORTS,
        RelayKind::Close => rent.used_nullifier + ata + 2 * SIGNATURE_LAMPORTS,
        RelayKind::Escape => 2 * rent.used_nullifier + 3 * SIGNATURE_LAMPORTS,
        RelayKind::Burn => 4 * SIGNATURE_LAMPORTS,
        RelayKind::Sweep => 2 * SIGNATURE_LAMPORTS,
    }
}

/// USDC base units for `lamports` at `sol_usd_micros` plus the margin,
/// rounded up. Saturates (never wraps) for absurd inputs.
pub fn fee_usdc(lamports: u64, sol_usd_micros: u64, margin_bps: u32) -> u64 {
    if lamports == 0 {
        return 0;
    }
    let Some(numerator) = u128::from(lamports)
        .checked_mul(u128::from(sol_usd_micros))
        .and_then(|value| value.checked_mul(10_000 + u128::from(margin_bps)))
    else {
        return u64::MAX;
    };
    let denominator = 1_000_000_000u128 * 10_000;
    u64::try_from(numerator.div_ceil(denominator)).unwrap_or(u64::MAX)
}

/// Worst-case quote of `kind` (an ATA created where the kind may create
/// one). A fallback receive is never charged (see [`cost_lamports`]).
pub fn quote(kind: RelayKind, rent: &RentTable, sol_usd_micros: u64, margin_bps: u32) -> u64 {
    if kind == RelayKind::Receive {
        return 0;
    }
    fee_usdc(cost_lamports(kind, rent, true), sol_usd_micros, margin_bps)
}

/// Kinds whose worst-case quote the SDK would reject. Logged at startup;
/// such requests then fail with `relay_fee_above_cap` against the wallet's
/// `max_fee`.
pub fn kinds_above_caps(
    rent: &RentTable,
    sol_usd_micros: u64,
    margin_bps: u32,
) -> Vec<(RelayKind, u64)> {
    RelayKind::ALL
        .into_iter()
        .map(|kind| (kind, quote(kind, rent, sol_usd_micros, margin_bps)))
        .filter(|(kind, quoted)| *quoted > kind.sdk_cap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Solana rent (mainnet and localnet): 6,960 lamports per (128 + data
    /// bytes), i.e. 3,480 lamports per byte-year for two years.
    pub(crate) fn mainnet_rent() -> RentTable {
        let rent = |bytes: u64| (128 + bytes) * 6_960;
        RentTable {
            note: rent(dagon_zkapi_solana_ledger::note_account_len() as u64),
            used_nullifier: rent(dagon_zkapi_solana_ledger::used_nullifier_account_len() as u64),
            token_account: rent(165),
            used_nonce: rent(9),
        }
    }

    #[test]
    fn fee_formula_rounds_up_and_applies_the_margin() {
        // 1 SOL at $150.000000 with no margin is exactly 150 USDC.
        assert_eq!(fee_usdc(1_000_000_000, 150_000_000, 0), 150_000_000);
        // 20% margin.
        assert_eq!(fee_usdc(1_000_000_000, 150_000_000, 2_000), 180_000_000);
        // 1 lamport at $150 is 0.00015 micro-USD: rounds up to one base unit.
        assert_eq!(fee_usdc(1, 150_000_000, 0), 1);
        assert_eq!(fee_usdc(0, 150_000_000, 2_000), 0);
        // 5,000 lamports at $88.89 + 20% = 533.34 → 534.
        assert_eq!(fee_usdc(5_000, 88_890_000, 2_000), 534);
        assert_eq!(fee_usdc(u64::MAX, u64::MAX, 10_000), u64::MAX);
    }

    #[test]
    fn costs_follow_the_contract() {
        let rent = mainnet_rent();
        assert_eq!(rent.token_account, 2_039_280);
        assert_eq!(
            cost_lamports(RelayKind::Deposit, &rent, true),
            rent.note + 10_000
        );
        assert_eq!(
            cost_lamports(RelayKind::Receive, &rent, true),
            rent.used_nonce + 5_000
        );
        assert_eq!(quote(RelayKind::Receive, &rent, 88_890_000, 2_000), 0);
        assert_eq!(
            cost_lamports(RelayKind::Close, &rent, true),
            rent.used_nullifier + rent.token_account + 10_000
        );
        assert_eq!(
            cost_lamports(RelayKind::Escape, &rent, true),
            2 * rent.used_nullifier + 15_000
        );
        // Worst cases at $88.89 and $150 + 20%.
        assert_eq!(quote(RelayKind::Deposit, &rent, 88_890_000, 2_000), 177_761);
        assert_eq!(quote(RelayKind::Close, &rent, 88_890_000, 2_000), 368_560);
        assert_eq!(quote(RelayKind::Escape, &rent, 88_890_000, 2_000), 301_534);
        assert_eq!(
            quote(RelayKind::Deposit, &rent, 150_000_000, 2_000),
            299_967
        );
        assert_eq!(quote(RelayKind::Close, &rent, 150_000_000, 2_000), 621_936);
        assert_eq!(quote(RelayKind::Escape, &rent, 150_000_000, 2_000), 508_832);
        assert_eq!(cost_lamports(RelayKind::Burn, &rent, true), 20_000);
        assert_eq!(cost_lamports(RelayKind::Sweep, &rent, true), 10_000);
        assert_eq!(quote(RelayKind::Burn, &rent, 150_000_000, 2_000), 3_600);
        assert_eq!(quote(RelayKind::Burn, &rent, 180_000_000, 2_000), 4_320);
        assert_eq!(quote(RelayKind::Sweep, &rent, 150_000_000, 2_000), 1_800);
        assert_eq!(quote(RelayKind::Sweep, &rent, 180_000_000, 2_000), 2_160);
    }

    /// The default margin fits every SDK cap at SOL prices up to $180; a
    /// sufficiently large price typo is reported for every charged kind.
    #[test]
    fn default_quotes_fit_the_sdk_caps() {
        let rent = mainnet_rent();
        for price in [88_890_000, 150_000_000, 180_000_000] {
            assert!(kinds_above_caps(&rent, price, 2_000).is_empty(), "${price}");
            for kind in RelayKind::ALL {
                assert!(quote(kind, &rent, price, 2_000) <= kind.sdk_cap());
            }
        }
        // Every charged kind (a fallback receive is free) is reported.
        assert_eq!(kinds_above_caps(&rent, 150_000_000_000, 2_000).len(), 5);
    }
}
