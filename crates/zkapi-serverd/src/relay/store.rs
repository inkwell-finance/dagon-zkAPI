//! Durable relay state in the server's SQLite database (`relay_*` tables).
//!
//! The relay keeps no debts: every relayer-paid cost is collected in the
//! same ek-signed transaction. What remains durable is the relayer's own
//! in-flight work:
//!
//! * `relay_sends`: every relayer-broadcast transaction, written before it
//!   is sent and reconciled until it confirms, fails or expires.
//! * `relay_event_accounts`: `MessageSent` accounts the relayer funded, to
//!   be reclaimed after Circle's 5-day window.
//! * `relay_meta`: the relay's address lookup table.
//! * `relay_receive_budget`: durable daily subsidy reservations and source/ek limits.
//! * `relay_receive_nonces`: attested messages already reserved, and the one
//!   receive transaction currently issued for each.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, thiserror::Error)]
#[error("relay store: {0}")]
pub struct StoreError(String);

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self(error.to_string())
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveAdmission {
    Accepted,
    BudgetExhausted,
    SourceLimited,
    OwnerLimited,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RiskAdmission {
    Accepted,
    /// The same signature is already reserved and outstanding.
    AlreadyReserved,
    LossBudgetExhausted,
    AddressBlocked,
    BurnFloatExhausted,
    /// Another submitted transaction of this owner is still executable.
    SubmissionPending,
    /// The sponsorship credential already covered a failed transaction.
    BackingSpent,
}

#[derive(Debug, Clone, Default)]
pub struct IssuedTransaction {
    pub signature: String,
    pub owner: String,
    pub source: String,
    pub last_valid_height: u64,
    pub fee_lamports: u64,
    /// Credential whose one-failure allowance covers this transaction.
    pub backing: Option<String>,
    /// Uncredentialed ek-co-signed work draws on the separate unbacked budget.
    pub unbacked: bool,
    /// Deposit instruction eligible for bounded note-id contention forgiveness.
    /// Every such failure is a loss; only the first three per ek/credential
    /// in rolling 24 hours avoid spending a credential or counting toward bans.
    pub contended_instruction: Option<u8>,
}

/// A relayer-signed transaction persisted before broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlight {
    pub signature: String,
    pub label: String,
    pub bytes: Vec<u8>,
    pub last_valid_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventAccount {
    pub address: String,
    pub signature: String,
    pub last_valid_height: u64,
    pub landed: bool,
    pub next_attempt_ms: u64,
}

pub struct RelayStore {
    conn: Mutex<Connection>,
}

fn to_i64(value: u64) -> StoreResult<i64> {
    i64::try_from(value).map_err(|_| StoreError("value exceeds SQLite integer range".into()))
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

impl RelayStore {
    pub fn open<P: AsRef<Path>>(path: P) -> StoreResult<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS relay_sends (
                signature TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                bytes BLOB NOT NULL,
                last_valid_height INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS relay_event_accounts (
                address TEXT PRIMARY KEY,
                signature TEXT NOT NULL,
                last_valid_height INTEGER NOT NULL,
                landed INTEGER NOT NULL DEFAULT 0,
                next_attempt_ms INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS relay_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS relay_receive_budget (
                day INTEGER NOT NULL,
                scope TEXT NOT NULL,
                subject TEXT NOT NULL,
                spent INTEGER NOT NULL,
                PRIMARY KEY(day, scope, subject)
            );
            CREATE TABLE IF NOT EXISTS relay_issued (
                signature TEXT PRIMARY KEY, owner TEXT NOT NULL, source TEXT NOT NULL,
                last_valid_height INTEGER NOT NULL, fee_lamports INTEGER NOT NULL,
                lost_at INTEGER, backing TEXT, unbacked INTEGER NOT NULL DEFAULT 0,
                contended_ix INTEGER, attributed INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS relay_burn_float (
                address TEXT PRIMARY KEY, lamports INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS relay_receive_nonces (
                nonce TEXT PRIMARY KEY, signature TEXT, bytes BLOB, last_valid_height INTEGER
            );
            CREATE TABLE IF NOT EXISTS relay_backings (
                key TEXT PRIMARY KEY, owner TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn in_memory() -> StoreResult<Self> {
        Self::open(":memory:")
    }

    fn with<T>(&self, f: impl FnOnce(&mut Connection) -> StoreResult<T>) -> StoreResult<T> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| StoreError("relay store lock poisoned".into()))?;
        f(&mut conn)
    }

    /// Atomically reserve all risk of a relay-only transaction before its
    /// signature leaves the server. `None` lost_at means outstanding;
    /// successful transactions are deleted.
    pub fn reserve_issuance(
        &self,
        issued: &IssuedTransaction,
        now: u64,
        budget: u64,
        event: Option<(&str, u64, u64)>,
    ) -> StoreResult<RiskAdmission> {
        self.reserve(issued, now, budget, event, false)
    }

    /// [`Self::reserve_issuance`] for an ek-co-signed transaction the relay is
    /// about to broadcast: additionally at most one executable submission per
    /// owner (one ek transfer cannot fail several relay transactions), and an
    /// unspent sponsorship credential when `issued.backing` is set.
    pub fn reserve_submission(
        &self,
        issued: &IssuedTransaction,
        now: u64,
        budget: u64,
        event: Option<(&str, u64, u64)>,
    ) -> StoreResult<RiskAdmission> {
        self.reserve(issued, now, budget, event, true)
    }

    fn reserve(
        &self,
        issued: &IssuedTransaction,
        now: u64,
        budget: u64,
        event: Option<(&str, u64, u64)>,
        submission: bool,
    ) -> StoreResult<RiskAdmission> {
        self.with(|conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let previous: u64 = tx.query_row("SELECT value FROM relay_meta WHERE key='risk_clock_ms'",
                [], |row| row.get::<_, String>(0)).optional()?.and_then(|value| value.parse().ok()).unwrap_or(0);
            let now = now.max(previous);
            tx.execute("INSERT OR REPLACE INTO relay_meta(key,value) VALUES ('risk_clock_ms',?1)", params![now.to_string()])?;
            let existing: Option<Option<i64>> = tx.query_row("SELECT lost_at FROM relay_issued WHERE signature=?1",
                params![issued.signature], |row| row.get(0)).optional()?;
            if let Some(lost) = existing {
                tx.commit()?;
                return Ok(if lost.is_none() { RiskAdmission::AlreadyReserved } else { RiskAdmission::AddressBlocked });
            }
            // Only actual Failed transactions reach lost_at. With our fixed
            // no-priority-fee signing policy, >1 signature means ek co-signed.
            // Relay-only receives/internal work must not ban their recipients.
            let failures: i64 = tx.query_row(
                "SELECT COUNT(*) FROM relay_issued WHERE lost_at>=?1 AND (owner=?2 OR source=?3) AND fee_lamports>?4 AND attributed=1",
                params![to_i64(now.saturating_sub(86_400_000))?, issued.owner, issued.source,
                    to_i64(super::fees::SIGNATURE_LAMPORTS)?], |row| row.get(0))?;
            if failures >= 3 { return Ok(RiskAdmission::AddressBlocked); }
            if submission {
                // Expiry alone does not prove non-execution: an earlier
                // failure may still await settlement and spend this backing.
                let pending: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM relay_issued WHERE lost_at IS NULL AND owner=?1
                     AND fee_lamports>?2",
                    params![issued.owner, to_i64(super::fees::SIGNATURE_LAMPORTS)?],
                    |row| row.get(0))?;
                if pending != 0 { return Ok(RiskAdmission::SubmissionPending); }
                if let Some(backing) = &issued.backing {
                    let failures: Option<i64> = tx.query_row(
                        "SELECT failures FROM relay_backings WHERE key=?1 AND owner=?2",
                        params![backing, issued.owner], |row| row.get(0)).optional()?;
                    if failures != Some(0) { return Ok(RiskAdmission::BackingSpent); }
                }
            }
            let spent: i64 = tx.query_row(
                "SELECT COALESCE(SUM(fee_lamports),0) FROM relay_issued WHERE (lost_at IS NULL OR lost_at>=?1) AND unbacked=?2",
                params![to_i64(now / 86_400_000 * 86_400_000)?, issued.unbacked], |row| row.get(0))?;
            if to_u64(spent).checked_add(issued.fee_lamports).is_none_or(|sum| sum > budget) {
                return Ok(RiskAdmission::LossBudgetExhausted);
            }
            if let Some((address, rent, limit)) = event {
                let known = tx.query_row("SELECT 1 FROM relay_event_accounts WHERE address=?1",
                    params![address], |_| Ok(())).optional()?.is_some();
                if !known {
                    // Unknown pre-upgrade events block new float until reconciled.
                    let unknown: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM relay_event_accounts e LEFT JOIN relay_burn_float f ON f.address=e.address WHERE f.address IS NULL",
                        [], |row| row.get(0))?;
                    let held: i64 = tx.query_row("SELECT COALESCE(SUM(lamports),0) FROM relay_burn_float", [], |row| row.get(0))?;
                    if unknown != 0 || to_u64(held).checked_add(rent).is_none_or(|sum| sum > limit) {
                        return Ok(RiskAdmission::BurnFloatExhausted);
                    }
                    tx.execute("INSERT INTO relay_burn_float(address,lamports) VALUES (?1,?2)", params![address, to_i64(rent)?])?;
                    tx.execute("INSERT INTO relay_event_accounts(address,signature,last_valid_height) VALUES (?1,?2,?3)",
                        params![address, issued.signature, to_i64(issued.last_valid_height)?])?;
                }
            }
            tx.execute("INSERT INTO relay_issued(signature,owner,source,last_valid_height,fee_lamports,backing,unbacked,contended_ix)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![issued.signature, issued.owner, issued.source, to_i64(issued.last_valid_height)?,
                    to_i64(issued.fee_lamports)?, issued.backing, issued.unbacked, issued.contended_instruction])?;
            tx.commit()?;
            Ok(RiskAdmission::Accepted)
        })
    }

    /// Undo a fresh reservation whose broadcast the RPC definitively refused
    /// (preflight): the complete transaction never left the relay, so it can
    /// never land.
    pub fn release_unbroadcast(&self, signature: &str) -> StoreResult<()> {
        self.with(|conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "DELETE FROM relay_burn_float WHERE address IN
                 (SELECT address FROM relay_event_accounts WHERE signature=?1 AND landed=0)",
                params![signature],
            )?;
            tx.execute(
                "DELETE FROM relay_event_accounts WHERE signature=?1 AND landed=0",
                params![signature],
            )?;
            tx.execute(
                "DELETE FROM relay_issued WHERE signature=?1 AND lost_at IS NULL",
                params![signature],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn outstanding_issuances(&self) -> StoreResult<Vec<IssuedTransaction>> {
        self.with(|conn| {
            let mut query = conn.prepare(
                "SELECT signature,owner,source,last_valid_height,fee_lamports,backing,unbacked,contended_ix
                FROM relay_issued WHERE lost_at IS NULL",
            )?;
            let rows = query.query_map([], |row| {
                Ok(IssuedTransaction {
                    signature: row.get(0)?,
                    owner: row.get(1)?,
                    source: row.get(2)?,
                    last_valid_height: to_u64(row.get(3)?),
                    fee_lamports: to_u64(row.get(4)?),
                    backing: row.get(5)?,
                    unbacked: row.get(6)?,
                    contended_instruction: row.get(7)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    /// Outstanding ek-co-signed issuances of `owner` (submission gate).
    pub fn pending_submissions(&self, owner: &str) -> StoreResult<Vec<IssuedTransaction>> {
        Ok(self
            .outstanding_issuances()?
            .into_iter()
            .filter(|issued| {
                issued.owner == owner && issued.fee_lamports > super::fees::SIGNATURE_LAMPORTS
            })
            .collect())
    }

    /// Finalized success or proven non-execution releases the reservation; an
    /// on-chain failure becomes a durable loss and, when the ek co-signed it,
    /// spends the one-failure allowance of its sponsorship credential.
    pub fn settle_issuance(&self, signature: &str, success: bool, now: u64) -> StoreResult<()> {
        self.settle(signature, if success { None } else { Some(true) }, now)
    }

    /// Forgive up to three deposit note-id races per ek or credential in a
    /// rolling 24 hours. Further races are ordinary attributed failures.
    pub fn settle_contention_failure(&self, signature: &str, now: u64) -> StoreResult<()> {
        self.settle(signature, Some(false), now)
    }

    /// `failure`: `None` = success, `Some(attributed)` = on-chain failure.
    fn settle(&self, signature: &str, failure: Option<bool>, now: u64) -> StoreResult<()> {
        self.with(|conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let previous: u64 = tx
                .query_row(
                    "SELECT value FROM relay_meta WHERE key='risk_clock_ms'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let now = now.max(previous);
            match failure {
                None => {
                    tx.execute(
                        "DELETE FROM relay_issued WHERE signature=?1 AND lost_at IS NULL",
                        params![signature],
                    )?;
                }
                Some(mut attributed) => {
                    if !attributed {
                        let forgiven: i64 = tx.query_row(
                            "SELECT COUNT(*) FROM relay_issued WHERE attributed=0 AND lost_at>=?1
                             AND (owner=(SELECT owner FROM relay_issued WHERE signature=?2)
                               OR backing=(SELECT backing FROM relay_issued WHERE signature=?2))",
                            params![to_i64(now.saturating_sub(86_400_000))?, signature],
                            |row| row.get(0),
                        )?;
                        attributed = forgiven >= 3;
                    }
                    if attributed {
                        tx.execute(
                            "UPDATE relay_backings SET failures=failures+1 WHERE key=
                             (SELECT backing FROM relay_issued WHERE signature=?1 AND lost_at IS NULL AND fee_lamports>?2)",
                            params![signature, to_i64(super::fees::SIGNATURE_LAMPORTS)?],
                        )?;
                    }
                    tx.execute(
                        "UPDATE relay_issued SET lost_at=?2, attributed=?3 WHERE signature=?1 AND lost_at IS NULL",
                        params![signature, to_i64(now)?, attributed],
                    )?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Record a sponsorship credential of `owner` (first owner wins: one
    /// credential never backs two emergency keys). Whether `key` backs `owner`.
    pub fn add_backing(&self, key: &str, owner: &str) -> StoreResult<bool> {
        self.with(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO relay_backings(key, owner) VALUES (?1, ?2)",
                params![key, owner],
            )?;
            let recorded: String = conn.query_row(
                "SELECT owner FROM relay_backings WHERE key=?1",
                params![key],
                |row| row.get(0),
            )?;
            Ok(recorded == owner)
        })
    }

    /// An unspent credential of `owner`, preferring `preferred`.
    pub fn unspent_backing(
        &self,
        owner: &str,
        preferred: Option<&str>,
    ) -> StoreResult<Option<String>> {
        self.with(|conn| {
            Ok(conn
                .query_row(
                    "SELECT key FROM relay_backings WHERE owner=?1 AND failures=0
                     ORDER BY key=?2 DESC, key LIMIT 1",
                    params![owner, preferred.unwrap_or("")],
                    |row| row.get(0),
                )
                .optional()?)
        })
    }

    /// Reserve before signing or spending any receive-related SOL. Reservations
    /// are never refunded: an issued transaction can still land after a timeout.
    ///
    /// A message's `used_nonce` rent can be paid at most once, and attested
    /// messages are public: repeated preparations of the same `nonce` (by
    /// anyone) charge neither `cost` nor the source/owner allowances again, so
    /// a third party cannot spend a victim's daily allowance with the victim's
    /// own message. Only new lookup-table rent (`extension`) is charged again.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_receive(
        &self,
        day: u64,
        nonce: &str,
        source: &str,
        owner: &str,
        cost: u64,
        extension: u64,
        policy: &super::config::ReceivePolicy,
    ) -> StoreResult<ReceiveAdmission> {
        self.with(|conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // A clock rollback must not reopen a previous day's allowance.
            let day: i64 = tx.query_row(
                "SELECT MAX(COALESCE(MAX(day), ?1), ?1) FROM relay_receive_budget",
                params![to_i64(day)?], |row| row.get(0))?;
            let known = tx
                .query_row("SELECT 1 FROM relay_receive_nonces WHERE nonce=?1", params![nonce], |_| Ok(()))
                .optional()?
                .is_some();
            let read = |scope: &str, subject: &str| -> StoreResult<u64> {
                let value: Option<i64> = tx.query_row(
                    "SELECT spent FROM relay_receive_budget WHERE day=?1 AND scope=?2 AND subject=?3",
                    params![day, scope, subject], |row| row.get(0)).optional()?;
                Ok(value.map(to_u64).unwrap_or(0))
            };
            let charge = if known {
                extension
            } else {
                cost.checked_add(extension)
                    .ok_or_else(|| StoreError("receive cost overflows".into()))?
            };
            if charge > 0
                && read("budget", "")?.checked_add(charge).is_none_or(|sum| sum > policy.daily_lamports)
            {
                return Ok(ReceiveAdmission::BudgetExhausted);
            }
            if !known {
                if read("source", source)? >= u64::from(policy.per_address_daily) {
                    return Ok(ReceiveAdmission::SourceLimited);
                }
                if read("owner", owner)? >= u64::from(policy.per_address_daily) {
                    return Ok(ReceiveAdmission::OwnerLimited);
                }
            }
            let allowances = if known { 0 } else { 1 };
            for (scope, subject, amount) in [("budget", "", charge), ("source", source, allowances), ("owner", owner, allowances)] {
                if amount == 0 {
                    continue;
                }
                tx.execute(
                    "INSERT INTO relay_receive_budget(day,scope,subject,spent) VALUES (?1,?2,?3,?4)
                     ON CONFLICT(day,scope,subject) DO UPDATE SET spent=spent+excluded.spent",
                    params![day, scope, subject, to_i64(amount)?])?;
            }
            if !known {
                tx.execute("INSERT INTO relay_receive_nonces(nonce) VALUES (?1)", params![nonce])?;
            }
            tx.commit()?;
            Ok(ReceiveAdmission::Accepted)
        })
    }

    /// The receive transaction last issued for `nonce`, if any.
    pub fn receive_transaction(&self, nonce: &str) -> StoreResult<Option<InFlight>> {
        self.with(|conn| {
            Ok(conn
                .query_row(
                    "SELECT signature, bytes, last_valid_height FROM relay_receive_nonces
                     WHERE nonce=?1 AND signature IS NOT NULL",
                    params![nonce],
                    |row| {
                        Ok(InFlight {
                            signature: row.get(0)?,
                            label: "receive".into(),
                            bytes: row.get(1)?,
                            last_valid_height: to_u64(row.get(2)?),
                        })
                    },
                )
                .optional()?)
        })
    }

    /// Remember the receive transaction issued for an already reserved `nonce`.
    pub fn set_receive_transaction(&self, nonce: &str, send: &InFlight) -> StoreResult<()> {
        self.with(|conn| {
            let updated = conn.execute(
                "UPDATE relay_receive_nonces SET signature=?2, bytes=?3, last_valid_height=?4 WHERE nonce=?1",
                params![nonce, send.signature, send.bytes, to_i64(send.last_valid_height)?],
            )?;
            if updated != 1 {
                return Err(StoreError("receive nonce was not reserved".into()));
            }
            Ok(())
        })
    }

    /// Record a relayer transaction before it is broadcast.
    pub fn insert_in_flight(&self, send: &InFlight) -> StoreResult<()> {
        self.with(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO relay_sends (signature, label, bytes, last_valid_height)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    send.signature,
                    send.label,
                    send.bytes,
                    to_i64(send.last_valid_height)?
                ],
            )?;
            Ok(())
        })
    }

    pub fn in_flight(&self) -> StoreResult<Vec<InFlight>> {
        self.with(|conn| {
            let mut statement = conn.prepare(
                "SELECT signature, label, bytes, last_valid_height FROM relay_sends
                 ORDER BY last_valid_height",
            )?;
            let rows = statement.query_map([], |row| {
                Ok(InFlight {
                    signature: row.get(0)?,
                    label: row.get(1)?,
                    bytes: row.get(2)?,
                    last_valid_height: to_u64(row.get(3)?),
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The transaction confirmed, failed or expired.
    pub fn remove_in_flight(&self, signature: &str) -> StoreResult<()> {
        self.with(|conn| {
            conn.execute(
                "DELETE FROM relay_sends WHERE signature = ?1",
                params![signature],
            )?;
            Ok(())
        })
    }

    pub fn event_accounts(&self) -> StoreResult<Vec<EventAccount>> {
        self.with(|conn| {
            let mut statement = conn.prepare(
                "SELECT address, signature, last_valid_height, landed, next_attempt_ms
                 FROM relay_event_accounts ORDER BY next_attempt_ms",
            )?;
            let rows = statement.query_map([], |row| {
                Ok(EventAccount {
                    address: row.get(0)?,
                    signature: row.get(1)?,
                    last_valid_height: to_u64(row.get(2)?),
                    landed: row.get::<_, i64>(3)? != 0,
                    next_attempt_ms: to_u64(row.get(4)?),
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    pub fn mark_event_landed(&self, address: &str) -> StoreResult<()> {
        self.with(|conn| {
            conn.execute(
                "UPDATE relay_event_accounts SET landed = 1 WHERE address = ?1",
                params![address],
            )?;
            Ok(())
        })
    }

    pub fn defer_event(&self, address: &str, next_attempt_ms: u64) -> StoreResult<()> {
        self.with(|conn| {
            conn.execute(
                "UPDATE relay_event_accounts SET next_attempt_ms = ?2 WHERE address = ?1",
                params![address, to_i64(next_attempt_ms)?],
            )?;
            Ok(())
        })
    }

    pub fn remove_event_account(&self, address: &str) -> StoreResult<()> {
        self.with(|conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "DELETE FROM relay_event_accounts WHERE address=?1",
                params![address],
            )?;
            tx.execute(
                "DELETE FROM relay_burn_float WHERE address=?1",
                params![address],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// A relay setting persisted across restarts (the lookup table address).
    pub fn meta(&self, key: &str) -> StoreResult<Option<String>> {
        self.with(|conn| {
            Ok(conn
                .query_row(
                    "SELECT value FROM relay_meta WHERE key = ?1",
                    params![key],
                    |row| row.get(0),
                )
                .optional()?)
        })
    }

    pub fn set_meta(&self, key: &str, value: &str) -> StoreResult<()> {
        self.with(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO relay_meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_state_persists_across_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        {
            let store = RelayStore::open(&path).unwrap();
            store
                .insert_in_flight(&InFlight {
                    signature: "sig".into(),
                    label: "finalize".into(),
                    bytes: vec![1, 2, 3],
                    last_valid_height: 77,
                })
                .unwrap();
            let issued = IssuedTransaction {
                signature: "sig".into(),
                owner: "ek".into(),
                source: "ata".into(),
                last_valid_height: 42,
                fee_lamports: 10,
                ..Default::default()
            };
            assert_eq!(
                store
                    .reserve_issuance(&issued, 1, 100, Some(("event", 20, 100)))
                    .unwrap(),
                RiskAdmission::Accepted
            );
            store.set_meta("lookup_table", "table").unwrap();
        }
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(
            store.in_flight().unwrap(),
            vec![InFlight {
                signature: "sig".into(),
                label: "finalize".into(),
                bytes: vec![1, 2, 3],
                last_valid_height: 77,
            }]
        );
        store.remove_in_flight("sig").unwrap();
        assert!(store.in_flight().unwrap().is_empty());
        store.mark_event_landed("event").unwrap();
        store.defer_event("event", 1_234).unwrap();
        assert_eq!(
            store.event_accounts().unwrap(),
            vec![EventAccount {
                address: "event".into(),
                signature: "sig".into(),
                last_valid_height: 42,
                landed: true,
                next_attempt_ms: 1_234,
            }]
        );
        store.remove_event_account("event").unwrap();
        assert!(store.event_accounts().unwrap().is_empty());
        assert_eq!(
            store.meta("lookup_table").unwrap().as_deref(),
            Some("table")
        );
    }

    #[test]
    fn receive_budget_and_address_limits_survive_restarts_and_clock_rollback() {
        use ReceiveAdmission::*;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let policy = super::super::config::ReceivePolicy {
            minimum_amount: 1_000_000,
            daily_lamports: 30,
            per_address_daily: 1,
        };
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(
            store
                .reserve_receive(10, "n1", "6:source-a", "ek-a", 10, 0, &policy)
                .unwrap(),
            Accepted
        );
        drop(store);
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(
            store
                .reserve_receive(10, "n2", "6:source-a", "ek-b", 10, 0, &policy)
                .unwrap(),
            SourceLimited
        );
        assert_eq!(
            store
                .reserve_receive(10, "n3", "6:source-b", "ek-a", 10, 0, &policy)
                .unwrap(),
            OwnerLimited
        );
        assert_eq!(
            store
                .reserve_receive(9, "n4", "6:source-a", "ek-b", 10, 0, &policy)
                .unwrap(),
            SourceLimited
        );
        assert_eq!(
            store
                .reserve_receive(10, "n5", "6:source-b", "ek-b", 20, 0, &policy)
                .unwrap(),
            Accepted
        );
        drop(store);
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(
            store
                .reserve_receive(10, "n6", "6:source-c", "ek-c", 1, 0, &policy)
                .unwrap(),
            BudgetExhausted
        );
        assert_eq!(
            store
                .reserve_receive(11, "n7", "6:source-a", "ek-a", 10, 0, &policy)
                .unwrap(),
            Accepted
        );
        let disabled = super::super::config::ReceivePolicy {
            daily_lamports: 0,
            ..policy
        };
        assert_eq!(
            store
                .reserve_receive(11, "n8", "6:source-b", "ek-b", 1, 0, &disabled)
                .unwrap(),
            BudgetExhausted
        );
    }

    #[test]
    fn concurrent_receive_preparations_cannot_overdraw_the_daily_budget() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let stores: Vec<_> = (0..8).map(|_| RelayStore::open(&path).unwrap()).collect();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(stores.len()));
        let threads: Vec<_> = stores
            .into_iter()
            .enumerate()
            .map(|(index, store)| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let policy = super::super::config::ReceivePolicy {
                        daily_lamports: 30,
                        per_address_daily: 100,
                        ..Default::default()
                    };
                    barrier.wait();
                    store
                        .reserve_receive(
                            10,
                            &format!("nonce-{index}"),
                            "6:source",
                            "ek",
                            10,
                            0,
                            &policy,
                        )
                        .unwrap()
                })
            })
            .collect();
        let accepted = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|result| *result == ReceiveAdmission::Accepted)
            .count();
        assert_eq!(accepted, 3);
    }

    #[test]
    fn a_message_is_reserved_once_and_its_issued_receive_survives_restarts() {
        use ReceiveAdmission::*;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let policy = super::super::config::ReceivePolicy {
            minimum_amount: 1_000_000,
            daily_lamports: 10,
            per_address_daily: 1,
        };
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(
            store
                .reserve_receive(1, "n", "s", "ek", 10, 0, &policy)
                .unwrap(),
            Accepted
        );
        assert!(store.receive_transaction("n").unwrap().is_none());
        let issued = InFlight {
            signature: "sig".into(),
            label: "receive".into(),
            bytes: vec![7, 8],
            last_valid_height: 50,
        };
        store.set_receive_transaction("n", &issued).unwrap();
        assert!(store
            .set_receive_transaction("unreserved", &issued)
            .is_err());
        drop(store);
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(store.receive_transaction("n").unwrap(), Some(issued));
        // Budget and both allowances are spent, yet the same message stays servable.
        assert_eq!(
            store
                .reserve_receive(1, "n", "s", "ek", 10, 0, &policy)
                .unwrap(),
            Accepted
        );
        assert_eq!(
            store
                .reserve_receive(1, "n", "s", "ek", 10, 1, &policy)
                .unwrap(),
            BudgetExhausted
        );
        assert_eq!(
            store
                .reserve_receive(1, "m", "s2", "ek2", 0, 0, &policy)
                .unwrap(),
            Accepted,
            "a zero-cost new message still needs only budget headroom"
        );
        assert_eq!(
            store
                .reserve_receive(1, "o", "s", "ek3", 0, 0, &policy)
                .unwrap(),
            SourceLimited
        );
    }

    fn issuance(signature: &str, owner: &str, source: &str) -> IssuedTransaction {
        IssuedTransaction {
            signature: signature.into(),
            owner: owner.into(),
            source: source.into(),
            last_valid_height: 100,
            fee_lamports: 10_000,
            ..Default::default()
        }
    }

    #[test]
    fn loss_budget_releases_success_and_persists_failures_and_address_blocks() {
        use RiskAdmission::*;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("risk.db");
        let store = RelayStore::open(&path).unwrap();
        let first = issuance("success", "ek", "source");
        assert_eq!(
            store.reserve_issuance(&first, 100, 30_000, None).unwrap(),
            Accepted
        );
        assert_eq!(
            store.reserve_issuance(&first, 100, 30_000, None).unwrap(),
            AlreadyReserved,
            "idempotent signature"
        );
        store.settle_issuance("success", true, 101).unwrap();
        assert!(store.outstanding_issuances().unwrap().is_empty());
        for i in 0..3 {
            let item = issuance(&format!("failed-{i}"), "ek", "source");
            assert_eq!(
                store.reserve_issuance(&item, 102, 30_000, None).unwrap(),
                Accepted
            );
            store.settle_issuance(&item.signature, false, 103).unwrap();
        }
        drop(store);
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(
            store
                .reserve_issuance(&issuance("new", "ek", "new-source"), 104, 100_000, None)
                .unwrap(),
            AddressBlocked
        );
        assert_eq!(
            store
                .reserve_issuance(&issuance("new", "new-ek", "source"), 104, 100_000, None)
                .unwrap(),
            AddressBlocked
        );
        assert_eq!(
            store
                .reserve_issuance(&issuance("new", "clean", "clean"), 104, 30_000, None)
                .unwrap(),
            LossBudgetExhausted
        );
        assert_eq!(
            store
                .reserve_issuance(&issuance("new", "ek", "source"), 86_400_104, 30_000, None)
                .unwrap(),
            Accepted
        );
    }

    #[test]
    fn outstanding_fee_and_event_rent_reservations_survive_restarts() {
        use RiskAdmission::*;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("float.db");
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(
            store
                .reserve_issuance(
                    &issuance("a", "a", "a"),
                    1,
                    20_000,
                    Some(("event-a", 20, 20))
                )
                .unwrap(),
            Accepted
        );
        drop(store);
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(
            store
                .reserve_issuance(
                    &issuance("b", "b", "b"),
                    1,
                    20_000,
                    Some(("event-b", 1, 20))
                )
                .unwrap(),
            BurnFloatExhausted
        );
        store.settle_issuance("a", true, 2).unwrap();
        assert_eq!(
            store
                .reserve_issuance(
                    &issuance("b", "b", "b"),
                    2,
                    20_000,
                    Some(("event-b", 1, 20))
                )
                .unwrap(),
            BurnFloatExhausted,
            "success releases fee risk, not the five-day event float"
        );
        store.remove_event_account("event-a").unwrap();
        assert_eq!(
            store
                .reserve_issuance(
                    &issuance("b", "b", "b"),
                    2,
                    20_000,
                    Some(("event-b", 20, 20))
                )
                .unwrap(),
            Accepted
        );
        assert_eq!(
            store
                .reserve_issuance(&issuance("c", "c", "c"), 2, 20_000, None)
                .unwrap(),
            Accepted
        );
        assert_eq!(
            store
                .reserve_issuance(&issuance("d", "d", "d"), 86_400_002, 20_000, None)
                .unwrap(),
            LossBudgetExhausted,
            "outstanding signatures do not reset at midnight"
        );
        store.settle_issuance("c", false, 86_400_002).unwrap();
        assert_eq!(
            store
                .reserve_issuance(&issuance("d", "d", "d"), 86_400_003, 20_000, None)
                .unwrap(),
            LossBudgetExhausted
        );
    }

    fn submission(signature: &str, owner: &str, backing: Option<&str>) -> IssuedTransaction {
        IssuedTransaction {
            signature: signature.into(),
            owner: owner.into(),
            source: format!("{owner}-ata"),
            last_valid_height: 100,
            fee_lamports: 10_000,
            backing: backing.map(Into::into),
            unbacked: backing.is_none(),
            contended_instruction: None,
        }
    }

    /// One executable submission per ek; each sponsorship credential covers
    /// exactly one ek-co-signed failure, durably; uncredentialed work has
    /// its own budget, so exhausting it never blocks credentialed users.
    #[test]
    fn submissions_need_an_unspent_credential_and_one_at_a_time() {
        use RiskAdmission::*;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("submit.db");
        let store = RelayStore::open(&path).unwrap();
        assert!(store.add_backing("nonce:aa", "ek").unwrap());
        assert!(
            !store.add_backing("nonce:aa", "thief").unwrap(),
            "first owner wins"
        );
        assert_eq!(store.unspent_backing("thief", None).unwrap(), None);
        assert_eq!(
            store.unspent_backing("ek", None).unwrap().as_deref(),
            Some("nonce:aa")
        );
        let first = submission("first", "ek", Some("nonce:aa"));
        assert_eq!(
            store.reserve_submission(&first, 1, 100_000, None).unwrap(),
            Accepted
        );
        assert_eq!(
            store
                .reserve_submission(
                    &submission("second", "ek", Some("nonce:aa")),
                    1,
                    100_000,
                    None,
                )
                .unwrap(),
            SubmissionPending,
            "the first is still executable at height 90"
        );
        assert_eq!(
            store.reserve_submission(&first, 1, 100_000, None).unwrap(),
            AlreadyReserved
        );
        // The first fails on chain: the credential is spent for good.
        store.settle_issuance("first", false, 2).unwrap();
        drop(store);
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(store.unspent_backing("ek", None).unwrap(), None);
        assert_eq!(
            store
                .reserve_submission(
                    &submission("third", "ek", Some("nonce:aa")),
                    3,
                    100_000,
                    None,
                )
                .unwrap(),
            BackingSpent
        );
        // A new credential restores sponsorship. Expiry alone cannot
        // release the old submission before its outcome is settled.
        assert!(store.add_backing("note:7", "ek").unwrap());
        assert_eq!(
            store
                .reserve_submission(
                    &submission("fourth", "ek", Some("note:7")),
                    3,
                    100_000,
                    None,
                )
                .unwrap(),
            Accepted
        );
        assert_eq!(
            store
                .reserve_submission(&submission("fifth", "ek", Some("note:7")), 3, 100_000, None,)
                .unwrap(),
            SubmissionPending
        );
        store.settle_issuance("fourth", true, 3).unwrap();
        assert_eq!(
            store
                .reserve_submission(&submission("fifth", "ek", Some("note:7")), 3, 100_000, None,)
                .unwrap(),
            Accepted
        );
        // Unbacked work has its own budget: 10,000 left for it, and filling
        // it does not touch the credentialed budget.
        assert_eq!(
            store
                .reserve_submission(&submission("u1", "x", None), 3, 10_000, None)
                .unwrap(),
            Accepted
        );
        assert_eq!(
            store
                .reserve_submission(&submission("u2", "y", None), 3, 10_000, None)
                .unwrap(),
            LossBudgetExhausted
        );
        assert!(store.add_backing("note:8", "z").unwrap());
        assert_eq!(
            store
                .reserve_submission(&submission("b1", "z", Some("note:8")), 3, 40_000, None)
                .unwrap(),
            Accepted,
            "credentialed: 10,000 lost + 10,000 outstanding + 10,000 fits 40,000"
        );
    }

    #[test]
    fn a_rejected_broadcast_releases_its_fresh_reservation_and_float() {
        use RiskAdmission::*;
        let store = RelayStore::in_memory().unwrap();
        let burn = submission("burn", "ek", None);
        assert_eq!(
            store
                .reserve_submission(&burn, 1, 30_000, Some(("event", 20, 20)))
                .unwrap(),
            Accepted
        );
        assert_eq!(
            store
                .reserve_submission(
                    &submission("other", "ek2", None),
                    1,
                    30_000,
                    Some(("event2", 1, 20)),
                )
                .unwrap(),
            BurnFloatExhausted
        );
        store.release_unbroadcast("burn").unwrap();
        assert!(store.outstanding_issuances().unwrap().is_empty());
        assert!(store.event_accounts().unwrap().is_empty());
        assert_eq!(
            store
                .reserve_submission(
                    &submission("other", "ek2", None),
                    1,
                    30_000,
                    Some(("event2", 20, 20)),
                )
                .unwrap(),
            Accepted
        );
    }

    /// The first three note-id races cost the budget, but no credential or ban.
    #[test]
    fn three_contention_failures_keep_the_credential_and_count_no_ban() {
        use RiskAdmission::*;
        let store = RelayStore::in_memory().unwrap();
        assert!(store.add_backing("nonce:bb", "ek").unwrap());
        for index in 0..3 {
            let issued = submission(&format!("deposit-{index}"), "ek", Some("nonce:bb"));
            assert_eq!(
                store.reserve_submission(&issued, 1, 100_000, None).unwrap(),
                Accepted
            );
            store
                .settle_contention_failure(&issued.signature, 2)
                .unwrap();
        }
        assert_eq!(
            store.unspent_backing("ek", None).unwrap().as_deref(),
            Some("nonce:bb")
        );
        assert_eq!(
            store
                .reserve_submission(
                    &submission("next", "ek", Some("nonce:bb")),
                    3,
                    100_000,
                    None,
                )
                .unwrap(),
            Accepted,
            "no ban, credential intact"
        );
        assert_eq!(
            store
                .reserve_submission(
                    &submission("full", "other", Some("nonce:bb")),
                    3,
                    40_000,
                    None,
                )
                .unwrap(),
            BackingSpent,
            "a credential backs only its own ek"
        );
    }

    #[test]
    fn contention_forgiveness_is_bounded_durable_and_rolling() {
        use RiskAdmission::*;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("contention.db");
        let store = RelayStore::open(&path).unwrap();
        assert!(store.add_backing("nonce:one", "ek").unwrap());
        for index in 0..3 {
            let issued = submission(&format!("race-{index}"), "ek", Some("nonce:one"));
            assert_eq!(
                store
                    .reserve_submission(&issued, 1_000, 1_000_000, None)
                    .unwrap(),
                Accepted
            );
            store
                .settle_contention_failure(&issued.signature, 1_000)
                .unwrap();
            // Duplicate reconciliation never spends a second allowance.
            store
                .settle_contention_failure(&issued.signature, 1_000)
                .unwrap();
        }
        drop(store);
        let store = RelayStore::open(&path).unwrap();
        assert_eq!(
            store.unspent_backing("ek", None).unwrap().as_deref(),
            Some("nonce:one")
        );
        let fourth = submission("fourth", "ek", Some("nonce:one"));
        assert_eq!(
            store
                .reserve_submission(&fourth, 999, 1_000_000, None)
                .unwrap(),
            Accepted
        );
        store.settle_contention_failure("fourth", 999).unwrap();
        assert_eq!(
            store.unspent_backing("ek", None).unwrap(),
            None,
            "fourth race spends the credential, even after restart/clock rollback"
        );
        // New credentials do not reset this ek's allowance.
        for index in 0..2 {
            let credential = format!("note:{index}");
            assert!(store.add_backing(&credential, "ek").unwrap());
            let issued = submission(&format!("extra-{index}"), "ek", Some(&credential));
            assert_eq!(
                store
                    .reserve_submission(&issued, 1_001, 1_000_000, None)
                    .unwrap(),
                Accepted
            );
            store
                .settle_contention_failure(&issued.signature, 1_001)
                .unwrap();
            assert_eq!(store.unspent_backing("ek", None).unwrap(), None);
        }
        assert_eq!(
            store
                .reserve_submission(&submission("banned", "ek", None), 1_002, 1_000_000, None)
                .unwrap(),
            AddressBlocked,
            "three over-limit races count as normal failures toward the ban"
        );
        // A different ek has its own allowance.
        assert!(store.add_backing("nonce:other", "other").unwrap());
        let other = submission("other", "other", Some("nonce:other"));
        assert_eq!(
            store
                .reserve_submission(&other, 1_002, 1_000_000, None)
                .unwrap(),
            Accepted
        );
        store.settle_contention_failure("other", 1_002).unwrap();
        assert_eq!(
            store.unspent_backing("other", None).unwrap().as_deref(),
            Some("nonce:other")
        );
        // Rolling 24 hours, not UTC midnight: the ek's forgiveness replenishes.
        assert!(store.add_backing("nonce:later", "ek").unwrap());
        let later = submission("later", "ek", Some("nonce:later"));
        let tomorrow = 86_400_000 + 1_002;
        assert_eq!(
            store
                .reserve_submission(&later, tomorrow, 1_000_000, None)
                .unwrap(),
            Accepted
        );
        store.settle_contention_failure("later", tomorrow).unwrap();
        assert_eq!(
            store.unspent_backing("ek", None).unwrap().as_deref(),
            Some("nonce:later")
        );
    }
}
