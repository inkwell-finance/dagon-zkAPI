# ZK API Usage Credits

This note describes the active zkAPI v2 usage-credit protocol as deployed by
Dagon on Solana. The implementation uses BN254 Groth16 proofs, BN254 Poseidon
hashing, Baby-JubJub Schnorr signatures, and USDC settlement (classic SPL
Token, one credit per micro-USDC) by the Anchor vault program. The protocol is chain-neutral and descends from
upstream [ethereum/zkapi](https://github.com/ethereum/zkapi), whose EVM vault
remains the Ethereum deployment. See [SPEC.md](SPEC.md) for exact public
statements and [setup compatibility](setup/v2/README.md) for the current circuit
revision and single-party setup trust assumptions.

The goal is: a user deposits funds on-chain once, and then makes many anonymous off-chain API requests. The server must be protected against replay and non-payment, while honest users remain unlinkable.

Compared to the original [RLN-based design](https://ethresear.ch/t/zk-api-usage-credits-llms-and-beyond/24104), this version removes:
- the "two points on a line" construction,
- ticket indices,
- growing refund histories.

Instead, it uses a much simpler **state-anchor chain**: each valid request consumes the user's current private spend state and yields a fresh next state signed by the server.

## Overview

A user registers on-chain with a commitment derived from a secret.  
Off-chain, the user carries a private state consisting of:
- a private balance commitment,
- a one-time state anchor,
- a server signature on that state.

To make a request, the user proves in zero knowledge that:
- they are a registered depositor,
- they know the secret behind the registration commitment,
- they know a valid current state,
- they are authorized to spend from that state,
- they have enough balance for the maximum per-request charge.

The server accepts the request only if the derived nullifier has not been seen before.

After execution, the server computes the actual deduction, updates the private balance, generates a fresh next anchor, signs the new state, and returns it to the user.

The funds remain escrowed on-chain until close-out. The server is paid by net settlement when the user withdraws or when an expired note is claimed.

This makes the protocol naturally sequential: one state authorizes one next request.

## Primitives

- $s$: user secret.
- $C = H(s, 0)$: on-chain registration commitment.
- $D$: prepaid usage deposit locked in the vault.
- $C_{\max}$: maximum ordinary per-request charge.
- $S_{\max}$: optional higher cap for policy-violation deductions.
- $B$: current private available balance.
- $L = H_{\text{leaf}}(\text{noteId}, C, D, T_{\text{exp}})$: active membership leaf.
- $E(B)$: shorthand for the note-bound homomorphic commitment
  $E(B,r,L) = B G + r H + L J$ on Baby-JubJub. The private leaf term remains
  fixed throughout every state transition and rerandomization.
- $\tau$: current state anchor.
- $\sigma_{\text{srv}}$: server signature on the current state $(E(B), \tau)$.
- $x_w$: withdrawal nullifier.
- $\sigma_{\text{clear}}$: server clearance signature on $x_w$ for instant withdrawal.
- $A_{\text{srv}}$: server treasury address.
- $T_{\text{exp}}$: note expiry time / TTL.

Initial private state:
- $B = D$
- $\tau = 1$

## Registration

1. The user samples a secret $s$.
2. The user computes the registration commitment:

$$
C = H(s, 0)
$$

3. The user deposits:

$$
D
$$

into the vault program.

4. The vault records the deposit amount $D$ and expiry $T_{\text{exp}}$, then inserts the full note leaf $L$ into the on-chain Merkle tree at the note ID.

## Request Generation

To make a request, the user sends:
- payload $M$,
- nullifier $x$,
- rerandomized balance commitment $E(B)_{\text{anon}}$,
- proof $\pi_{\text{req}}$.

The proof $\pi_{\text{req}}$ proves:

1. **Membership**  
   $L = H_{\text{leaf}}(\text{noteId}, H(s, 0), D, T_{\text{exp}})$ is in the active Merkle tree.

2. **Secret knowledge**  
   The prover knows $s$.

3. **Spend authorization**  
   Either:
   - first request:

$$
x = H(d_{\text{null}}, s, n, 1)
$$

   - later request:

$$
x = H(d_{\text{null}}, s, n, \tau)
$$

   where $n$ is the note ID (the nullifier is note-bound) and $\tau = H(d_{\text{anchor}}, x_{\text{prev}})$ is the anchor derived from the previous nullifier; the circuit enforces this chain.

4. **State validity**  
   For non-genesis spends, the prover knows a valid server signature on the current state:

$$
\sigma_{\text{srv}} \text{ on } (E(B), \tau)
$$

5. **Balance correctness**  
   The prover knows the opening of $E(B)$.

6. **Rerandomization correctness**  
   $E(B)_{\text{anon}}$ is a valid rerandomization of $E(B)$.

7. **Solvency**

$$
B \geq C_{\max}
$$

If the optional policy-penalty extension below is enabled, this lower bound becomes:

$$
B \geq \max(C_{\max}, S_{\max})
$$

The public request statement includes an authorization tag binding the request
nullifier to the exact client request ID and payload hash. It also includes a
request time; the proof requires the private note expiry to be at least that
time. The server validates the current time and deployment-bound public inputs.

## Server Verification

Upon receiving a request, the server:

1. verifies $\pi_{\text{req}}$;
2. checks whether $x$ is already in `spent_nullifiers`;
3. rejects the request if $x$ was already seen;
4. otherwise stores $x$ and executes the request.

The server stores **all seen nullifiers**.

Importantly, the server does **not** need to know which state is the user's "latest" one.  
It only needs to enforce one-time use of nullifiers.

## Settlement and State Update

After execution, the server computes the actual deduction $\Delta$, with:

$$
0 \leq \Delta \leq C_{\max}
$$

The updated private balance is:

$$
B_{\text{new}} = B - \Delta
$$

The server then:

1. derives the next anchor $\tau_{\text{new}} = H(d_{\text{anchor}}, N)$ from the request nullifier $N$ (never random);
2. computes the updated balance commitment $E(B_{\text{new}})$;
3. signs the new state:

$$
\sigma_{\text{new}} = \text{Sign}_{\text{srv}}(E(B_{\text{new}}), \tau_{\text{new}})
$$

4. returns:

$$
(\text{response}, E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})
$$

The user stores:

$$
(E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})
$$

as their new private spend state.

## Optional Policy Penalty Extension

The base protocol only needs the ordinary per-request cap $C_{\max}$.

If a deployment wants a stronger deterrent for policy-breaking requests, it may additionally define:

$$
S_{\max} \geq C_{\max}
$$

When this extension is enabled:
- the request proof must establish $B \geq \max(C_{\max}, S_{\max})$;
- ordinary requests still deduct at most $C_{\max}$;
- a request that violates provider policy may instead apply a policy deduction $\Delta_{\text{policy}}$ with:

$$
0 \leq \Delta_{\text{policy}} \leq S_{\max}
$$

In that case, the server still consumes the current nullifier, computes:

$$
B_{\text{new}} = B - \Delta_{\text{policy}}
$$

and returns a rejection payload together with the fresh next state $(E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})$.

A practical deployment may additionally require the server to attach signed policy metadata, such as a reason code and an evidence hash, so abusive deductions remain externally auditable.

No separate on-chain policy stake or `slashPolicyStake` function is required. The larger policy penalty is just an optional bounded state transition, and it is automatically included in the eventual net settlement $D - B_{\text{final}}$.

## Withdrawal

Withdrawal is modeled as a **final spend** of the current state. The withdrawal nullifier lives in the same nullifier namespace as ordinary requests.

The user chooses a destination address $\text{Dest}$ and prepares:
- a withdrawal nullifier $x_w$,
- a withdrawal proof $\pi_{\text{wd}}$.

The proof shows:

1. recomputation of the registration $C = H(s, 0)$ and of the full note leaf $L = H_{\text{leaf}}(n, C, D, e)$ from range-checked public note fields (no Merkle path and no root: the exit is bound to the leaf by its fields, which the vault compares with the stored note);
2. knowledge of $s$;
3. knowledge of the current state $(E(B), \tau_{\text{current}}, \sigma_{\text{current}})$;
4. validity of $\sigma_{\text{current}}$ on $(E(B), \tau_{\text{current}})$ bound to $L$;
5. knowledge of the opening of $E(B)$, so $B$ is the state balance with $B = B_{\text{final}} + c$ (no wrap) and $B \leq D$;
6. the note-bound nullifier $x_w = H(d_{\text{null}}, s, n, \tau_{\text{current}})$, with genesis iff $\tau = 1$ and the anchor chain $\tau = H(d_{\text{anchor}}, H(d_{\text{null}}, s, n, \tau_{\text{prev}}))$ for later states;
7. for escape, the successor nullifier $N^+ = H(d_{\text{null}}, s, n, H(d_{\text{anchor}}, x_w))$; for mutual close, $N^+ = 0$ and $c = 0$.

The anchor is derived, never random: $\tau_{k+1} = H(d_{\text{anchor}}, N_k)$. The withdrawal statement has 16 public inputs: protocol version, chain ID, deployment binding, registration, state key (x, y), clearance key (x, y), packed note fields $(n, D, e)$, $B_{\text{final}}$, destination binding, $x_w$, has-clearance, $N^+$, $c$, `valid_until`. There is no withdrawal tag. The user then has two close-out paths.

### Mutual Close (Instant Path)

1. The user sends only $x_w$ to the server.
2. The server checks whether $x_w$ is already in `spent_nullifiers`.
3. If it is clean, the server signs:

$$
\sigma_{\text{clear}}(x_w)
$$

and marks $x_w$ as spent in its nullifier set.

4. The user submits:

$$
(B_{\text{final}}, \text{Dest}, x_w, \pi_{\text{wd}}, \sigma_{\text{clear}})
$$

to the vault.

5. The vault verifies $\pi_{\text{wd}}$ and $\sigma_{\text{clear}}$, then immediately settles the note.

The server learns no balance or routing data from this clearance request; it only sees the nullifier $x_w$.

### Escape Hatch (Fallback Path)

If the server is offline or maliciously refuses to clear the withdrawal, the user submits the same payload without $\sigma_{\text{clear}}$, plus the successor nullifier $N^+$, the concession $c$, and a `valid_until` timestamp:

$$
(B_{\text{final}}, c, \text{Dest}, x_w, N^+, \text{valid\_until}, \pi_{\text{wd}})
$$

The proof is leaf-bound and root-free: it carries no Merkle path and the vault does not check any root, so no deposit can invalidate it. The vault verifies $\pi_{\text{wd}}$ and `now <= valid_until`, checks the note fields against the stored note, consumes $x_w$ and $N^+$, records the pending withdrawal, and starts the configured challenge window (24 hours in the deployment profile). The leaf stays in the tree.

If the withdrawal is neither defeated nor raised during that window, anyone finalizes it and the vault settles the note as in the mutual-close path. Exits are blocked only while the vault is effectively paused; the pause is bounded to `MAX_PAUSE_DURATION` (7 days) with a `PAUSE_COOLDOWN` of 1 day, `execute_claim_expired` is blocked while paused, and paused time extends each note's claimable time. `retire_closed_leaf` is the permissionless, `Closed`-only instruction that removes a closed leaf.

## Challenge Rule for Escape-Hatch Withdrawal

This prevents the user from withdrawing using an **old** state that still reflects a higher balance, without leaf removal, a second phase, or any root dependency.

Suppose the user escapes from state $S_k$ with nullifier $N_k = H(d_{\text{null}}, s, n, \tau_k)$. The proof also reveals the derived successor nullifier $N_{k+1} = H(d_{\text{null}}, s, n, H(d_{\text{anchor}}, N_k))$, which is the request nullifier of $S_{k+1}$. If the user already spent $S_{k+1}$ in a request, the operator holds that request proof.

During the challenge window the escape can be answered in two ways:

- **Defeat.** Anyone submits a valid request proof whose request nullifier equals the pending $N_{k+1}$. The pending payout is deleted, $N_k$ becomes `Challenged`, $N_{k+1}$ is released, the note stays `Active`, and the vault emits `EscapeWithdrawalDefeated`. Defeat needs no Merkle path and does not check the root, so a root-changing deposit cannot front-run it. There is no restore step: the leaf never left the tree.
- **Raise.** A request proof at the escaped nullifier $N_k$ whose owed charge exceeds the proven concession $c$ raises it to $c' = \min(\text{amount}, sb, B)$ with $c' > c$. The pending payout becomes $B - c'$, the deadline is unchanged, a later defeat is still possible, and the vault emits `EscapeConcessionRaised`.

After the deadline, `finalize_escape` is permissionless and pays the pending final balance to the destination and the rest of the deposit to the treasury. The destination is checked to be a writable, creditable account when the escape is initiated, so it can neither keep the note pending nor lock the operator share.

**Concession rule and guarantees.** The escape statement reveals a concession $c$ (the in-flight amount the user concedes) with $B = B_{\text{final}} + c$ and $B \leq D$. The client releases at most one bound $b_k$ per state. With that rule:

- **G1 (honest user).** For the newest installed state $S_k$, the user is paid at least $B_k - b_k$ with no operator cooperation. An operator that withholds the successor state, a depositor that front-runs the exit, or a pause cannot take the unspent balance.
- **G2 (honest operator).** Total paid out on a note is at most $D - \sum \text{owed}(\text{served requests})$. A user who received and spent $S_{k+1}$ cannot be paid from $S_k$: the evidence defeats the escape or raises the concession to what is owed.
- **G3 (privacy).** Requests remain unlinkable. New linkage appears only at exit, only for the exiting note, and only for its last request.

The request proof establishes authorization, not delivery of the successor state, so the server signs the successor only after the request nullifier is confirmed unused on-chain (settle-then-sign), and keeps request evidence in an append-only table for the challenger.

This is the clean replacement for RLN-style secret-recovery slashing in the simplified design.

## How the Server Gets Paid

Because honest off-chain requests are unlinkable, the vault cannot settle funds on a per-request basis. Instead, it pays the server in aggregate when the note closes.

On either the instant mutual-close path or a successful escape-hatch withdrawal, the withdrawal proof reveals the user's final balance $B_{\text{final}}$. The vault then performs net settlement:

$$
\text{payout to user} = B_{\text{final}}
$$

$$
\text{payout to server} = D - B_{\text{final}}
$$

and closes the note (the leaf is later removed by `retireClosedLeaf`).

This means the server is paid for the user's entire lifetime of API usage in one aggregated settlement transaction, including any optional policy deductions reflected in the final private balance.

To handle abandoned accounts, each note carries the expiry time $T_{\text{exp}}$. If the note is still open and no withdrawal is in progress when it expires, the server may call:

$$
\text{execute\_claim\_expired}(\text{noteId})
$$

The vault then closes the note and credits the full deposit $D$ to the server treasury $A_{\text{srv}}$. `execute_claim_expired` needs no Merkle path, is blocked while the vault is effectively paused, and is only allowed after the note's claimable time, which includes accumulated paused time and the post-defeat `claimable_after`.

This guarantees that the server is eventually paid even if the user disappears without withdrawing. An implementation may additionally offer a separate rollover / renewal transaction that extends $T_{\text{exp}}$, but that mechanism is orthogonal to the accounting model described here.

## Privacy Note

The current state anchor $\tau$ and the server signature $\sigma_{\text{srv}}$ should remain **private witnesses inside the ZK proof**, not public inputs.

This is important because it prevents the server from trivially correlating requests by directly observing the user's carried state.

In the mutual-close path, the server sees only the withdrawal nullifier $x_w$. The final balance and destination address are revealed only to the vault when the user actually closes the note.

The next anchor is derived from the request nullifier, $\tau_{\text{new}} = H(d_{\text{anchor}}, N)$, so the client and the vault can compute the successor nullifier without any server-supplied value. Server randomness stays only in the blinding delta.

## Extensions

This base design is **sequential**: one state authorizes one next request.

If parallelism is needed, it should be added as a separate extension, for example by allowing one state transition to mint multiple child anchors.

That should remain outside the base specification so the core design stays simple and easy to reason about.

## Summary

The simplified protocol replaces RLN's line-based nullifier construction with a one-time **state-anchor chain**.

Each request:
- consumes the current state,
- emits one nullifier,
- updates the private balance,
- yields a fresh server-signed next state.

This keeps the main properties we want in the single-server setting:
- anonymous prepaid access,
- unlinkable honest usage,
- replay prevention,
- net settlement at withdrawal or expiry,
- instant mutual close with an optimistic escape hatch,
- optional higher policy-penalty cap via $S_{\max}$.

At the same time, it substantially simplifies both the protocol logic and the proving interface.
