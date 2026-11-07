// Replay of Pyth's sponsored SOL/USD feed for the local parity stack.
//
// The server's price account (push-oracle shard 0) is kept updated by Pyth's
// sponsor on a 60 s heartbeat and on any 0.5% price move. Anyone may push the
// same account too (on 2026-11-06 a third party pushed it every ~10 s), but
// the sponsor's target policy is what the local account models (not a delivery
// guarantee). This module follows signed updates of the account as they land
// on mainnet and posts the newest one under that policy: once the local price
// is a heartbeat old, or when the newest
// price deviates by 0.5% from it. A posted update carries the same signed
// instructions as on mainnet: the guardian-signed VAA is written to a fresh
// encoded-VAA account and verified against the cloned guardian set
// (VerifyEncodedVaaV1, full verification), and UpdatePriceFeed posts the
// Merkle-proven SOL/USD message through the cloned push oracle and receiver.
// Nothing is fabricated or re-signed; only the fee payer and the temporary
// encoded-VAA account are local. `stall()` reproduces a sponsor outage.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, ComputeBudgetProgram, sendAndConfirmTransaction } from '@solana/web3.js';

const profile = JSON.parse(readFileSync(new URL('../../solana/profile/shared.json', import.meta.url), 'utf8'));
export const RECEIVER = profile.pyth.receiver_program;
export const PUSH = profile.pyth.push_oracle_program;
export const WORMHOLE = profile.pyth.wormhole_program;
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function decode58(text) {
  let n = 0n;
  for (const c of text) { const i = alphabet.indexOf(c); if (i < 0) throw new Error('invalid base58'); n = n * 58n + BigInt(i); }
  const bytes = [];
  while (n) { bytes.push(Number(n & 255n)); n >>= 8n; }
  for (const c of text) { if (c !== '1') break; bytes.push(0); }
  return Buffer.from(bytes.reverse());
}
const discriminator = name => createHash('sha256').update(`global:${name}`).digest().subarray(0, 8);

export async function rpc(url, method, params, signal) {
  for (let attempt = 0; ; attempt++) {
    const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: signal ?? AbortSignal.timeout(30_000) });
    if (response.status === 429 && attempt < 6) { await delay(Math.min(1000 * 2 ** attempt, 8000), undefined, { signal }); continue; }
    if (!response.ok) throw new Error(`${method}: HTTP ${response.status}`);
    const body = await response.json();
    if (body.error?.code === 429 && attempt < 6) { await delay(Math.min(1000 * 2 ** attempt, 8000), undefined, { signal }); continue; }
    if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
    return body.result;
  }
}

/** Feed, price and publish time of a Pyth PriceFeedMessage (big-endian wire format). */
function priceMessage(message) {
  if (message.length < 85 || message[0] !== 0) throw new Error('not a Pyth PriceFeedMessage');
  return { feedId: `0x${message.subarray(1, 33).toString('hex')}`, price: message.readBigInt64BE(33), publishTime: Number(message.readBigInt64BE(53)) };
}

// Pyth's push policy for sponsored feeds (https://docs.pyth.network/pro/sponsored-feeds).
export const SPONSOR_HEARTBEAT_SECONDS = 60;
export const SPONSOR_DEVIATION_BPS = 50;

/** Why Pyth's sponsor would replace the account's `current` price with `candidate` now, or null. */
export function sponsorPushReason(current, candidate, now) {
  if (candidate.publishTime <= current.publishTime) return null;
  if (now - current.publishTime >= SPONSOR_HEARTBEAT_SECONDS) return 'heartbeat';
  const moved = candidate.price > current.price ? candidate.price - current.price : current.price - candidate.price;
  const base = current.price < 0n ? -current.price : current.price;
  return moved * 10_000n >= BigInt(SPONSOR_DEVIATION_BPS) * base ? 'deviation' : null;
}

/** A transaction's instructions with resolved accounts, signer and writable flags. */
function resolvedInstructions(tx) {
  const m = tx.transaction.message;
  const keys = [...m.accountKeys, ...(tx.meta.loadedAddresses?.writable ?? []), ...(tx.meta.loadedAddresses?.readonly ?? [])];
  const h = m.header;
  const writable = index => index < h.numRequiredSignatures ? index < h.numRequiredSignatures - h.numReadonlySignedAccounts : index < m.accountKeys.length ? index < m.accountKeys.length - h.numReadonlyUnsignedAccounts : index < m.accountKeys.length + (tx.meta.loadedAddresses?.writable.length ?? 0);
  return m.instructions.map(i => ({ programId: keys[i.programIdIndex], data: decode58(i.data), keys: i.accounts.map(index => ({ pubkey: keys[index], isSigner: index < h.numRequiredSignatures, isWritable: writable(index) })) }));
}
const is = (ix, program, name) => ix.programId === program && ix.data.subarray(0, 8).equals(discriminator(name));

/** The UpdatePriceFeed of the account in `tx`, if any. */
function priceUpdate(tx, priceAccount) {
  if (!tx || tx.meta?.err) return null;
  return resolvedInstructions(tx).find(ix => is(ix, PUSH, 'update_price_feed') && ix.keys[5]?.pubkey === priceAccount) ?? null;
}

/**
 * A fully verified mainnet push of the account as replayable instructions:
 * create + init + write of the encoded VAA, its guardian verification, the
 * UpdatePriceFeed in `tx` and, if present, the close. Pushers either do this in
 * one transaction or split it; `earlier` holds the encoded-VAA account's
 * preceding transactions of a split push.
 */
export function replayPlan(tx, priceAccount, earlier = []) {
  const update = priceUpdate(tx, priceAccount);
  if (!update || earlier.some(t => t.meta?.err)) return null;
  const encoded = update.keys[2].pubkey;
  const ixs = [...earlier.flatMap(resolvedInstructions), ...resolvedInstructions(tx)].filter(ix => ix.keys.some(k => k.pubkey === encoded));
  const create = ixs.find(ix => ix.programId === '11111111111111111111111111111111' && ix.keys[1]?.pubkey === encoded && ix.data.readUInt32LE(0) === 0);
  const init = ixs.find(ix => is(ix, WORMHOLE, 'init_encoded_vaa'));
  const writes = ixs.filter(ix => is(ix, WORMHOLE, 'write_encoded_vaa'));
  const verify = ixs.find(ix => is(ix, WORMHOLE, 'verify_encoded_vaa_v1'));
  const close = ixs.find(ix => is(ix, WORMHOLE, 'close_encoded_vaa'));
  if (!create || !init || !writes.length || !verify) return null;
  if (init.keys[1].pubkey !== encoded || writes.some(ix => ix.keys[1].pubkey !== encoded) || verify.keys[1].pubkey !== encoded) return null;
  // UpdatePriceFeed(PostUpdateParams { MerklePriceUpdate { message, .. }, .. }, ..), Borsh.
  const messageLength = update.data.readUInt32LE(8);
  const message = priceMessage(update.data.subarray(12, 12 + messageLength));
  if (message.feedId !== profile.pyth.feed_id) return null;
  return {
    signature: tx.transaction.signatures[0], publishTime: message.publishTime, price: message.price, encoded,
    payer: tx.transaction.message.accountKeys[0], config: update.keys[3].pubkey, guardian: verify.keys[2].pubkey,
    instructions: [create, init, ...writes, verify, update, ...(close ? [close] : [])],
  };
}

export async function latestPlan(url, priceAccount, seen = new Set(), signal) {
  // Intersect address histories before fetching transactions: price-account
  // readers vastly outnumber updates and public RPC rate-limits getTransaction.
  const signatures = await rpc(url, 'getSignaturesForAddress', [priceAccount, { limit: 1000, commitment: 'confirmed' }], signal);
  const pushes = await rpc(url, 'getSignaturesForAddress', [PUSH, { limit: 100, commitment: 'confirmed' }], signal);
  const pushSignatures = new Set(pushes.filter(item => !item.err).map(item => item.signature));
  const transaction = signature => rpc(url, 'getTransaction', [signature, { encoding: 'json', maxSupportedTransactionVersion: 1, commitment: 'confirmed' }], signal);
  for (const item of signatures) {
    if (item.err || !pushSignatures.has(item.signature)) continue;
    // Once the newest usable update was posted, never walk backwards through
    // old VAAs. Wait for a new mainnet update rather than replaying stale data.
    if (seen.has(item.signature)) return null;
    const tx = await transaction(item.signature);
    let plan = replayPlan(tx, priceAccount);
    const update = !plan && priceUpdate(tx, priceAccount);
    if (update) {
      // A split push: collect the encoded VAA's earlier transactions, back to its creation.
      const history = await rpc(url, 'getSignaturesForAddress', [update.keys[2].pubkey, { limit: 10, commitment: 'confirmed' }], signal);
      const earlier = [];
      for (const entry of history.slice(history.findIndex(h => h.signature === item.signature) + 1)) {
        const previous = await transaction(entry.signature);
        earlier.unshift(previous);
        if (resolvedInstructions(previous).some(ix => is(ix, WORMHOLE, 'init_encoded_vaa'))) break;
      }
      plan = replayPlan(tx, priceAccount, earlier);
    }
    if (plan) { seen.add(item.signature); return plan; }
    await delay(250, undefined, { signal });
  }
  return null;
}

/** Post one mainnet update locally: the same instructions with a local payer and encoded-VAA account. */
export async function replay(connection, payer, plan) {
  const encoded = Keypair.generate();
  const remap = key => key === plan.payer ? payer.publicKey : key === plan.encoded ? encoded.publicKey : new PublicKey(key);
  const ixs = plan.instructions.map(i => new TransactionInstruction({ programId: new PublicKey(i.programId), data: i.data, keys: i.keys.map(k => ({ ...k, pubkey: remap(k.pubkey) })) }));
  // Account creation is local funding, not oracle data. Mainnet creates and
  // closes the temporary VAA within one transaction. Splitting it across
  // legacy packets requires local rent exemption at the intermediate boundary.
  const space = Number(ixs[0].data.readBigUInt64LE(12));
  ixs[0] = SystemProgram.createAccount({
    fromPubkey: payer.publicKey, newAccountPubkey: encoded.publicKey,
    space, lamports: await connection.getMinimumBalanceForRentExemption(space),
    programId: new PublicKey(WORMHOLE),
  });
  // Legacy packets are capped at 1232 bytes, unlike current mainnet v1 packets.
  // Preserve ordering and state across packets, including verification before use.
  const batches = [];
  let batch = [];
  const size = items => {
    const tx = new Transaction({ feePayer: payer.publicKey, recentBlockhash: '11111111111111111111111111111111' }).add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ...items);
    try { return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).length; } catch { return Infinity; }
  };
  for (const ix of ixs) {
    if (size([...batch, ix]) > 1232) { if (!batch.length) throw new Error('single mainnet instruction exceeds legacy packet limit'); batches.push(batch); batch = []; }
    batch.push(ix);
    if (size(batch) > 1232) throw new Error('single mainnet instruction exceeds legacy packet limit');
  }
  if (batch.length) batches.push(batch);
  for (const items of batches) {
    const signers = items.some(i => i.keys.some(k => k.isSigner && k.pubkey.equals(encoded.publicKey))) ? [payer, encoded] : [payer];
    // A single local validator occasionally rejects a just-fetched blockhash in
    // preflight; nothing executed, so resend the packet with a fresh one.
    for (let attempt = 1; ; attempt++) {
      try {
        await sendAndConfirmTransaction(connection, new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ...items), signers, { commitment: 'confirmed', preflightCommitment: 'confirmed' });
        break;
      } catch (error) {
        if (attempt >= 3 || !/Blockhash not found/.test(error.message)) throw error;
        await delay(1000);
      }
    }
  }
}

/** Publish time, price and finality of the price account at `commitment`; it must be a fully verified PriceUpdateV2. */
export async function priceFreshness(url, priceAccount, commitment = 'finalized') {
  const account = await rpc(url, 'getAccountInfo', [priceAccount, { encoding: 'base64', commitment }]);
  if (account.value?.owner !== RECEIVER) throw new Error('Pyth price owner mismatch');
  const data = Buffer.from(account.value.data[0], 'base64');
  const expectedDiscriminator = createHash('sha256').update('account:PriceUpdateV2').digest().subarray(0, 8);
  if (data.length !== 134 || !data.subarray(0, 8).equals(expectedDiscriminator) || data[40] !== 1) throw new Error('Pyth update is not fully verified PriceUpdateV2');
  const price = data.readBigInt64LE(73);
  const publishTime = Number(data.readBigInt64LE(93));
  const postedSlot = Number(data.readBigUInt64LE(125));
  return { publishTime, price, postedSlot, finalized: postedSlot <= account.context.slot, age: Math.floor(Date.now() / 1000) - publishTime };
}

/**
 * Act as Pyth's sponsor over the real mainnet updates: follow every signed
 * update of the account as it lands on mainnet, and post the newest one locally
 * when `sponsorPushReason` says the sponsor would. A failed mainnet read is
 * retried; a failed local read or post is fatal (`onFailure`). While stalled
 * nothing is posted, as when the sponsor stops; after `resume()` the heartbeat
 * posts the newest update at once, as a recovering sponsor would.
 */
export function startReplay({ mainnetUrl, rpcUrl, priceAccount, payer, log = () => {}, onFailure = () => {}, signal }) {
  const connection = new Connection(rpcUrl, 'confirmed');
  const seen = new Set();
  let stalled = false; let posting = null; let candidate = null; let mainnetUpdates = 0; let updatesPosted = 0; let last = null;
  const status = () => ({ stalled, heartbeat_seconds: SPONSOR_HEARTBEAT_SECONDS, deviation_bps: SPONSOR_DEVIATION_BPS,
    mainnet_updates_seen: mainnetUpdates, updates_posted: updatesPosted, last_mainnet_tx: last?.signature ?? null,
    last_publish_time: last?.publishTime ?? null, last_reason: last?.reason ?? null });
  const task = (async () => {
    while (!signal.aborted) {
      const started = Date.now();
      try {
        const plan = await latestPlan(mainnetUrl, priceAccount, seen, signal);
        if (plan && (!candidate || plan.publishTime > candidate.publishTime)) { candidate = plan; mainnetUpdates += 1; }
      } catch (error) {
        if (signal.aborted) break;
        log(`Pyth replay: mainnet read failed, retrying: ${error.message}`);
      }
      if (!stalled && candidate) {
        const current = await priceFreshness(rpcUrl, priceAccount, 'confirmed');
        const reason = sponsorPushReason(current, candidate, Math.floor(Date.now() / 1000));
        if (candidate.publishTime <= current.publishTime) candidate = null;
        // No await between this check and `posting`: a stall() during the read wins.
        else if (reason && !stalled) {
          const plan = candidate;
          posting = replay(connection, payer, plan);
          try { await posting; } finally { posting = null; }
          candidate = null; updatesPosted += 1; last = { ...plan, reason };
          log(`Pyth replay posted (${reason}) mainnet_tx=${plan.signature} publish_time=${plan.publishTime}, replacing a price ${Math.floor(Date.now() / 1000) - current.publishTime} s old`);
        }
      }
      if (seen.size > 1000) { const keep = [...seen].slice(-500); seen.clear(); for (const sig of keep) seen.add(sig); }
      await delay(Math.max(0, 2000 - (Date.now() - started)), undefined, { signal }).catch(() => {});
    }
  })().catch(error => { if (!signal.aborted) onFailure(error); });
  return {
    /** Stop posting; resolves once no replayed update is in flight. */
    async stall() { stalled = true; await posting?.catch(() => {}); log('Pyth replay stalled'); return status(); },
    resume() { stalled = false; log('Pyth replay resumed'); return status(); },
    status,
    done: task,
  };
}
