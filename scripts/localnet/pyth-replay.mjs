// Recorded Hermes for the local parity stack. Hermes needs an API key that a
// local test run may not have, so this module rebuilds Hermes'
// `/v2/updates/price/latest` response from the signed update that mainnet's
// own push-oracle transactions carried: the guardian-signed VAA (from its
// WriteEncodedVaa chunks) and the SOL/USD message plus Merkle proof (from its
// UpdatePriceFeed). The bytes are re-encoded exactly as Hermes serves them
// (a PNAU accumulator update), so the operator pusher runs its production code
// path against real signed data and posts it through the cloned Wormhole,
// receiver and push-oracle programs. Nothing is fabricated or re-signed.
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';

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
const isInstruction = (ix, name) => decode58(ix.data).subarray(0, 8).equals(discriminator(name));

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

/** The SOL/USD PriceFeedMessage fields (big-endian Pyth wire format). */
export function decodePriceMessage(message) {
  if (message.length < 85 || message[0] !== 0) throw new Error('not a Pyth PriceFeedMessage');
  return {
    feedId: message.subarray(1, 33).toString('hex'), price: message.readBigInt64BE(33), conf: message.readBigUInt64BE(41),
    expo: message.readInt32BE(49), publishTime: Number(message.readBigInt64BE(53)), prevPublishTime: Number(message.readBigInt64BE(61)),
    emaPrice: message.readBigInt64BE(69), emaConf: message.readBigUInt64BE(77),
  };
}

/** Hermes' binary update: PNAU v1.0, no trailing header, WormholeMerkle proof, one price update. */
export function accumulatorUpdate(vaa, message, proof) {
  const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
  if (vaa.length > 0xffff || message.length > 0xffff || proof.length > 0xff) throw new Error('update too large for the PNAU wire format');
  return Buffer.concat([Buffer.from('PNAU'), Buffer.from([1, 0, 0, 0]), u16(vaa.length), vaa, Buffer.from([1]), u16(message.length), message, Buffer.from([proof.length]), ...proof]);
}

/** A self-contained, fully verified mainnet push of the account, as the recorded Hermes update it carried. */
export function replayPlan(tx, priceAccount) {
  if (!tx || tx.meta?.err) return null;
  const m = tx.transaction.message;
  const keys = [...m.accountKeys, ...(tx.meta.loadedAddresses?.writable ?? []), ...(tx.meta.loadedAddresses?.readonly ?? [])];
  const ixs = m.instructions;
  const update = ixs.find(i => keys[i.programIdIndex] === PUSH && isInstruction(i, 'update_price_feed') && keys[i.accounts[5]] === priceAccount);
  if (!update) return null;
  const wormhole = ixs.filter(i => keys[i.programIdIndex] === WORMHOLE);
  const init = wormhole.find(i => isInstruction(i, 'init_encoded_vaa'));
  const writes = wormhole.filter(i => isInstruction(i, 'write_encoded_vaa'));
  const verify = wormhole.find(i => isInstruction(i, 'verify_encoded_vaa_v1'));
  const close = wormhole.find(i => isInstruction(i, 'close_encoded_vaa'));
  const encoded = init && keys[init.accounts[1]];
  const create = ixs.find(i => keys[i.programIdIndex] === '11111111111111111111111111111111' && keys[i.accounts[1]] === encoded && decode58(i.data).readUInt32LE(0) === 0);
  if (!init || !writes.length || !verify || !close || !create) return null;
  if (writes.some(i => keys[i.accounts[1]] !== encoded) || keys[verify.accounts[1]] !== encoded || keys[update.accounts[2]] !== encoded) return null;
  // The VAA occupies the encoded account after its 46-byte header.
  const vaa = Buffer.alloc(Number(decode58(create.data).readBigUInt64LE(12)) - 46);
  let written = 0;
  for (const write of writes) {
    const data = decode58(write.data);
    const index = data.readUInt32LE(8); const length = data.readUInt32LE(12);
    if (16 + length !== data.length || index + length > vaa.length) return null;
    data.copy(vaa, index, 16); written += length;
  }
  if (written !== vaa.length) return null;
  // UpdatePriceFeed(PostUpdateParams { MerklePriceUpdate { message, proof }, treasury_id }, shard_id, feed_id), Borsh.
  const data = decode58(update.data);
  let offset = 8;
  const messageLength = data.readUInt32LE(offset); offset += 4;
  const message = data.subarray(offset, offset + messageLength); offset += messageLength;
  const proofLength = data.readUInt32LE(offset); offset += 4;
  const proof = Array.from({ length: proofLength }, (_, i) => data.subarray(offset + 20 * i, offset + 20 * (i + 1))); offset += 20 * proofLength;
  if (offset + 1 + 2 + 32 !== data.length) return null;
  const decoded = decodePriceMessage(message);
  if (`0x${decoded.feedId}` !== profile.pyth.feed_id) return null;
  return {
    signature: tx.transaction.signatures[0], publishTime: decoded.publishTime, message: decoded,
    config: keys[update.accounts[3]], treasury: keys[update.accounts[4]], guardian: keys[verify.accounts[2]],
    binary: accumulatorUpdate(vaa, message, proof),
  };
}

export async function latestPlan(url, priceAccount, seen = new Set(), signal) {
  // Intersect address histories before fetching transactions: price-account
  // readers vastly outnumber updates and public RPC rate-limits getTransaction.
  const signatures = await rpc(url, 'getSignaturesForAddress', [priceAccount, { limit: 1000, commitment: 'confirmed' }], signal);
  const pushes = await rpc(url, 'getSignaturesForAddress', [PUSH, { limit: 100, commitment: 'confirmed' }], signal);
  const pushSignatures = new Set(pushes.filter(item => !item.err).map(item => item.signature));
  for (const item of signatures) {
    if (item.err || !pushSignatures.has(item.signature)) continue;
    // Once the newest usable update was recorded, never walk backwards through
    // old VAAs. Wait for a new mainnet update rather than serving stale data.
    if (seen.has(item.signature)) return null;
    const tx = await rpc(url, 'getTransaction', [item.signature, { encoding: 'json', maxSupportedTransactionVersion: 1, commitment: 'confirmed' }], signal);
    const plan = replayPlan(tx, priceAccount);
    if (plan) { seen.add(item.signature); return plan; }
    await delay(250, undefined, { signal });
  }
  return null;
}

export async function priceFreshness(url, priceAccount) {
  const account = await rpc(url, 'getAccountInfo', [priceAccount, { encoding: 'base64', commitment: 'finalized' }]);
  if (account.value?.owner !== RECEIVER) throw new Error('Pyth price owner mismatch');
  const data = Buffer.from(account.value.data[0], 'base64');
  const expectedDiscriminator = createHash('sha256').update('account:PriceUpdateV2').digest().subarray(0, 8);
  if (data.length !== 134 || !data.subarray(0, 8).equals(expectedDiscriminator) || data[40] !== 1) throw new Error('Pyth update is not fully verified PriceUpdateV2');
  const publishTime = Number(data.readBigInt64LE(93));
  const postedSlot = Number(data.readBigUInt64LE(125));
  return { publishTime, postedSlot, finalized: postedSlot <= account.context.slot, age: Math.floor(Date.now() / 1000) - publishTime };
}

/** Hermes' `/v2/updates/price/latest` JSON for one recorded update. */
export function hermesResponse(plan, encoding = 'base64') {
  const m = plan.message;
  const price = (value, conf) => ({ price: String(value), conf: String(conf), expo: m.expo, publish_time: m.publishTime });
  return {
    binary: { encoding, data: [plan.binary.toString(encoding)] },
    parsed: [{ id: m.feedId, price: price(m.price, m.conf), ema_price: price(m.emaPrice, m.emaConf),
      metadata: { prev_publish_time: m.prevPublishTime } }],
  };
}

/**
 * Serve the newest recorded mainnet update with Hermes' route, query and
 * Bearer API-key contract; record new mainnet updates as they appear.
 */
export async function startHermesReplay({ mainnetUrl, priceAccount, apiKey, initialPlan, log = () => {}, signal }) {
  if (!apiKey) throw new Error('apiKey is required: Hermes refuses unauthenticated requests');
  let latest = initialPlan ?? null;
  const seen = new Set(latest ? [latest.signature] : []);
  const expected = Buffer.from(`Bearer ${apiKey}`);
  const feed = profile.pyth.feed_id.slice(2);
  const server = createServer((request, response) => {
    const send = (status, body) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(body)); };
    const url = new URL(request.url, 'http://hermes.local');
    const auth = Buffer.from(request.headers.authorization ?? '');
    if (auth.length !== expected.length || !timingSafeEqual(auth, expected)) return send(401, { message: 'missing or invalid API key' });
    if (request.method !== 'GET' || url.pathname !== '/v2/updates/price/latest') return send(404, { message: 'not found' });
    const ids = url.searchParams.getAll('ids[]').map(id => id.toLowerCase().replace(/^0x/, ''));
    if (ids.length !== 1 || ids[0] !== feed) return send(404, { message: 'price ids not found' });
    const encoding = url.searchParams.get('encoding') ?? 'hex';
    if (!['hex', 'base64'].includes(encoding)) return send(400, { message: 'invalid encoding' });
    if (!latest) return send(503, { message: 'no recorded update yet' });
    send(200, hermesResponse(latest, encoding));
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const poller = (async () => {
    while (!signal?.aborted) {
      try {
        const plan = await latestPlan(mainnetUrl, priceAccount, seen, signal);
        if (plan) { latest = plan; log(`Recorded Hermes update from mainnet_tx=${plan.signature} publish_time=${plan.publishTime}`); }
      } catch (error) {
        if (signal?.aborted) break;
        log(`Recorded Hermes: mainnet read failed, retrying: ${error.message}`);
      }
      if (seen.size > 1000) { const keep = [...seen].slice(-500); seen.clear(); for (const sig of keep) seen.add(sig); }
      await delay(2000, undefined, { signal }).catch(() => {});
    }
  })();
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    latest: () => latest,
    async stop() { server.close(); server.closeAllConnections?.(); await poller; },
  };
}
