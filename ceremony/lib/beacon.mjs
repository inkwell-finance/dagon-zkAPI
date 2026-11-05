import { createHash } from "node:crypto";

// Public randomness for the final contribution. The source is committed in ceremony.json before the ceremony closes:
//   { "source": "drand",   "round": N,  "chain": "<hash>", "applyAfter": "<ISO UTC>" }
//   { "source": "bitcoin", "height": H,                    "applyAfter": "<ISO UTC>" }
// Every value is fetched from TWO independent public services and must agree; otherwise nothing is applied.

export const DRAND_DEFAULT_CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"; // quicknet, 3 s period
export const DRAND_RELAYS = ["https://api.drand.sh", "https://api2.drand.sh"];
export const BITCOIN_APIS = ["https://blockstream.info/api", "https://mempool.space/api"];
export const BITCOIN_CONFIRMATIONS = 6;

export const DEFAULT_ITERATIONS_EXP = 20;

async function getJson(fetcher, url) {
  const response = await fetcher(url);
  if (!response.ok) throw new Error(`GET ${url}: HTTP ${response.status}`);
  return response.json();
}

async function getText(fetcher, url) {
  const response = await fetcher(url);
  if (!response.ok) throw new Error(`GET ${url}: HTTP ${response.status}`);
  return (await response.text()).trim();
}

function requireAgreement(observations, what) {
  const values = new Set(observations.map((o) => o.value));
  if (values.size !== 1) {
    throw new Error(`${what}: the sources disagree: ${observations.map((o) => `${o.url} -> ${o.value}`).join("; ")}`);
  }
}

async function drandValue(spec, { fetch: fetcher, relays = DRAND_RELAYS }) {
  const chain = spec.chain ?? DRAND_DEFAULT_CHAIN;
  const observations = [];
  for (const relay of relays) {
    const url = `${relay}/${chain}/public/${spec.round}`;
    const body = await getJson(fetcher, url);
    if (body.round !== spec.round) throw new Error(`${url}: answered round ${body.round}`);
    const expected = createHash("sha256").update(Buffer.from(body.signature, "hex")).digest("hex");
    if (body.randomness !== expected) throw new Error(`${url}: randomness is not sha256(signature)`);
    observations.push({ url, value: body.randomness });
  }
  requireAgreement(observations, `drand round ${spec.round}`);
  return { value: observations[0].value, description: `drand chain ${chain} round ${spec.round}`, urls: observations.map((o) => o.url) };
}

async function bitcoinValue(spec, { fetch: fetcher, apis = BITCOIN_APIS }) {
  const observations = [];
  for (const api of apis) {
    const tip = Number(await getText(fetcher, `${api}/blocks/tip/height`));
    if (!(tip >= spec.height + BITCOIN_CONFIRMATIONS)) {
      throw new Error(`${api}: block ${spec.height} has ${Math.max(0, tip - spec.height + 1)} confirmations, ${BITCOIN_CONFIRMATIONS} required`);
    }
    const url = `${api}/block-height/${spec.height}`;
    const hash = (await getText(fetcher, url)).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${url}: not a block hash`);
    observations.push({ url, value: hash });
  }
  requireAgreement(observations, `bitcoin block ${spec.height}`);
  return { value: observations[0].value, description: `bitcoin block ${spec.height}`, urls: observations.map((o) => o.url) };
}

/**
 * @returns {Promise<{value: string, description: string, urls: string[], iterationsExp: number}>}
 * `value` is lowercase hex, the exact string handed to `snarkjs zkey beacon`.
 */
export async function fetchBeacon(spec, { fetch: fetcher = fetch, now = Date.now, relays, apis } = {}) {
  if (now() < Date.parse(spec.applyAfter)) throw new Error(`the beacon may not be applied before ${spec.applyAfter}`);
  const fetched = spec.source === "drand" ? await drandValue(spec, { fetch: fetcher, relays }) : await bitcoinValue(spec, { fetch: fetcher, apis });
  return { ...fetched, iterationsExp: spec.iterationsExp ?? DEFAULT_ITERATIONS_EXP };
}
