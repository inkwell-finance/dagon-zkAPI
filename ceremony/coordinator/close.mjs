import { readFile } from "node:fs/promises";
import { loadConfig } from "../lib/config.mjs";
import { hashFile, writeJsonAtomic } from "../lib/files.mjs";
import { Store } from "./store.mjs";

/** Run with the coordinator stopped; publish the returned checkpoint independently before beacon availability. */
export async function closeCeremony({ dataDir, now = Date.now }) {
  const store = new Store(dataDir);
  const config = await loadConfig(store.path("ceremony.json"));
  if (await store.isClosed()) return JSON.parse(await readFile(store.path("closed.json"), "utf8"));
  if (!config.beacon || now() >= Date.parse(config.beacon.applyAfter)) throw new Error("closure must be recorded and published before beacon availability");
  const tip = await store.latest();
  if (!tip || tip.kind !== "contribution") throw new Error("closure requires an accepted contribution");
  const checkpoint = { version: 1, time: new Date(now()).toISOString(), ceremonySha256: await hashFile(store.path("ceremony.json")), round: tip.round, attestation: tip.attestation, circuits: Object.fromEntries(config.circuits.map((c) => [c.id, tip.circuits[c.id].sha256])) };
  await writeJsonAtomic(store.path("closed.json"), checkpoint);
  return checkpoint;
}
