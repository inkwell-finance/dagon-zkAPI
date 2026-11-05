import { sha256Hex } from "./hex.mjs";

export const ATTESTATION_DOMAIN = "dagon-zkapi-ceremony-v1";

/**
 * The short value a contributor posts publicly: sha256 over a fixed text listing the round this contribution created and
 * the blake2b-512 contribution hash snarkjs reports for each circuit, in ceremony.json order. Anyone can recompute it
 * from transcript.json.
 */
export function attestationText(round, circuits) {
  let text = `${ATTESTATION_DOMAIN}\nround:${round}\n`;
  for (const c of circuits) text += `${c.id}:${c.contributionHash}\n`;
  return text;
}

export function attestationHash(round, circuits) {
  return sha256Hex(new TextEncoder().encode(attestationText(round, circuits)));
}

/** A display name that is safe in a zkey (snarkjs stores 64 UTF-16 units), in transcript.json and in HTML. */
export function normalizeName(raw) {
  const name = String(raw ?? "").normalize("NFC").replace(/\s+/g, " ").trim();
  if (name === "") return "Anonymous";
  if (name.length > 64) throw new Error("the name can be at most 64 characters");
  if (!/^[\p{L}\p{M}\p{N}\p{P}\p{S} ]+$/u.test(name)) throw new Error("the name may only contain letters, digits, punctuation and spaces");
  return name;
}
