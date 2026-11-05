import table from "./hermez-ptau.json" with { type: "json" };

/**
 * The published blake2b-512 hash of the Hermez Perpetual Powers of Tau file for `power`, copied from the snarkjs README
 * table (see hermez-ptau.json). verify-ceremony checks ceremony.json against this independent list.
 * @returns {{file: string, hash: string, url: string} | undefined}
 */
export function hermezPin(power) {
  const entry = table.files[String(power)];
  return entry && { ...entry, url: `${table.urlBase}${entry.file}` };
}
