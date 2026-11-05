// Upload body of PUT /api/contribution: "DZC1" | u32 big-endian metaLength | meta JSON (UTF-8) | zkey bytes of every
// circuit, back to back, in the order of meta.circuits. One request carries all circuits so a contribution is either
// accepted for every circuit or for none.

export const BUNDLE_MAGIC = "DZC1";
export const MAX_META_BYTES = 16 * 1024;

export function encodeBundle(meta, zkeys) {
  const json = new TextEncoder().encode(JSON.stringify(meta));
  const head = new Uint8Array(8 + json.length);
  head.set(new TextEncoder().encode(BUNDLE_MAGIC), 0);
  new DataView(head.buffer).setUint32(4, json.length);
  head.set(json, 8);
  return new Blob([head, ...zkeys]);
}
