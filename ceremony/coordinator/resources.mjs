import { totalmem } from "node:os";

// Full-size verification measured ~1.47 GiB RSS on Windows/Node 26. Reserve headroom for
// the coordinator, native FFT/curve buffers, and the Node 24 container; this is not an OS hard limit.
export const MIN_MEMORY_BYTES = 4 * 1024 ** 3;
export function requireMemory({ limit = process.constrainedMemory() || totalmem() } = {}) {
  if (limit < MIN_MEMORY_BYTES) throw new Error(`ceremony requires at least 4 GiB memory; detected ${limit} bytes. Benchmark the production image/cgroup before invitations.`);
  return limit;
}
