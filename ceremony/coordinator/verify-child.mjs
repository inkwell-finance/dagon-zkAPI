import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";

const JOB = fileURLToPath(new URL("./verify-job.mjs", import.meta.url));

/** Production verifier: one `node verify-job.mjs` per zkey, killed after `timeoutMs`. */
export function childVerifier({ timeoutMs = 30 * 60_000 } = {}) {
  return ({ r1cs, ptau, zkey }) =>
    new Promise((resolve) => {
      execFile(process.execPath, [JOB, JSON.stringify({ r1cs, ptau, zkey })], { timeout: timeoutMs, maxBuffer: 1 << 20, windowsHide: true }, (error, stdout, stderr) => {
        if (error) {
          resolve({ ok: false, errors: [`the verification process failed: ${error.killed ? "timed out" : error.message}${stderr ? ` (${stderr.trim().slice(-300)})` : ""}`] });
          return;
        }
        try {
          resolve(JSON.parse(stdout.trim().split("\n").pop()));
        } catch {
          resolve({ ok: false, errors: ["the verification process produced no result"] });
        }
      });
    });
}
