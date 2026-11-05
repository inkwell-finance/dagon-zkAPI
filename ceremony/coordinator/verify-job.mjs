// Child process entry: verifies one zkey so the (CPU heavy, memory hungry) snarkjs work never stalls the HTTP server and
// an out-of-memory crash only fails that verification. Input: one JSON argument {r1cs, ptau, zkey}. Output: one JSON line.
import { terminateThreads, verifyZkey } from "../lib/snark.mjs";

const result = await verifyZkey(JSON.parse(process.argv[2]));
process.stdout.write(`${JSON.stringify(result)}\n`, async () => {
  await terminateThreads();
  process.exit(0);
});
