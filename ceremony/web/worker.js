// Runs the contribution off the page's main thread so the page stays responsive while snarkjs works.
// The same contributeZkey() the CLI uses; this file only carries messages.
import { contributeZkey } from "../lib/contribute-core.mjs";

self.onmessage = async ({ data }) => {
  const { id, zkey, name, entropyText } = data;
  try {
    const result = await contributeZkey({ zkey, name, entropyText, onProgress: (fraction) => self.postMessage({ id, type: "progress", fraction }) });
    self.postMessage({ id, type: "done", zkey: result.zkey, contributionHash: result.contributionHash });
  } catch (error) {
    self.postMessage({ id, type: "error", message: error instanceof Error ? error.message : String(error) });
  }
};
