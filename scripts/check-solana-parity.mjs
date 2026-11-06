import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { parseArgs } from 'node:util';
const exec = promisify(execFile);
export const root = resolve(fileURLToPath(new URL('..', import.meta.url)));

export async function checkParity({ identityPath, rpcUrl, binDir = join(root, 'target/release'), mainnetRpcUrl = process.env.MAINNET_RPC_URL ?? 'https://api.mainnet-beta.solana.com', execute = exec, log = console.log }) {
  if (!identityPath || !rpcUrl) throw new Error('identityPath and rpcUrl are required');
  const dir = await mkdtemp(join(tmpdir(), 'dagon-parity-'));
  const binary = join(binDir, 'dagon-zkapi-deploy');
  try {
    const local = await execute(binary, ['observe', '--solana-identity', identityPath, '--solana-rpc-url', rpcUrl], { maxBuffer: 4 * 1024 * 1024, env: { ...process.env, MAINNET_RPC_URL: mainnetRpcUrl } });
    const reference = await execute(binary, ['expected', '--solana-identity', join(root, 'solana/profile/mainnet-beta.identity.json'), '--mainnet-rpc-url', mainnetRpcUrl], { maxBuffer: 4 * 1024 * 1024 });
    // Reject malformed output before passing it to the authoritative Rust diff.
    JSON.parse(local.stdout); JSON.parse(reference.stdout);
    await writeFile(join(dir, 'local.json'), local.stdout);
    await writeFile(join(dir, 'reference.json'), reference.stdout);
    const result = await execute(binary, ['diff', join(dir, 'local.json'), join(dir, 'reference.json')]);
    log(result.stdout.trim());
    return { local: JSON.parse(local.stdout), reference: JSON.parse(reference.stdout) };
  } finally { await rm(dir, { recursive: true, force: true }); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const { values } = parseArgs({ options: { 'solana-identity': { type: 'string' }, 'solana-rpc-url': { type: 'string' }, 'bin-dir': { type: 'string' }, 'mainnet-rpc-url': { type: 'string' } } });
  await checkParity({ identityPath: values['solana-identity'], rpcUrl: values['solana-rpc-url'], binDir: values['bin-dir'], mainnetRpcUrl: values['mainnet-rpc-url'] });
}
