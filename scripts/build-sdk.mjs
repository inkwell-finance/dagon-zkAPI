// Build one Solana deployment's browser SDK assets:
//   node scripts/build-sdk.mjs --identity <network|identity.json> --deployment <deployment.json>
//       [--out-dir DIR] [--public-path /zkapi/] [--deployment-api-proxy-path /zkapi-deployment/]
// Shared parameters come from the packaged copy of solana/profile/shared.json;
// an undeployed identity (null accounts) is refused.
import fs from 'node:fs/promises';
import path from 'node:path';
import { build } from 'esbuild';
import { buildBrowserSdkAssets } from '../sdk/build.mjs';

const args = process.argv.slice(2);
const known = ['--identity', '--deployment', '--out-dir', '--public-path', '--deployment-api-proxy-path'];
for (let index = 0; index < args.length; index += 2) {
    if (!known.includes(args[index]) || args[index + 1] === undefined) {
        throw new Error(`Usage: build-sdk.mjs ${known.map(flag => `${flag} VALUE`).join(' ')} (unexpected ${args[index]}).`);
    }
}
const option = name => args.includes(name) ? args[args.indexOf(name) + 1] : null;
const identityArgument = option('--identity');
const deploymentFile = option('--deployment');
if (!identityArgument || !deploymentFile) {
    throw new Error('Both --identity <network|identity.json> and --deployment <deployment.json> are required.');
}
const identity = identityArgument.endsWith('.json')
    ? JSON.parse(await fs.readFile(path.resolve(identityArgument), 'utf8'))
    : identityArgument;
const deployment = JSON.parse(await fs.readFile(path.resolve(deploymentFile), 'utf8'));
const network = typeof identity === 'string' ? identity : identity.network;
const result = await buildBrowserSdkAssets({
    outDir: path.resolve(option('--out-dir') || `dist/sdk-${network}`),
    identity,
    deployment,
    publicPath: option('--public-path') || '/zkapi/',
    deploymentApiProxyPath: option('--deployment-api-proxy-path'),
    build
});
console.log(`Built ${result.manifest.deploymentId} zkAPI SDK assets: ${result.directory}`);
