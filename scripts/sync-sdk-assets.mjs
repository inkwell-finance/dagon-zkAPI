// Regenerate (default) or verify (--check) the SDK's packaged artifacts:
// proving keys from protocol/setup/v2, the shared Solana profile and every
// network identity from solana/profile, and the hash manifest over them and
// the WASM build. The SDK never carries a hand-written copy of a profile value.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readPackagedSolanaProfile, verifyBrowserSdkAssets } from '../sdk/build.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const profileDir = path.join(root, 'solana/profile');
const configDir = path.join(root, 'sdk/assets/config');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const identityFiles = async directory => (await fs.readdir(directory))
    .filter(name => name.endsWith('.identity.json')).sort();
// Packaged config file -> its source of truth.
const configSources = async () => [
    ['profile.json', path.join(profileDir, 'shared.json')],
    ...(await identityFiles(profileDir)).map(name => [name, path.join(profileDir, name)])
];

if (process.argv.includes('--check')) {
    await verifyBrowserSdkAssets();
    const sources = await configSources();
    const packaged = (await fs.readdir(configDir)).sort();
    const expected = sources.map(([name]) => name).sort();
    if (JSON.stringify(packaged) !== JSON.stringify(expected)) {
        throw new Error(`sdk/assets/config has ${packaged.join(', ')}; solana/profile generates ${expected.join(', ')}. Run node scripts/sync-sdk-assets.mjs.`);
    }
    for (const [name, source] of sources) {
        if (digest(await fs.readFile(path.join(configDir, name))) !== digest(await fs.readFile(source))) {
            throw new Error(`sdk/assets/config/${name} differs from ${path.relative(root, source)}. Run node scripts/sync-sdk-assets.mjs.`);
        }
    }
    const manifest = JSON.parse(await fs.readFile(path.join(root, 'sdk/assets/manifest.json'), 'utf8'));
    const pinned = Object.keys(manifest.files).filter(relative => relative.startsWith('assets/config/')).sort();
    if (JSON.stringify(pinned) !== JSON.stringify(expected.map(name => `assets/config/${name}`))) {
        throw new Error('sdk/assets/manifest.json does not pin exactly the generated Solana configs.');
    }
    console.log('SDK public artifact hashes and Solana profile configs verified.');
} else {
    const manifestFile = path.join(root, 'sdk/assets/manifest.json');
    const manifest = JSON.parse(await fs.readFile(manifestFile, 'utf8'));
    const protocolRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: path.join(root, 'protocol'), encoding: 'utf8' }).trim();
    const setup = JSON.parse(await fs.readFile(path.join(root, 'protocol/setup/v2/manifest.json'), 'utf8'));
    const shared = JSON.parse(await fs.readFile(path.join(profileDir, 'shared.json'), 'utf8'));
    if (setup.circuit_id !== shared.protocol.circuit_id) {
        throw new Error(`protocol/setup/v2 proves ${setup.circuit_id}, but solana/profile/shared.json pins ${shared.protocol.circuit_id}.`);
    }
    for (const kind of ['request', 'withdrawal']) {
        await fs.copyFile(path.join(root, `protocol/setup/v2/${kind}.pk`), path.join(root, `sdk/assets/proofs/${kind}.pk`));
    }
    const sources = await configSources();
    await fs.mkdir(configDir, { recursive: true });
    for (const name of await fs.readdir(configDir)) {
        if (!sources.some(([packaged]) => packaged === name)) await fs.rm(path.join(configDir, name));
    }
    for (const [name, source] of sources) await fs.copyFile(source, path.join(configDir, name));
    await readPackagedSolanaProfile();
    const relatives = [
        'wasm/zkapi_browser.js',
        'wasm/zkapi_browser_bg.wasm',
        'assets/proofs/request.pk',
        'assets/proofs/withdrawal.pk',
        ...sources.map(([name]) => `assets/config/${name}`)
    ];
    manifest.files = {};
    for (const relative of relatives) {
        manifest.files[relative] = digest(await fs.readFile(path.join(root, 'sdk', relative)));
    }
    manifest.circuitId = setup.circuit_id;
    manifest.protocolRevision = protocolRevision;
    await fs.writeFile(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log('Updated SDK artifact provenance; review and commit the generated changes.');
}
