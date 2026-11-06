import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import { PublicKey } from '@solana/web3.js';
import { readPackagedSolanaIdentity, readPackagedSolanaProfile, resolveSolanaIdentity, solanaBrowserConfig,
    solanaChainId, solanaDeploymentBinding } from '../build.mjs';

const fixture = async name => JSON.parse(await fs.readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
const bytes = hex => Uint8Array.from(hex.slice(2).match(/../g), pair => parseInt(pair, 16));

test('chain ID and deployment binding match the zkapi-types Solana vectors', async () => {
    const text = await fs.readFile(new URL('../../protocol/test-vectors/solana-bindings.json', import.meta.url), 'utf8');
    const vector = JSON.parse(text);
    // chain_id exceeds 2^53: read it exactly from the source text.
    const chainId = text.match(/"chain_id":\s*(\d+)/)[1];
    assert.equal(solanaChainId(bytes(vector.genesis_hash)), chainId);
    assert.equal(solanaDeploymentBinding(bytes(vector.program_id), bytes(vector.vault_state), bytes(vector.genesis_hash)),
        vector.deployment_binding);
});

test('the browser trust anchor takes every shared value from the profile and identity values from the identity', async () => {
    const profile = await readPackagedSolanaProfile();
    const identity = await fixture('localnet.identity.json');
    const deployment = await fixture('localnet.deployment.json');
    const config = await solanaBrowserConfig({ identity, deployment });
    const trusted = config.trusted_deployment;
    assert.equal(trusted.program_id, profile.program.program_id);
    assert.equal(trusted.circuit_id, profile.protocol.circuit_id);
    assert.equal(trusted.request_charge_cap, profile.vault.request_charge_cap);
    assert.equal(trusted.note_ttl_seconds, profile.vault.note_ttl_seconds);
    assert.equal(trusted.pyth_receiver_program, profile.pyth.receiver_program);
    assert.equal(trusted.pyth_feed_id, profile.pyth.feed_id);
    assert.equal(trusted.pyth_max_age_seconds, profile.pyth.max_age_seconds);
    assert.equal(trusted.pyth_max_confidence_bps, profile.pyth.max_confidence_bps);
    for (const field of ['network', 'genesis_hash', 'vault_state', 'pyth_price_account']) {
        assert.equal(trusted[field], identity[field], field);
    }
    const genesis = new PublicKey(identity.genesis_hash).toBytes();
    assert.equal(trusted.chain_id, solanaChainId(genesis));
    assert.equal(trusted.contract_address, solanaDeploymentBinding(new PublicKey(profile.program.program_id).toBytes(),
        new PublicKey(identity.vault_state).toBytes(), genesis));
    assert.equal(trusted.deployment_id, `dagon-localnet-${identity.vault_state}`);
    assert.equal(trusted.verifier_url, null);
    assert.equal(config.require_oa_key_source, false);
    const verified = await solanaBrowserConfig({ identity,
        deployment: { ...deployment, oa_verifier_url: 'https://verifier.example/' } });
    assert.equal(verified.trusted_deployment.verifier_url, 'https://verifier.example');
    assert.equal(verified.require_oa_key_source, true);
});

test('identities are validated exactly like the operator binaries and undeployed ones are refused', async () => {
    const profile = await readPackagedSolanaProfile();
    const identity = await fixture('localnet.identity.json');
    assert.equal(resolveSolanaIdentity(identity, profile).walletStandardChain, 'solana:localnet');
    const mainnet = await readPackagedSolanaIdentity('mainnet-beta');
    assert.throws(() => resolveSolanaIdentity(mainnet, profile), /mainnet-beta identity has no vault_authority \(undeployed\)/);
    assert.throws(() => resolveSolanaIdentity({ ...identity, extra: 1 }, profile), /unknown fields extra/);
    assert.throws(() => resolveSolanaIdentity({ ...identity, schema: 'other' }, profile), /Unsupported identity schema/);
    assert.throws(() => resolveSolanaIdentity({ ...identity, network: 'Local' }, profile), /lowercase/);
    assert.throws(() => resolveSolanaIdentity({ ...identity, network: 'mainnet-beta' }, profile), /must go together/);
    assert.throws(() => resolveSolanaIdentity({ ...mainnet, network: 'localnet' }, profile), /must go together/);
    assert.throws(() => resolveSolanaIdentity({ ...identity, network: 'staging' }, profile), /No Wallet Standard chain/);
    assert.throws(() => resolveSolanaIdentity({ ...identity, treasury: null }, profile), /no treasury \(undeployed\)/);
    assert.throws(() => resolveSolanaIdentity({ ...identity, vault_state: identity.treasury }, profile), /not the vault PDA/);
    assert.throws(() => resolveSolanaIdentity({ ...identity, pyth_price_account: '0x00' }, profile), /base58/);
    assert.throws(() => resolveSolanaIdentity({ ...identity, pyth_price_account: identity.treasury }, profile),
        /not the push-oracle account/);
});

test('deployment inputs are strict: known fields, secure URLs and signing-key field elements only', async () => {
    const identity = await fixture('localnet.identity.json');
    const deployment = await fixture('localnet.deployment.json');
    for (const [changes, error] of [
        [{ extra: true }, /unknown fields extra/],
        [{ schema: 'other' }, /Unsupported deployment schema/],
        [{ rpc_url: 'http://rpc.example' }, /rpc_url must be a credential-free HTTPS or loopback URL/],
        [{ protocol_server_url: 'https://user:pass@server.example' }, /protocol_server_url/],
        [{ indexer_url: 'not a url' }, /indexer_url must be an absolute URL/],
        [{ state_signing_key: { x: '0x1' } }, /state_signing_key/],
        [{ clearance_signing_key: { x: '0x1', y: `0x${'f'.repeat(64)}` } }, /clearance_signing_key/]
    ]) {
        await assert.rejects(solanaBrowserConfig({ identity, deployment: { ...deployment, ...changes } }), error);
    }
    const { rpc_url: _rpc, ...missing } = deployment;
    await assert.rejects(solanaBrowserConfig({ identity, deployment: missing }), /missing fields rpc_url/);
    await assert.rejects(solanaBrowserConfig({ identity, deployment, deploymentApiProxyPath: '//other.example/' }),
        /same-origin/);
});
