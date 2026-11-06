import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { checkParity } from './check-solana-parity.mjs';

test('parity observes both chains and invokes the authoritative diff', async () => {
  const calls = []; let temporary;
  const execute = async (bin, args) => {
    assert.equal(bin, join('/bin', 'dagon-zkapi-deploy')); calls.push(args[0]);
    if (args[0] === 'diff') {
      temporary = args[1]; assert.deepEqual(JSON.parse(await readFile(args[1], 'utf8')), { observed: 'local' });
      assert.deepEqual(JSON.parse(await readFile(args[2], 'utf8')), { observed: 'mainnet' });
      return { stdout: 'Solana parity PASS\n' };
    }
    return { stdout: JSON.stringify({ observed: args[0] === 'observe' ? 'local' : 'mainnet' }) };
  };
  let message;
  await checkParity({ identityPath: '/identity.json', rpcUrl: 'http://localhost:8899', binDir: '/bin', execute, log: m => { message = m; } });
  assert.deepEqual(calls, ['observe', 'expected', 'diff']); assert.equal(message, 'Solana parity PASS');
  await assert.rejects(access(temporary));
});

test('observation, mainnet reference and diff failures all fail closed', async () => {
  for (const fail of ['observe', 'expected', 'diff']) {
    let logged = false;
    await assert.rejects(checkParity({ identityPath: '/identity.json', rpcUrl: 'http://localhost:8899', execute: async (_, args) => {
      if (args[0] === fail) throw new Error(`failure at ${fail}`);
      return { stdout: '{}' };
    }, log: () => { logged = true; } }), new RegExp(`failure at ${fail}`));
    assert.equal(logged, false);
  }
});

test('malformed output cannot pass parity', async () => {
  await assert.rejects(checkParity({ identityPath: '/identity.json', rpcUrl: 'http://localhost:8899', execute: async () => ({ stdout: 'not json' }) }));
});
