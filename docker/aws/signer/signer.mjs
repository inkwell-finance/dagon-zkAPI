import { Interface, Wallet, getAddress, isHexString } from 'ethers';

export function parseChainId(value) {
  if (value !== '1' && value !== '11155111') throw new Error('Explicit challenge chain ID must be 1 or 11155111');
  return BigInt(value);
}
const REQUEST_TUPLE = '(uint16 protocolVersion,uint64 chainId,address contractAddress,uint256 activeRoot,uint256 stateSigningKeyX,uint256 stateSigningKeyY,uint64 requestTime,uint128 solvencyBound,uint256 requestNullifier,uint256 authorizationTag,uint256 anonymousCommitmentX,uint256 anonymousCommitmentY) inputs';
// The challenger sends exactly two concession-exit calls: a defeat (request
// evidence at the escape's successor nullifier) and a raise (request evidence
// at the escaped nullifier, capped on-chain by its solvency bound).
export const CHALLENGE_ABI = `function challengeEscapeWithdrawal(uint32 noteId,${REQUEST_TUPLE},bytes proof)`;
export const RAISE_ABI = `function raiseEscapeConcession(uint32 noteId,${REQUEST_TUPLE},bytes proof,uint128 amount)`;
export const AUTHORIZED_CALLS = Object.freeze(['challengeEscapeWithdrawal', 'raiseEscapeConcession']);
export const vaultInterface = new Interface([CHALLENGE_ABI, RAISE_ABI]);
const readMethods = new Set([
  'eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getLogs',
  'eth_getTransactionReceipt', 'eth_getTransactionByHash',
  'eth_getTransactionCount', 'eth_call', 'eth_estimateGas', 'eth_gasPrice',
]);
const transactionFields = new Set(['from', 'to', 'data', 'gas', 'nonce', 'value', 'chainId', 'gasPrice']);

export class RpcError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
function requireValid(condition, message) {
  if (!condition) throw new RpcError(-32602, message);
}
function address(value) {
  try { return getAddress(value).toLowerCase(); }
  catch { throw new RpcError(-32602, 'Invalid address'); }
}
function quantity(value, label) {
  requireValid(typeof value === 'string' && /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value), `Invalid ${label}`);
  return BigInt(value);
}

// Upstream exceptions are never returned or logged: provider errors can contain
// URLs, credentials, raw signed transactions, or untrusted response bodies.
export function createUpstream(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(parsed.hostname))) {
    throw new Error('Upstream RPC must use HTTPS or loopback HTTP');
  }
  let nextId = 0;
  return async (method, params) => {
    try {
      const response = await fetch(url, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++nextId, method, params }),
        signal: AbortSignal.timeout(20_000), redirect: 'error',
      });
      if (!response.ok) throw new Error();
      const body = await response.json();
      if (body.error || !Object.hasOwn(body, 'result')) throw new Error();
      return body.result;
    } catch { throw new RpcError(-32000, 'Upstream RPC request failed'); }
  };
}

export function createSigner({ privateKey, vault, rpc, chainId, maxGas = 12_000_000n, maxGasPrice = 10_000_000_000n }) {
  requireValid(chainId === 1n || chainId === 11155111n, 'Explicit challenge chain ID must be 1 or 11155111');
  const wallet = new Wallet(privateKey);
  const sender = wallet.address.toLowerCase();
  const destination = address(vault);
  requireValid(destination !== '0x0000000000000000000000000000000000000000', 'Vault must be nonzero');
  requireValid(maxGas > 0n && maxGas <= 16_777_216n, 'Gas limit cap is invalid');
  requireValid(maxGasPrice > 0n && maxGasPrice <= 100_000_000_000n, 'Gas price cap is invalid');
  let queue = Promise.resolve();

  async function checkChain() {
    if (quantity(await rpc('eth_chainId', []), 'upstream chain ID') !== chainId) {
      throw new RpcError(-32000, 'Upstream RPC does not match the configured chain');
    }
  }

  function validateTransaction(tx) {
    requireValid(tx && typeof tx === 'object' && !Array.isArray(tx), 'Expected transaction object');
    requireValid(Object.keys(tx).every(key => transactionFields.has(key)), 'Unsupported transaction field');
    requireValid(address(tx.from) === sender, 'Sender is not authorized');
    requireValid(address(tx.to) === destination, 'Destination is not authorized');
    requireValid(tx.value === undefined || quantity(tx.value, 'value') === 0n, 'Value must be zero');
    requireValid(tx.chainId === undefined || quantity(tx.chainId, 'chain ID') === chainId, 'Chain ID does not match the configured chain');
    const gasLimit = quantity(tx.gas, 'gas');
    requireValid(gasLimit > 0n && gasLimit <= maxGas, 'Gas exceeds configured limit');
    const nonce = quantity(tx.nonce, 'nonce');
    requireValid(nonce <= BigInt(Number.MAX_SAFE_INTEGER), 'Nonce is too large');
    requireValid(isHexString(tx.data) && tx.data.length <= 16_386, 'Invalid calldata');
    let decoded;
    let name;
    try {
      ({ name, args: decoded } = vaultInterface.parseTransaction({ data: tx.data }));
      requireValid(AUTHORIZED_CALLS.includes(name), 'Unauthorized vault call');
      requireValid(vaultInterface.encodeFunctionData(name, decoded).toLowerCase() === tx.data.toLowerCase(), 'Noncanonical challenge calldata');
    } catch { throw new RpcError(-32602, 'Only canonical challengeEscapeWithdrawal or raiseEscapeConcession calls are authorized'); }
    requireValid(decoded.inputs.protocolVersion === 2n && decoded.inputs.chainId === chainId && address(decoded.inputs.contractAddress) === destination, 'Challenge proof targets another deployment');
    requireValid(isHexString(decoded.proof, 256), 'Challenge requires a 256-byte Groth16 proof');
    requireValid(name !== 'raiseEscapeConcession' || decoded.amount > 0n, 'A raise must name a positive concession');
    // A defeat may replace an unmined raise at the same nonce; the caller then
    // names a higher gas price, still bounded by the configured cap.
    const gasPriceFloor = tx.gasPrice === undefined ? 0n : quantity(tx.gasPrice, 'gas price');
    requireValid(gasPriceFloor <= maxGasPrice, 'Gas price exceeds configured limit');
    return { to: destination, data: tx.data, value: 0n, chainId: chainId, gasLimit, nonce: Number(nonce), type: 0, gasPriceFloor };
  }

  async function signAndSend(tx) {
    const { gasPriceFloor, ...transaction } = validateTransaction(tx);
    await checkChain();
    const simulation = { from: sender, to: destination, data: transaction.data, value: '0x0' };
    await rpc('eth_call', [simulation, 'latest']);
    const estimate = quantity(await rpc('eth_estimateGas', [simulation]), 'gas estimate');
    requireValid(estimate <= transaction.gasLimit, 'Gas limit is below current estimate');
    const upstreamGasPrice = quantity(await rpc('eth_gasPrice', []), 'gas price');
    const gasPrice = upstreamGasPrice > gasPriceFloor ? upstreamGasPrice : gasPriceFloor;
    requireValid(gasPrice > 0n && gasPrice <= maxGasPrice, 'Gas price exceeds configured limit');
    const raw = await wallet.signTransaction({ ...transaction, gasPrice });
    const hash = await rpc('eth_sendRawTransaction', [raw]);
    if (!isHexString(hash, 32)) throw new RpcError(-32000, 'Upstream RPC omitted the transaction hash');
    return hash;
  }

  return {
    sender, vault: destination, chainId, checkChain,
    async handle(method, params) {
      requireValid(Array.isArray(params), 'Expected positional parameters');
      if (method === 'eth_sendTransaction') {
        requireValid(params.length === 1, 'Expected one transaction');
        // Preserve the caller's durable nonce; never allocate a new nonce on
        // ambiguous sends. Serialize signing so callers cannot race fee checks.
        const result = queue.then(() => signAndSend(params[0]));
        queue = result.catch(() => {});
        return result;
      }
      if (!readMethods.has(method)) throw new RpcError(-32601, 'RPC method is not allowed');
      return rpc(method, params);
    },
  };
}
