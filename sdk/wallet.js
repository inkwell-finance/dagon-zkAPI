// Concession-exit vault (leaf-bound, root-free exits). Selectors and topics
// are keccak256 of the signatures beside them; sdk/test/wallet.test.mjs
// recomputes every one. WITHDRAWAL_TUPLE is Types.WithdrawalPublicInputs:
// 18 static words, the note fields (noteId, depositAmount, expiryTs)
// unpacked; REQUEST_TUPLE is Types.RequestPublicInputs.
const WITHDRAWAL_TUPLE = "(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,uint64,uint128,address,uint256,bool,uint256,uint128,uint64)";
const REQUEST_TUPLE = "(uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256)";

const ABI = Object.freeze({
  // deposit(bytes32,uint128,uint256[32])
  deposit: "c588341c",
  // mutualClose(WITHDRAWAL_TUPLE,bytes)
  mutualClose: "46c303dc",
  // initiateEscapeWithdrawal(WITHDRAWAL_TUPLE,bytes)
  initiateEscapeWithdrawal: "bfecb22f",
  // finalizeEscapeWithdrawal(uint32)
  finalizeEscapeWithdrawal: "ff8f5585",
  // challengeEscapeWithdrawal(uint32,REQUEST_TUPLE,bytes): the defeat; decoded only
  challengeEscapeWithdrawal: "da0ce43d",
  // raiseEscapeConcession(uint32,REQUEST_TUPLE,bytes,uint128): decoded only
  raiseEscapeConcession: "dd0064ba",
  // claimExpired(uint32): the treasury sweep; decoded only
  claimExpired: "a940507e",
  // retireClosedLeaf(uint32,uint256[32]): decoded only
  retireClosedLeaf: "e41f4c31",
  challengePeriod: "f3f480d9",
  legacyChallengePeriod: "c3a079ed",
  currentRoot: "fdab463d",
  nextNoteId: "7a2043a3",
  // notes(uint32): commitment, depositAmount, expiryTs, status, claimableAfter, pausedOffset
  notes: "9f18e4ed",
  // pendingWithdrawals(uint32): exists, withdrawalNullifier, nextNullifier,
  // stateBalance, conceded, finalBalance, destination, challengeDeadline
  pendingWithdrawals: "a2f9f1ce",
  usedNullifiers: "aad24061",
  // nullifierState(uint256): 0 unused or released, 1 consumed, 2 challenged
  nullifierState: "41b870b8",
  // claimableAt(uint32): the pause-adjusted second from which claimExpired may sweep
  claimableAt: "6dcafbc4",
  paused: "5c975abb",
  pausedAt: "2e55d0f2",
  // NoteDeposited(uint32 indexed noteId, bytes32 indexed commitment, uint128 amount,
  // uint64 expiryTs, uint256 newRoot)
  noteDeposited: "0x7c83dba8534bea9e30d6444f9ca6462dc906897f9938d220dbbe4358c1f7a063",
  // MutualClose(uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination)
  mutualCloseEvent: "0x1f43fa4711ca18e1d26398f26bf598bd3a62992cdd0e84f055f2bb506e9d7031",
  // EscapeWithdrawalInitiated(uint32 indexed noteId, uint256 nullifier, uint256 nextNullifier,
  // uint128 finalBalance, uint128 conceded, address destination, uint64 challengeDeadline)
  escapeInitiatedEvent: "0xe07c7138787331ec03e4635d32f3b6fec16a19ce0441b645dd7c6c1bb9096ffa",
  // EscapeWithdrawalDefeated(uint32 indexed noteId, uint256 nullifier, uint256 nextNullifier)
  escapeDefeatedEvent: "0x6964176acd3dbabf47d60aded3cecb60920a90834b90bc12c3ce367eed4fbff8",
  // EscapeConcessionRaised(uint32 indexed noteId, uint256 nullifier, uint128 conceded, uint128 finalBalance)
  escapeConcessionRaisedEvent: "0x3faf5608f821061643ff6fdfe6dd0f6d7fb074bb565f35e3537a86ac08f0897c",
  // EscapeWithdrawalFinalized(uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination)
  escapeFinalizedEvent: "0x163f2e46c4004f0ed9682e2db8c84efac31310720266b17ea9904ba348c26504",
  // EscapePayoutDeferred(uint32 indexed noteId, address indexed destination, uint128 amount)
  escapePayoutDeferredEvent: "0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942",
  // ExpiredClaimed(uint32 indexed noteId, uint128 depositAmount)
  expiredClaimedEvent: "0xe5962fdd811b0b8d9b9cdaf37e396f36dd238f127d52ef65ae07d96edb32fd96",
  // ClosedLeafRetired(uint32 indexed noteId, uint256 newRoot)
  closedLeafRetiredEvent: "0x64572cec8ef079a5baa4f2860f8b65efb52a96f64ee679d315fd2a0541ea28b3",
  // VaultPaused(uint64 pausedAt) / VaultUnpaused(uint64 unpausedAt)
  vaultPausedEvent: "0xb53915db538e59d4102a31a4528531ea8d15fbfd8ef0262ca14ad1f51608b2d4",
  vaultUnpausedEvent: "0xcede2163dbea432de7db852e333280f4fe8ae24f8752d6063f5a5cf4efc762a1",
});

// Vault Types.NoteStatus. Value 4 is reserved and never written: a defeated
// escape returns its note to Active (the leaf never leaves the tree).
const NOTE_STATUS = Object.freeze({
  uninitialized: 0,
  active: 1,
  pendingWithdrawal: 2,
  closed: 3,
});

// Vault nullifier states (nullifierState(uint256)).
const NULLIFIER_STATE = Object.freeze({
  unused: 0,
  consumed: 1,
  challenged: 2,
});

function abiWord(value) {
  const hex = typeof value === "string" ? value.replace(/^0x/, "") : BigInt(value).toString(16);
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length > 64) {
    throw new Error("Value cannot be encoded for the vault contract.");
  }
  return hex.padStart(64, "0");
}

// An unsigned integer public input: a JSON number, a bigint, a decimal string
// (u64/u128 values the wallet serializes losslessly) or a 0x-prefixed felt.
function uintWord(value, label) {
  let parsed;
  if (typeof value === "bigint") parsed = value;
  else if (typeof value === "number" && Number.isSafeInteger(value)) parsed = BigInt(value);
  else if (typeof value === "string" && /^0x[0-9a-fA-F]{1,64}$/.test(value)) parsed = BigInt(value);
  else if (typeof value === "string" && /^[0-9]{1,78}$/.test(value)) parsed = BigInt(value);
  if (parsed === undefined || parsed < 0n || parsed >= (1n << 256n)) {
    throw new Error(`The withdrawal proof has an invalid ${label}.`);
  }
  return parsed.toString(16).padStart(64, "0");
}

function addressWord(address) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address || "")) {
    throw new Error("MetaMask returned an invalid account address.");
  }
  return abiWord(address);
}

function callData(selector, words) {
  return `0x${selector}${words.join("")}`;
}

function toBytes32(felt) {
  return `0x${String(felt).replace(/^0x/, "").padStart(64, "0")}`;
}

function normalizedEscapePeriod(seconds) {
  return Math.max(1, Number(seconds) || 24 * 60 * 60);
}

function escapePeriodLabel(seconds) {
  const value = normalizedEscapePeriod(seconds);
  if (value % 86_400 === 0) return `${value / 86_400}-day`;
  if (value % 3_600 === 0) return `${value / 3_600}-hour`;
  if (value % 60 === 0) return `${value / 60}-minute`;
  return `${value}-second`;
}

function escapePeriodPhrase(seconds) {
  const value = normalizedEscapePeriod(seconds);
  if (value % 86_400 === 0) {
    const days = value / 86_400;
    return `${days} ${days === 1 ? "day" : "days"}`;
  }
  if (value % 3_600 === 0) {
    const hours = value / 3_600;
    return `${hours} ${hours === 1 ? "hour" : "hours"}`;
  }
  if (value % 60 === 0) {
    const minutes = value / 60;
    return `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
  }
  return `${value} ${value === 1 ? "second" : "seconds"}`;
}

function escapePeriodBadge(seconds) {
  const value = normalizedEscapePeriod(seconds);
  if (value >= 3_600) return `${Math.round(value / 3_600)}h`;
  if (value >= 60) return `${Math.round(value / 60)}m`;
  return `${value}s`;
}

function encodeDeposit(plan, amount) {
  if (!Array.isArray(plan?.zero_path) || plan.zero_path.length !== 32) {
    throw new Error("The private note has an invalid 32-level deposit path.");
  }
  return callData(ABI.deposit, [
    abiWord(toBytes32(plan.commitment)),
    abiWord(amount),
    ...plan.zero_path.map((value) => abiWord(value)),
  ]);
}

function decodeBase64(value) {
  if (typeof value !== "string" || !value) throw new Error("The daemon returned an empty withdrawal proof.");
  try {
    if (typeof atob === "function") {
      const decoded = atob(value);
      return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    }
    if (typeof Buffer === "function") return Uint8Array.from(Buffer.from(value, "base64"));
  } catch (_) {
    throw new Error("The daemon returned malformed base64 proof data.");
  }
  throw new Error("This browser cannot decode the withdrawal proof.");
}

function bytesHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function destinationHex(value) {
  if (typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value)) return value.toLowerCase();
  if (!Array.isArray(value) || value.length !== 20
      || value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new Error("The daemon returned an invalid withdrawal destination.");
  }
  return `0x${bytesHex(value)}`;
}

function bigUint(value, label) {
  return BigInt(`0x${uintWord(value, label)}`);
}

/**
 * Encode mutualClose or initiateEscapeWithdrawal. Exits are leaf-bound: the
 * vault compares registration and (noteId, depositAmount, expiryTs) with the
 * note it stores, so the call carries no Merkle path and no root.
 */
function encodeWithdrawal(plan, expectedMode, expectedDestination, expectedVault) {
  const mode = String(expectedMode || "").toLowerCase();
  if (!['mutual', 'escape'].includes(mode) || plan?.mode !== mode) {
    throw new Error("The daemon returned a different withdrawal mode than requested.");
  }
  if (plan?.proof?.backend !== "groth16_bn254") {
    throw new Error("The daemon returned an unsupported withdrawal proof backend.");
  }
  const inputs = plan.public_inputs || {};
  const destination = destinationHex(inputs.destination);
  if (destination !== String(expectedDestination || "").toLowerCase()) {
    throw new Error("The proof destination does not match the requested withdrawal address.");
  }
  if (expectedVault && String(inputs.contract_address).toLowerCase() !== String(expectedVault).toLowerCase()) {
    throw new Error("The withdrawal proof is bound to a different vault contract.");
  }
  if (Boolean(inputs.has_clearance) !== (mode === "mutual")) {
    throw new Error("The withdrawal proof has the wrong server-clearance state.");
  }
  const nullifier = bigUint(inputs.withdrawal_nullifier, "withdrawal nullifier");
  const nextNullifier = bigUint(inputs.next_nullifier, "successor nullifier");
  const conceded = bigUint(inputs.conceded, "concession");
  const finalBalance = bigUint(inputs.final_balance, "final balance");
  const depositAmount = bigUint(inputs.deposit_amount, "deposit amount");
  if (mode === "mutual" && (nextNullifier !== 0n || conceded !== 0n)) {
    throw new Error("A mutual close must not publish a successor nullifier or a concession.");
  }
  if (mode === "escape" && (nextNullifier === 0n || nextNullifier === nullifier)) {
    throw new Error("The escape proof does not publish its successor nullifier.");
  }
  if (finalBalance + conceded > depositAmount) {
    throw new Error("The withdrawal proof pays more than the note's deposit.");
  }
  if (bigUint(inputs.valid_until, "validity deadline") === 0n) {
    throw new Error("The withdrawal proof has no validity deadline.");
  }
  const proof = decodeBase64(plan.proof.proof);
  if (proof.length !== 256) {
    throw new Error("The Groth16 withdrawal proof must contain exactly 256 bytes.");
  }

  const tuple = [
    uintWord(inputs.protocol_version, "protocol version"),
    uintWord(inputs.chain_id, "chain ID"),
    uintWord(inputs.contract_address, "vault address"),
    uintWord(inputs.registration, "registration"),
    uintWord(inputs.state_signing_key_x, "state key"),
    uintWord(inputs.state_signing_key_y, "state key"),
    uintWord(inputs.clearance_signing_key_x, "clearance key"),
    uintWord(inputs.clearance_signing_key_y, "clearance key"),
    uintWord(inputs.note_id, "note ID"),
    uintWord(inputs.deposit_amount, "deposit amount"),
    uintWord(inputs.expiry_ts, "expiry"),
    uintWord(inputs.final_balance, "final balance"),
    abiWord(destination),
    uintWord(inputs.withdrawal_nullifier, "withdrawal nullifier"),
    abiWord(inputs.has_clearance ? 1 : 0),
    uintWord(inputs.next_nullifier, "successor nullifier"),
    uintWord(inputs.conceded, "concession"),
    uintWord(inputs.valid_until, "validity deadline"),
  ];
  // The static tuple occupies 18 words and the bytes offset one more, so the
  // dynamic proof starts at word 19.
  const head = [...tuple, abiWord(19n * 32n)];
  const tail = [abiWord(proof.length), ...Array.from({ length: 8 }, (_, index) => (
    bytesHex(proof.slice(index * 32, (index + 1) * 32))
  ))];
  const selector = mode === "mutual" ? ABI.mutualClose : ABI.initiateEscapeWithdrawal;
  return callData(selector, [...head, ...tail]);
}

function encodeFinalizeEscape(noteId) {
  return callData(ABI.finalizeEscapeWithdrawal, [abiWord(noteId)]);
}

function dataWords(log) {
  const data = String(log.data || "").replace(/^0x/, "");
  return data.match(/.{64}/g) || [];
}

function vaultLogs(receipt, vaultAddress, topic) {
  return (receipt?.logs || []).filter((log) => log.address?.toLowerCase() === vaultAddress.toLowerCase()
    && log.topics?.[0]?.toLowerCase() === topic && log.topics.length >= 2);
}

/**
 * The withdrawal event of a mined mutual close, escape initiation or escape
 * finalization. An escape initiation also reports its nullifiers, its
 * declared concession and its deadline.
 */
function parseWithdrawalReceipt(receipt, vaultAddress, mode) {
  const expectedTopic = mode === "mutual" ? ABI.mutualCloseEvent
    : mode === "escape" ? ABI.escapeInitiatedEvent
      : mode === "finalize" ? ABI.escapeFinalizedEvent : null;
  if (!expectedTopic) throw new Error("Unknown withdrawal receipt mode.");
  for (const log of vaultLogs(receipt, vaultAddress, expectedTopic)) {
    const words = dataWords(log);
    if (mode === "escape") {
      if (words.length < 6) continue;
      return {
        noteId: BigInt(log.topics[1]),
        nullifier: BigInt(`0x${words[0]}`),
        nextNullifier: BigInt(`0x${words[1]}`),
        finalBalance: BigInt(`0x${words[2]}`),
        conceded: BigInt(`0x${words[3]}`),
        destination: `0x${words[4].slice(24)}`.toLowerCase(),
        challengeDeadline: BigInt(`0x${words[5]}`),
      };
    }
    if (words.length < 3) continue;
    const parsed = {
      noteId: BigInt(log.topics[1]),
      nullifier: BigInt(`0x${words[0]}`),
      finalBalance: BigInt(`0x${words[1]}`),
      destination: `0x${words[2].slice(24)}`.toLowerCase(),
    };
    if (mode !== "finalize") return parsed;
    // A destination that rejected the gas-bounded push was credited instead;
    // the payout then waits in escapePayoutCredits for claimEscapePayout.
    parsed.payoutDeferred = vaultLogs(receipt, vaultAddress, ABI.escapePayoutDeferredEvent)
      .some((entry) => BigInt(entry.topics[1]) === parsed.noteId);
    return parsed;
  }
  return null;
}

/** Every EscapeConcessionRaised for `noteId` in a receipt, in log order. */
function parseConcessionRaises(receipt, vaultAddress, noteId) {
  return vaultLogs(receipt, vaultAddress, ABI.escapeConcessionRaisedEvent)
    .filter((log) => BigInt(log.topics[1]) === BigInt(noteId))
    .map(dataWords)
    .filter((words) => words.length >= 3)
    .map((words) => ({
      nullifier: BigInt(`0x${words[0]}`),
      conceded: BigInt(`0x${words[1]}`),
      finalBalance: BigInt(`0x${words[2]}`),
    }));
}

/** The EscapeWithdrawalDefeated for `noteId` in a receipt, or null. */
function parseEscapeDefeated(receipt, vaultAddress, noteId) {
  const log = vaultLogs(receipt, vaultAddress, ABI.escapeDefeatedEvent)
    .find((entry) => BigInt(entry.topics[1]) === BigInt(noteId));
  const words = log ? dataWords(log) : [];
  if (words.length < 2) return null;
  return { nullifier: BigInt(`0x${words[0]}`), nextNullifier: BigInt(`0x${words[1]}`) };
}

function parseNoteDeposited(receipt, vaultAddress) {
  for (const log of receipt?.logs || []) {
    if (log.address?.toLowerCase() !== vaultAddress.toLowerCase()
        || log.topics?.[0]?.toLowerCase() !== ABI.noteDeposited) continue;
    const data = String(log.data || "").replace(/^0x/, "");
    if (log.topics.length >= 3 && data.length >= 192) {
      return {
        noteId: BigInt(log.topics[1]),
        commitment: log.topics[2],
        amount: BigInt(`0x${data.slice(0, 64)}`),
        expiryTs: BigInt(`0x${data.slice(64, 128)}`),
        newRoot: BigInt(`0x${data.slice(128, 192)}`),
      };
    }
  }
  return null;
}

const walletCodec = Object.freeze({
  ABI,
  REQUEST_TUPLE,
  WITHDRAWAL_TUPLE,
  abiWord,
  addressWord,
  callData,
  encodeDeposit,
  encodeFinalizeEscape,
  encodeWithdrawal,
  escapePeriodBadge,
  escapePeriodLabel,
  escapePeriodPhrase,
  NOTE_STATUS,
  NULLIFIER_STATE,
  parseConcessionRaises,
  parseEscapeDefeated,
  parseNoteDeposited,
  parseWithdrawalReceipt,
});

export default walletCodec;
export { ABI, NOTE_STATUS, NULLIFIER_STATE, REQUEST_TUPLE, WITHDRAWAL_TUPLE, abiWord, addressWord, callData, encodeDeposit, encodeFinalizeEscape, encodeWithdrawal, escapePeriodBadge, escapePeriodLabel, escapePeriodPhrase, parseConcessionRaises, parseEscapeDefeated, parseNoteDeposited, parseWithdrawalReceipt };
