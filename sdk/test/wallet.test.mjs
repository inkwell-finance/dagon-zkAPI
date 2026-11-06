import test from "node:test";
import assert from "node:assert/strict";

import wallet from "../wallet.js";

test("escape-period labels follow the deployed vault duration", () => {
  assert.equal(wallet.ABI.currentRoot, "fdab463d");
  assert.equal(wallet.ABI.challengePeriod, "f3f480d9");
  assert.equal(wallet.ABI.legacyChallengePeriod, "c3a079ed");
  assert.equal(wallet.escapePeriodLabel(60), "1-minute");
  assert.equal(wallet.escapePeriodPhrase(60), "1 minute");
  assert.equal(wallet.escapePeriodBadge(60), "1m");
  assert.equal(wallet.escapePeriodPhrase(86_400), "1 day");
  assert.equal(wallet.escapePeriodPhrase(172_800), "2 days");
  assert.equal(wallet.escapePeriodBadge(30), "30s");
});

test("deposit calldata uses the deployed vault signature and 32 static siblings", () => {
  const plan = {
    commitment: "0x2a",
    zero_path: Array.from({ length: 32 }, (_, index) => `0x${(index + 1).toString(16)}`),
  };
  const encoded = wallet.encodeDeposit(plan, 100_000n);
  assert.ok(encoded.startsWith("0xc588341c"));
  assert.equal(encoded.length, 2 + 8 + (34 * 64));
  assert.equal(encoded.slice(10, 74), wallet.abiWord("0x2a"));
  assert.equal(encoded.slice(74, 138), wallet.abiWord(100_000n));
});

test("NoteDeposited receipt parsing returns canonical note id and expiry", () => {
  const vault = "0x590df9abbfb21074016daa486c771ae0af729ee2";
  const receipt = {
    logs: [{
      address: vault.toUpperCase().replace("0X", "0x"),
      topics: [wallet.ABI.noteDeposited, `0x${wallet.abiWord(21n)}`, `0x${wallet.abiWord(42n)}`],
      data: `0x${wallet.abiWord(100_000n)}${wallet.abiWord(1_800_000_000n)}${wallet.abiWord(99n)}`,
    }],
  };
  assert.deepEqual(wallet.parseNoteDeposited(receipt, vault), {
    noteId: 21n,
    commitment: `0x${wallet.abiWord(42n)}`,
    amount: 100_000n,
    expiryTs: 1_800_000_000n,
    newRoot: 99n,
  });
});


// A dependency-free Keccak-256, so every selector and topic below is derived
// from its signature instead of being trusted as a constant.
const MASK = (1n << 64n) - 1n;
const ROTATIONS = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const ROUND_CONSTANTS = (() => {
  const constants = [];
  let lfsr = 1;
  for (let round = 0; round < 24; round += 1) {
    let constant = 0n;
    for (let bit = 0; bit < 7; bit += 1) {
      if (lfsr & 1) constant ^= 1n << BigInt((1 << bit) - 1);
      lfsr = ((lfsr << 1) ^ ((lfsr >> 7) * 0x71)) & 0xff;
    }
    constants.push(constant);
  }
  return constants;
})();
const rotl = (value, count) => count === 0 ? value : ((value << BigInt(count)) | (value >> BigInt(64 - count))) & MASK;
function keccakF(state) {
  for (let round = 0; round < 24; round += 1) {
    const parity = Array.from({ length: 5 }, (_, x) => state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]);
    for (let x = 0; x < 5; x += 1) {
      const mix = parity[(x + 4) % 5] ^ rotl(parity[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) state[x + y] ^= mix;
    }
    const moved = new Array(25);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) moved[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], ROTATIONS[x + 5 * y]);
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[x + 5 * y] = moved[x + 5 * y] ^ ((~moved[((x + 1) % 5) + 5 * y] & MASK) & moved[((x + 2) % 5) + 5 * y]);
      }
    }
    state[0] ^= ROUND_CONSTANTS[round];
  }
}
function keccak256(text) {
  const input = Buffer.from(text, "utf8");
  const rate = 136;
  const padded = Buffer.alloc(Math.ceil((input.length + 1) / rate) * rate);
  input.copy(padded);
  padded[input.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let lane = 0; lane < rate / 8; lane += 1) state[lane] ^= padded.readBigUInt64LE(offset + lane * 8);
    keccakF(state);
  }
  const out = Buffer.alloc(32);
  for (let lane = 0; lane < 4; lane += 1) out.writeBigUInt64LE(state[lane], lane * 8);
  return out.toString("hex");
}
const selector = signature => keccak256(signature).slice(0, 8);
const topic = signature => `0x${keccak256(signature)}`;

test("the local Keccak matches published vectors", () => {
  assert.equal(keccak256(""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(selector("transfer(address,uint256)"), "a9059cbb");
});

test("every vault selector and topic is derived from the concession-exit signatures", () => {
  const W = wallet.WITHDRAWAL_TUPLE;
  const R = wallet.REQUEST_TUPLE;
  assert.equal(W, "(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,uint64,uint128,address,uint256,bool,uint256,uint128,uint64)");
  assert.equal(R, "(uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256)");
  const selectors = {
    deposit: "deposit(bytes32,uint128,uint256[32])",
    mutualClose: `mutualClose(${W},bytes)`,
    initiateEscapeWithdrawal: `initiateEscapeWithdrawal(${W},bytes)`,
    finalizeEscapeWithdrawal: "finalizeEscapeWithdrawal(uint32)",
    challengeEscapeWithdrawal: `challengeEscapeWithdrawal(uint32,${R},bytes)`,
    raiseEscapeConcession: `raiseEscapeConcession(uint32,${R},bytes,uint128)`,
    claimExpired: "claimExpired(uint32)",
    retireClosedLeaf: "retireClosedLeaf(uint32,uint256[32])",
    challengePeriod: "challengePeriod()",
    currentRoot: "currentRoot()",
    nextNoteId: "nextNoteId()",
    notes: "notes(uint32)",
    pendingWithdrawals: "pendingWithdrawals(uint32)",
    usedNullifiers: "usedNullifiers(uint256)",
    nullifierState: "nullifierState(uint256)",
    claimableAt: "claimableAt(uint32)",
    paused: "paused()",
    pausedAt: "pausedAt()",
  };
  for (const [name, signature] of Object.entries(selectors)) assert.equal(wallet.ABI[name], selector(signature), name);
  const topics = {
    noteDeposited: "NoteDeposited(uint32,bytes32,uint128,uint64,uint256)",
    mutualCloseEvent: "MutualClose(uint32,uint256,uint128,address)",
    escapeInitiatedEvent: "EscapeWithdrawalInitiated(uint32,uint256,uint256,uint128,uint128,address,uint64)",
    escapeDefeatedEvent: "EscapeWithdrawalDefeated(uint32,uint256,uint256)",
    escapeConcessionRaisedEvent: "EscapeConcessionRaised(uint32,uint256,uint128,uint128)",
    escapeFinalizedEvent: "EscapeWithdrawalFinalized(uint32,uint256,uint128,address)",
    escapePayoutDeferredEvent: "EscapePayoutDeferred(uint32,address,uint128)",
    expiredClaimedEvent: "ExpiredClaimed(uint32,uint128)",
    closedLeafRetiredEvent: "ClosedLeafRetired(uint32,uint256)",
    vaultPausedEvent: "VaultPaused(uint64)",
    vaultUnpausedEvent: "VaultUnpaused(uint64)",
  };
  for (const [name, signature] of Object.entries(topics)) assert.equal(wallet.ABI[name], topic(signature), name);
  // The phase-2 restoration machinery is gone; status 4 is reserved and never written.
  for (const removed of ["restoreChallengedNote", "challengedNoteRestoredEvent", "escapeChallengedEvent"]) {
    assert.equal(wallet.ABI[removed], undefined);
  }
  assert.equal(wallet.encodeRestoreChallengedNote, undefined);
  assert.deepEqual(Object.values(wallet.NOTE_STATUS), [0, 1, 2, 3]);
  assert.deepEqual(wallet.NULLIFIER_STATE, { unused: 0, consumed: 1, challenged: 2 });
});

// Threat: a destination that rejects the vault's gas-bounded push is credited
// (escapePayoutCredits) instead of locking the note; the SDK must not report
// such a finalize as a returned payout.
test("finalize receipts report a deferred escape payout only for their own note", () => {
  const word = (value) => BigInt(value).toString(16).padStart(64, "0");
  const finalized = (noteId) => ({ address: VAULT, topics: [wallet.ABI.escapeFinalizedEvent, `0x${word(noteId)}`],
    data: `0x${word(0x16)}${word(1_800_000)}${word(DESTINATION)}` });
  const deferred = (noteId) => ({ address: VAULT,
    topics: [wallet.ABI.escapePayoutDeferredEvent, `0x${word(noteId)}`, `0x${word(DESTINATION)}`], data: `0x${word(1_800_000)}` });
  const parse = (logs) => wallet.parseWithdrawalReceipt({ logs }, VAULT, "finalize");
  assert.equal(parse([finalized(21)]).payoutDeferred, false);
  assert.equal(parse([deferred(21), finalized(21)]).payoutDeferred, true);
  assert.equal(parse([deferred(22), finalized(21)]).payoutDeferred, false);
  assert.equal(wallet.parseWithdrawalReceipt({ logs: [finalized(21)] }, VAULT, "mutual"), null);
});

const DESTINATION = "0x2222222222222222222222222222222222222222";
const VAULT = "0x590df9abbfb21074016daa486c771ae0af729ee2";

function withdrawalPlan(mode = "mutual") {
  return {
    mode,
    public_inputs: {
      protocol_version: 2,
      chain_id: "11155111",
      contract_address: VAULT,
      registration: "0x11",
      state_signing_key_x: "0x12",
      state_signing_key_y: "0x13",
      clearance_signing_key_x: "0x14",
      clearance_signing_key_y: "0x15",
      note_id: 21,
      deposit_amount: 2_000_000,
      expiry_ts: "1900000000",
      final_balance: mode === "mutual" ? 1_850_000 : 1_800_000,
      destination: Array(20).fill(0x22),
      withdrawal_nullifier: "0x16",
      has_clearance: mode === "mutual",
      next_nullifier: mode === "mutual" ? "0x0" : "0x17",
      conceded: mode === "mutual" ? 0 : "50000",
      valid_until: "1800003600",
    },
    proof: {
      backend: "groth16_bn254",
      proof: Buffer.from(Array.from({ length: 256 }, (_, index) => index)).toString("base64"),
    },
  };
}

test("mutual-close calldata encodes the 18-word leaf-bound tuple and the dynamic proof, with no path", () => {
  const plan = withdrawalPlan("mutual");
  const encoded = wallet.encodeWithdrawal(plan, "mutual", DESTINATION, VAULT);
  assert.ok(encoded.startsWith(`0x${wallet.ABI.mutualClose}`));
  assert.equal(encoded.length, 2 + 8 + (28 * 64));
  const word = index => encoded.slice(10 + (index * 64), 10 + ((index + 1) * 64));
  assert.equal(word(1), wallet.abiWord(11_155_111n), "decimal chain IDs are not read as hex");
  assert.equal(word(3), wallet.abiWord(0x11n), "registration replaces the active root");
  assert.equal(word(8), wallet.abiWord(21n));
  assert.equal(word(9), wallet.abiWord(2_000_000n));
  assert.equal(word(10), wallet.abiWord(1_900_000_000n));
  assert.equal(word(11), wallet.abiWord(1_850_000n));
  assert.equal(word(12), wallet.addressWord(DESTINATION));
  assert.equal(word(14), wallet.abiWord(1n));
  assert.equal(word(15), wallet.abiWord(0n));
  assert.equal(word(16), wallet.abiWord(0n));
  assert.equal(word(17), wallet.abiWord(1_800_003_600n));
  assert.equal(word(18), wallet.abiWord(19n * 32n));
  assert.equal(word(19), wallet.abiWord(256n));
  assert.equal(encoded.slice(-64), Buffer.from(Array.from({ length: 32 }, (_, index) => index + 224)).toString("hex"));
});

test("escape calldata publishes the successor nullifier, concession and validity deadline", () => {
  const plan = withdrawalPlan("escape");
  const encoded = wallet.encodeWithdrawal(plan, "escape", DESTINATION);
  assert.ok(encoded.startsWith(`0x${wallet.ABI.initiateEscapeWithdrawal}`));
  const word = index => encoded.slice(10 + (index * 64), 10 + ((index + 1) * 64));
  assert.equal(word(14), wallet.abiWord(0n));
  assert.equal(word(15), wallet.abiWord(0x17n));
  assert.equal(word(16), wallet.abiWord(50_000n));
  assert.equal(wallet.encodeFinalizeEscape(21), `0x${wallet.ABI.finalizeEscapeWithdrawal}${wallet.abiWord(21)}`);
});

test("withdrawal encoder rejects substitutions and malformed concession statements", () => {
  assert.throws(() => wallet.encodeWithdrawal(withdrawalPlan("mutual"), "mutual", "0x3333333333333333333333333333333333333333"), /destination/);
  const cases = [
    ["mutual", { has_clearance: false }, /clearance/],
    ["mutual", { next_nullifier: "0x9" }, /successor nullifier or a concession/],
    ["mutual", { conceded: 1 }, /successor nullifier or a concession/],
    ["escape", { next_nullifier: "0x0" }, /successor nullifier/],
    ["escape", { next_nullifier: "0x16" }, /successor nullifier/],
    ["escape", { conceded: "200001" }, /more than the note's deposit/],
    ["escape", { valid_until: 0 }, /validity deadline/],
    ["escape", { conceded: -1 }, /invalid concession/],
    ["escape", { conceded: 1.5 }, /invalid concession/],
  ];
  for (const [mode, patch, error] of cases) {
    const plan = withdrawalPlan(mode);
    Object.assign(plan.public_inputs, patch);
    assert.throws(() => wallet.encodeWithdrawal(plan, mode, DESTINATION), error, JSON.stringify(patch));
  }
});

test("withdrawal events expose note, nullifiers, concession, destination, balance and deadline", () => {
  const receipt = {
    logs: [{
      address: VAULT,
      topics: [wallet.ABI.escapeInitiatedEvent, `0x${wallet.abiWord(21n)}`],
      data: `0x${wallet.abiWord(99n)}${wallet.abiWord(100n)}${wallet.abiWord(1_850_000n)}${wallet.abiWord(50_000n)}${wallet.addressWord(DESTINATION)}${wallet.abiWord(1_900_000_000n)}`,
    }, {
      address: VAULT,
      topics: [wallet.ABI.escapeConcessionRaisedEvent, `0x${wallet.abiWord(21n)}`],
      data: `0x${wallet.abiWord(99n)}${wallet.abiWord(70_000n)}${wallet.abiWord(1_830_000n)}`,
    }, {
      address: VAULT,
      topics: [wallet.ABI.escapeDefeatedEvent, `0x${wallet.abiWord(21n)}`],
      data: `0x${wallet.abiWord(99n)}${wallet.abiWord(100n)}`,
    }],
  };
  assert.deepEqual(wallet.parseWithdrawalReceipt(receipt, VAULT, "escape"), {
    noteId: 21n,
    nullifier: 99n,
    nextNullifier: 100n,
    finalBalance: 1_850_000n,
    conceded: 50_000n,
    destination: DESTINATION,
    challengeDeadline: 1_900_000_000n,
  });
  assert.deepEqual(wallet.parseConcessionRaises(receipt, VAULT, 21), [{ nullifier: 99n, conceded: 70_000n, finalBalance: 1_830_000n }]);
  assert.deepEqual(wallet.parseConcessionRaises(receipt, VAULT, 22), []);
  assert.deepEqual(wallet.parseEscapeDefeated(receipt, VAULT, 21), { nullifier: 99n, nextNullifier: 100n });
  assert.equal(wallet.parseEscapeDefeated(receipt, VAULT, 22), null);
  const finalized = { logs: [{ address: VAULT, topics: [wallet.ABI.escapeFinalizedEvent, `0x${wallet.abiWord(21n)}`],
    data: `0x${wallet.abiWord(99n)}${wallet.abiWord(1_830_000n)}${wallet.addressWord(DESTINATION)}` }] };
  assert.deepEqual(wallet.parseWithdrawalReceipt(finalized, VAULT, "finalize"),
    { noteId: 21n, nullifier: 99n, finalBalance: 1_830_000n, destination: DESTINATION, payoutDeferred: false });
});
