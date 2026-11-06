# You're invited: Dagon zkAPI trusted setup ceremony

This page explains what we're asking you to do, why, what it costs you, and how to check us. It is written so you
can read it yourself or hand it to an AI assistant to summarise and walk you through it. Everything here can be
checked against the source code in this repository.

**The ask, in one sentence:** spend about 10 minutes, before **4 December 2026, 00:00 UTC**, running a small program
that mixes your own randomness into the cryptographic keys of Dagon zkAPI, then post the short hash it prints.

## Why we need you

Dagon zkAPI lets people pay for an AI API privately: they deposit funds, and later spend from that deposit without
the service being able to tell which deposit paid for which usage. This works with zero-knowledge proofs (Groth16).

Those proofs need public keys that are generated from secret random numbers. **Anyone who knew those secret numbers
could forge proofs**, for example to spend money that was never deposited. The secret has to be destroyed, and
nobody can prove they destroyed it.

A multi-party ceremony solves this: many people take turns adding their own randomness and throwing it away. The
final keys are safe **as long as at least one participant was honest**. If you take part and are honest, you
personally guarantee the keys are safe, without having to trust us or anyone else. That is why independent
participants matter: the more unrelated people take part, the more believable it is that at least one was honest.

## What you will do

Pick one way. All three do the same computation.

### 1. Browser (easiest, ~5–10 minutes)

1. Open <https://ceremony.dagon.so> on a laptop or phone you own.
2. Optionally type a name to appear in the public list (or stay anonymous).
3. Press **Contribute my randomness**. You may wait in a short queue.
4. Keep the tab open until it says **Done**. It downloads about 105 MB, computes, and uploads about 105 MB.
5. Copy the **attestation hash** and post it publicly (X, Farcaster, a GitHub gist, your blog).

### 2. Terminal, checked against published pins (recommended; needs Node.js 24+)

```sh
curl -fsSL https://ceremony.dagon.so/contribute.mjs -o contribute.mjs
curl -fsSL https://raw.githubusercontent.com/inkwell-finance/dagon-zkAPI/ccc634b/ceremony/ceremony.json -o ceremony.json
sha256sum contribute.mjs ceremony.json
```

The two hashes must equal the ones published at
<https://gist.github.com/lmvdz/65969dc3b92a53b2664acec90940342b> (and in this repository's `ceremony/README.md`):

```
8d87e42f22d3b4b2a6732f4c7b6b56852b7645896e21d59b0e0ca7c75624e32b  contribute.mjs
fa188c5cb0e15827626cfce1e168321839a65e452a93a89602fab4349e076c5e  ceremony.json
```

Then:

```sh
node contribute.mjs --server https://ceremony.dagon.so --ceremony ceremony.json --name "Your name"
```

It prints your attestation hash and saves a receipt file. Keep the receipt and post the hash.

### 3. Build it yourself (strongest; removes any need to trust us)

```sh
git clone https://github.com/inkwell-finance/dagon-zkAPI && cd dagon-zkAPI && git checkout ccc634b
cd ceremony && npm ci && node build.mjs
node web/dist/contribute.mjs --server https://ceremony.dagon.so --ceremony ceremony.json --name "Your name"
```

The built `web/dist/contribute.mjs` should hash to the same value as above. If even one participant does this and
reads the code, the "you must trust the server's code" caveat below disappears.

## What it costs you, and what it doesn't

- **Time:** about 5–10 minutes, mostly download and upload.
- **Money, wallets, accounts, email:** none. Nothing to sign, nothing to connect.
- **Install:** nothing for the browser path; Node.js for the terminal paths.
- **What becomes public:** the name you choose (or "Anonymous"), the time, and the hashes of your contribution.
- **What we see:** while you're connected, a salted hash of your IP address in memory, used only for rate limiting;
  it is not written to disk. Our hosting provider's edge may keep standard access logs.
- **Never** type a password, seed phrase or any existing secret into the page or the program. It does not need one.

## Honest caveats

- **The browser and the downloadable CLI come from our server.** A compromised server could serve code that leaks
  your randomness. Checking the CLI against the published hashes (option 2) or building from source (option 3)
  removes that risk; the browser path cannot fully remove it.
- **Erasing memory is best effort.** The program discards your randomness when it finishes, but no program can
  guarantee the OS never swapped it to disk. Close the tab or process afterwards.
- The ceremony tooling and the circuits were reviewed internally through several independent AI audit passes (the
  circuits, both vaults and the server were hardened as a result), not by an external audit firm. A circuit change
  after the ceremony would void it; we fixed known issues before opening it for that reason.

## How you can check your contribution was used

1. Your attestation hash appears in the public transcript: <https://ceremony.dagon.so/files/transcript.json>.
2. After the ceremony is sealed, anyone can re-verify everything from scratch:
   `node verify-ceremony.mjs https://ceremony.dagon.so --ceremony ceremony.json` (see `ceremony/README.md`).

## Timeline

| When | What |
| --- | --- |
| Now – 4 Dec 2026, 00:00 UTC | Contributions open |
| 4 Dec 2026 | Contributions close; the final state is published |
| 7 Dec 2026, 00:00 UTC | The public drand randomness beacon round 34599412 (chosen in advance, in `ceremony.json`) seals the keys, so even the last contributor cannot steer the result |
| After | Final keys, transcript and verifier output are published; the keys replace the current single-party keys |

## Technical summary (for reviewers and AI assistants)

- Groth16 phase 2 on BN254 using snarkjs 0.7.6, over the public Hermez Perpetual Powers of Tau (power 16, pinned
  blake2b-512 hash). Three circuits of `zkapi-v2-concession-v1`: `request`, `withdrawal`, `transition`, with r1cs
  pinned by sha256 and reproducible from source (`ceremony_export`, see `ceremony/README.md`).
- Each upload must extend the previous round by exactly one contribution and is fully re-verified
  (`snarkjs zkey verify` against the r1cs and Powers of Tau) before it is accepted.
- Attestation = sha256 of `dagon-zkapi-ceremony-v1\nround:<n>\n` followed by `<circuit>:<contribution hash>\n` for
  each circuit in order.
- Source: <https://github.com/inkwell-finance/dagon-zkAPI/tree/ccc634b/ceremony>. Design and operator guide:
  `ceremony/README.md`.

Questions: reply to whoever sent you this link. Thank you for helping.
