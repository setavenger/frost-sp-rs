# W1: FROST layer and receiving

Read `run/RULES.md` first. Work-package id: `w1`. Branch: `feat/w1-receive`. Worktree: `/work/frost-sp-poc-wt/w1`.

## Scope

### 1. A FROST layer that signs under a tweaked key

It must sign under `P = X + τ·G`, where `τ` is a plain (not x-only) tweak, with **no** BIP 341 taproot tweak and even-Y handled after the tweak. Options, in order of preference:

- **(a) Keep ZF `frost-secp256k1-tr`.** Tweak the key material: add `τ` to every signing share, and `τ·G` to every verification share and the group key. This works because Lagrange weights sum to 1. Then find a signing path that skips the automatic taproot tweak; check the frost-core and frost-secp256k1-tr APIs and source.
- **(b)** secp256kfun `schnorr_fun::frost`, using `homomorphic_add` for the tweak.
- **(c)** A Rust port of the BIP 445 reference (bitcoin/bips PR #2070, branch `siv2r/bips:bip-frost-signing`) that passes its JSON vectors.

Pick the smallest change that passes T1–T3, and record why. If (a) needs a patched crate, vendor or patch it inside this repo.

### 2. New crate `crates/frost-sp-wallet`

- Group setup. A trusted dealer is fine for the PoC; label it as such.
- Shared `b_scan`.
- SP address encoding: `sp1…`/`tsp1…`, labels, change at `m = 0`.
- Scanning a set of transactions into owned outputs, each with `(outpoint, value, τ = t_k + ℓ_m)`.
  - It must run the full k-loop and match labels; follow BIP 352 exactly.
  - Reuse the `silentpayments` crate's receiving API where it fits.

### 3. Spend one received output with FROST

- Pay to a plain P2TR address.
- Build the transaction, FROST-sign under `P_k`, finalise the key path, and verify (T2).
- The signer API takes the funding transaction plus the signer's own `b_scan`, never a tweak (T7).

### 4. Tests

- **T1:** BIP 352 receiving vectors, labels included.
  - For each case, split the vector's `b_spend` into shares with a test-only trusted dealer.
  - Check that scanning finds exactly the vector's outputs.
  - Check that the FROST signature verifies under each output key.
- **T2:** signature validity and consensus validity.
- **T3:** parity and tweak cases.
- **T7:** re-derivation, including a coordinator that supplies a wrong tweak, which must be refused.

## Out of scope

Paying SP addresses from the wallet, multi-input spends, the GUI, and BlindBit test kit work. W2 and W3 cover the first and last.

## Hand-off

Your summary must state:
- the FROST-layer API that W2 will build on: types, functions, and how to sign with a tweak;
- every place where the code assumes a single input.
