# W2: Paying Silent Payment addresses from an SP-only FROST wallet

Read `run/RULES.md` first. Work-package id: `w2`. Branch: `feat/w2-send`. Worktree: `/work/frost-sp-poc-wt/w2`, created from `frost-sp`, which now includes W1.

## Start from

- **W1's crate `crates/frost-sp-wallet`.** Read `run/w1-SUMMARY.md` first, especially "Hand-off for W2" and the list of places that assume a single input.
  - FROST tweak signing: `tweak::tweak_key_package` and `tweak_public_key_package`, then the plain `round2::sign`/`aggregate`. Never use the `*_with_tweak` functions.
- **Reusable code from macgyver13's example** (port it, or depend on it):
  - `examples/frost-signer/src/frost_spdk.rs`: threshold ECDH interpolation, DLEQ verification, SP derivation, output checks.
  - `examples/frost-signer/src/frost_psbt.rs`: local PSBT fields.
- **PSBT is optional for the PoC.** Typed in-memory message structs, as W1 used, are fine.

## Scope

### 1. Multi-input spends

All inputs are received SP outputs, each with its own `τ_j` re-derived by each signer (T7). Each input gets its own FROST session and nonces, and its message is that input's sighash.

### 2. Paying SP addresses

Any number of recipients, and more than one output per recipient (BIP 352's k-loop on the sender side).

1. **Validate each recipient `B_scan`** (T4).
2. **Per distinct recipient scan key**, each signer in `S` returns `D_i = x_i·B_scan` and a BIP 374 proof against its **untweaked** verification share `X_i`. Use rust-dleq (already a dependency) or bdk-sp's `dleq`, whichever passes the BIP 374 vectors.
3. **The coordinator computes**
   `a·B_scan = (Σ_j g_j)·Σ_{i∈S} λ_i·D_i + (Σ_j g_j·τ_j)·B_scan`,
   where `g_j = −1` if input key `x + τ_j` has odd Y, else `+1`.
   Then it computes `input_hash` (smallest outpoint, `A = Σ` of the even-Y input keys) and the outputs per BIP 352.
4. **Change goes to the wallet's own change address** (label `m = 0`). For its own scan key the wallet doesn't need shares: `a·B_scan = b_scan·A` (ECDH symmetry), and every cosigner holds `b_scan`. Use that, so self-payments put nothing through the `x·Y` exposure.

### 3. Checks every signer makes before signing

- verify all DLEQ proofs
- recompute every SP output
- check recipients and amounts against what it approved (extend `ApprovedSpend` to take SP recipients)
- check that each input's FROST message equals that input's sighash
- re-derive each `τ_j`
- check that the fee is within the approved maximum

### 4. Coin selection guard

- Refuse any input set with `Σ g_j = 0`.
- Add a test that shows the leak the guard prevents: with two opposite-parity inputs from one payer, that payer computes the wallet's outgoing shared secret.
- See `research/parity-cancellation.md`.

### 5. Exposure counter

- Count share releases per group key: distinct non-self recipient scan keys, plus aborted sessions that released shares.
- Expose a rotation threshold setting (1e3 / 1e6 / 1e9). Above it, the wallet refuses to release shares until the key is rotated.
- Keep it minimal.

## Tests

- **T1 (sending):** run the BIP 352 sending vectors through the coordinator math.
  - For each vector case whose inputs are all single-key eligible types, pick a random test `x`.
  - Set test-only tweaks `τ_j` so that each vector input key equals `g_j·(x + τ_j)` (taproot) or `x + τ_j` (non-taproot, no negation).
  - Produce shares of `x` and run the threshold ECDH.
  - The outputs must equal the vector's expected outputs.
  - This test-only path bypasses re-derivation; label it.
- **T3:** mixed-parity input sets and labelled inputs.
- **T4:** invalid scan keys.
- **T5:** the adversarial suite from RULES, each case a separate test that names the culprit where possible: wrong `D_i`, bad proof, swapped output, swapped recipient, message ≠ sighash, wrong tweak.
- **T6:** the BIP 374 vectors (fetch them into `tests/vectors/bip-0374/`); nonce separation; no nonce reuse after aborts.
- **In-process round trip:**
  1. FROST wallet A pays FROST wallet B and a single-key spdk receiver C.
  2. B and C find their outputs with their own scanners.
  3. B spends what it received to C.
  4. A finds its own change.
  5. Every transaction is consensus-verified (libbitcoinconsensus, as in W1).

## Out of scope

The BlindBit test kit and regtest (W4), the GUI, and standardising PSBT fields.

## Hand-off

The summary must give W4 a CLI or library entry point that matches the external-signer interface W3 is building. W3's spec will be at `/work/blindbit/blindbit-testkit-frost/docs/external-signer.md` once W3 finishes. If it isn't there yet, provide a library function W4 can wrap: inputs are owned UTXOs, funding transactions, destinations and fee rate; the output is a signed transaction.
