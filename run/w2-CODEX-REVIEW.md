# W2 correctness and security review

Reviewed `feat/w2-send` at `dc7293ebc5096e8a7aedb780c82abde810926d7c` against local `frost-sp` at `970c6173eb16c36a4c036f008482cd115802e3c4`. Findings concern added or modified code and are ordered by severity. **Two medium findings and one low finding; no concrete key-compromise or unauthorized-signing exploit established.** No repository code was edited.

## 1. Medium: the sender signs payments beyond the receiver's BIP 352 scan limit

**Location:** `crates/frost-sp-wallet/src/send.rs:539` (unchecked per-scan-key counter); `crates/frost-sp-wallet/src/send.rs:777` (signer accepts the resulting scripts).

`derive_scripts` increments `k` without enforcing `K_MAX = 2323`. Both coordinator construction and independent signer verification call this function, so every honest signer accepts a batch exceeding that limit. BIP 352 requires senders to reject oversized groups, while receivers stop before `k = 2323`. This wallet's receiver implements that stop at `wallet.rs:176`.

**Reproduced:** a single 2,000,000-sat coin, 2,324 payments of 500 sats to one recipient scan key, and change. `send_payment` returned a finalized transaction with 2,325 outputs and all input script checks passing. The recipient wallet found only 2,323 payments; the payment at vout 2323 was absent from its scan results.

This batch was 100,045 vB, so it exceeds the ordinary 100-kvB standard transaction size limit. It would need nonstandard relay/direct mining to confirm; this finding does not imply that an ordinary standard-sized send loses a payment. If confirmed, however, normal BIP 352 scanning and this crate's receive/spend APIs cannot discover the excess payment without special recovery handling. Successful signature/script verification does not establish that an SP recipient can find every output.

**Recommendation:** reject any scan-key group with more than `wallet::K_MAX` SP outputs in the shared derivation/validation path, including self-payments and change. Exercise both the limit and limit-plus-one through signer validation.

**Specification:** BIP 352, “Creating outputs” and “Scanning.”
https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

## 2. Medium: coin selection rejects affordable payments that need no change

**Location:** `crates/frost-sp-wallet/src/send.rs:1095`.

The only success condition requires enough value for `fee_with_change`, calculated with an extra 34-byte change script. The later dust branch can remove change, but selection never considers a coin set that can afford the payment and its actual fee without that output. Such a send fails with “insufficient funds,” or unnecessarily selects another coin if one is available.

**Reproduced:** one 100,000-sat, even-parity coin, a 99,880-sat SP payment, and a requested fee rate of 1 sat/vB. `plan_send` rejected it because the change-inclusive estimate requires 155 sats. Supplying the same single coin and payment in a manual `SendPlan`, with a 120-sat fee ceiling, succeeded through `execute_send`: the signed transaction was 111 vB and paid 120 sats. The coin passes the parity guard and genuinely covers the requested payment and fee rate.

**Recommendation:** assess the transaction without change as well as with change. Accept a sufficient no-change set when the residual belongs in the fee, and add change only when its amount covers its own cost and meets the dust rule.

## 3. Low: the fee estimator undercounts CompactSize encodings

**Location:** `crates/frost-sp-wallet/src/send.rs:1057` (fixed serialization overhead); `crates/frost-sp-wallet/src/send.rs:1093` (fee calculation).

`est_vsize` assumes one-byte input/output counts and one-byte script lengths. At 253 outputs the output count occupies three bytes. The estimator's rounding does not cover this increase, so `send_payment` can return a transaction below the caller's requested fee rate. Input-count and script-length boundaries have the same underlying omission.

**Reproduced:** one input, 252 SP payments of 500 sats, and one change output, requesting 1 sat/vB. The returned plan paid 10,948 sats, but the finalized transaction was 10,949 vB. A relay endpoint requiring the requested rate would reject this otherwise correctly signed payment. The size error is small, hence low severity.

**Recommendation:** calculate weight using the actual CompactSize lengths, or construct the candidate transaction with representative 64-byte key-path witnesses and use its calculated virtual size.

## Verification and coverage

- `cargo test --locked -p frost-sp-wallet --tests`: **43 passed, 0 failed** (21 send tests, 18 spend tests, one sending-vector test, one receiving-vector test, two DLEQ-vector tests).
- Three additional reproduction tests passed in a temporary harness outside the checkout: `/tmp/w2-codex-probe/src/lib.rs`. They link the unchanged wallet crate and reuse its test fixtures. Evidence logs: `/tmp/w2-codex-existing-tests.log`, `/tmp/w2-codex-probes.log`, and `/tmp/w2-codex-fee-probe.log`.
- Traced the signed input-key sum, Lagrange coefficients, smallest-outpoint serialization, input hash, per-scan-key output indexing, labels, self ECDH, and the parity-cancellation guard. No concrete algebra or parity bug established.
- Inspected FROST 3.0's `pre_sign`/`pre_aggregate`: plain signing and aggregation negate the already-tweaked key when needed. The caller applies the plain additive tweak and does not invoke the BIP 341 tweak APIs. No concrete tweak-order bug established.
- Inspected the selected rust-dleq standalone implementation and its BIP 374 wrappers, verification against untweaked verification shares, duplicate/missing/foreign-share handling, and independent signer recomputation. No practical proof-forgery or nonce-coupling issue established. Standard-generator vectors pass; the vector harness explicitly skips custom-generator cases.
- Traced approved outpoints, funding-key matching, re-derived tweaks, exact destinations/amounts, fee ceilings, signing-set checks, commitment checks in FROST, and per-input message/sighash binding. Pending FROST nonces are consumed before validation and are separate for each input; no reuse path established after success or refusal.
- Reviewed exposure accounting and its intentionally in-memory PoC scope. Assumed authenticated, consistent provisioned key packages and a correctly used cryptographic RNG, as required by the example's documented security model.
- Checked for a PR after completing the audit: `gh pr list --repo setavenger/frost-sp-rs --state all --head feat/w2-send` returned none, so there was no PR discussion to incorporate.
- No bitcoind, mempool acceptance, real-chain funding validation, formal cryptographic proof, or workspace-wide test run was performed. libbitcoinconsensus evidence here establishes input script verification against supplied prevouts, not complete chain/mempool validation.
