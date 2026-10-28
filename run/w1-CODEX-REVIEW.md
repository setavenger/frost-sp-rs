# W1 correctness and security review

Reviewed `feat/w1-receive` (`57bad5aeb40067ae3aa6c4926833f760a326150b`) against local `frost-sp` (`49c6663a681cd90655bb65e730f37e2578842fb2`). Findings are ordered by severity. No code was changed.

## 1. High: signer approval does not constrain the fee or selected input

**Location:** `crates/frost-sp-wallet/src/spend.rs:157` (outpoint check), `crates/frost-sp-wallet/src/spend.rs:164` (approval check).

The only out-of-band approval is `approved_outputs`. The input is checked against the funding transaction supplied in the same untrusted request, rather than against an approved outpoint, input value, or fee limit. There is no check of `funding_txo.value - sum(spend_tx.output.value)`.

A coordinator can obtain approval for a 99,000-sat payout intended to spend a 100,000-sat output, then request a spend of a different 1,000,000-sat output belonging to the wallet. The payout still equals `approved_outputs`; the funding output, derived tweak, outpoint and sighash checks all pass. Honest signers release valid shares for a transaction paying a 901,000-sat fee instead of the intended 1,000 sats. This allows unauthorized destruction of wallet value without changing any approved destination or payout amount.

**Recommendation:** bind approval to the selected funding outpoint and value, or require an independently approved maximum absolute fee and enforce it before releasing a share. Compute the fee from the signer's verified funding output.

**Evidence:** static control-flow review; no exploit test executed.

## 2. Medium: an unrelated invalid Taproot output prevents receiving and spending a valid payment

**Location:** `crates/frost-sp-wallet/src/wallet.rs:158`.

Every output with the `OP_1 PUSH32` template is parsed with `XOnlyPublicKey::from_slice(...)?`. An invalid x-coordinate therefore returns an error from the entire scan. Bitcoin permits creating such an output, even though its key path cannot be spent. A funding transaction can contain both a valid Silent Payment and an unrelated output with a witness program such as 32 bytes of `0xff`.

The valid payment is never returned. This also blocks spending it through this API: `Signer::sign` calls `scan_tx` at `spend.rs:135` and propagates the error before finding the requested output. A sender or collaborative transaction participant can thus make an otherwise spendable payment inaccessible through the wallet until the scanner is fixed.

**Recommendation:** skip P2TR-shaped output candidates that cannot be parsed as curve points; continue matching the remaining outputs. Add a case containing both a valid payment and an invalid candidate.

**Evidence:** static review of candidate parsing and the signer call path. The dependency's `is_p2tr` checks the script template and length only.

## 3. Medium: finalization verifies the signing package's message instead of the returned transaction

**Location:** `crates/frost-sp-wallet/src/spend.rs:210`–`217`.

`Coordinator::finalize` verifies the aggregated signature against `signing_package.message()`, then attaches it to the separately supplied `spend_tx`. It never recomputes that transaction's sighash or confirms that its input spends `owned.outpoint`.

After collecting valid shares for transaction A, passing transaction B with a changed destination, amount, sequence, or locktime returns `Ok(Transaction)` with a witness that does not authorize B. Signer checks do not prevent this because they checked A earlier. The signature remains secure, but finalization can silently report success for an unbroadcastable transaction.

**Recommendation:** check the single input and owned outpoint, reconstruct the prevout from the owned output, recompute the supplied transaction's key-path sighash, and compare it with the signing package message before returning the finalized transaction.

**Evidence:** static review of aggregation, Schnorr verification and witness attachment; no runtime reproduction executed.

## Coverage and limits

- Read the new wallet, group, tweak and spending implementations, manifests, test helpers, receiving-vector test and spend/refusal tests. Compared with the work-package requirements and BIP 352 receiving specification. Reviewed the vendored vector fixture through its harness and metadata rather than manually auditing every JSON entry.
- Checked the plain-tweak construction: adding tau to every Shamir share and tau*G to every verification share preserves interpolation at zero. Inspected the installed FROST 3.0 dependency: its plain signing and aggregation preprocess the already-tweaked key for even Y; these paths do not add the BIP 341 tweak. No concrete parity or tweak-order bug found.
- Checked nonce ownership and refusal paths: the signer takes its pending nonce pair before validation, and the FROST dependency checks minimum commitment count, presence of the signer's commitment, and equality with its nonce commitments. No concrete nonce-reuse bug found in the reviewed flow.
- Checked the signer's own scan-key derivation, coordinator tweak-hint comparison, funding-key match, one-input restriction, requested outpoint, exact approved outputs and message-to-sighash binding. The fee-approval gap is finding 1.
- DLEQ and threshold sending are outside W1. W1 derives its receiving shared secret locally from its own scan key and does not accept peer ECDH shares; missing DLEQ verification is therefore not a W1 finding. Existing sending-example DLEQ code was not audited as a new branch change.
- A separate native adversarial source review also identified findings 2 and 3. No test suite, additional reproduction program, bitcoind, or mempool check was run for this review. Existing tests were inspected, not claimed as passing.
