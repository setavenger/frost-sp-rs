# W2 security review (Opus): sending side

Reviewed `frost-sp` at `da7fc63` (W2 merged in `70c0741`), crate `crates/frost-sp-wallet`, read-only. Static review against BIP 352 (bitcoin/bips master) and the RULES.md "Math" section. Tests were not re-run (W2 and Codex ran them). W1 findings and the three Codex findings are not repeated; the Codex fixes are present (`send.rs:542`, `:1114`, `:1062-1077`).

**Verdict.** The sending side is sound under the stated trust model (dealer-provisioned, authentic `PublicKeyPackage`). There are no Critical or High findings. One cheap check would remove the trust assumption behind NEEDS-OPUS-REVIEW (b) and (d); it is F1.

## Findings, most severe first

### F1 (Medium if the pkp is not dealer-authentic, otherwise Low): DLEQ shares are checked against `X_j` from an unvalidated pkp
`spend.rs:120-123` accepts any `PublicKeyPackage`. `send.rs:481-488` verifies each `D_j` only against that package's `X_j`. `send.rs:494-506` then combines the shares, and nothing ties `Σ_{i∈S} λ_i X_i` to the group key.
- **Scenario.** A signer's pkp carries a substituted `X_j' = x_j'·G` (bad provisioning, a coordinator-supplied pkp, or a future DKG without commitment agreement). Cosigner `j` returns `D_j' = x_j'·B` with a valid proof. Every signer derives the same wrong ECDH, and the transaction verifies and is signed, because FROST uses the real `x_j`. The recipient can never find the output. Whoever knows `x_j' − x_j` can compute `t_k'`, so it can ransom the payment.
- **Fix (a few lines).** In `ecdh_for_outputs`, require `Σ_{i∈S} λ_i^S·X_i == key_package.verifying_key()` (untweaked) for the signing set. In `with_public_key_package`, require `pkp.verifying_key == key_package.verifying_key` and `pkp.share[own id] == key_package.verifying_share`. With this check, DLEQ against each `X_i` forces `Σλ_i D_i = x·B` whatever the other `X_j` are, because `X` is already bound to `B_spend` by `Signer::new` (`spend.rs:99-105`).

### F2 (Low): the exposure counter over-counts aborts and can be reset or bypassed
`exposure.rs:51, 77-79`; `send.rs:659-662, 710-714`; `exposure.rs:82-85` with `spend.rs:129-131`.
- `D_i = x_i·B` is deterministic in `B`, so an aborted session reveals nothing beyond the scan key that was already counted. Counting aborts is pure over-count.
- **Scenario.** A coordinator holding one approval re-runs round A and aborts about 1000 times. That exhausts the default 1e3 budget and forces a key rotation (DoS).
- Under-count paths are API-only: the counter lives in memory (a restart resets it, already W2-LATER-1), and `exposure_mut().reset_after_rotation()` is public with no proof that the key was rotated.
- No path releases `D_i` without `record_release`: `check_release` and `record_release` cover exactly the deduplicated requested keys (`send.rs:675-697`).

### F3 (Low/Info): culprit attribution is unauthenticated
`EcdhShare.id` (`send.rs:263-268`) is self-declared and unsigned. A relaying coordinator can attach a bad proof to an honest signer's id, or drop that signer's share, and the honest signer is named (`send.rs:470-487, 500-503`). Blame is only meaningful over authenticated channels; state this, or sign shares.

### F4 (Info): privacy fingerprints
- Change is always the last output, and payments keep the caller's order (`send.rs:1127-1131`).
- Locktime is pinned to 0 (`send.rs:556-569, 905-906`), so the transaction never uses anti-fee-sniping.
- Fix: shuffle the outputs before approval (the approval binds the order, so shuffle in `plan_send`), and optionally allow `lock_time ≤ tip`.

### F5 (Info): `input_hash = 0` is not rejected
`send.rs:183-186` uses `scalar_from_be` (`tweak.rs:17-20`), which accepts 0. BIP 352 says to fail. The probability is negligible.

## The requested checks

1. **Sender formula: correct for every parity mix and for labelled inputs.**
   - `g_j` comes from the parity of the full point `P_j = X + τ_j·G`, which the signer computes from authenticated data (`send.rs:392-410`). `τ_j` already includes `ℓ_m`.
   - `A = Σ g_j·P_j = Σ lift_x(x(P_j))` (`:167-177`), which matches what receivers compute.
   - `a·B = Σ g_j(x+τ_j)·B = (Σg)·xB + (Σgτ)·B` (`:200-208`), and `xB = Σ_{i∈S} λ_i^S·D_i` for any `S` with `|S| ≥ t`.
   - `input_hash` uses the minimum of `txid_LE‖vout_LE` over all transaction inputs (`:93-98, :178-186`); the transaction inputs equal the resolved coins (`:747-751`).
   - `k` is counted per scan key across every `B_m` in output order, and K_max is checked (`:526-550`). BIP 352 imposes no order inside a group; the sort by amount is only for test-vector determinism (BIP line 386).
2. **DLEQ and Lagrange weights: correct.**
   - The proof is made with the untweaked `x_i` (`:303-308`) and verified as `(A=X_i, B=B_scan, C=D_i)` (`:486`) by every signer in round B, before any signing.
   - Replay across scan keys or signers is impossible, because `A`, `B` and `C` enter the challenge. Replay across sessions returns the same `D_i`, which is harmless.
   - The Lagrange weights are computed for the FROST signing set taken from the packages (`:757-771`). Shares must cover that set exactly (`:474-476, :499-503`). Mixing sets is either refused or yields the same `xB`, apart from the F1 case.
3. **Signer checks: everything the sighash covers is bound.** This covers the coins, outputs, amounts, fee (computed from authenticated prevouts), version, locktime and sequence, and each `message == sighash` (`:621-648, :737-822`). Nothing a coordinator controls is left unbound. `EcdhRequest.signing_set` is unused, which is harmless.
4. **Self/change path: correct (`a·b_scan·G = b_scan·A`) and safe.**
   - "Self" is the exact `PublicKey` equality with the signer's own `b_scan·G`, so a foreign key can never pass as self.
   - A key with flipped parity (`−B_scan`) is treated as foreign. Releasing shares for it only reveals `−b_scan·X`, which the coordinator already knows. Change sent there would be lost, but only if the user approved that exact address. UI rule: label an output "change" only when it equals `change_address()` exactly.
5. **Exposure counter:** see F2.
6. **Nonces: correct.** There is one pair per input (`:600-614`), taken before any check (`:708`). frost-core's own-commitment check stops cross-session or cross-input use. DLEQ uses separate `aux_rand`, and its BIP 374 nonce is hedged with the secret, `A` and `C`.

## NEEDS-OPUS-REVIEW answers
- **(a)** The formula is correct; the algebra is in item 1 and amounts to a full proof. The only assumption is the authenticity of `X_i`, see F1.
- **(b)** Acceptable for the trusted-dealer PoC. The F1 check removes the dependency on the other signers' `X_j`.
- **(c)** The right unit is distinct non-self `B`; drop the abort count (F2). The 1e3 threshold is very conservative. Cheon's attack needs `d | n−1`; the largest such `d` ≤ 1e3 is 894, ≤ 1e6 is 752,152 and ≤ 1e9 is 18,051,648. That costs at most about 5, 10 and 12 bits of the 128-bit level.
- **(d)** With the F1 check, only `X` must be authentic, and `Signer::new` already binds it to `B_spend`. A DKG still needs commitment agreement among participants (echo broadcast).

**Blocks "sound":** nothing under the stated trust model. Add the F1 check before claiming (b) and (d) are closed.
