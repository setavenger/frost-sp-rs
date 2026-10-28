# W2 summary: paying Silent Payment addresses from an SP-only FROST wallet

## 1. State
`crates/frost-sp-wallet` now spends multiple received SP outputs and pays any number of SP recipients (several outputs per recipient, SP change to itself) with threshold ECDH + BIP 374 proofs; T1 (sending), T3, T4, T5, T6 pass, the Opus W1 findings F1-F4 and the 3 Codex findings are fixed with tests. Branch `feat/w2-send`, pushed to `origin`, PR against `frost-sp` (not merged).

## 2. Built
- `src/send.rs`: `SenderContext` (A, input_hash, sum g, sum g*tau; `a*B = (sum g)*sum lambda_i*D_i + (sum g*tau)*B`, self scan key via `b_scan*A`), `validate_scan_key`, `make_ecdh_share`/`ecdh_for_outputs` (BIP 374 against untweaked `X_i`, names the culprit), `Signer::{commit_inputs, ecdh_shares, sign_send}`, `SendCoordinator::{ecdh_request, build_tx, signing_packages, finalize}`, `ApprovedSend`, `check_parity_guard`, `plan_send` (coin selection never picks `sum g = 0`), `execute_send`, `send_payment`, `verify_consensus_all`.
- `src/exposure.rs`: share-release counter (distinct non-self scan keys + aborted sessions), thresholds 1e3/1e6/1e9, refuses above it until `reset_after_rotation`.
- Tests: `tests/send_e2e.rs` (24), `tests/t1_sending.rs`, `tests/t6_dleq_vectors.rs`, new cases in `tests/spend_e2e.rs`; vectors `tests/vectors/bip-0374/` (bitcoin/bips master, `afaa8566`), README updated. Plan: `run/w2-PLAN.md`; Codex review: `run/w2-CODEX-REVIEW.md`.
- **Opus W1 Low findings folded in (each has a test in `spend_e2e.rs`):** F1 `check_tx_shape` (version 2, locktime 0, RBF sequence) before signing; F2 approved outpoint checked before scanning the funding tx (also in the send path); F3 `scan_tx` skips transactions that spend a SegWit v>1 output; F4 `Coordinator::finalize` checks `x(X+tau*G)` against the output key first, so a wrong tau is a coordinator error and no honest signer is blamed.
- **Codex findings fixed (tests `codex1..3`):** K_max (2323) outputs per scan key enforced on the sender; no-change sends that afford the fee are planned; fee estimate uses real CompactSize lengths.

Test tail (`cargo test --workspace --exclude psbt-viewer`): frost-sp-wallet 24 + 18 + 1 + 1 + 2 passed, 0 failed; frost-signer 25, bip375-helpers 29 passed. `cargo clippy -p frost-sp-wallet --all-targets`: clean.

| ID | Status | Evidence |
|----|--------|----------|
| T1 send | pass | 22 BIP 352 sending cases (7 ineligible/failing skipped) with random `x`, test tweaks, 2-of-3 shares: outputs and `shared_secrets` equal the vectors; 2 negated taproot inputs, 6 multi-output |
| T3 | pass | 8 parity/label sets (1-4 coins, mixed, labelled), signing-set independence; round trips |
| T4 | pass | off-curve, x>=p, x==p, infinity, prefixes, lengths |
| T5 | pass | one test each: wrong `D_i`, bad proof (culprit id named), swapped script, swapped recipient (also refused in round A), message != sighash, wrong tweak, plus amount/fee/coin order |
| T6 | pass | BIP 374: 5 proofs reproduced, 4 invalid inputs rejected, 3 accepted + 9 rejected verify cases (5 custom-G skipped); fresh aux per proof, one nonce pair per input, no reuse after refusal or success |
| T2 | pass | every tx consensus-verified with libbitcoinconsensus (taproot) for all inputs |
| Round trip | pass | A pays FROST B (labelled, k=0,1), spdk C and a plain script; B and C scan; A finds label-0 change; B (2 coins) pays C |
| Guard | pass | Σg=0 refused by selection, signers and coordinator; leak test: payer recovers the outgoing shared secret for parities {+,-}, not for {+,+} or {-,-,+} |
| T7, T8 | T7 per input yes (re-derived in both rounds); T8 not W2 | |

### Hand-off for W4
Library entry: `send::send_payment(&SendCoordinator, &mut [Signer], signing_set, &[SpendableCoin], &[Payment], fee_rate_sat_vb, rng) -> (Transaction, SendPlan)`. `SpendableCoin` = funding tx + funding prevout scripts + vout + value (the testkit's `funding_tx_hex` + `funding_prevouts`). Gaps against `docs/external-signer.md` that a CLI wrapper must close: (1) the spec spends **all** given utxos, `plan_send` selects; add a "spend exactly these" planner (call `ApprovedSend` construction directly, keep the Σg guard); (2) the spec's `change_address` is never taproot, mine pays SP change; (3) a CLI needs the key packages (the PoC holds all shares in process) and the JSON/env plumbing.

## 3. To-do
| Item | Owner | Blocker | ID |
|------|-------|---------|----|
| CLI wrapper + "spend exactly these utxos" planner for the testkit | W4 / orchestrator | spec mismatches above | W2-CLI-1 |
| Regtest end to end, `testmempoolaccept` | W4 | no bitcoind here | T8 |
| Persist the exposure counter | later | PoC keeps it in memory | W2-LATER-1 |
| Pin `frost-secp256k1-tr = "=3.0.0"` (Opus F5) | orchestrator | global dependency choice | W2-LATER-2 |

## 4. Decided
- New `ApprovedSend` next to W1's `ApprovedSpend` (not an extension): the single-input type stays valid for W1 tests; sends need ordered coins and typed destinations.
- ECDH round before the transaction exists, signers check scan keys against approved recipients and the parity guard before releasing any share.
- Shares are released only for non-self scan keys; self/change uses `b_scan*A`.
- DLEQ `aux_rand` fresh per proof from the RNG, independent of FROST nonce generation.
- One nonce pair per input, all taken from the signer before any check; a refusal after shares were released counts as an aborted session.
- Signers also pin version 2 / locktime 0 / RBF sequence in the send path.
- Rotation threshold default 1e3.
- BIP 352 K_max enforced on the sender.
- Custom-generator BIP 374 vectors skipped: rust-dleq supports only G.

## 5. Not done / not verified
- Gstack flow in reduced form (as W1): `/autoplan` = plan written from the brief; `/review` = my own pass plus the Codex review (no specialist army); `/qa` = the test suite only (the crate has no binaries, example binaries' CLI paths not exercised); `/ship` = push and PR only.
- No `testmempoolaccept` (no bitcoind). Workspace excludes `psbt-viewer` (pre-existing missing sibling `bips` checkout); other crates keep their old clippy warnings.
- `NEEDS-OPUS-REVIEW`: (a) the sender formula `(Σg)·ΣλD + (Σgτ)·B` is verified by the BIP 352 vectors and an independent oracle, not formally; (b) DLEQ proofs are checked against `X_i` of the signer's own `PublicKeyPackage`, trusting that package; (c) exposure counting policy (what counts as one exposure) is a judgement call; (d) the public key package is assumed authentic.
- Concurrent sessions per signer are unsupported (one pending nonce set).

STATUS: DONE
