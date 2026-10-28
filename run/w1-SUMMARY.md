# W1 summary: FROST layer and receiving

## 1. State
`crates/frost-sp-wallet` receives BIP 352 outputs for a 2-of-3 FROST group and spends one received output with FROST under `P_k = X + tau*G` (single input, plain P2TR payout); T1, T2, T3, T7 pass, other T-IDs are out of W1 scope. Branch `feat/w1-receive`, commits `57bad5a`, `ac553bb`; not merged, no `origin`, so no `/ship`.

## 2. Built
- **FROST layer, option (a), no patch** (`src/tweak.rs`): `frost-secp256k1-tr` 3.0 plain `round2::sign`/`aggregate` skip the taproot tweak (only `*_with_tweak` adds it) and negate for even Y after whatever key they get. `tweak_key_package` adds `tau` to each share, `tau*G` to each verifying share and the group key; `tweak_public_key_package` does the same for the public package. `x + tau` is never formed.
- `src/group.rs`: trusted dealer (PoC only) `FrostGroup::{trusted_dealer, from_secret}`; shared `b_scan`.
- `src/wallet.rs`: `SpWallet` (addresses via spdk `Receiver`: base, labelled, change m=0; `sp`/`tsp`/`sprt` by `Network`), `scan_tx` -> `OwnedOutput {outpoint, value, script_pubkey, tau, label}`. Own k-loop (K_MAX 2323, labels matched on both output parities); spdk used for input-key extraction, input hash, ECDH secret.
- `src/spend.rs`: `Signer`, `Coordinator`, `SignRequest`, `ApprovedSpend`, `build_spend_tx`, `key_path_sighash`, `verify_consensus`.
- Tests: `tests/t1_vectors.rs`, `tests/spend_e2e.rs`, `tests/common/mod.rs`; vectors in `tests/vectors/` (bitcoin/bips master, file last touched at `3c68d3f`; README names it).

Test output (`cargo test -p frost-sp-wallet`, after the Codex fixes):
```
tests/spend_e2e.rs: test result: ok. 14 passed; 0 failed
tests/t1_vectors.rs: test result: ok. 1 passed; 0 failed
T1: 30 receiving cases, 99 FROST signatures verified, 10 labelled outputs   (printed before the Codex fixes)
T2/T3: 96 spends consensus-verified; P_k even/odd = 47/49; X even/odd = 44/52   (printed before the Codex fixes)
```
Before the Codex fixes: `cargo test --workspace --exclude psbt-viewer` all `ok` (frost-signer 25, bip375-helpers 29, multi-signer 2, W1 11+1). `cargo clippy --workspace --all-targets --exclude psbt-viewer` clean for `frost-sp-wallet` and finished (other crates keep their old warnings), re-run after the fixes.

| ID | Status | Evidence |
|----|--------|----------|
| T1 | pass | every receiving case of the BIP 352 vector file: addresses, outputs and `tau` == vector `priv_key_tweak` (K_max case: count), 3 signer sets sign `sha256("message")`, BIP 340 verifies under each output key |
| T2 | pass | BIP 340 verify + libbitcoinconsensus with taproot flag; negative test shows flipped sig bit and wrong prevout amount fail. No bitcoind here, so no `testmempoolaccept` |
| T3 | pass | 96 spends: labelled/unlabelled/change, P2WPKH and P2TR (odd/even) funding inputs, 2-input funding, both parities of `P_k` and `X`; `tau` compared with an independent test sender |
| T7 | pass | signer re-derives `tau` from funding tx + own `b_scan`; wrong tweak hint, lying prevout scripts, wrong `b_scan` all refused |
| T4-T6, T8 | not in W1 | W2/W3 |

Partial T5 (refusals present): swapped output, FROST message != sighash, wrong tweak hint, excess fee, wrong coin, nonce reuse after refusal.

### Hand-off for W2: FROST-layer API
- Sign with a tweak: `let kp = tweak::tweak_key_package(&key_package, &tau)?` then plain `frost_secp256k1_tr::round2::sign(&signing_package, &nonces, &kp)`. Aggregate with `tweak::tweak_public_key_package(&pkp, &tau)?` then `frost_secp256k1_tr::aggregate`. Never use `sign_with_tweak`/`aggregate_with_tweak`. `tau: [u8;32]` big-endian, `t_k + l_m`.
- `wallet::SpWallet::new(b_scan, B_spend, Network)`, `.add_label(m)`, `.address(Option<u32>)`, `.scan_tx(&Transaction, &[prevout_spks]) -> Vec<OwnedOutput>`.
- `spend::Signer::new(name, KeyPackage, SpWallet)`, `.commit(rng)`, `.sign(&SignRequest, &ApprovedSpend)`. `SignRequest` has the funding tx, its input prevout scripts, the funding vout, the spend tx, the `SigningPackage` and an untrusted `coordinator_tau_hint` (compared, never used). There is no tweak parameter. Nonces are taken out of the signer before any check, so a refused session cannot reuse them.
- `spend::Coordinator::{signing_package, finalize}`; `finalize` re-checks input, outpoint and sighash before attaching the witness.
- For a multi-input spend each input needs its own `tau_j`: sign each input with its own tweaked package, and the FROST message per input is that input's sighash.

### Hand-off: places that assume a single input
1. `Signer::sign` (`spend.rs`): `spend_tx.input.len() == 1`, one funding output, one `tau`, prevout list is one element.
2. `key_path_sighash` signs input index 0 with `Prevouts::All([one])`.
3. `Coordinator::finalize` sets `tx.input[0].witness` and checks `input.len() == 1`.
4. `Coordinator::signing_package` makes one message for one sighash.
5. `ApprovedSpend` holds one outpoint.
6. `build_spend_tx` builds 1-in-1-out.
7. `verify_consensus` checks input 0 only.
8. Sending side (W2) must handle the parity sum `sum_j g_j` and per-input `tau_j` (RULES Math); nothing here computes `g_j` because W1 has no sender.

## 3. To-do
| Item | Owner | Blocker | ID |
|------|-------|---------|----|
| Sending to SP addresses with threshold ECDH + DLEQ, multi-input | W2 | uses the API above | W2 |
| Regtest end to end, `testmempoolaccept` | W3 / orchestrator | bitcoind not on this VM | T8 |
| Fix `psbt-viewer` build (needs sibling `bips` checkout) | orchestrator | environment, pre-existing | W1-ENV-1 |
| Remove duplicate k-loop if spdk adds K_max and k tracking | later | upstream change | W1-LATER-1 |

## 4. Decided
- FROST option (a): the library's plain sign/aggregate already skip the taproot tweak and negate after tweak, so no patch, no vendoring.
- Own k-loop instead of `Receiver::scan_transaction`: the spdk loop ignores K_max (vector with 2324 matches fails) and loses `k`; spdk still supplies input-key extraction, input hash and addresses.
- Tweak API takes `[u8;32]` big-endian: avoids a k256/secp256k1 scalar type clash at the boundary.
- Signer refuses a coordinator tweak hint on mismatch instead of ignoring silently: gives a named culprit (T5/T7).
- `ApprovedSpend` = outpoint + exact outputs + max fee (Codex finding 1): outputs alone let a coordinator burn a different coin to fees.
- Consensus check calls `bitcoinconsensus` directly: rust-bitcoin's `Transaction::verify` leaves taproot off and accepted a corrupted signature in my first negative test.
- Vectors: only BIP 352 fetched (W1 needs only that); BIP 374/375 left to the packages that use them.
- Dev profile opt-level 3 for k256/secp256k1-sys/frost crates in the root `Cargo.toml`: the vector run took 138 s unoptimised, now 0.3 s. This is a global build change; remove it if unwanted.
- Cargo.toml workspace member added for the new crate.

## 5. Not done / not verified
- **Gstack flow was run in reduced form.** `/autoplan`: preamble only, plan written to `run/w1-PLAN.md` from the brief with a self-review; the CEO/eng phases, snapshot tool, outside voices and approval gate were not run. `/review`: no `origin` remote, so no merge-base fetch; I did the core critical pass by hand plus the Codex review, not the specialist army, QA probes or the checklist tooling. `/qa`: not run as a skill; the crate has no binaries, so QA = the test suite above, and the example binaries' CLI paths were not exercised (frost-signer is a GUI app). `/ship`: skipped, no `origin`.
- Codex review: done in a Herdr pane (`run/w1-CODEX-REVIEW.md`); all 3 findings fixed with tests (excess fee/wrong coin, invalid P2TR candidate aborting a scan, `finalize` not checking the sighash). Rebuttals: none. Codex wrote the file only after a second prompt.
- The final workspace-wide test run was before the Codex fixes; after them only `cargo test -p frost-sp-wallet` and workspace clippy were re-run.
- `psbt-viewer` excluded from workspace test/clippy: it fails on a missing `../../../../bips/bip-0375/bip375_test_vectors.json`, unrelated to W1.
- No `testmempoolaccept` (no bitcoind); consensus via libbitcoinconsensus 26 only.
- `NEEDS-OPUS-REVIEW`: (a) tweak/parity handling relies on frost-secp256k1-tr 3.0 `pre_sign`/`pre_aggregate` negating after the tweak; tested across both parities and by libsecp/consensus verification, not formally proven. (b) The signer cannot independently verify the funding transaction is confirmed or that `funding_prevout_spks` are the real prevouts; a lie there only changes the derived key and makes the match fail, but a fake funding tx paid to the wallet's own key would be accepted (needs chain access, out of PoC scope).
- Trusted dealer sees the group secret and `b_scan` (PoC only, labelled in code).
- `Signer::commit` keeps one pending nonce pair; concurrent sessions per signer are unsupported.

STATUS: DONE
