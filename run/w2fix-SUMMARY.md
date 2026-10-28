# w2fix summary

## State
Opus W2 review findings F1-F5 fixed with tests on `fix/w2-review`; workspace tests and clippy green; PR open against `frost-sp`, not merged.

## Built
- F1: `validate_public_key_package` in `crates/frost-sp-wallet/src/send.rs`, called in `sign_send_inner` before any DLEQ is accepted. Checks group key, own `X_i`, and `sum lambda_i X_i == X` for the signing set. Tests: `f1_substituted_verifying_share_with_matching_d_is_refused_by_every_signer`, `f1_package_with_wrong_own_share_or_group_key_is_refused`.
- F2: `exposure.rs` counts distinct non-self scan keys only; abort counting and `ecdh_pending` removed. Public reset replaced by `Signer::rotate` (new key material + reset; refuses the same group key). In-memory-only documented. Tests: `f2_aborts_on_one_scan_key_cost_nothing_distinct_keys_do` (1000 aborted sessions), `exposure_limit_blocks_release_until_rotation`, `signer_refuses_ecdh_at_the_exposure_limit`.
- F3: doc comment on `ecdh_for_outputs` (culprit ids unauthenticated).
- F4: one-line comments (change last, locktime 0), no code change. F5: `nonzero_input_hash` + unit test.
- Tests: `cargo test --workspace --exclude psbt-viewer` all ok (e.g. send_e2e 27 passed, spend_e2e 18 passed, frost-sp-wallet unit 1 passed); `cargo clippy -p frost-sp-wallet --all-targets` no warnings.
- Review: own diff read-through (full gstack /review multi-agent run not executed). Codex review: `run/w2fix-CODEX-REVIEW.md`, one Low finding (reset not tied to signer key), fixed via `Signer::rotate`; rest clean.

## To-do
- Orchestrator: merge PR; W4 may conflict in `send.rs`/`spend.rs` (small edits only).

## Decided
- Validation runs at sign time, not in `with_public_key_package`, to keep its infallible signature (W4 compatibility).
- Reset API moved from the counter (now crate-private) to `Signer::rotate` after the Codex finding.

## Not done / not verified
- Full `/review` skill pipeline and `/qa` not run; no regtest.
- F4 shuffling and anti-fee-sniping left as is per brief.
- Exposure counter is in-memory; restart resets it (documented).

STATUS: DONE
