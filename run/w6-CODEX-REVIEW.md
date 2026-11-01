# W6 Codex review

No actionable correctness or security bugs were identified in the changes from `frost-sp` to `w6-demo-trace`.

- Reviewed head: `38d6fe1d2e343f59aa6af36f2d5a4509ebcd7ada`.
- Base and merge base: `207a2f7fadc8a12e31bf86748e6bcd7515939de0`.
- Scope: the full 13-file branch diff, with particular attention to `FROST_SP_TRACE`, its callers, and surrounding key math, parity, tweaks, DLEQ verification, signer approval checks and nonce handling. No source or test code was edited.

## Findings

None.

## Security and behavior checks

- `crates/frost-sp-wallet/src/trace.rs:15` and `:28`: unset and empty values disable file access. Records are serialized as JSON, appended, and newly created files use mode 0600 on Unix. Trace-only computations do not consume the signing/DKG RNG. Some callers eagerly construct JSON while tracing is disabled; this adds allocation/computation but no observed change to cryptographic results or decisions.
- `crates/frost-sp-wallet/src/dkg/ceremony.rs:235`: the DKG record selects public keys, verification shares, hashes, counts, certificate checks and errors. It does not serialize device keys, round-2 plaintexts, signing shares, host secrets or channel material. `crates/frost-sp-cli/src/lib.rs:258` selects public output fields explicitly, excluding the seeded output's scan secret and the seed itself. The AEAD/HKDF path in `crates/frost-sp-wallet/src/dkg/channel.rs:41` has no trace hook.
- `crates/frost-sp-wallet/src/send.rs:415`, `:783` and `:1061`: input records contain the allowed re-derived tweaks and comparisons; ECDH records contain points and BIP 374 proofs. The combined ECDH point is explicitly marked test-only. These values are wallet-private demo data, not the prohibited secret scalars or channel keys.
- `crates/frost-sp-wallet/src/send.rs:1198`: the logged hiding/binding values come from public `SigningCommitments`, not `SigningNonces`. The logged scalar responses are signature shares, not long-term signing shares. Secret nonce pairs remain in signer state and are taken before validation at `send.rs:806` and `spend.rs:192`; tracing introduces no reuse or extra random draws. The pinned FROST core also checks each signer's commitment against its pending nonces before signing.
- `crates/frost-sp-wallet/src/send.rs:827`: signers still independently re-derive input tweaks, enforce the parity guard, validate the signing set/public package, verify every supplied DLEQ proof, recompute approved outputs, and check amounts, fees and sighashes before signing. The trace check record follows those checks at `:926`. Plain tweaks and subsequent BIP 340 parity normalization remain unchanged. Final signature and consensus errors still propagate after their status is recorded at `:1225` and `:1241`.
- `crates/frost-sp-wallet/src/spend.rs:176`: traced refusal reasons were followed to their producers; the reviewed error paths report reasons and identifiers, without formatting prohibited secret values.

## Validation

`cargo test -p frost-sp-wallet -p frost-sp-cli --all-targets` passed: **96 tests, 0 failures** across 10 test binaries. Log: `/tmp/w6-codex-tests.log`.

This includes `tests/trace.rs::trace_holds_no_secret_not_even_a_nonce_and_stops_when_unset`, the CLI tests `trace_records_keygen_and_a_spend_and_no_secret` and `without_frost_sp_trace_no_file_is_written`, BIP 352/374 vectors, mixed parity/label tests, malicious-coordinator refusals, and nonce reuse refusals. The trace tests search for signing shares, tweaked shares, host secrets, scan/group secrets and their negations; the in-process test additionally reproduces and searches the actual FROST nonce scalars.

A separate CLI probe ran keygen with identical seed 4077 and tracing unset, empty, enabled, and unopenable. All four succeeded with byte-identical device files and equal public JSON output; the enabled trace contained two valid JSONL records. Evidence: `/tmp/w6-codex-differential-avk7q3fp/`.

`git diff --check frost-sp...w6-demo-trace` passed. A separate native adversarial reviewer found no actionable issues; it reviewed non-test source and surrounding paths, with test changes in summary mode. The primary review read the full test diff and ran the tests above.

Limits: no full-workspace/clippy or live bitcoind/testkit run was performed for this review. The hex-search tests do not dynamically enumerate DKG channel keys or prove secrecy for every possible execution; exclusion of AEAD/HKDF material was checked by source/data-flow inspection. The differential probe covers keygen, not byte-for-byte signing equivalence. This is a branch review, not a proof of the entire underlying protocol.
