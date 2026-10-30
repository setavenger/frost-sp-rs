# W5 summary: real distributed key generation, with its checks

## 1. State
The wallet's keys now come from a byte-level DKG between devices that each hold one share. D1–D11 pass, as do the DKG-based spend/send e2e suites and T8 on regtest with DKG device files. The work is in PR https://github.com/setavenger/frost-sp-rs/pull/4 (base `frost-sp`, not merged), and the testkit constants are pushed to https://github.com/setavenger/blindbit-testkit/pull/28 (`85f844d`, not merged).

## 2. Built

**frost-sp-rs, branch `feat/w5-dkg`:** commits `d524808` (feature) and `3ab8a90` (review fixes).

`crates/frost-sp-wallet/src/dkg/` is new:

| File | What it does |
|---|---|
| `mod.rs` | `Params`: sorted host keys plus `t` and `n`. Refuses `t<2`, `t>n`, `n∉[2,32]`, duplicate hosts and same-x hosts. Also holds the session id, `DkgError` with culprit, the echo hash, the transcript `T` and the check code. |
| `wire.rs` | Strict envelope: magic, version, kind, session, sender, recipient, length, payload. Plaintext kinds carry a BIP 340 host-key signature. |
| `channel.rs` | Round-2 sealing: ECDH of the host keys, then HKDF-SHA256 (salt = session id; info binds both host keys and both ids), then ChaCha20-Poly1305. Random 12-byte nonce; AAD = session ‖ sender ‖ recipient. |
| `device.rs` | `Device` holds only its own host key, RNG, ZF secret packages and finally its `DeviceKey`. Steps run in order: start (`part1`, and device 1 draws `b_scan`), round 1, echo, round 2 (`part2` runs only after all `n−1` echoes match, then the shares are sealed), round 2 open (`part3`, key checks, sign `T`), certificate. Any refused message aborts the device for good. |
| `ceremony.rs` | Coordinator and network that move only `Vec<u8>`. Keeps the full log. A per-round hook can read, drop, replace, reorder, add or misroute messages, and any seat can be a cheating `Participant`. `keygen()` runs an honest ceremony. |
| `key.rs` | `DeviceKey` plus `Certificate`. `verify()` recomputes the session id and rebuilds the public key package from the round-1 commitments. It checks `X_i == x_i·G`, that every `X_i` lies on one degree-`t−1` polynomial (`n−t+1` interpolation checks), `T`, and all `n` signatures. |

Other changes in `frost-sp-wallet`:
- `group.rs`: `trusted_dealer`, `from_secret` and `reconstruct_for_tests` sit behind `cfg(test)` / the `test-dealer` feature. `cargo tree -p frost-sp-cli -e normal,features -i frost-sp-wallet` shows only `default`. `FrostGroup::from_device_keys` gathers DKG output for tests.
- `tests/common::env` and `spend_e2e::world` now build groups with `dkg::keygen(2, 3, seed)`. T1 (`t1_vectors`, `t1_sending`) stays on the test-only dealer split, because the vectors fix `b_spend`.

`crates/frost-sp-cli`:
- `keygen --n --t --out-dir [--seed] [--network]` writes one `device-<i>.json` per device: mode 0600, never overwritten, and either all files or none.
- The signer takes one `--state` per device (at least `t`), and each file gets its own `Signer`.
- `reconstruct-test-secret` is test-only and re-derives the group from its recorded seed.
- Fixtures are `tests/fixtures/frost-rs-roundtrip/device-{1,2,3}.json`, made with `keygen --seed 352`: check code `9b86-bf13-29f1`, `B_spend 02e92500…2831`.

**blindbit-testkit, branch `feat/external-signer-wallet` (PR #28):** `scenarios/frost-rs-roundtrip.toml` (new `scan_secret`, `spend_pubkey`, mock `--spend-secret`), `internal/scenario/scenarios_test.go` (`frostRSAddress`) and `docs/external-signer.md`.

Evidence on the final commit `3ab8a90`:
- `cargo test --workspace --exclude psbt-viewer`: every suite ok, 149 passed and 0 failed.
  - CLI: `16 passed; 0 failed`.
  - Wallet unit and DKG: `23 passed`.
  - `send_e2e`: `32 passed`.
  - `spend_e2e`: `18 passed`.
  - `t1_sending`: 1; `t1_vectors`: 1; `t6_dleq_vectors`: 2.
  - Other crates: bip375-helpers 29, frost-signer 25, multi-signer 2.
- `cargo clippy -p frost-sp-wallet -p frost-sp-cli --all-targets`: `Finished`, 0 warnings. Workspace clippy with `--exclude psbt-viewer` also exits 0; its remaining warnings are in upstream examples only.
- Go: `go vet ./...` is clean, and `go test -count=1 ./...` reports `ok` for all 21 packages that have tests.
- **T0** (Rust signer, lib tier, full-basic): `status: PASS`, `8 payments: 8 must-find (8 found)`. It passed with `--state device-1 --state device-2` and again with devices 1 and 3 on the final binary.
- **T2 / T8** (`TESTKIT_REGTEST=1`, bitcoind 30.3, signer `--state device-2.json --state device-3.json`, final binary):
  ```
  e2e_test.go:302: frost-rs-roundtrip full-basic: pass, 8 must-find found, 0 expected-absent absent, findings []
  e2e_test.go:302: frost-rs-roundtrip full-dust: pass, 8 must-find found, 0 expected-absent absent, findings []
  --- PASS: TestRegtestShippedScenarios/frost-rs-roundtrip/full-basic (97.00s)
  --- PASS: TestRegtestShippedScenarios/frost-rs-roundtrip/full-dust (97.13s)
  --- PASS: TestRegtestShippedScenarios/frost-rs-roundtrip/cut-through-dust (99.29s)
  ok  	github.com/setavenger/blindbit-testkit/internal/regtest	293.441s
  ```
  - bitcoind accepted both FROST-signed spends. In every config, `wallet frost … agree on 6 outputs` and `wallet bob … agree on 2 outputs` hold live and on a fresh rescan, and `to-bob`, `to-bob-labelled`, `frost-change` and `frost-change-2` exist only in those two spends.
  - The cut-through findings (`frost-in-1..3` served) are the pinned expected ones, the same as in W4.

| ID | Status | Test(s) |
|----|--------|---------|
| D1 | pass | `d1_honest_2_of_3` and `d1_honest_3_of_5`: same `X`, `B_scan`, check code and certificate on every device. Every `t`-subset gives a BIP 340 signature under `X` and under `X+τG`, and test-only reconstruction gives `x·G == X`. `d1_keygen_is_reproducible_only_with_the_same_seed` also passes. |
| D2 | pass | `d2_bad_proof_of_knowledge_names_the_culprit`; `d2_rogue_key_attempt…`, where `C_0 = target − ΣC_0` would have made `Σ C_0 = target`. Honest devices abort with `ProofOfKnowledge{culprit}` and send no share. |
| D3 | pass | `d3_inconsistent_share…`: device 3 gets `SecretShare{culprit: 2}`, the others get `Missing([3])`, and none accepts. |
| D4 | pass | `d4_equivocation…`: `ViewMismatch` with 0 round-2 messages in the log. Control test: without the echo check, devices 1 and 3 finish part 3 with different `X`. |
| D5 | pass | `d5_flipped_ciphertext_bit…`: `Decrypt{sender: 1}`, and device 2 sends no certificate signature. |
| D6 | pass | `d6_log_holds_no_share_and_no_scan_key_{2_of_3,3_of_5}`: no sent share, final share, host secret or `b_scan` appears in any logged message. |
| D7 | pass | Replay gives `WrongSession`. A swapped sender gives `BadSignature` in round 1 and `Decrypt` in round 2. Misrouting gives `Misrouted` in round 1 and round 2. Duplicate and missing messages are also covered. |
| D8 | pass | `d8_different_scan_keys…`: 6 certificate signatures are sent, all three devices fail with `Certificate`, and none accepts. `d8_scan_key_from_anyone_but_device_1…` also passes. |
| D9 | pass | Dropped or forged certificate signature: `Missing` / `Certificate` (`d9_missing_or_forged…`). Stored key with a tampered signature, removed signature, wrong T, wrong nonce, another ceremony, wrong host or wrong scan key: refused (`d9_a_stored_key…`). CLI: `d9_signer_refuses_a_state_file_without_a_valid_certificate`. |
| D10 | pass | `d10_bad_parameters_and_unknown_participants…`: `t>n`, `t<2`, `n` out of range, duplicate and same-x hosts, outsider device, coordinator seat, sender 9. CLI: `d10_keygen_refuses…`. |
| D11 | pass | `d11_each_device_file_holds_exactly_its_own_signing_share`: each file holds its own share hex and no other's, and an injected `key_packages` field is refused. `d11_a_device_key_debug_print_shows_no_secret` also passes. |
| T1 | pass, dealer split | `bip352_receiving_vectors_with_frost_shares` and `bip352_sending_vectors_with_threshold_ecdh`, both on the test-only dealer. |
| T2/T3/T5/T7 | pass on DKG groups | `spend_e2e` and `send_e2e`, and the CLI tests on the DKG fixture. |
| T8 | pass | T2 above. |

## 3. To-do
| Owner | Item | Blocker | ID |
|---|---|---|---|
| orchestrator | Merge PR #4 into `frost-sp`; PR #28 now carries `85f844d` | review | W5-MERGE |
| Opus | Review the `NEEDS-OPUS-REVIEW` decisions below | none | W5-OPUS |
| later | Separate OS processes and a real transport; ChillDKG-style recovery backup; persisted exposure counter | out of scope | W5-LATER |
| later | Zeroize host secret, `b_scan` and `DeviceKey` copies (`SecretKey` is plain and `DeviceKey: Clone`) | PoC | W5-ZEROIZE |
| later | Forward secrecy for round 2 (ephemeral ECDH per session) | brief specifies static ECDH | W5-FS |
| maintainer | `psbt-viewer` does not compile on `frost-sp` either: it `include_str!`s `../../../../bips/bip-0375/…`, which lies outside the repo | upstream example | W5-PSBTVIEWER |

## 4. Decided
- Plaintext DKG messages (round 1, echo, certificate) are BIP 340-signed by the sender's host key. The brief only asks to refuse wrong senders, and that needs authentication; the coordinator is untrusted. `NEEDS-OPUS-REVIEW`: the same host key now signs and does the ECDH.
- Host-key signatures use deterministic BIP 340 nonces (zero aux randomness) so that seeded ceremonies are reproducible. BIP 340 allows this; aux randomness only hardens against side channels.
- ZF's `post_dkg` BIP 341 "unspendable script" tweak is kept, so `X = P + H_TapTweak(P)·G`. Every device computes it identically, and SP adds no further tweak; this is checked by D1 and T8. `NEEDS-OPUS-REVIEW`.
- Any refused message aborts the device for the session (no retries or partial rounds). This is conservative, and a coordinator can always stall anyway.
- `ViewMismatch`, `Decrypt`, `Duplicate`, `Missing` and `Certificate` name no culprit, because the untrusted coordinator could cause each of them. PoK, share and scan-key failures do name one.
- The echo hashes the canonical round-1 bytes; non-canonical encodings and wrong commitment lengths are refused before the echo.
- Each simulated device gets its own ChaCha12 `StdRng`, seeded with 32 bytes from the caller's RNG (OsRng normally, seeded StdRng for `--seed`).
- `n` is capped at 32: load checks grow with `n³`, and QA saw `--n 100` run for more than 2 minutes.
- The D tests live inside the crate (`src/dkg/tests.rs`), because the D4 control needs a `cfg(test)` echo-skip knob and D6 needs the sent shares. Nothing test-only reaches non-test builds.
- The trusted dealer sits behind the `test-dealer` feature, enabled only by the wallet's self dev-dependency. The CLI's normal build does not enable it; see `cargo tree` above.
- Device files are strict (`deny_unknown_fields`) and fully re-verified on load. `check_code` and `spend_pubkey` are recomputed and must match.
- `reconstruct-test-secret` re-derives the group from `test_only_seed` before trusting it (fixes /review #1 and QA #2). On the signer path the mark stays advisory: seeded files are refused on mainnet, and a hand-edited mark is out of scope (/review #2, documented).
- The signer refuses unseeded device files that others can read. Seeded fixtures are exempt because git checks them out 0644.
- keygen prints `scan_secret` only for seeded runs, and writes all files or none (fixes /review #5 and QA #1).
- `--signing-set` was dropped: the signing set is the set of loaded device files.
- T8 used devices 2 and 3 on regtest and devices 1+2 and 1+3 at T0, so three different `t`-subsets signed.
- **Rebutted, /review #3** ("host list needs pinning outside the files"): `BLINDBIT_SIGNER_SPEND_PUBKEY` anchors the files. A forged ceremony can only reuse a real share under fake host keys, which gains nothing, and mixing it with genuine files fails the certificate-equality check.
- **Rebutted, /review #4** (feature unification in workspace test builds): the CLI builds without the feature, and its normal build tree shows `default` only.
- **Not changed:** QA #7 (pretty-printed JSON is still one document); env-mismatch errors still come after the request parses (cosmetic).

## 5. Not done / not verified
- **Out of scope:**
  - Separate OS processes or machines, and real transport (files, nostr).
  - ChillDKG recovery backup.
  - Persisting the exposure counter.
- **Gstack flow:**
  - `/autoplan` was not run as a skill. The plan (`run/w5-PLAN.md`) was written from the brief, which already fixed the design.
  - `/review` ran in a Sonnet subagent, which did the review by hand and skipped the skill's telemetry, Greptile and specialist steps.
  - `/qa` ran in a Sonnet subagent as `qa-only` CLI checks, with no valid spend request; spends are covered by T0, T2 and the CLI tests.
  - `/ship` was a push plus `gh pr create`: the repo has no VERSION or CHANGELOG.
- **Codex review** (`run/w5-CODEX-REVIEW.md`): no actionable findings. It reviewed commit `d524808` and was not re-run after the fixes in `3ab8a90`.
- **First T2 attempt:** it hit Go's default 10-minute timeout while docker tore down the full-basic stack. The leftover containers, volumes and networks (`bbtk-t2-c83e9f37`, `bbtk-t2-9f453393`) were removed by hand. The re-run with `-timeout 30m` passed, and no `bbtk` containers or volumes remain.
- **Mock regression:** the testkit's T2 mock scenarios (`frost-receive`, `frost-roundtrip`) were not re-run on regtest; only `go test ./...` (lib tier) ran. The `frost-rs-roundtrip` mock path ran green in the lib-tier suite with the new secret.
- **Workspace build:** `cargo test --workspace` and `cargo clippy --workspace` need `--exclude psbt-viewer`, which was already broken on `frost-sp` (W5-PSBTVIEWER).
- **No load-time PoK check:** a loaded device file's round-1 proofs of knowledge are not re-verified, because ZF keeps that function crate-private. The certificate signatures and the commitment-derived key package are verified.
- **Panes:** the Codex pane `w18:pJ` and the regtest pane `w18:pM` are closed.

STATUS: DONE
