# W4 summary: regtest end to end with the Rust FROST signer (T8)

## 1. State
The Rust FROST signer (`frost-sp-signer`) signs the test kit's spends at T0 and T2, and bitcoind accepts its transactions (3-input spend with SP change, then a spend of that change); both PRs are open and not merged.
PRs: https://github.com/setavenger/frost-sp-rs/pull/3 (base `frost-sp`) and https://github.com/setavenger/blindbit-testkit/pull/28 (W3's PR, two more commits pushed).

## 2. Built
**frost-sp-rs, branch `feat/w4-e2e`** (merged `origin/frost-sp` after PR #2, no conflicts, tests re-run):
- `crates/frost-sp-cli`: `frost-sp-signer` (`docs/external-signer.md`: env, JSON stdin, `{tx_hex}`/`{error}`), PoC state file with all key packages, `dealer` subcommand (seeded, `--print-group-secret` for the mock), README.
- `send::plan_spend_exact` (`crates/frost-sp-wallet/src/send.rs`): spends exactly the given coins in order, keeps the Σg = 0 guard, SP change last, checked money arithmetic, per-script dust, no-change burn limit. Signers' fee sums are now checked too.
- `frost-secp256k1-tr = "=3.0.0"` pinned; dev-profile opt-level override removed.
- `run/w4-PLAN.md`, `run/w4-CODEX-REVIEW.md`.

**blindbit-testkit, branch `feat/external-signer-wallet`:** `change = "sp"` for pubkey wallets and `change = true` recipients (`internal/scenario`, `internal/extsigner`, `internal/judge`, `internal/tier/lib`, `internal/regtest`), mock signer pays SP change, `scenarios/frost-rs-roundtrip.toml` (dealer seed 352 constants; 4 payments plain and m=7, spends 3, SP change, spends the change), docs and README.

Evidence:
- Rust: `cargo test -p frost-sp-wallet -p frost-sp-cli -p frost-signer -p bip375-helpers`: 119 passed, 0 failed. `cargo clippy -p frost-sp-wallet -p frost-sp-cli --all-targets`: 0 warnings. Full test run is under 10 s without the opt-level override (**decision: removed**).
- Go: `go vet ./...` clean; `go test -count=1 ./...` all packages ok; `testkit mutate -tier lib`: 8 caught, 0 failed, 0 undetectable.
- **T0 with the Rust signer** (`TESTKIT_EXTERNAL_SIGNER="…/frost-sp-signer --state …/frost-rs-roundtrip-state.json" testkit run -tier lib -backend lib -index-mode full-basic -scenario scenarios/frost-rs-roundtrip.toml`): `status: PASS`, `8 payments: 8 must-find (8 found)`.
- **T2 with the Rust signer** (`TESTKIT_REGTEST=1`, real bitcoind 30.3, final binary after the merge and review fixes): `--- PASS` for `frost-rs-roundtrip` under full-basic, full-dust and cut-through-dust, `ok … 274.743s`. The run mines the signed transactions, so bitcoind accepted them; friglet finds all 6 FROST outputs (4 payments + 2 SP change) live and on a fresh rescan, and bob finds both his outputs.
- **Regression, T2 with the mock signers** (no override): `frost-receive`, `frost-roundtrip`, `frost-rs-roundtrip` x 3 configs, all PASS, `ok … 659.167s`.

| ID | Status | Evidence |
|----|--------|----------|
| T8 | pass | T2 above; the Rust signer plugged in with `TESTKIT_EXTERNAL_SIGNER` |
| T2 | pass | consensus-verified in the signer (libbitcoinconsensus) and accepted by bitcoind |
| T3, T7 | pass on the CLI path | CLI test passes a wrong `tweak: 1111…` and still signs; coins with parities (+,+,−); change is spent via the label-0 tweak at T2 |
| T5 | pass (CLI) | Σg = 0 refused, wrong value/scan secret/group key refused, mainnet SP address refused, wrapping and zero amounts refused |
| Σg = 0 | covered in Rust | `refuses_inputs_whose_parities_cancel` in `crates/frost-sp-cli/tests/cli.rs`; the testkit scenario spends 3 inputs, so Σg is odd and never 0 whatever the txids (the mock would sign Σg = 0, so it is not a scenario) |

## 3. To-do
| Owner | Item | Blocker | ID |
|---|---|---|---|
| orchestrator | merge Rust PR #3 into `frost-sp` and testkit PR #28 | review | W4-MERGE |
| maintainer | go-bip352: label matching compares only the label point's x coordinate (`receive.go:182`, `bytes.Equal(labelMatch[1:], label.PubKey[1:])`), so an output built with the negated label is matched with a tweak that cannot spend it; separate issue/PR | out of scope here | W4-GOBIP352 |
| later | persist the exposure counter; real DKG / one key package per machine | PoC scope | W4-LATER-1 |
| later | `Verify` still ignores nLockTime/sequence/standardness | low | W3 follow-up |

## 4. Decided
- SP change = declared `change = "sp"` on the wallet plus one `change = true` recipient (last, no amount/label, pays the spender); the request carries the m = 0 address as `change_address`. Reason: reuses the recipient binding, expectations and ledger machinery.
- The judge compares a change output's reported amount with the amount the verified spend bound; dust-filtering configs assume change qualifies and the judge refuses a run where it did not. Reason: Codex #3/#4.
- Shipped scenario signer is the mock with the dealer's reconstructed secret (`--print-group-secret`), the Rust binary overrides via env. Reason: shipped suites stay green without a Rust toolchain.
- Scenario spends 3 inputs. Reason: an odd count makes Σg ≠ 0 independent of funding txids.
- `tsp` accepted for regtest/signet in the signer (BIP 352 shared namespace); `sp` only mainnet.
- Codex findings 1-7 all fixed (0600 state file, checked money arithmetic and zero amounts, SP network check, per-script dust in Rust and mock, judge amount, dust-filter loader, change-only rejected). Not re-reviewed by Codex after the fixes.
- Pinned T2 findings for the new scenario: none for full-basic/full-dust (both spends pay the wallet, so friglet sees them), `served` for the three spent inputs under cut-through-dust.

## 5. Not done / not verified
- Gstack flow abbreviated as in W1-W3: `/autoplan` = plan written from the brief; `/review` = own pass plus Codex; `/qa` = test suites plus the CLI paths (`dealer`, signer via T0/T2, error paths in `cli.rs`) and no separate skill run; `/ship` = push and `gh pr create`.
- `NEEDS-OPUS-REVIEW`: (a) the CLI runs all cosigners in one process, so the nonce/round isolation between machines is untested; (b) the burn limit (10x fee) and dust choices are judgement calls; (c) signers still trust the coordinator-supplied public key package as in W2.
- No Σg = 0 case at testkit level (mock cannot refuse); Rust CLI test only.
- Codex was not re-run after the fixes; the testkit's replay and GUI tiers were not run (pubkey wallets are refused there by design).
- go-bip352 label-sign: confirmed by reading the source (`receive.go:166-183`), not by a test.
- Pane `w18:pC` (T2 runs) is closed below; Codex pane closed earlier.

STATUS: DONE
