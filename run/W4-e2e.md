# W4: Regtest end to end with the Rust FROST signer (T8)

Read `run/RULES.md` first. Work-package id: `w4`. You touch two repos:

- **frost-sp-rs:** branch `feat/w4-e2e` off `frost-sp`, worktree `/work/frost-sp-poc-wt/w4`. PR against `frost-sp`.
- **blindbit-testkit:** keep working on W3's branch `feat/external-signer-wallet` in `/work/blindbit/blindbit-testkit-frost`, and push to the same PR #28. Do **not** merge it. Follow that repo's `CLAUDE.md` and `.claude/skills`.

Read these first:
- `run/w2-SUMMARY.md` (its "Hand-off for W4" lists the gaps to close)
- `/work/blindbit/blindbit-testkit-frost/run/w3-SUMMARY.md`
- `/work/blindbit/blindbit-testkit-frost/docs/external-signer.md`

## Scope

### 1. Signer CLI

Build a `frost-sp-signer` binary, as a new `crates/frost-sp-cli` or a `[[bin]]` in `frost-sp-wallet`, implementing `docs/external-signer.md` exactly: env for wallet config, JSON on stdin, `{tx_hex}` or `{error}` on stdout.

- **PoC key handling:** it loads a state file holding all `n` key packages (trusted dealer) and runs a `t`-of-`n` session in process: ECDH shares and proofs, then FROST rounds, using W2's `send` module. Label it as PoC-only.
- **Spend-exactly-these planner:** the spec spends every given UTXO.
  - Keep the `Σg = 0` guard. When it trips, return a clear `{error}`.
  - Change goes to the wallet's own SP change address (label `m = 0`).
- **A `dealer` subcommand:** writes the state file and prints `scan_secret`/`spend_pubkey` for scenarios.

### 2. Test-kit change for SP change

**Decision (orchestrator):** an SP-only wallet's change is a Silent Payment to itself.

- Extend the test kit so a pubkey wallet can declare SP change (e.g. `change = "sp"`).
- The test kit binds it by running that wallet's own receiver with its scan secret, the same way it binds recipients.
- Undeclared taproot change stays refused.

### 3. Scenarios

Generate the keys with your dealer and commit them as test constants in new scenario files.

- `frost-rs-roundtrip.toml`:
  1. The FROST wallet receives at least 3 payments (labelled and unlabelled).
  2. It spends 2 or more of them in one transaction to another SP wallet, with SP change.
  3. The recipient detects its output.
  4. The FROST wallet detects its change, both live and on rescan.
- Choose the inputs so that `Σg ≠ 0`. With fixed keys this is deterministic; check it.
- If the test kit can express an expected signer refusal, add a case where `Σg = 0` must be refused. Otherwise cover it in a Rust test that drives the CLI.

### 4. Run

Run with `TESTKIT_EXTERNAL_SIGNER=<path to release binary>` at T0 (`-tier lib`) and T2 (`TESTKIT_REGTEST=1`, real bitcoind). Quote the results, including bitcoind accepting the FROST-signed transaction. Re-run W3's mock scenarios to show nothing regressed.

### 5. Small follow-ups

- Pin `frost-secp256k1-tr = "=3.0.0"` (Opus F5).
- Remove the dev-profile opt-level override only if build times stay acceptable without it; say which you chose.

## Out of scope

- Changes to blindbit-oracle, blindbit-rs, friglet or go-bip352. Describe them instead, including W3's go-bip352 label-sign observation, which you may confirm with a read-only test.
- The GUI.

## Deliverable

`run/w4-SUMMARY.md` on `feat/w4-e2e`, plus a copy at `/work/frost-sp-poc/run/w4-SUMMARY.md`, in the RULES format, with both PR URLs.
