# FROST × Silent Payments PoC: run rules

Shared rules for every worker in this run. Your work-package brief (`run/W<n>-*.md`) adds the scope.

## Goal

A t-of-n FROST wallet that receives and sends BIP 352 Silent Payments, written in Rust and verified by tests. The wallet holds only Silent Payment outputs: every UTXO is an SP output spent through its key path, so there are no script paths or recovery leaves. Nobody ever reconstructs the group secret, except test-only code that checks against test vectors.

Background brief (read only if you need it): https://claude.ai/artifact/VnQsgZmFjaXvKXaU6mjv9n

## How you work

- You run interactively in a Herdr pane on a shared VM. **Every agent you spawn also runs in a Herdr pane.** No headless `codex exec` or `claude -p`, and no `&`/nohup background jobs.
  - Native subagents (the Agent tool) are fine for reading and searching. Use model `sonnet` or `haiku` for them.
- **Panes:**
  - At most two agent panes per tab; open a new tab for more (`herdr tab create --workspace w18 --label <name> --no-focus`).
  - Close every pane you created once its result is collected (`herdr pane close <id>`).
  - Never touch panes you didn't create.
- **Shell:** one simple command per call. No `cd … &&` chains and no inline heredoc pipelines. Write scripts to files.
- **Decisions:** don't stop to ask; decide sensibly. Record every decision with one line of reasoning in your summary.
  - For a hard cryptographic judgement call, pick the conservative option and mark it `NEEDS-OPUS-REVIEW` in the summary.
- **Waste:** if you are waiting on something you know is unnecessary, end it with the smallest safe fix and say so.

## Repos and branches

- **PoC repo:** `/work/frost-sp-poc`, a clone of `macgyver13/bip375-examples` (MIT).
  - Integration branch: `frost-sp` (upstream `frost-signer` plus this run's files).
  - Remote `upstream` is macgyver13's repo. **Never push to it.**
  - `origin` is `github.com/setavenger/frost-sp-rs` (**public**). Push your feature branch there and open your PR against `frost-sp`, never `main`. Don't merge.
- **Your work:** a feature branch off `frost-sp`, in your own git worktree:
  `git -C /work/frost-sp-poc worktree add /work/frost-sp-poc-wt/<wp> -b <branch> frost-sp`
  Commit on your branch. **Don't merge**; the orchestrator merges into `frost-sp`.
- **Starting point:** `examples/frost-signer`. Read its README first; it explains the security model.
  - Key files: `src/frost_spdk.rs` (threshold ECDH, DLEQ, SP derivation, output checks; single input only) and `src/frost_psbt.rs` (local PSBT fields).
  - Dependencies: `frost-secp256k1-tr` 3.0 (ZF), `rust-dleq`, `silentpayments` (spdk).
- **PSBT fields:** add local or proprietary fields as needed. No standardisation write-up.

## Math (normative for this PoC)

**Keys**
- Group secret `x`, shares `x_i`, verification shares `X_i = x_i·G`.
- `B_spend` is the group key `X` (33 bytes).
- Scan key `b_scan` is a plain scalar that every cosigner holds.

**Receiving**
- Output key: `P_k = B_spend + (t_k + ℓ_m)·G`.
- `t_k = H_BIP0352/SharedSecret(ser(input_hash·b_scan·A) ‖ ser32(k))`.
- `ℓ_m = H_BIP0352/Label(ser256(b_scan) ‖ ser32(m))`, or 0 when unlabelled. `m = 0` is change.
- SP outputs carry **no BIP 341 taproot tweak**.
- Spending: produce a BIP 340 FROST signature under `P_k` with a plain tweak `τ = t_k + ℓ_m`, applying even-Y negation after the tweak. The secret `x + τ` is never formed.

**Sending** to a recipient `(B_scan, B_spend')`
1. Validate `B_scan`: on the curve, not infinity, canonical encoding.
2. Each signer `i` in signing set `S` returns `D_i = x_i·B_scan` and a BIP 374 proof for `(A = X_i, B = B_scan, C = D_i)`. There is one `D_i` per distinct recipient scan key per transaction, because all inputs share `x`.
3. For each input `j` with key `x + τ_j` and parity `g_j` (−1 if that key has odd Y):
   `a·B_scan = Σ_j g_j·(Σ_{i∈S} λ_i·D_i + τ_j·B_scan) = (Σ_j g_j)·Σ_i λ_i·D_i + (Σ_j g_j·τ_j)·B_scan`
4. Then compute `input_hash`, `t_k` and the outputs per BIP 352.

**Before signing, every signer:**
- verifies all DLEQ proofs
- recomputes every SP output
- checks each recipient SP address against the one it approved
- checks that the FROST message equals the sighash of the PSBT it verified
- re-derives every input's `τ_j` from the funding transaction with its own `b_scan`, and never uses a tweak the coordinator supplied

**Coin selection:** never pick an input set with `Σ g_j = 0`. In that case `x` cancels out of the input key sum, and the payers of those inputs could compute the shared secret. This is a privacy guard.

## Acceptance tests (IDs used in every summary)

| ID | Check |
|----|-------|
| T1 | Scan results and derived outputs match the BIP 352 vectors. Tests may split a vector's `b_spend` into shares with a test-only trusted dealer, and may reconstruct `x` via Lagrange **in tests only**. |
| T2 | FROST signatures verify as BIP 340, and the finalised tx is consensus-valid (rust-bitcoin + libsecp verification; `testmempoolaccept` on regtest where a node is available). If a BIP 445 port is used, its vectors pass. |
| T3 | Parity `g` and tweak `τ` are correct for every case: labelled and unlabelled inputs, odd and even keys, mixed sets. |
| T4 | Invalid scan keys are rejected: off-curve, infinity, x ≥ p, wrong prefix byte. |
| T5 | Adversarial suite. Every honest signer refuses, and names the culprit where possible, when given: a wrong `D_i`, a bad DLEQ proof, a swapped output script, a swapped recipient address, a FROST message ≠ sighash, or a coordinator-supplied wrong tweak. |
| T6 | BIP 374 vectors pass. DLEQ nonces follow BIP 374 and are separate from FROST nonces, with no reuse after aborted sessions. |
| T7 | Signers re-derive `t_k`/`ℓ_m` from the funding transaction. |
| T8 | Regtest end to end through the BlindBit test kit. |

**Vectors:** fetch them from bitcoin/bips `master` into `tests/vectors/` in your crate, with a README naming the commit hash:
- `bip-0352/send_and_receive_test_vectors.json`
- `bip-0374` CSVs
- `bip-0375` vectors

## Process: the gstack flow is mandatory

1. **Plan:** `/autoplan` on your brief. Save the plan to `run/<wp>-PLAN.md` on your branch.
2. **Implement** with tests.
3. **Green:** `cargo test --workspace` and `cargo clippy --workspace --all-targets` pass. Quote the output tail in your summary.
4. **Review:** commit, then run `/review` on your branch diff with base `frost-sp`.
5. **QA:** run `/qa` in CLI mode: the test suite plus the example binaries' command-line paths end to end. Browser and GUI work are out of scope.
6. **Codex review:** an independent review in a Herdr pane (recipe below). Fix every finding, or rebut it in your summary.
7. **Ship:** run `/ship` with base `frost-sp`: push the branch and open the PR against `frost-sp`. Don't merge.

### Codex review recipe

1. `herdr tab create --workspace w18 --label <wp>-codex --no-focus`
2. Find the new tab's pane with `herdr pane list`.
3. `herdr agent start <wp>-codex --kind codex --pane <pane> -- --dangerously-bypass-approvals-and-sandbox`
4. `herdr pane read <pane>`. If an update prompt shows, choose **skip**; never update Codex. If a trust prompt for this repo shows, accept it. Continue only once the `› Ask Codex` input line is visible.
5. `herdr agent prompt <pane> "<prompt>" --wait --until idle --until done`, with this prompt:
   *"Review branch `<branch>` against `frost-sp` in `<worktree>` for correctness and security bugs (key math, parity, tweaks, DLEQ, signer checks, nonce handling). Write findings, most severe first with file:line, to `<worktree>/run/<wp>-CODEX-REVIEW.md`. Do not edit code."*
6. Read the file, then `herdr pane close <pane>`.

## Deliverable

`run/<wp>-SUMMARY.md` on your branch, **and a copy** at `/work/frost-sp-poc/run/<wp>-SUMMARY.md`. The orchestrator watches that path. It uses these sections:

1. **State:** one sentence.
2. **Built:** with paths, and which T-IDs pass, shown by the quoted test output.
3. **To-do:** owner, blocker, and ID for each item.
4. **Decided:** your decisions, one line each.
5. **Not done / not verified.**

The last line must be exactly `STATUS: DONE` or `STATUS: BLOCKED <reason>`.
