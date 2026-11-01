# W6: recorded end-to-end demo run (DKG → receive → spend → send)

Read `run/RULES.md` first; it applies here. Work package W6. Model: you.

## Goal

The user wants to *see* the PoC work: one fresh, real run from distributed key generation to receiving, spending and sending on regtest, with every step's inputs, outputs and checks recorded as data. Someone else turns your data into an HTML page. Your deliverable is the data, plus one small opt-in trace feature that makes the internal steps visible. Do not build anything else.

## Steps

1. **Worktree.** `git -C /work/frost-sp-poc worktree add /work/frost-sp-poc-wt/w6 -b w6-demo-trace frost-sp`. Commit this brief on the branch.

2. **Opt-in trace** in `crates/frost-sp-wallet` / `crates/frost-sp-cli`. When `FROST_SP_TRACE=<path>` is set, append one JSON object per line (`{"step": "...", ...}`); when unset, no file and no behaviour change. Keep it small.
   - **Record (public or wallet-private test values):**
     - keygen: n, t, device ids, host pubkeys, each round's message count, the echo digest, verification shares `X_i`, group key `X`, `B_scan`, check code, certificate validity, the SP address (`sprt1…`/`tsp1…`).
     - spend/send, per input: outpoint, value, re-derived `t_k`, label `m`, recomputed `P_k` matches the scriptPubKey (bool), parity `g_j`, whether the handed `tweak` matched the re-derived one.
     - per transaction: `Σg`, the guard decision, `input_hash`, signing set, Lagrange `λ_i`.
     - per device and recipient scan key: `D_i`, its DLEQ proof, and whether every device verified it.
     - combined shared-secret point (label it `test-only` in the field name), each output with its recipient, `k` and amount.
     - FROST signing per input: nonce commitments, signature shares, the final signature, and whether it verifies under `P_k`. Final `tx_hex` and txid.
   - **Never record:** signing shares `x_i`, nonces, `b_scan`, the group secret, host secret keys, AEAD/HKDF keys.
   - **Test:** a D6-style test that runs keygen and a spend with the trace on, then asserts that none of the secrets above appears in the trace file (hex search). Plus: trace unset → no file.

3. **Fresh key generation.** Run `frost-sp-signer keygen --n 3 --t 2` into the demo directory (below). Prefer OS randomness (no `--seed`). Use a seed only if the testkit cannot run without the mock signer's reconstructed secret; then say so. Record the full command and each device file's public fields. Never copy signing shares into the demo data.

4. **Regtest run.** Copy `/work/blindbit/blindbit-testkit-frost/scenarios/frost-rs-roundtrip.toml` into the demo directory as `frost-demo.toml`. Set the new `scan_secret` and `spend_pubkey`, keep only the `full-basic` configuration, and keep the actions unchanged. Run it on the regtest tier (bitcoind) with:
   - `TESTKIT_EXTERNAL_SIGNER` = the release signer with `--state device-2.json --state device-3.json`, so device 1 never signs;
   - `FROST_SP_TRACE` set.
   Find the right way to run one scenario file on regtest yourself (`testkit run …` or the Go test; see `docs/external-signer.md`). Don't commit to the testkit repo or PR #28. If the run needs a testkit change, work around it in the demo directory and say so.
   Capture, before the stack is torn down:
   - the testkit's report (machine-readable if it has one) and its log;
   - every transaction (4 fundings, 2 FROST spends): txid, raw hex, decoded inputs and outputs (addresses, scriptPubKeys, amounts), block height, and node acceptance;
   - what each wallet (frost, bob) found, live and on rescan.

5. **Refusals (real output, not prose).** Run the existing tests that show the safety checks, with `--nocapture`, and record the test name, pass/fail and the error each one produces:
   - two inputs whose parities cancel (Σg = 0) are refused (`crates/frost-sp-cli/tests/cli.rs`);
   - DKG: D4 equivocation, D5 flipped ciphertext bit, D2 bad proof of knowledge, D9 tampered certificate;
   - a wrong handed tweak is ignored or refused (if a test exists).

6. **Suite.** `cargo test --workspace --exclude psbt-viewer` on your branch; record the totals.

7. **Output.** Everything goes into `/tmp/claude-1000/-work/729cb345-796a-492c-ad9f-eea95d9bdadb/scratchpad/demo-run/` (create it). Not into any repo: the repos are public.
   - `demo.json`: `{meta: {date, frost-sp-rs commit, testkit commit, bitcoind version, commands}, steps: [{id, title, plain_summary, inputs: {…}, outputs: {…}, checks: [{what, passed, evidence}]}], refusals: [{what, test, passed, error}], suite: {…}}`.
     - Steps in order: keygen, address, the 4 receives, scan, spend 1 (3 inputs → bob + SP change), spend 2 (change → bob labelled + change-2), rescan.
     - `plain_summary` is one sentence a non-cryptographer understands.
     - Every value must come from a file in `raw/`; name that file in `evidence`.
   - `raw/`: trace.jsonl, the testkit report and log, tx hex and decoded JSON, the device files' public parts, test outputs.
   - `README.md`: what each file is, in a few lines.

8. **PR.** Push `w6-demo-trace` to `origin`, open a PR against `frost-sp` ("Opt-in trace for demo runs"). Run gstack `/review` on it, then a Codex review in a second Herdr pane (Codex with `--dangerously-bypass-approvals-and-sandbox`; clear update/trust prompts first, never update it). Fix real findings. Don't merge.

9. **Clean up.** No `bbtk` containers, volumes or networks left (`docker ps -a`, `docker volume ls`, `docker network ls`). Remove your worktree after pushing (it holds a large `target/`). Close every pane you created.

10. **Summary.** `run/w6-SUMMARY.md` on your branch (pushed), first line `STATUS: DONE` or `STATUS: BLOCKED <why>`: what ran, what passed, the PR link, the demo directory, decisions, anything skipped.

## Constraints

- Test keys on regtest only.
- If a step fails, record the failure as data in `demo.json` (with its output) and keep going. Do not fake or hand-edit values.
- Be economical: one regtest configuration, one run. A re-run only if the first failed for an environmental reason.
