STATUS: DONE

# W6 summary: recorded end-to-end demo run

1. **State:** a fresh 2-of-3 FROST wallet ran DKG → 4 receives → spend (3 inputs) → spend (change) on real regtest, all judged `pass`, and the data is in the demo directory; PR #5 holds the opt-in trace.

2. **Built**
   - PR: https://github.com/setavenger/frost-sp-rs/pull/5 (`w6-demo-trace` → `frost-sp`, not merged).
   - `FROST_SP_TRACE=<path>`: `crates/frost-sp-wallet/src/trace.rs` plus hooks in dkg/ceremony.rs, send.rs, spend.rs, the CLI. Tests: `crates/frost-sp-wallet/tests/trace.rs`, `trace_records_keygen_and_a_spend_and_no_secret` and `without_frost_sp_trace_no_file_is_written` in `crates/frost-sp-cli/tests/cli.rs`.
   - Refusal tests now print `REFUSAL …` lines (no assertion changes).
   - Suite: `cargo test --workspace --exclude psbt-viewer`: 152 passed, 0 failed, 28 binaries. Clippy (same exclusion): no warnings in the frost-sp crates.
   - Demo dir: `/tmp/claude-1000/-work/729cb345-796a-492c-ad9f-eea95d9bdadb/scratchpad/demo-run/` (`demo.json`, `README.md`, `frost-demo.toml`, `raw/`). 10 steps, every check true; 9 refusal tests all passed with their real error text.
   - Regtest (bitcoind 30.3, blocks 102–108): testkit `pass`, 8/8 outputs found; frost 6 and bob 2 outputs agree live and on rescan. Signer: release `frost-sp-signer` with `--state device-2.json --state device-3.json` only (device 1 never signed). Spend 1: Σg = 1, g = [1,-1,1]; both spends `testmempoolaccept` allowed, FROST signatures verify under P_k, consensus-valid.
   - Reviews: Codex (`run/w6-CODEX-REVIEW.md`): no findings. Independent review agent in place of the interactive gstack /review: no findings (two INFORMATIONAL notes, comment wording at dkg/ceremony.rs:232 and a redundant test case; not changed).
   - Leak check: key material of the three device files (host secrets, b_scan, key packages) is absent from every file in the demo dir except `frost-demo.toml`, which holds the regtest `b_scan` by design.

3. **To-do**
   - Orchestrator: merge PR #5; turn `demo.json` into the HTML page (the demo dir is outside any repo).

4. **Decided**
   - Fresh OS randomness for keygen (no `--seed`); the testkit needed no reconstructed secret because `TESTKIT_EXTERNAL_SIGNER` replaces the mock.
   - The testkit has no keep-stack option, so I captured chain data with a watcher script (blocks, container logs) in a Herdr pane and a signer wrapper that records request/response and runs `testmempoolaccept`; no testkit change.
   - Ran the regtest scenario twice: run 1 passed but my watcher could not find Docker's random RPC port; run 2 is the recorded one (run 1 files in `scratchpad/run1-discarded`).
   - Commit trailer set to Sonnet 5.5 per the repo instruction (the implementer agent had used Opus; amended).
   - Used a general-purpose review agent instead of invoking the full interactive `/review` skill (it needs Aside/bun probes); the skill's QA/ship stages were not run.

5. **Not done / not verified**
   - `/qa` and `/ship` skills not run (brief step 8 asked for PR + review + Codex only); PR opened with `gh` directly.
   - Trace not hooked into the single-input `Signer::sign` path (the CLI does not use it).
   - DKG round-2 plaintext/AEAD/HKDF keys are not covered by the hex-search test (not reachable; none passed to `emit`).
   - Regtest addresses print as `tsp1…` (not `sprt1…`); recipients in `send.build_tx` are scan/spend keys, addresses are in `spend.request`.
   - Container logs for the two rescan scanners of frost/bob were gone before the watcher's last snapshot; their counts are in `testkit.log`.
   - psbt-viewer excluded (does not build from the worktree path); clippy not run for it.
   - Docker clean: no `bbtk` containers, volumes or networks left.

STATUS: DONE
