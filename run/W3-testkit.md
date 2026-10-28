# W3: BlindBit test kit, public-key wallet and external signer

Read `/work/frost-sp-poc/run/RULES.md` first. Of those rules, everything applies except the PoC repo and branch rules; for this repo, use the ones below. Work-package id: `w3`.

## Repo

- `/work/blindbit/blindbit-testkit`: Go, private repo `setavenger/blindbit-testkit`, default branch `master`.
- Follow its `CLAUDE.md` and `.claude/skills`, especially `blindbit-fix-pr` (branch and PR rules) and `bip352-math`.
- The main checkout is behind `origin` and has an untracked file someone else owns, so **don't touch it**. Use a worktree:
  - `git -C /work/blindbit/blindbit-testkit fetch origin`
  - `git -C /work/blindbit/blindbit-testkit worktree add /work/blindbit/blindbit-testkit-frost -b feat/external-signer-wallet origin/master`
- Push the branch and open a PR against `master`, then run the Codex review recipe on it. **Don't merge.**

## What exists

- The regtest tier (bitcoind, oracle, friglet) already scans for a spend *public* key: friglet takes `FRIGLET_SCAN_SECRET` and `FRIGLET_SPEND_PUBKEY` (`compose/compose.yaml:110-111`).
- Scenario wallets come only from mnemonics (`internal/scenario/load.go:38`, `internal/scenario/wallet.go:86-117`).
- The spend secret is used at `internal/tier/lib/actions.go:216`, `internal/regtest/wallet.go:579` and `internal/synth/synth.go:797`.

## Scope

1. **A `pubkey` scenario wallet type:** scan secret plus spend public key, no mnemonic.
   - It must receive, scan and detect at the `lib` (T0) and `regtest` (T2) tiers.
   - `spend` actions go to an external signer.
2. **External signer interface:** a scenario field names a command.
   - The test kit sends JSON on stdin: network, fee rate, destinations (SP or plain addresses with amounts), and the owned UTXOs (outpoint, value, scriptPubKey, the funding transaction hex, and the tweak the test kit found). The tweak is informational only, because the external signer must re-derive it.
   - It expects either `{ "tx_hex": … }` or `{ "error": … }` on stdout.
   - Document the interface in `docs/external-signer.md`.
3. **A mock external signer** in Go, test-only, using one reconstructed single key, so the path is green without the Rust PoC. The W4 work package will plug in the Rust FROST signer later.
4. **Scenarios:**
   - `scenarios/frost-receive.toml`: pay the pubkey wallet and detect it at T0 and T2.
   - `scenarios/frost-roundtrip.toml`: the pubkey wallet receives, spends through the external signer to another SP wallet, and that wallet detects it.
5. Run the repo's own checks, mutation checks included, plus both scenarios at both tiers. Quote the results.

## Out of scope

Changes to blindbit-oracle, blindbit-rs or friglet. If one turns out to be needed, describe it in your summary instead.

## Deliverable

Write the summary to `/work/frost-sp-poc/run/w3-SUMMARY.md`, in the format from the run rules, including the PR URL.
