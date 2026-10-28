# W4 correctness and security review

Reviewed 2026-10-28. Findings are ordered by consequence; P2 = fix before relying on this path, P3 = lower priority edge case.

Scope:
- Rust: `feat/w4-e2e`, initially `d0a88f5691c18efe5a93247c05ade82b6cce9900`, then `fbed4e738bfd7b1c2ec7f17d9207887b905cce04` after an upstream merge occurred during review. The W4 delta against `frost-sp` stayed unchanged. Rust line numbers below refer to the merged head, with base `4bb8d52c9c2e7f482aa2d8f32bd2b3918f24a657`.
- Go: only commit `015834c385360475db3d70063a3fdec42bfde3c6` on `feat/external-signer-wallet`.
- Contract: `/work/blindbit/blindbit-testkit-frost/docs/external-signer.md`.

## Findings

1. **[P2] The dealer creates a state file readable by other local users.**

   Rust: `crates/frost-sp-cli/src/main.rs:93`.

   `std::fs::write` creates a new file with mode 0666 filtered by the process umask. The file contains every signing share, including for an unseeded dealer, so another local user who can traverse the containing directory can recover the spend key and sign without the owner. This is separate from the intentional PoC decision to store all shares together: even the non-test dealer exposes them outside its owning account. Reproduced an unseeded `dealer --out /tmp/...json`: exit 0, file mode **0664**, all three key packages present. With umask 022 the mode is 0644. Create the secret file as 0600 and handle an existing destination without preserving permissive access.

2. **[P2] Unchecked monetary arithmetic signs invalid transactions and panics in debug builds.**

   Rust: `crates/frost-sp-wallet/src/send.rs:1229`, `crates/frost-sp-wallet/src/send.rs:1232`; request entry at `crates/frost-sp-cli/src/lib.rs:281`.

   Request amounts are arbitrary `u64`s, with no Bitcoin monetary-range validation. Input/payment sums, fee multiplication, `target + fee`, and the burn-limit multiplication are unchecked. Using one valid 100,000-sat coin, set two destination amounts to **18446744073709461616** (`2^64 - 90000`) and **100000**. The release build wraps the target to 10,000, signs successfully, and returns outputs whose signed wire values are **-90000, 100000, 89015**. The signers' existing output-sum calculation also wraps, and libbitcoinconsensus verifies scripts rather than the transaction's monetary validity, so finalization does not reject it. The debug executable instead exits **101**, with an overflow panic and no JSON error document.

   Independently, a zero-valued destination is accepted and signed, although the testkit refuses zero outputs. A huge fee rate can also wrap to a small fee: choosing `rate * 111 == 5 (mod 2^64)` permits a 50-sat no-change fee. Validate monetary ranges and positive payment amounts, and use checked sums/products throughout the new planner before starting a signing session.

3. **[P2] The judge no longer detects wrong scanner amounts for SP change.**

   Go: `internal/judge/judge.go:268`.

   The signer may choose the change amount, but after `extsigner.Verify` binds the signed transaction, its actual amount is known in `runner.OutputBinding.AmountSats`. Excluding every `payment.Change` from the judge's amount check also excludes comparisons with that known transaction value. Verify checks the signer's transaction before the client is observed; its fee bound cannot validate the amount the client later reports. Reproduced the shipped roundtrip, changed only the scanner observation for `frost-change-2` from **397990** to **1**, and reran `judge.Judge`: **Pass() == true**, no error. Compare observed change against its verified binding, rather than dropping amount verification.

4. **[P2] Unknown change amounts are treated as zero when validating dust-filter expectations.**

   Go: `internal/scenario/load.go:651`, `internal/scenario/scenario.go:424`; downstream consumers are `internal/scenario/expect.go:343` and `internal/scenario/expect.go:393`.

   Change enters `Payment` with `AmountSats == 0`, but the existing filtering checks interpret it as a real zero-sat output. A valid transaction with a **600-sat recipient and 498685-sat SP change**, under a 1000-sat dust limit, must remain served in full because the change qualifies. The loader instead rejects `must_find` for both outputs with “no output its transaction tracks is at or above the dust limit.” Conversely, declaring both outputs absent for `dust_filtered` is accepted. The amounts above were confirmed by constructing the same spend through the real mock signer at T0; no oracle-filter simulation was used. The shipped scenario hides this because its ordinary recipient always qualifies on its own. Keep unknown amounts distinct from zero and resolve change-dependent filtering against the verified transaction before judging expectations.

5. **[P2] Silent Payment destinations bypass the configured network check.**

   Rust: `crates/frost-sp-cli/src/lib.rs:305`.

   `parse_dest` immediately accepts any decodable Silent Payment code. Only the plain-address branch calls `require_network`, although the SP code exposes its network too. Reproduced a regtest request and wallet with a valid **mainnet `sp1...` destination**: the signer exits 0 and returns a signed transaction. The same bypass applies to `change_address`. A network/address mistake therefore pays on the configured chain instead of being refused at the signer boundary. Check SP address networks too, preserving the contract's intentional shared `tsp` namespace for signet/regtest.

6. **[P2] Fixed dust thresholds mishandle the newly supported change types.**

   Rust: `crates/frost-sp-wallet/src/send.rs:1253`. Go: `internal/extsigner/mock/mock.go:199`.

   The Rust planner reuses the SP/P2TR threshold of **330 sats** for every change destination. With one 100,000-sat input, a 98,875-sat SP payment, rate 5 and a valid P2PKH change address, it signs a **400-sat P2PKH change output**. That output is below the 546-sat P2PKH dust threshold and fails normal relay policy; the script-only finalization does not catch it.

   The mock has the inverse problem: its new SP-change branch reuses **546 sats**, so it drops valid 330–545-sat P2TR change. Reproduced one 100,000-sat input and a 98,800-sat payment at rate 5: the mock leaves **485 sats** below its cutoff and returns only the payment, while the Rust signer returns the payment plus **430-sat** SP change. With a declared change recipient, the mock run then fails the required output binding. Choose the dust threshold for the actual change script in both implementations.

7. **[P3] A change-only spend loads successfully but fails with either signer.**

   Go: `internal/extsigner/types.go:78`, with loader acceptance at `internal/scenario/load.go:640`. Rust wire type: `crates/frost-sp-cli/src/lib.rs:122`.

   A spend whose sole recipient is `change = true` satisfies the new loader rules. `AddRecipient` puts its address only in `ChangeAddress`, leaving `Destinations` nil, which serializes as JSON `null`. Reproduced a loaded change-only scenario: the Rust signer refuses with **“invalid type: null, expected a sequence”**; the mock refuses with **“a spend needs at least one utxo and one destination.”** Rust successfully signs the equivalent request when destinations is explicitly `[]`. Either support a consolidation-to-change spend consistently (including JSON array normalization and the mock), or reject it in the loader with a clear constraint.

## Verification and limits

- On merged Rust head: `cargo test --release -p frost-sp-cli -p frost-sp-wallet` passed **60 tests**, including 30 send tests, 18 spend tests, 7 CLI tests, BIP 352 vectors and BIP 374 vectors. Log: `/tmp/w4-codex-rust-tests-merged.log`.
- `go test ./internal/extsigner/... ./internal/scenario ./internal/judge ./internal/tier/lib` passed all five selected packages. Log: `/tmp/w4-codex-go-tests.log`.
- Additional Go probes used `go test -overlay /tmp/w4-codex-go-overlay.json ... -run TestCodexReview -v`; repository source files were unchanged. They reproduced the judge, filtering and change-only findings, and passed the shipped Rust roundtrip under **full-basic at T0**. T0 deliberately refuses filtering configurations; no T2/Docker/oracle end-to-end run was performed by this review.
- CLI probes used synthetic funding transactions with the committed fixture's public test keys. Script verification succeeding is not evidence that synthetic funding exists on a chain or that negative-valued outputs satisfy full transaction consensus. Probe generator: `/tmp/w4-codex-probe.py`.
- Traced the input-key sum and parity guard, plain SP tweaks and post-tweak signing parity, DLEQ verification, independent signer output/sighash checks, and per-input FROST nonces consumed on refusal. No additional in-scope issue was established in those paths. Existing PoC limitations (all shares in one process, public seeded fixtures, nonpersistent exposure state) were not reported as new bugs.
- After the independent audit, checked Go PR #28's discussion, reviews and inline comments: all empty. No Rust PR existed for `feat/w4-e2e` at that time. No findings came from another reviewer.
- Consulted the canonical BIP 352 and BIP 374 texts alongside the repository's required math checklist. Protocol sources:

https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki

Only this report was written in either repository. No source code was edited.
