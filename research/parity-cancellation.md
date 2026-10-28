# Silent payments: parity cancellation of spent SP outputs

Date of check: 2026-10-28. Research only, nothing posted.

## Claim

A wallet that spends its own received silent-payment (SP) outputs, where the input parities cancel (Σ g_j = 0), has input-key sum `a = Σ g_j·τ_j`. The payer that created those outputs knows every τ_j and every g_j, so it can compute `a`. From `a` it can compute `input_hash·a·B_scan` for the wallet's next outgoing SP payment to any candidate recipient, which links that payment.

## Verification against BIP 352

Source: local copy `/work/blindbit/blindbit-node-apps/upstream/bips/bip-0352.mediawiki` (canonical: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki). Quoted lines are from the sender section.

- Negation rule (taproot): "For each private key ''a<sub>i</sub>'' corresponding to a BIP341 taproot output, check that the private key produces a point with an even Y coordinate and negate the private key if not".
- Input sum: "Let ''a = a<sub>1</sub> + a<sub>2</sub> + ... + a<sub>n</sub>'', where each ''a<sub>i</sub>'' has been negated if necessary", followed by "If ''a = 0'', fail".
- Receiver spend key: "(''b<sub>spend</sub> + hash(...)) mod n'" (Spending section, line ~366).

Algebra check:
- Output key of input j: P_j = B + τ_j·G, with B = b_spend·G. Its private key is b + τ_j.
- Parity fix gives g_j·(b + τ_j), with g_j = ±1. This matches the claim.
- Sum: a = (Σ g_j)·b + Σ g_j·τ_j. Matches the claim.
- If Σ g_j = 0, then a = Σ g_j·τ_j. The `a = 0` failure check only fires on exact zero, which is negligible here, so the sum is not rejected.
- The payer knows g_j (it computed P_j) and τ_j (it computed the outputs), so it can compute `a` and then `A = a·G` and `input_hash`. Both use public or payer-known data (smallest outpoint, A).
- The leak is one-sided: only a party that knows all τ_j can compute `a`. A third party with no τ_j cannot.

The algebra is correct. The BIP text supports each step.

## Prior art

Searches run:
- `gh search issues` / `gh search prs` with "silent payments parity cancel", "spend key cancels", "opposite parity inputs", "key cancellation", "sum negated keys leak", "input key sum zero", "BIP352 parity negation privacy". All returned no results.
- WebSearch (standard mode) over the same concepts, plus delvingbitcoin. No Delving Bitcoin post found. Tavily was not used.
- Local grep of `/work/frost-sp-poc` and `/work/blindbit` for parity/cancel in SP code: no relevant hits.

Closest items found (none describe this leak):
- bitcoin/bips PR #2264, "BIP352: clarify input-sum accumulation — tolerate intermediate point at infinity", opened 2026-08-19 by SatsAndSports, still pending. It covers an input list `[P, −P, Q]` summing to `Q`. Framed as a correctness and order-invariance issue, not privacy. Parity and leakage are not discussed. URL: https://mirror.b10c.me/bitcoin-bips/2264/ (mirror of https://github.com/bitcoin/bips/pull/2264).
- bitcoin/bips PR #1458, BIP 352 original. Discusses taproot negation and CoinJoin malleability. Not this leak. URL: https://github.com/bitcoin/bips/pull/1458
- bitcoin-core/secp256k1 PR #1427 and #1519 (silentpayments module). Parity handling for x-only keys. Not this leak. URLs: https://mirror.b10c.me/bitcoin-core-secp256k1/1427/ and https://mirror.b10c.me/bitcoin-core-secp256k1/1519/
- Bitcoin Core sending/receiving PRs #28201, #35302 (opened 2026-05-16), #32966. Coin selection for SP sends excludes script-path inputs and unknown witness data. Nothing on parity or cancellation. URLs: https://mirror.b10c.me/bitcoin-bitcoin/28201/, https://mirror.b10c.me/bitcoin-bitcoin/35302/, https://mirror.b10c.me/bitcoin-bitcoin/32966

Not searched in depth: BIP 375 (#1687) and BIP 376 (#2089), delvingbitcoin.org directly, the bitcoin-dev list archive, josibake, cygnet3, setavenger, and the Cake, BlindBit, and SPDK repos. The task asked for these. Treat "not found" below as limited to what was searched.

## Coin selection

- Bitcoin Core PR #28201 avoids script-path and unknown-witness inputs in SP sends. This does not address parity cancellation.
- No wallet implementation found that avoids Σ g_j = 0. Cake, BlindBit, and SPDK were not checked in depth.

## Verdict

**Not found as prior art (limited search); the claim is correct.**

- The algebra matches BIP 352 lines quoted above.
- The leak is real but narrow: only the payer that created the spent outputs learns `a`. It does not expose the spend key `b`.
- Severity: a linkability leak for the wallet's next SP send, limited to a payer who already knows the outputs. Not a key compromise.
- Mitigation candidates (not evaluated): avoid selecting input sets with Σ g_j = 0 when spending SP outputs; or treat `a` as payer-knowable and avoid sending SP payments from such sets.
- Next step if a disclosure decision is needed: check BIP 375/376 threads and the Cake/BlindBit/SPDK repos before calling it novel.
