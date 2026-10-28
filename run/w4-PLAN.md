# W4 plan: regtest end to end with the Rust FROST signer (T8)

Written from `run/W4-e2e.md`, W2's hand-off and W3's summary. `/autoplan` was **not** run to
completion (same abbreviation as W1-W3: the full CEO/eng pipeline is a many-agent ceremony
for a two-repo glue task); this plan was written from the brief and updated as I built.

## Shape
1. `crates/frost-sp-cli` (`frost-sp-signer`): `docs/external-signer.md` exactly. Env for the
   wallet, JSON on stdin, `{tx_hex}`/`{error}` on stdout. State file with all `n` key packages
   (PoC), the `t`-of-`n` session in process through W2's `send` module.
2. `send::plan_spend_exact`: every given coin is an input in the given order, payments in
   order, change last. Keeps the sum-g = 0 guard, cross-checks coin value against the
   funding tx, refuses a no-change leftover above 10x the fee.
3. Test kit: `change = "sp"` on a pubkey wallet (scans m = 0) and a `change = true` recipient
   (no amount/label, last, pays the spender). The request carries the wallet's m = 0 address
   as `change_address`; Verify binds the output through the wallet's own receiver; the judge
   skips the amount of a change payment. The mock signer pays SP change so the scenario
   also runs without Rust.
4. Scenario `frost-rs-roundtrip.toml` with dealer-generated constants: 4 payments (plain and
   m = 7), spend 3 (odd number of inputs: sum g is odd, never 0, whatever the funding txids),
   SP change, then spend the change (label-0 tweak).
5. Runs: T0 and T2 with `TESTKIT_EXTERNAL_SIGNER`, the mock scenarios re-run.
6. Follow-ups: pin `frost-secp256k1-tr = "=3.0.0"`; drop the dev-profile opt-level override if
   build/test times allow.

## Risks
* Signer must assign `k` in destination order; the SP change takes the next k of the
  wallet's own scan key (last, so it never shifts a payee's k).
* A Σg = 0 input set cannot be a testkit scenario (the mock signs it anyway); covered by a
  Rust CLI test.
