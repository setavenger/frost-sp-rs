# frost-sp-signer (PoC)

External signer for the BlindBit test kit (`docs/external-signer.md` in `blindbit-testkit`,
PR #28) backed by a `t`-of-`n` FROST Silent Payment wallet (`frost-sp-wallet`).

**PoC only.** The state file holds *every* key package (trusted dealer) and one process plays
all cosigners. The protocol code is the real one (threshold ECDH + BIP 374 proofs, FROST
rounds per input under `X + tau_j*G`, every signer re-deriving `tau_j` from the funding
transaction), but a deployment needs one key package per machine, DKG instead of a dealer, and
a persisted exposure counter.

```
# one-off: write the state file, print the scenario constants (seeded = reproducible)
frost-sp-signer dealer --out state.json --seed 352 --print-group-secret

# per spend (what the test kit does): wallet config in env, request on stdin
BLINDBIT_SIGNER_NETWORK=regtest BLINDBIT_SIGNER_SCAN_SECRET=... \
BLINDBIT_SIGNER_SPEND_PUBKEY=... BLINDBIT_SIGNER_LABELS=7 \
  frost-sp-signer --state state.json [--signing-set 2,3] < request.json   # {"tx_hex"} or {"error"}
```

* **Spend exactly these coins**, in the order given. Payments are paid in order, then change.
  Change goes to `change_address`; with the test kit's `change = "sp"` that is the wallet's own
  label `m = 0` address. Without a change address a leftover over 10x the fee is refused.
* **Parity guard.** A set of inputs whose key parities `g_j` sum to 0 is refused with an
  `{error}`: the input key sum would not contain the group key.
* The request's `tweak` is ignored. `script_pubkey` and `value_sats` are cross-checked against
  the funding transaction.
* `--print-group-secret` also prints the reconstructed secret so the same scenario can run with
  the test kit's single-key mock signer. Test constants only.

`tests/fixtures/frost-rs-roundtrip-state.json` is the dealer's output for the keys committed in
`scenarios/frost-rs-roundtrip.toml`; it holds all key packages and is test data.
