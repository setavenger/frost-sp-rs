# frost-sp-signer (PoC)

External signer for the BlindBit test kit (`docs/external-signer.md` in `blindbit-testkit`,
PR #28) backed by a `t`-of-`n` FROST Silent Payment wallet (`frost-sp-wallet`).

Keys come from a **distributed key generation** (`frost_sp_wallet::dkg`), not a dealer:

* `keygen` runs a simulated ceremony between `n` devices: ZF's Pedersen DKG with proofs of
  knowledge, an echo round so every device saw the same commitments, round-2 shares sealed
  device to device (ECDH host keys → HKDF-SHA256 → ChaCha20-Poly1305), `b_scan` drawn by
  device 1, and a certificate: every device signs the transcript hash `T` with its host key and
  accepts only with all `n` signatures on its own `T`.
* It writes one file per device (`device-<i>.json`, mode 0600, never overwritten). Each holds
  exactly **one** signing share, the group's public key package, `b_scan`, the device's host
  key and the certificate. Each device shows a check code (from `T`) and the SP address for the
  user to compare.
* The signer takes `--state` once per participating device (at least `t`). Each file is fully
  re-verified on load (certificate, key material, `X_i == x_i·G`) and goes into its own
  cosigner; files with the same identifier, another group key or another certificate are
  refused.

**PoC:** the devices of one ceremony, and the cosigners of one signing run, share a process.
Their state, secrets and messages are separate, but there is no real transport, the exposure
counter is not persisted, and there is no recovery backup.

```
# one-off: the ceremony (seeded = reproducible TEST constants; refused on mainnet)
frost-sp-signer keygen --n 3 --t 2 --out-dir keys/ --seed 352

# per spend (what the test kit does): wallet config in env, request on stdin
BLINDBIT_SIGNER_NETWORK=regtest BLINDBIT_SIGNER_SCAN_SECRET=... \
BLINDBIT_SIGNER_SPEND_PUBKEY=... BLINDBIT_SIGNER_LABELS=7 \
  frost-sp-signer --state keys/device-1.json --state keys/device-3.json < request.json
  # {"tx_hex"} or {"error"}

# TEST ONLY, for the test kit's single-key mock signer: x from t files of a seeded group
frost-sp-signer reconstruct-test-secret --state keys/device-1.json --state keys/device-2.json
```

* **Spend exactly these coins**, in the order given. Payments are paid in order, then change.
  Change goes to `change_address`; with the test kit's `change = "sp"` that is the wallet's own
  label `m = 0` address. Without a change address a leftover over 10x the fee is refused.
* **Parity guard.** A set of inputs whose key parities `g_j` sum to 0 is refused with an
  `{error}`: the input key sum would not contain the group key.
* The request's `tweak` is ignored. `script_pubkey` and `value_sats` are cross-checked against
  the funding transaction.
* `reconstruct-test-secret` only accepts files marked `test_only_seed`, and re-derives the
  group from that seed before trusting the mark; the signer never reconstructs anything. On
  the signer path the mark is advisory (seeded files are refused on mainnet; unseeded files
  must be mode 0600).
* The check code is 48 bits of `H(T)`: enough for people comparing screens (the echo round and
  the certificate already bind every device to one `T`), not a collision-resistant fingerprint.
* Round-2 sealing uses the static host keys (static-static ECDH, as specified): no forward
  secrecy; a later leak of a host key exposes that device's recorded round-2 traffic. The host
  key also signs the device's messages and certificate. `n` is capped at 32 for the PoC.

`tests/fixtures/frost-rs-roundtrip/device-{1,2,3}.json` are `keygen --n 3 --t 2 --seed 352`:
the keys committed in the test kit's `scenarios/frost-rs-roundtrip.toml`. Test data.
