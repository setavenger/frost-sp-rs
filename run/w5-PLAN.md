# W5 plan: real DKG with its checks

Brief: `run/W5-dkg.md`. Branch `feat/w5-dkg` off `frost-sp`.

## Library (`crates/frost-sp-wallet/src/dkg/`)

| File | Content |
|---|---|
| `mod.rs` | `Params` (sorted host keys, `t`, `n`; refuses `t > n`, `t < 2`, duplicate hosts), session id, `DkgError` (culprit where known), tagged hashes, transcript `T`, check code |
| `wire.rs` | Envelope: `magic ‖ version ‖ kind ‖ session id ‖ sender ‖ recipient ‖ payload ‖ sig`. Plaintext kinds (round 1, echo, certificate) carry a BIP 340 host-key signature; round 2 is AEAD only |
| `channel.rs` | Round-2 sealing: ECDH(host keys) → HKDF-SHA256 (salt = session id, info binds both host keys and indices) → ChaCha20-Poly1305, random 12-byte nonce, AAD = session id ‖ sender ‖ recipient |
| `device.rs` | `Device`: own host key, own RNG, ZF `part1/2/3` secrets only. Steps `start → on_round1 → on_echo → on_round2 → on_certificates`; any refused message aborts the device for the session |
| `ceremony.rs` | `Participant` trait, `Ceremony` (coordinator/network): moves `Vec<u8>` only, keeps the full log, test hook per round can read/drop/replace/reorder/misroute; `keygen()` helper for honest runs |
| `key.rs` | `DeviceKey` (one share) + `Certificate`; `verify()` re-checks everything from stored public data on load |

Checks per device: session/sender/recipient/duplicate/missing; echo of `H(session, all n round-1 packages)`; ZF PoK (`part2`) and share check (`part3`); `validate_public_key_package` on `n−t+1` subsets (all `X_i` on one degree `t−1` polynomial); `X_i == x_i·G`; `T` signed by all `n` host keys.

`group.rs`: `trusted_dealer`/`from_secret` behind feature `test-dealer` (dev-dependency on itself for T1 tests).

## CLI (`crates/frost-sp-cli`)
- `keygen --n --t --out-dir [--seed] [--network]` (seed refused on mainnet, files 0600, `create_new`).
- `frost-sp-signer --state dX.json` repeated: one `Signer` per file; refuses duplicate ids, mismatched group key/certificate, unverifiable certificate, fewer than `t` files.
- `reconstruct-test-secret --state …` (test-only, for the testkit mock).
- Fixture: `tests/fixtures/frost-rs-roundtrip/device-{1,2,3}.json` from `keygen --seed 352`.

## Tests
- `src/dkg/tests.rs`: D1–D11 (adversarial hooks need crate internals).
- `tests/common`: DKG groups for spend/send e2e; T1 vectors stay on the dealer split.
- CLI tests: keygen → signer with 2 of 3 device files; D9/D11 on files.
- T8: testkit `frost-rs-roundtrip.toml` constants regenerated; regtest with `--state d1 --state d2`.
