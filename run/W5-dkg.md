# W5: Real distributed key generation (DKG), with its checks

Read `run/RULES.md` first. Work-package id: `w5`.

- **frost-sp-rs:** branch `feat/w5-dkg` off `frost-sp`, worktree `/work/frost-sp-poc-wt/w5`. PR against `frost-sp`.
- **blindbit-testkit:** only if T8 needs new scenario constants. Work on W3's branch `feat/external-signer-wallet` in `/work/blindbit/blindbit-testkit-frost` and push to PR #28. Do **not** merge it.

## Why

So far the PoC creates its keys with a trusted dealer (`keys::generate_with_dealer`, `crates/frost-sp-wallet/src/group.rs:31`). One state file holds every share, and one process plays every cosigner. The signing and Silent Payment code is real threshold code, but the trust split is not: the dealer and the state file both see the group secret `x`.

The user's requirement, in their words: real FROST keys, "proper key generation and checking", "properly simulated", because "it's important that this actually can work and it's not just a thing we made up with some basic functions where we then just pretend".

Plain-language background: https://claude.ai/artifact/YZEGV4qL1QUhkCnKVHTvRx

Running the cosigners as separate OS processes is out of scope. Separate state, separate secrets and byte-level messages are in scope.

## Design (decided by the orchestrator)

1. **DKG core:** ZF's `frost_secp256k1_tr::keys::dkg::{part1, part2, part3}`. These already give the proof of knowledge (`InvalidProofOfKnowledge { culprit }`) and the share check against commitments (`InvalidSecretShare { culprit }`). Do not reimplement Pedersen DKG.
2. **Devices and network.**
   - Each `Device` holds only its own secrets: its DKG secret packages, its host secret key, and later its `KeyPackage`.
   - A coordinator/network moves only serialized bytes (`Vec<u8>`) between devices.
   - Tests can hook the coordinator to read, drop, replace, reorder or misroute any message, and can swap in a cheating device.
3. **Host keys and session.**
   - Each device has a static secp256k1 host key pair. The participant list is the sorted host public keys plus `t` and `n`, confirmed out of band (a test fixture).
   - A device's FROST identifier is its 1-based position in that sorted list.
   - The session id is a tagged hash of (sorted host public keys, `t`, `n`, 32 random bytes from the coordinator).
   - Every message carries the session id and sender. Refuse a wrong session, a wrong or unknown sender, duplicates, and missing participants.
4. **Round 1 (broadcast):** ZF `round1::Package`.
5. **Same-view check (echo round)**, before any share leaves a device:
   - Each device sends every other device the hash of (session id, all `n` round-1 packages sorted by identifier).
   - A device aborts unless all `n−1` echoes equal its own hash.
   - ZF requires a secure broadcast and leaves this to the application (`frost-core-3.0.0/src/keys/dkg.rs:5-35`).
6. **Round 2 (private):** each `round2::Package` is encrypted and authenticated to its recipient.
   - Cipher: ChaCha20-Poly1305 (`chacha20poly1305` crate).
   - Key: HKDF-SHA256 over the static ECDH of the two host keys, bound to the session id, sender and recipient.
   - AAD: session id ‖ sender ‖ recipient. Nonce: a random 12-byte nonce carried in the message.
   - Use maintained crates only; no hand-rolled primitives.
7. **Scan key:** the device with identifier 1 draws `b_scan` from a CSPRNG and puts it inside its encrypted round-2 payload to every other device.
8. **Finalise and certify.**
   - Every device runs `part3`, then `validate_public_key_package`, and checks `X_i == x_i·G` for its own share.
   - It computes a transcript hash `T` over the session id, all round-1 packages, the `PublicKeyPackage` (`X` and every `X_i`) and `B_scan`.
   - It BIP 340-signs `T` with its host key and sends the signature to all devices.
   - A device accepts the result only when it holds valid signatures on **its own** `T` from all `n` host keys. That set is the certificate, and the device stores it.
   - Each device shows a short check code derived from `T`, plus the SP address, for the user to compare.
9. **Storage.**
   - One state file per device, holding its `KeyPackage`, the `PublicKeyPackage`, `b_scan`, its host secret key and the certificate. Mode 0600.
   - No file holds more than one signing share.
10. **CLI.**
    - Replace `dealer` with `keygen --n <n> --t <t> --out-dir <dir> [--seed <u64>]`. It runs the simulated ceremony and writes `device-<i>.json` for each device.
    - `--seed` gives reproducible test constants. Label it test-only and refuse it on mainnet.
    - `frost-sp-signer` takes `--state` once per participating device. It loads each file into its own `Signer`, and refuses files that duplicate an identifier or disagree on the group key or certificate.
    - The testkit mock still needs a spend secret. Provide it through a separate subcommand, clearly test-only, that reconstructs `x` from `t` device files. It is never used by the signer.
11. **Dealer code.** Keep `FrostGroup::trusted_dealer`/`from_secret` only for the BIP 352 vector tests: the vectors fix `b_spend`, which a DKG cannot produce. Gate them behind `cfg(test)` or a `test-dealer` feature. The CLI and the library's non-test paths must not reach them.

## Tests (IDs for your summary)

| ID | Check |
|----|-------|
| D1 | Honest 2-of-3 and 3-of-5 ceremonies: every device ends with the same `X`, `B_scan`, check code and certificate. Every `t`-subset produces a BIP 340 signature valid under `X`, and a tweaked one under `X + τ·G` (the SP spend path). A test-only reconstruction from `t` shares gives `x·G == X`. |
| D2 | Bad proof of knowledge, including a rogue-key attempt (`C_0` chosen as a target minus the others' commitments, with no known discrete log): honest devices abort in round 2 and name the culprit. |
| D3 | A share inconsistent with the sender's commitments, sent to one honest device: that device aborts and names the culprit, and no device accepts a result. |
| D4 | Equivocation: a device sends different round-1 packages to different devices, and the echo round aborts before any share is sent. **Control test:** with the echo round skipped, the devices end with different group keys. This shows the check is needed. |
| D5 | The coordinator flips a bit in a round-2 ciphertext: AEAD fails, and the recipient aborts without accepting a share. |
| D6 | The coordinator's full message log contains no plaintext signing-share bytes and no `b_scan` bytes. |
| D7 | Replay from another session, a swapped sender or a misrouted message is refused. |
| D8 | Device 1 sends different `b_scan` values to different devices: transcripts differ, no certificate completes, and no device accepts. |
| D9 | A missing or forged certificate signature means no acceptance. The signer CLI refuses a state file without a valid certificate. |
| D10 | Parameters: `t > n`, `t < 2`, duplicate host keys and an unknown participant are refused. |
| D11 | Each written device file holds exactly one signing share, and no file contains another device's share bytes. |

**End to end with DKG keys**
- Re-run the receive, spend and send round trips (`tests/spend_e2e.rs`, `tests/send_e2e.rs`, or equivalent) on DKG-generated groups wherever they don't depend on fixed vector keys.
- T1 stays on the test-only dealer split. Say so in the summary.
- **T8:** regtest through the testkit with DKG device files, e.g.
  `TESTKIT_EXTERNAL_SIGNER="frost-sp-signer --state d1.json --state d2.json"`.
  Regenerate the scenario constants from a seeded `keygen`. Quote the PASS lines and bitcoind accepting the transactions.
- Tear down any regtest or docker stack when you are done. The VM's docker logs are uncapped.

## Out of scope

- Separate OS processes or machines, and real transport (files, nostr).
- ChillDKG's recovery backup.
- Persisting the exposure counter.

List each of these under "Not done".

## Deliverable

`run/w5-SUMMARY.md` on `feat/w5-dkg`, plus a copy at `/work/frost-sp-poc/run/w5-SUMMARY.md`, in the RULES format, with the PR URL(s).
