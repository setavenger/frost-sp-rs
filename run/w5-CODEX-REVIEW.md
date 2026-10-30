# W5 Codex review

Reviewed `frost-sp...feat/w5-dkg` in `/work/frost-sp-poc-wt/w5`.

- Feature commit: `d52480874500aee798d5fe5c1383edd1ab8bb3b7`.
- Base / merge base: `573a30e35eff5299d8e0b54e24bbfd2266944f31`.
- Scope and threat model: `run/W5-dkg.md` and `run/RULES.md`; review only, no code changes.

No actionable correctness or security findings were identified in the added or modified code under the brief's simulated-device threat model.

Reviewed paths and checks:

- `crates/frost-sp-wallet/src/dkg/device.rs:167`: exact participant collection, session and recipient binding, host authentication, duplicates/missing messages, terminal aborts, and round ordering. The signed echo is checked before ZF `part2` releases shares; ZF verifies proofs of knowledge and, in `part3`, shares against commitments.
- `crates/frost-sp-wallet/src/dkg/channel.rs:32` and `wire.rs:82`: directional ECDH/HKDF key binding, session/sender/recipient AAD, random AEAD nonces, authenticated ciphertexts, signed plaintext framing, and strict envelope lengths. Host identities with the same x coordinate are rejected by `Params`.
- `crates/frost-sp-wallet/src/dkg/device.rs:333` and `mod.rs:213`: only device 1 distributes a valid scan scalar, inside the private channel. The transcript commits to its public point, all round-1 packages, the session, threshold, group key and verification shares; acceptance requires every host's signature on the receiver's own transcript.
- `crates/frost-sp-wallet/src/dkg/key.rs:82`: reload verification binds the host secret to the identifier, reconstructs the public package from certified commitments, checks the local secret share and threshold, validates polynomial consistency, recomputes the transcript and verifies the complete certificate.
- `crates/frost-sp-wallet/src/dkg/key.rs:179`: public-package reconstruction matches the pinned ZF 3.0.0 `post_dkg` behavior, including even-Y normalization and its initial TapTweak. The resulting full point is used as `B_spend`; the existing SP spend path adds its plain tweak and performs BIP 340 parity handling without applying a second TapTweak.
- `crates/frost-sp-cli/src/lib.rs:117`, `:248`, `:279`, `:385`, and `src/main.rs:81`: certified per-device loading, duplicate and mixed-ceremony rejection, threshold enforcement, one share per written file, exclusive 0600 file creation, seeded-mainnet rejection, and separation of reconstruction from signing. Signing continues through the existing independent tweak, DLEQ, recipient, sighash and nonce checks.
- `crates/frost-sp-wallet/src/group.rs:56` and `Cargo.toml`: trusted-dealer constructors are restricted to tests / the explicit `test-dealer` feature.

Validation completed:

```text
cargo test -p frost-sp-wallet -p frost-sp-cli --all-targets
CLI integration:       14 passed; 0 failed
Wallet unit / DKG:     23 passed; 0 failed
Send end to end:       32 passed; 0 failed
Spend end to end:      18 passed; 0 failed
BIP 352 sending:        1 passed; 0 failed
BIP 352 receiving:      1 passed; 0 failed
BIP 374 vectors:        2 passed; 0 failed
Total:                 91 passed; 0 failed

git diff --check frost-sp...feat/w5-dkg
Passed (no output).
```

The test log is `/tmp/w5-codex-tests.log`. No full-workspace/clippy run or external bitcoind/testkit T8 run was performed during this review. Process isolation, real transport, recovery backups and persisted exposure counters remain outside this work package as specified; passing simulation tests does not verify those properties.
