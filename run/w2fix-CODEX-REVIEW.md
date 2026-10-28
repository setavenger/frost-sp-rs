# W2 review-fix correctness and security review

Reviewed `fix/w2-review` at `323b238423edb5c79d87becf2c3cd032d9f617df` against local `frost-sp` at `395ac61469c1673396fd57c98f26c232cf329fc8`. Read the complete four-file diff and the related ECDH, signing, tweak, scanning, and dependency implementations. No code was edited.

**Result:** one Low finding remains in the attempted exposure-reset hardening. No new Critical, High, or Medium bug, unauthorized-signing path, or practical key-compromise path was established. The finding below is an incomplete fix of the previously reported reset bypass, not a newly introduced regression.

## 1. Low: the rotation reset does not require the signer's key to rotate

**Location:** `crates/frost-sp-wallet/src/exposure.rs:87`, especially the clear/rebind at `:97`; caller access at `crates/frost-sp-wallet/src/spend.rs:131` and release at `crates/frost-sp-wallet/src/send.rs:735`.

`reset_for_rotation(new_group_key)` checks only that caller-supplied bytes differ from the counter's stored bytes. It then clears the counter and changes that metadata. It neither changes nor checks the live `Signer.key_package`. Subsequent `ecdh_shares` calls still compute `D_i` with the original signing share, without checking that the counter remains bound to that share's actual group key. Passing an unrelated key, or just the original key with its compressed parity prefix flipped, therefore restores the budget for the same secret. Alternating two unequal values can repeat this indefinitely.

**Existing executable reproduction:** `crates/frost-sp-wallet/tests/send_e2e.rs:698` (`signer_refuses_ecdh_at_the_exposure_limit`). The test fills the counter, observes refusal, supplies an unrelated key at `:717`, resets at `:718`, and successfully releases another share at `:719`. It never replaces the signer, its key package, wallet, or public key package. This test passed during the review; it currently asserts the bypass as successful rotation.

**Impact and scope:** the new API cannot enforce its documented requirement of an actual key change. A local caller using it as a rotation guard can exceed the configured distinct-key budget under the old secret. This needs access to the mutable counter; the coordinator's typed requests cannot invoke it. The base already exposed an unconditional reset through the same mutable accessor, so this remains Low under the in-process PoC trust model and is not evidence of a remote key-recovery exploit. The explicitly documented restart reset is separate.

**Recommendation:** bind the exposure state to the live signer key, rather than accepting a stand-alone assertion of rotation. For this PoC, removing independent reset and constructing a new signer for genuinely new key material is sufficient. If rotation is retained, update the actual key material together with its counter and reject a counter/key mismatch before release. The regression test should require the unchanged signer to continue refusing after an unrelated-key reset attempt.

## Other requested checks

- **Key-package validation:** `send.rs:460` binds the group key to the local key package, `:464` checks the local verifying share, and `:471` checks `sum(lambda_i * X_i) == X` for the exact signing set used in round B. Together with valid DLEQ proofs, this ties the interpolated ECDH value to the signing key. Missing/substituted shares and a substituted group key are rejected before signing.
- **Parity and tweaks:** the sender uses each re-derived full output key's parity and `sum(g_j) * sum(lambda_i * D_i) + sum(g_j * tau_j) * B`. The plain additive tweak is applied before FROST 3.0's even-Y normalization in `pre_sign`/`pre_aggregate`; no extra BIP 341 tweak is introduced. The parity-cancellation guard remains enforced in both signer rounds.
- **DLEQ and signer checks:** proofs remain against untweaked shares; duplicate, foreign, missing, and invalid shares fail. Each signer re-derives input tweaks and checks approved coins, recipient scripts/amounts, fees, transaction shape, and each message against the corresponding sighash. The new input-hash check correctly rejects zero, as required by BIP 352.
- **Nonces and exposure accounting:** `sign_send` still consumes all pending FROST nonces before validation; the dependency also checks the signer's own commitment. Each input gets a separate pair. DLEQ uses fresh auxiliary randomness and its own nonce derivation. Removing abort charges does not remove nonce consumption; repeated proofs for the same scan key prove the same deterministic `D_i` and do not add a distinct DH-oracle result.

## Validation and limits

- `cargo test -p frost-sp-wallet --locked`: **50 passed, 0 failed** (1 unit, 27 send, 18 spend, 1 sending-vector, 1 receiving-vector, and 2 DLEQ-vector tests). Log: `/tmp/w2fix-codex-review-tests.log`.
- `git diff --check frost-sp...fix/w2-review`: passed.
- An independent native Codex adversarial pass found no supported newly introduced bug and independently noted the remaining reset bypass. That pass reviewed tests/fixtures in summary mode only; the primary review read the complete changed test diff and executed the tests above.
- DLEQ vector tests cover the standard generator used by this wallet and explicitly skip custom-generator cases. No workspace-wide test/clippy run, bitcoind/mempool test, live-chain validation, or formal cryptographic proof was performed.

Primary specifications consulted:

https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki
