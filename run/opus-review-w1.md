# W1 security review (Opus): FROST tweak, scanning, signer checks, P3 carry-over

Reviewed `frost-sp` at `170ea8c` (W1 merged in `d849bc9`), crate `crates/frost-sp-wallet`. Read-only static review against the installed sources `frost-core 3.0.0`, `frost-secp256k1-tr 3.0.0`, `frost-rerandomized 3.0.0` (Cargo.lock pins 3.0.0) and spdk `silentpayments` at `0fcf8e7`. No tests were run and no code was changed. Registry paths below are relative to `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`.

**Verdict.** The core cryptography is correct: no Critical, High or Medium findings. The tweak is consistent for every signer set. Even-Y negation happens after the tweak, in both signing and aggregation. Binding factor and challenge both commit to the tweaked key, and the signer cannot be made to sign under an untweaked or foreign key. All findings are Low or Info.

## Part 1: findings, most severe first

### F1 (Low): the approval does not bind nLockTime, nSequence or version
`src/spend.rs:76-81` (`ApprovedSpend`), checks at `src/spend.rs:157-177`.
- The sighash (SIGHASH_DEFAULT) commits to locktime, sequence and version, but the signer never checks them. The coordinator chooses them freely.
- **Scenario.** A malicious coordinator sets `nLockTime = 1_000_000` (height), or a BIP 68 relative lock in `nSequence`. The signed tx is valid but cannot be mined for years. The user sees "payment stuck" and approves the same payout again from coin B. Coin A stays unspent, and when the lock matures the first tx becomes valid: the recipient is paid twice.
- **Fix.** Add `lock_time` and per-input `sequence` to `ApprovedSpend`, or have the signer require `lock_time` ≤ its view of the tip (anti-fee-sniping range) and `sequence ∈ {0xfffffffd, 0xfffffffe, 0xffffffff}`.

### F2 (Low): the signer scans an unauthenticated funding tx before checking the approved outpoint (CPU DoS)
`src/spend.rs:135-137` (scan) runs before `src/spend.rs:160-169` (txid/outpoint vs `approved.outpoint`).
- The k-loop costs about `k_matches × candidates × 2` point additions (`src/wallet.rs:169-197`), and nothing limits the size of the funding tx.
- **Scenario.** The coordinator holds `b_scan`, as every cosigner does. It sends a fabricated, never-broadcast funding tx with 2323 matching outputs and 10^6 P2TR decoys. Each signer then does about 4.6·10^9 point additions before it refuses. On a hardware signer that is hours.
- **Fix.** First check `funding_tx.compute_txid() == approved.outpoint.txid` and `funding_vout == approved.outpoint.vout`, then scan. This also makes the funding tx authenticated before any expensive work; see Q(b).

### F3 (Low): the BIP 352 rule "skip tx that spends a SegWit v>1 output" is not enforced
`src/wallet.rs:130-141`. spdk's `get_pubkey_from_input` returns `Ok(None)` for every unknown script (`silentpayments/src/utils/receiving.rs:237`), so a v2+ input is silently treated as ineligible instead of making the tx unscannable.
- BIP 352 ("Scanning silent payment eligible transactions") requires that the transaction "does not spend an output with SegWit version > 1". No case in the vector file covers this (29 cases checked), so T1 cannot catch it.
- **Scenario.** A non-compliant sender pays the wallet in a tx that also spends a v2 output. This wallet credits the output, but a compliant wallet restored from the same keys never sees it. After a future soft fork gives v2 inputs key semantics (which is the reason for the rule), this wallet would compute a different `A` than compliant senders, and payments would be missed.
- **Fix.** In `scan_tx`, return `Ok(vec![])` when any `prevout_spks[i]` is a witness program with version 2..=16. Add a vector-style test.

### F4 (Low): with a wrong `tau`, the coordinator names an honest signer as the cheater
`src/spend.rs:232-233`. `aggregate` uses `CheaterDetection::FirstCheater` (`frost-core-3.0.0/src/lib.rs:571-576`).
- If `owned.tau` is wrong (a coordinator bug, or in W2 a per-input `tau_j` mix-up), the aggregate signature fails to verify. `detect_cheater` (`frost-core-3.0.0/src/lib.rs:690-744`) then checks shares against the wrongly tweaked verifying shares and returns `InvalidSignatureShare { culprits: [honest id] }`.
- **Scenario.** W2's multi-input aggregation swaps `tau_0` and `tau_1`. The coordinator logs signer 1 as malicious and excludes it from later sessions.
- **Fix.** Before `aggregate`, check that `x(X + tau·G)` equals the key in `owned.script_pubkey[2..]` and return a coordinator-side error if not. `spend.rs:236-238` already parses that key.

### F5 (Info): correctness depends on frost-secp256k1-tr 3.0 internals
- The design is correct only because plain `round2::sign` and `aggregate` apply no taproot tweak and run `pre_sign`/`pre_aggregate` on the package they are given (see Q(a)).
- `Cargo.toml` says `frost-secp256k1-tr = "3.0.0"`, which is a caret requirement; only Cargo.lock pins 3.0.0. A 3.x release that changes these hooks would silently break SP spends. T2/T3 would catch it, but only if they run on every bump.
- Pin `=3.0.0`, or keep T2/T3 mandatory in CI.
- Heads-up for the later move to DKG: `post_dkg` (`frost-secp256k1-tr-3.0.0/src/lib.rs:478-491`) bakes a TapTweak into the DKG group key. That is harmless here, because `B_spend` is read from the resulting package (`src/group.rs:81-84`). The trusted dealer has no such hook.

### F6 (Info): the output sum can overflow
`src/spend.rs:173`. `out_sum: u64 = …sum()` panics in debug builds and wraps in release builds.
- It can only be reached if the approved outputs themselves overflow, since the outputs must equal the approved ones.
- Use `checked_add`, or reject any output above MAX_MONEY.

## Part 1: the requested checks, with answers

**Tweak correctness for every signer set (`src/tweak.rs:23-52`): correct.**
- `KeyPackage` stores only identifier, `signing_share`, `verifying_share`, `verifying_key` and `min_signers` (`frost-core-3.0.0/src/keys.rs:635-651`). `KeyPackage::new` neither validates nor derives anything (`keys.rs:658-673`).
- `PublicKeyPackage` stores only the share map, `verifying_key` and `min_signers` (`keys.rs:728-743`). Nothing is cached, and no VSS commitment travels with either package.
- Verifying shares are `evaluate_vss(id, C)` (`keys.rs:200-215, 452-454`). So `X_i + τG` is exactly the share that a commitment with `C_0' = C_0 + τG` would give: the tweaked packages describe the polynomial `f(z) + τ`.
- `Σ_{i∈S} λ_i^S(0) = 1` for any set of distinct identifiers, including `|S| > t` (it interpolates the constant 1). `round2::sign` rejects `|S| < min_signers` (`frost-core-3.0.0/src/round2.rs:130-132`).
- ZF's own re-randomized FROST tweaks packages the same way (`frost-rerandomized-3.0.0/src/lib.rs:68-121`) and then calls the same plain `frost::round2::sign`/`aggregate`.
- `tweak.rs` correctly does **not** lift `X` to even Y before tweaking. BIP 352 uses the full `B_spend` point, unlike the library's BIP 341 `Tweak` impl (`frost-secp256k1-tr-3.0.0/src/lib.rs:776-792`), which is not used.

**Even-Y after the tweak, in signing and aggregation: yes.**
- **Signing.** `round2::sign` → `pre_sign` (`frost-core-3.0.0/src/round2.rs:145-146` → `frost-secp256k1-tr-3.0.0/src/lib.rs:308-325`) → `KeyPackage::into_even_y` (`frost-secp256k1-tr-3.0.0/src/lib.rs:654-678`). This negates share, verifying share and group key together iff the **tweaked** `Q` has odd Y.
  - The binding factor (`round2.rs:150-151`) and the challenge (`round2.rs:166-170`, `frost-secp256k1-tr-3.0.0/src/lib.rs:380-392`, which is `BIP0340/challenge(x(R)‖x(Q)‖m)`) are both computed from that negated, tweaked key.
  - The nonces are negated iff `R` has odd Y (`frost-secp256k1-tr-3.0.0/src/lib.rs:394-416`).
- **Aggregation.** `pre_aggregate` (`frost-core-3.0.0/src/lib.rs:630-631` → `frost-secp256k1-tr-3.0.0/src/lib.rs:329-346`) negates the tweaked public package the same way. The binding factor is computed from it (`frost-core-3.0.0/src/lib.rs:635-636`), and so is cheater detection.
- **Algebra.** With `g_Q, g_R ∈ {±1}`: `z = Σ z_i = g_R·r + c·g_Q·Σλ_i(x_i+τ) = g_R·r + c·g_Q·(x+τ)`. So `z·G = lift_x(x(R)) + c·lift_x(x(Q))`, which is a valid BIP 340 signature under `x(Q)`.

**Can a signer sign under an untweaked or wrongly tweaked key? No, not through the `Signer` API.**
- `Signer::new` binds the package to `B_spend` (`src/spend.rs:93-98`).
- `sign` always tweaks with the self-derived `τ` and refuses unless `x(X+τG)` equals the funding output key (`src/spend.rs:149-154`). There is no tweak parameter, and the hint is only compared (`src/spend.rs:141-146`).
- A second `τ'` with the same x-coordinate would need `τ' = −2x − τ`, which means knowing `x`.

**Scanning (`src/wallet.rs:118-212`): correct.**
- **k-loop.** It continues on any cryptographic match and stops at the first k without one (`:198`).
- **K_max.** `0..K_MAX` checks k = 0…2322, which matches "if k == K_max stop".
- **Labels.** Matched on `±output − P_k` (`:183-193`), with change (m = 0) always registered (`:64`). The resulting `τ = t_k + ℓ_m` gives `x(X+τG) = x(output)` in both parities.
- **Input keys.** Extracted by spdk: P2PKH window search, P2SH-P2WPKH, P2WPKH (hash-checked), P2TR lifted to even, NUMS script paths skipped, annex handled.
- **input_hash.** Uses the minimum over **all** inputs' outpoints (`silentpayments/src/utils/common.rs:165-167`), compared byte-wise on `txid_le‖vout_le` (`src/wallet.rs:133-136`).
- **Edge cases.** An all-ineligible tx and a point-at-infinity sum both return empty (`:139-149`; the variant matches spdk's `From<secp256k1::Error>`). Invalid P2TR x-coordinates are skipped (`:157`).
- The only gap is F3. Failing on `t_k ≥ n` or on `t_k + ℓ_m = 0` (`:171, :188`) has negligible probability.

**Signer checks (`src/spend.rs:128-186`): correct, apart from F1 and F2.**
- **τ.** Re-derived from the funding tx with the signer's own `b_scan` and labels (T7 ✓).
- **Coin.** Outpoint = `compute_txid(funding_tx):vout` = `approved.outpoint`.
- **Outputs and fee.** Exact equality of `Vec<TxOut>`. Fee = authenticated prevout value − Σ outputs ≤ `max_fee`.
- **Message.** The FROST message must equal the signer's own BIP 341 key-path sighash, computed with `Prevouts::All([funding_txo])` after enforcing one input.
- **Nonces.** `take()` runs before every check (`:129-132`), so every refusal and every error consumes them. `commit` overwrites rather than accumulating. frost-core also checks that the package carries this signer's own commitment (`round2.rs:134-143`).
- I found no path where a nonce pair is used twice, or where one nonce pair is used under two keys.

### The W1 summary's NEEDS-OPUS-REVIEW items

**(a) Does tweak/parity handling rely correctly on `pre_sign`/`pre_aggregate` negating after the tweak?** Yes; verified by reading the source, not only by tests.
- The tweaked package goes into plain `round2::sign`/`aggregate`, which apply no taproot tweak (`frost-secp256k1-tr-3.0.0/src/lib.rs:856-862, 894-900`).
- Both run the even-Y hook on whatever package they receive, before computing the binding factors, R, the challenge and the shares. Line references and the algebra are above.
- Signer and coordinator negate consistently, because both decide by the parity of the same tweaked `Q`.
- **Residual risk:** dependency drift only (F5).

**(b) The signer cannot check that the funding tx is confirmed or that `funding_prevout_spks` are real. Is that acceptable?** Yes for the PoC (Low), and the risk is narrower than the summary states.
- **What is authenticated.** The non-witness part of the funding tx is bound by `compute_txid() == approved.outpoint.txid`, so output values and scripts are authentic relative to the approved outpoint.
- **What is not, and why it is harmless.** Prevout scripts and witnesses are not committed by the txid. Changing them only changes which input keys count, and so `A`, `τ` and the derived key, which then fails the output-key match: a refusal, not a mis-signature.
- **Fabricated funding tx.** One is accepted only if the approver approved its non-existent outpoint. The BIP 341 sighash then commits to that outpoint, amount and script, so the signature cannot move any real coin.
- **Forgery.** No advantage: P3's game already lets the adversary pick `Z` freely, and the fabricated tx is just such a choice.
- **What remains is UX:** a user may believe a payment was made.
- **Handling.**
  - Approval shows only coins from the signer's own chain view (W3).
  - Do the outpoint check before scanning (F2).

## Part 2: does P3 carry over to ZF RFC 9591 FROST with tweaked packages?

**Source check.** Both hashes an honest share depends on commit to the **tweaked** key, because the PoC passes the tweaked package into `round2::sign`.
- **Binding factor (H1).** Computed after `pre_sign` with `key_package.verifying_key` (`frost-core-3.0.0/src/round2.rs:150-151`).
  - Its preimage is `ser(lift_even(Q)) ‖ H4(m) ‖ H5(commitments) ‖ id` (`frost-core-3.0.0/src/lib.rs:413-431`; the key is at `:423`).
  - Because of the even lift, the 33-byte encoding carries exactly `xbytes(Q)`.
  - The coordinator side does the same (`frost-core-3.0.0/src/lib.rs:635-636`).
- **Challenge (H2).** `BIP0340/challenge(x(R) ‖ x(Q) ‖ m)` with the same tweaked key (`round2.rs:166-170`; `frost-secp256k1-tr-3.0.0/src/lib.rs:380-392`).
- **Design note.** This holds only because the tweak goes into the package. Keeping the untweaked package and adding `τ` at aggregation, BIP 445-style, would make H1 commit to `X` instead. P3 §2 shows the lemma then fails (the ROS case). Keep the `tweak.rs` design.

**What changes in the P3 §2 reduction.**
1. **Partial signatures.** In BIP 445 the tweak enters only at aggregation. Here every share carries `λ_i·c·g_Q·τ`.
   - A share in the PoC is `z_i = g_R(d_i + ρ_i e_i) + λ_i·c·g_Q·(x_i + τ)`.
   - With P3's programming `c·g_Q = g_X·c'` and `ρ_i = ρ'_i`, this gives `z_i = z'_i + λ_i·c·g_Q·τ`.
   - So `B` must **add** `λ_i·c·g_Q·τ` to the share returned by its own oracle, instead of returning it unchanged. Every term is public to `B`.
   - The shares sum to `c·g_Q·τ`, exactly the aggregation term in BIP 445, so the forgery map `s* − g_X·c'·τ*` is unchanged.
2. **Pre-hashed message.** H1 contains `H4(m)`, not `m`. `B` simulates H4 lazily and keeps a table, so it can recover `m` and map `H1(ser(Q)‖h4‖h5‖id)` to `H1'(ser(lift_even(X))‖H4'(msg(τ,m))‖h5‖id)`.
   - This adds an `O(q_h²/p)` term for H4 collisions or unseen preimages. H5 and the per-identifier suffix pass through unchanged.
3. **Per-signer binding factors** (FROST1 shape rather than FROST3's single `b`). The mapping is applied per identifier; `R`, and with it the nonce negation, is identical in both worlds, as in P3.
4. **Base theorem.** The target is no longer CGRS23.
   - RFC 9591 cites [StrongerSec22] (BCKMTZ22, CRYPTO 2022). In their FROST1, `d_i = h1(vk, lr, i)` with `vk` inside, and they prove TS-SUF-3 under OMDL in the ROM **with trusted key generation**.
   - That matches the PoC's dealer and gives a freshness notion at least as strong as P3's TS-UF-0.
   - GK24 (Re-Randomized FROST, AOMDL + ROM) is the closest direct precedent. It uses the same tweak-the-package construction, which ZF ships as `frost-rerandomized`.
   - But GK24's tweak is a single RO output that the honest oracle hashes. The SP sum `t_k + ℓ_m` still needs P3's lemma (P3 §2, the table row on the label sum).
5. **New gaps for this variant.**
   - I found no proof of RFC 9591 / FROST1 signing combined with a DKG. BCKMTZ22 and CKM21 cover FROST2 + PedPoP; CGRS23 covers FROST3 + SimplPedPoP.
   - Moving the PoC to ZF's PedPoP DKG would therefore leave the key-generation step unproven.
   - `frost-secp256k1-tr` is ZF's BIP 340 adaptation and not an RFC 9591 ciphersuite: x-only challenge, even-Y key and nonce negation. No paper covers it. This is the same x-only gap P3 lists for BIP 445 (P3 §4, gap 2).

**Conclusion.** P3's argument carries over to the PoC: H1 and H2 both bind `xbytes(X+τG)`, and T7 holds (`src/spend.rs:135-146`).
- **Required edits to P3:**
  - In the simulated sign oracle, `B` adds `λ_i·c·g_Q·τ` to each honest share, because the PoC tweaks per share.
  - `B` also simulates H4 so it can un-hash `m`, at a small additive cost.
- **Base theorem:** BCKMTZ22's FROST1 theorem (OMDL, ROM, trusted dealer) replaces CGRS23. GK24 is the nearest precedent for tweaked packages.
- **Still open:**
  - a written proof;
  - the x-only/even-Y adaptation;
  - any DKG for the RFC 9591 shape.

References: BCKMTZ22 = Bellare, Crites, Komlo, Maller, Tessaro, Zhu, "Better than Advertised Security for Non-interactive Threshold Signatures", CRYPTO 2022 (full version eprint 2022/833, "Stronger Security for Non-Interactive Threshold Signatures: BLS and FROST"). GK24 = eprint 2024/436. CGRS23 = eprint 2023/899. CKM21 = Crites, Komlo, Maller, eprint 2021/1375. RFC 9591 §7 (Security Considerations).
