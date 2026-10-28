# P3: BIP 445 FROST stays unforgeable under Silent Payment tweaks

Draft proof sketch, 2026-10-28. Not reviewed. Confidence is marked per section.

**Result.** P3 holds, with a tight reduction. The reduction goes to the untweaked BIP 445 / FROST3 theorem (CGRS23, which is what BIP 445 itself relies on), not to GK24. The link is one short lemma, "a tweak is part of the message". It works because both hashes that an honest partial signature depends on commit to the tweaked key `Q`. GK24 does not apply directly: it proves a different FROST variant, and its tweak is a single hash output rather than a sum of two. T7 is what makes the lemma go through.

Notation: `p` is the group order (BIP 445 calls it `ord`), and `G` is the generator. `g_Y ∈ {±1}` is +1 iff the point `Y` has even y. `H_ss`, `H_lab`, `H_non` and `H_sig` are the tagged hashes `BIP0352/SharedSecret`, `BIP0352/Label`, `BIP0445/noncecoef` and `BIP0340/challenge`. They are modelled as independent random oracles. `H_reg` is the DKG's proof-of-possession hash.

## 1. Statement (confidence: high)

**In plain words.** Fix one FROST key `X`. The adversary controls fewer than `t` cosigners and the coordinator, knows `b_scan`, and chooses any number of funding transactions. Each honest signer computes the SP tweak itself and signs under `X + τ·G`. The adversary still cannot produce a valid BIP 340 signature under any SP-derived key (or `X`) for a (key, message) pair that no honest signer partially signed.

**Tweak function.** For `w = (Z, k, j)`, where `Z` is a point, `k ∈ [0, 2^32)` and `j ∈ [0, 2^32) ∪ {⊥}`:

```
τ(w) = H_ss(ser(Z) ‖ ser32(k)) + H_lab(ser256(b_scan) ‖ ser32(j))   mod p   (H_lab term = 0 if j = ⊥)
Q(w) = X + τ(w)·G,     signing key = xbytes(Q(w)),   τ(⊥) := 0
```

Letting the adversary pick `Z` freely is stronger than letting it pick `A` and the outpoints, since those only yield `Z = input_hash·b_scan·A`.

**Game SP-UF.** The game follows CGRS23's TS-UF, which is notion TS-UF-0 with static corruption.
1. The adversary picks `CS` with `|CS| < t`. Key generation runs as in BIP 445: SimplPedPop or ChillDKG, or a trusted dealer. The adversary gets `X`, the public shares, the shares of the players in `CS`, and `b_scan`.
2. Oracles:
   - all the random oracles;
   - `OPreRound(i)`: a fresh nonce pair for honest signer `i`;
   - `OSignRound(i, sid, ids, aggnonce, w, m)`: honest signer `i` **computes `τ(w)` itself (T7)** and runs BIP 445 `Sign` with the single plain tweak `τ(w)`. Two plain tweaks `ℓ` then `t` give the same `Q`, `gacc = 1` and `tacc = τ`. The game records `Sigs[(xbytes(Q(w)), m)] ∪= {i}`.
3. The adversary outputs `(w*, m*, σ*)`. It wins iff `BIP340Verify(xbytes(Q(w*)), m*, σ*)` holds and `Sigs[(xbytes(Q(w*)), m*)] = ∅`.

**Claim P3.** Let `A` win SP-UF with advantage `ε`, using `q_s` signing queries, `q_h` queries to each oracle, and `q_ss` / `q_lab` distinct `H_ss` / `H_lab` inputs (including those the honest signers derive). Then some `B` wins TS-UF against untweaked BIP 445 with:

```
Adv_B  ≥  ε − 8·q_h·(q_ss+1)·(q_lab+1)/p
```

`B` uses the same `CS` and `q_s`, makes at most one oracle query per query of `A` plus two per signing query, and takes time `t_A + O((q_h+q_s)·q_lab)` group operations. CGRS23 Theorem 1 then bounds `Adv_B` by AOMDL.

The freshness condition is per (key, message), which is stronger than the message-only condition in CGRS23 and GK24.

## 2. Reduction (confidence: medium-high; checked algebraically, not yet written out in full)

**Key fact (BIP 445 §Signing).** An honest partial signature is `s_i = k1 + b·k2 + e·λ_i·g_Q·gacc·d'_i`. The nonce coefficient is `b = H_non(u ‖ ids ‖ aggnonce ‖ xbytes(Q) ‖ m)` and the challenge is `e = H_sig(xbytes(R) ‖ xbytes(Q) ‖ m)`. So `τ` reaches an honest signer only through `b`, `e` and the sign `g_Q`, and both hashes commit to `Q`. This makes the earlier note that "a tweak is like a message" exact.

**`B` ("tweak as message").** `B` plays TS-UF against untweaked BIP 445, using oracles `H'_non` and `H'_sig`.
- It forwards key generation, `OPreRound` and `H_reg` unchanged.
- It simulates `H_ss` and `H_lab` itself by lazy sampling. It keeps a table `T` of `xbytes(X + τ·G)` for every `τ ∈ {0, t, t+ℓ}` that it can form from values sampled so far.
- Encoding: `msg(τ, m) = 0x01 ‖ ser256(τ) ‖ m`. This is injective and prefix-separated from the `0x00 ‖ m` used for keys not in `T`.
- `A` queries `H_sig(xR ‖ xQ ‖ m)`:
  - if `xQ ∈ T` with tweak `τ`, return `g_Q·g_X · H'_sig(xR ‖ xbytes(X) ‖ msg(τ, m))`;
  - otherwise return `H'_sig(xR ‖ xQ ‖ 0x00‖m)`.
- `A` queries `H_non(u ‖ ids ‖ N ‖ xQ ‖ m)`: the same mapping, without the sign factor. The input parses uniquely: 4 bytes, then 4u bytes, 66 bytes and 32 bytes, then the rest.
- `A` queries `OSignRound(…, w, m)`: `B` computes `τ(w)` from its own tables and calls its own `OSignRound` on message `msg(τ, m)` with no tweak. It returns the partial signature unchanged. This is correct:
  - `b` is equal in both worlds, and so is `R`, and with it the nonce negation.
  - `e·g_Q = g_X·e'`, and `gacc = 1`.
  - So `s_i` is identical.
- Forgery `(w*, m*, (R*, s*))`: `B` outputs `msg(τ*, m*)` and `(R*, s* − g_X·e'·τ*)`. From `s*·G = R* + e*·g_Q*·Q*` with `e*·g_Q* = g_X·e'`, we get `(s* − g_X·e'·τ*)·G = R* + e'·with_even_y(X)`. This is a valid BIP 340 signature, and it is fresh because `msg` is injective.

The simulation is perfect except for the bad event that `A` queries `H_non` or `H_sig` on some `xQ` that only enters `T` later. Each fresh `t` (or `ℓ`) adds at most `q_lab+1` (or `q_ss+1`) uniform keys. Each one hits one of at most `2q_h` earlier x-coordinates with probability at most `4q_h/p` (two points per x). That gives the crude bound in §1. Two different tweaks with the same `xbytes(Q)` would imply `2X = −(τ+τ')·G`, which reveals `x`. That has negligible probability.

**Can the reduction program the SP hashes as in the hash-derived case?** Yes, by lazily sampling `H_ss` and `H_lab`. It needs less than "planting" values, though: it only has to see every tweak before `A` can use the tweaked key. Uniformity of the tweaks is used only in the bad-event bound. Each variation in the setting has the following effect:

| Variation | Effect on the lemma |
|---|---|
| `X` not in the tag hash | None for one key. GK24's `H_r(α, aux)` also omits the key. Only a statement over several FROST keys would need a hybrid argument, or per-key tables. |
| Adversarial, adaptive preimage; `b_scan` known to `A` | None. `A` only chooses which oracle outputs get used, and `B` sees all of them. This is the same as GK24's adversary choosing `(α, aux)`. |
| Unbounded number of tweaks | It appears only in the additive term `q_h·q_ss·q_lab/p`. There is no guessing. |
| Label sum `τ = t + ℓ` | `τ(w)` is **not** a random oracle on `(Z, k, j)`: `τ(Z,k,j) − τ(Z,k,j')` does not depend on `(Z, k)`. So SP cannot be plugged into GK24's `H_r` as written. In the lemma the sum costs nothing: `B` recognises pairs, and `τ` is uniform as long as one summand is fresh. |

If `b` committed only to `X` and not to `Q`, the lemma would fail. A tweak chosen after `aggnonce` would then move `e` while `R` stays fixed, which is ROS territory. BIP 445 does commit to `Q`.

## 3. Tightness (confidence: medium-high)

- **SP layer.** The SP layer adds only an additive term of about `8·q_h·q_ss·q_lab/p`, which is at most `2^-60` for every `q ≤ 2^64`. There is no multiplicative factor in `q_h`, `q_ss` or the number of tweaks. The time overhead is `O(q_lab)` point operations per oracle query, or a precomputed table.
- **End to end.** P3 inherits CGRS23 Theorem 1 unchanged: `ε' ≥ ε²/(8q) − (6+q²)/2^(λ−3)` with `q = 3q_h + 2q_s + t`, and running time about `8q²t²/ε² · ln(·)` times that of `A`. This is a square-root loss from forking, the same as for untweaked BIP 445.
- **Where a factor of `q_h` would come from.** It would come from a DEFLR21-style reduction through "honestly re-randomised keys". There the game hands out uniform randomisers, and the reduction from that notion to plain unforgeability loses a factor in the number of derived keys, which for ECDSA is up to the number of oracle queries. The lemma avoids this because the BIP 340 and BIP 445 hashes commit to the tweaked key. GK24's own bound (eq. 3, `Adv ≤ √(q·Adv_AOMDL + 2q²/p)` with `q = q_h + q_s`) has no tweak-dependent factor either. The radical is garbled in the extracted text; I read it as a square root.

## 4. GK24 as read, and remaining gaps (confidence: high on GK24, medium on the gap list)

**Reading GK24.** The eprint PDF sits behind a Cloudflare challenge for curl and WebFetch. I read the full text from the web.archive.org copy of the only version (2024-03-13, 13 pages). What it actually proves:
- **Scheme.** FROST with **per-signer** binding factors, `a_i = H_non(k, m, PK̄, B)` and `R = Π R_i·S_i^{a_i}`. This is the RFC 9591 / BCKMTZ22 variant, **not FROST3**. BIP 445's footnote extends GK24 to FROST3 by analogy; it is not a theorem about BIP 445.
- **Tweak model (Fig. 4/5).**
  - `PK̄ = PK·g^{H_r(α, aux)}`, with `(α, aux)` chosen by the adversary in each signing query, and the honest oracle hashes them itself.
  - `H_r` does not contain `PK`.
  - There is one additive tweak, with no x-only or parity handling (the setting is Jubjub/Pallas).
  - Key generation is by trusted dealer, and corruption is static.
  - Win condition: `m* ∉ Q`, over all keys; the forgery is under `PK` or `RandPK(PK, α*, aux*)`.
- **Proof.** The proof is a sketch: nonce extraction is "identical to the proof for FROST". It never uses the uniformity of `H_r`, only the fact that the tweak is public. That suggests arbitrary known tweaks would also work for that variant, but nobody has written that proof, and BIP 445 calls arbitrary tweaks open.
- **Implementation (§7).** The coordinator sends the tweak `α̂` itself to the signers, so ZF's crate runs outside the paper's own model. It has no rule equivalent to T7.

**Remaining gaps.**
1. The §2 lemma is a sketch. It needs a written proof and an independent check of the bad-event bound, the sign bookkeeping and the injectivity of the parsing.
2. P3 inherits every assumption of the untweaked scheme:
   - that BIP 445 is covered by CGRS23's Olaf theorem (x-only keys, even-R negation, the `R = G` fallback, `u`-prefixed sorted ids);
   - static corruption only;
   - SimplPedPop, ChillDKG or trusted-dealer key generation;
   - TS-UF-0: a forgery doesn't count if any honest signer partially signed `(Q*, m*)`.
3. `DeterministicSign` is not covered. Its nonce hash includes the tweaked key and would need the same mapping.
4. Several FROST keys, or a shared `b_scan`, are not covered.
5. Outside P3, but readers may assume it is covered: when sending, honest signers return `D_i = x_i·B_scan` for a `B_scan` the recipient chose. That is a static Diffie–Hellman oracle on the shares, which no FROST proof models and which the AOMDL reduction cannot simulate. It needs its own item, for example a count-limited Brown–Gallant/Cheon bound.
6. According to `run/RULES.md`, the PoC currently signs with ZF `frost-secp256k1-tr` 3.0 (RFC 9591), not BIP 445. The lemma carries over to it if its binding factor commits to the tweaked key, in which case the base theorem is BCKMTZ22 and GK24 is the closer reference. I have not checked this.

## 5. Why T7 is needed (confidence: high)

- **It puts the tweak inside the honest oracle.** In SP-UF the honest signer computes `τ(w)` itself. So every key it signs under is `X + τ·G`, where `τ` is a random-oracle output that `B` sampled before `A` could use that key. This is exactly what the mapping in §2 needs.
- **Without it the lemma fails.** If a signer accepted `τ`, or even only `ℓ` while still deriving `t` itself, then `A` could query `H_sig` or `H_non` on `X + τ·G` before revealing `τ`. `B` could not map that query to `msg(τ, m)`, and the lemma would break. That is the "arbitrary tweaks" case BIP 445 calls open. GK24's game does not cover it either, because there the oracle hashes `(α, aux)` itself.
- **Minimal form P3 needs.** The signer computes both tag hashes itself and applies only that one plain tweak, with no extra or x-only tweaks from the coordinator. The preimage `(Z, k, j)` may come from anyone. "From the funding transaction with its own `b_scan`" goes beyond that; that part serves correctness and authorisation, not unforgeability.
- **Status of a direct proof.** A direct proof that re-runs CGRS23 with `τ` as a public coefficient might not need T7. That is the open question, and P3 should not depend on it.

## References

- BIP 445 (bitcoin/bips#2070, `siv2r:bip-frost-signing`), v0.12.1: §Signing, §Tweaking, footnote `arbitrary-tweaks`.
- [GK24] Gouvêa, Komlo. Re-Randomized FROST. https://eprint.iacr.org/2024/436
- [CGRS23] Chu, Gerhart, Ruffing, Schröder. Practical Schnorr Threshold Signatures Without the AGM (Olaf). https://eprint.iacr.org/2023/899. Thm 1.
- [DEFLR21] Das, Erwig, Faust, Loss, Riahi. The Exact Security of BIP32 Wallets. CCS 2021, https://eprint.iacr.org/2021/1287
- [MSMHI15] Morita et al. Schnorr/DSA against related-key attacks. https://eprint.iacr.org/2015/1135. Key-prefixed variants are RKA-secure, single signer. I read only the abstract.
