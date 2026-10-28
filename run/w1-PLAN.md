# W1 plan: FROST layer and receiving

Process note: `/autoplan` was started, but its full CEO/design/DX/eng pipeline (snapshot tool, Codex voices, approval gate) is built for interactive plan review and was not run end to end; this plan is the brief plus a self-review, recorded as a deviation in the summary.

## FROST layer: option (a), unpatched
- `frost-secp256k1-tr` 3.0: plain `round2::sign` / `aggregate` apply NO taproot tweak (only `*_with_tweak` does). `KeyPackage::new` and `PublicKeyPackage::new` are public.
- Tweak by rebuilding packages: `s_i' = s_i + tau`, `X_i' = X_i + tau*G`, `X' = X + tau*G`. Lagrange weights sum to 1, so sum(l_i s_i') = x + tau. The internal `pre_sign`/`pre_aggregate` then negate for even Y *after* the tweak. No vendoring needed.
- Chosen over (b)/(c): smallest change, already a dependency, same signature format.

## Crate `crates/frost-sp-wallet`
- `tweak.rs`: `tweak_key_package`, `tweak_public_key_package`, plain tau (x-only handled by the library).
- `group.rs`: trusted-dealer setup (PoC only): `FrostGroup`, `from_secret` (split an existing secret for vectors).
- `wallet.rs`: `SpWallet` (spdk `Receiver`, labels, `sp1`/`tsp1`/`sprt1` addresses, change at m=0), `scan_tx` -> `OwnedOutput {outpoint, value, spk, tau, label}`; full k-loop via spdk.
- `spend.rs`: `Signer` (own `b_scan`, own nonces consumed on use), `Coordinator`, `SignRequest` carrying funding tx + funding-input prevout scripts, never a tweak. Signer re-derives tau, checks funding output key, approved outputs, outpoint, sighash == FROST message. Single input.
- Tests: T1 (BIP 352 receiving vectors, labels, FROST sig verifies under each output key, tau == vector priv_key_tweak), T2 (BIP340 + libbitcoinconsensus script verification), T3 (parity/tweak matrix), T7 (re-derivation, wrong tweak refused).

## Risks
- k256 vs secp256k1 type bridging: go through 32/33-byte encodings.
- No bitcoind here: `testmempoolaccept` not run; consensus check via `bitcoinconsensus`.
