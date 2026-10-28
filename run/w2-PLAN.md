# W2 plan: paying SP addresses from an SP-only FROST wallet

Reduced autoplan (same as W1): written from the brief, no CEO/eng phases run.

## Design
- `send.rs`: pure sender math (`SenderContext`: A, input_hash, sum g, sum g*tau; threshold ECDH `a*B = (sum g)*sum lambda_i D_i + (sum g*tau)*B`; self scan key via `b_scan*A`), BIP 374 shares (`make_ecdh_share`, `ecdh_for_outputs` verifies every proof against the untweaked X_i and names the culprit), `Signer::{commit_inputs, ecdh_shares, sign_send}`, `SendCoordinator`, `plan_send` (coin selection with the sum g != 0 guard), `execute_send`/`send_payment` (W4 library entry).
- Two rounds: A = ECDH shares (signer checks coins, parity guard, approved scan keys, exposure limit); B = sign (signer re-derives tau_j, verifies all proofs, recomputes every SP output, amounts, fee, tx shape, per-input sighash).
- One nonce pair per input; nonces taken before any check.
- `exposure.rs`: distinct non-self scan keys + aborted sessions, thresholds 1e3/1e6/1e9.
- W1 follow-ups from the Opus review: F1-F4.

## Tests
T1 sending vectors (threshold path), T3 mixed parity/labels, T4 scan keys, T5 adversarial (one test per case), T6 BIP 374 vectors and nonce rules, round trip A->B,C / B->C / A change, leak demo for the guard, exposure counter.
