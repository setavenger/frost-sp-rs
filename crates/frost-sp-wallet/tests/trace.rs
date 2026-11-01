#![allow(clippy::unwrap_used)]
//! `FROST_SP_TRACE` in process. The variable is process-global, so this test binary holds
//! exactly one test (no other test can race on it). A DKG and a three-input send by devices 1
//! and 3 with the trace on: no secret appears in the trace, the FROST nonces included (replayed
//! from a copy of the RNG the signer drew them from). With the variable empty or removed,
//! nothing more is written.
mod common;

use std::collections::BTreeMap;

use common::*;
use frost_secp256k1_tr as frost;
use frost_sp_wallet::group::FrostGroup;
use frost_sp_wallet::send::{
    execute_send, plan_spend_exact, resolve_input, trace_input, InputSource, Payment, PaymentDest,
    SendCoordinator, SendSignRequest,
};
use frost_sp_wallet::trace;
use frost_sp_wallet::tweak::tweak_key_package;
use frost_sp_wallet::wallet::SpWallet;
use secp256k1::{Scalar, SecretKey};
use serde_json::Value;
use silentpayments::Network;

#[test]
fn trace_holds_no_secret_not_even_a_nonce_and_stops_when_unset() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("trace-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::env::set_var(trace::ENV, &path);
    assert!(trace::enabled());

    // DKG (traced by `keygen`), then a wallet with label 5.
    let keys = frost_sp_wallet::dkg::keygen(2, 3, &mut rng(61)).unwrap();
    let group = FrostGroup::from_device_keys(&keys).unwrap();
    let mut w = SpWallet::new(group.b_scan, group.b_spend().unwrap(), Network::Regtest).unwrap();
    w.add_label(5).unwrap();
    let mut env = Env {
        signers: make_signers(&group, Network::Regtest, &[5]),
        coord: SendCoordinator::new(group.public_key_package.clone(), w),
        group,
        labels: vec![5],
    };
    let mut coins = fund_coins(&env, &[1, -1], None, 1000, 100_000);
    coins.extend(fund_coins(&env, &[1], Some(5), 2000, 100_000)); // sum g = 1
    let taus: Vec<[u8; 32]> = coins.iter().map(|c| resolve_input(env.coord.wallet(), &c.source).unwrap().tau).collect();
    // The right tweak handed in for input 0, a wrong one for the others.
    for (j, c) in coins.iter().enumerate() {
        let handed = if j == 0 { hex::encode(taus[0]) } else { "11".repeat(32) };
        trace_input(env.coord.wallet(), &c.source, Some(&handed));
    }
    let payments = [Payment { dest: PaymentDest::Sp(SpdkReceiver::new(60).code()), amount: bitcoin::Amount::from_sat(150_000) }];
    let change = PaymentDest::Sp(env.coord.wallet().change_address());
    let plan = plan_spend_exact(env.coord.wallet(), &coins, &payments, Some(&change), 5).unwrap();

    // `execute_send` step by step, to see each signer's nonces.
    let set = vec![ident(1), ident(3)];
    let inputs: Vec<InputSource> = plan.coins.iter().map(|c| c.source.clone()).collect();
    let req = env.coord.ecdh_request(&inputs, &plan.approved.outputs, set.clone());
    let mut r = rng(62);
    let (mut shares, mut commitments, mut nonces) = (vec![], BTreeMap::new(), vec![]);
    for s in env.signers.iter_mut().filter(|s| set.contains(&s.identifier())) {
        shares.extend(s.ecdh_shares(&req, &plan.approved, &mut r).unwrap());
        // Same signing share, same RNG state: the replay draws the signer's very nonces.
        let mut replay = r.clone();
        let c = s.commit_inputs(inputs.len(), &mut r);
        for want in &c {
            let (n, again) = frost::round1::commit(env.group.key_packages[&s.identifier()].signing_share(), &mut replay);
            assert_eq!(&again, want, "the replay reproduces the signer's nonces");
            nonces.push(n.hiding().serialize());
            nonces.push(n.binding().serialize());
        }
        commitments.insert(s.identifier(), c);
    }
    let tx = env.coord.build_tx(&inputs, &plan.approved.outputs, &shares, &set).unwrap();
    let packages = env.coord.signing_packages(&tx, &inputs, &commitments).unwrap();
    let sign_req = SendSignRequest {
        inputs: &inputs,
        tx: &tx,
        ecdh_shares: &shares,
        signing_packages: &packages,
        coordinator_tau_hints: None,
    };
    let mut sig_shares = BTreeMap::new();
    for s in env.signers.iter_mut().filter(|s| set.contains(&s.identifier())) {
        sig_shares.insert(s.identifier(), s.sign_send(&sign_req, &plan.approved).unwrap());
    }
    let signed = env.coord.finalize(&tx, &inputs, &packages, &sig_shares).unwrap();

    // The records.
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.lines().all(|l| l.starts_with("{\"step\":")));
    let records: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let of = |step: &'static str| records.iter().filter(move |r| r["step"] == step).collect::<Vec<_>>();
    let ins = of("spend.input");
    assert_eq!(ins.iter().map(|r| r["handed_tweak_matches"].clone()).collect::<Vec<_>>(), [true, false, false]);
    assert_eq!(ins.iter().map(|r| r["label_m"].clone()).collect::<Vec<_>>(), [Value::Null, Value::Null, 5.into()]);
    assert_eq!(ins[0]["t_k"], ins[0]["tweak_t_k_plus_l_m"], "unlabelled: tau = t_k");
    assert_ne!(ins[2]["t_k"], ins[2]["tweak_t_k_plus_l_m"], "labelled: tau = t_k + l_m");
    assert_eq!(of("keygen.dkg").len(), 1);
    assert_eq!(of("send.ecdh_share").len(), 2);
    assert_eq!(of("send.signer_checks").len(), 2);
    assert_eq!(of("send.build_tx")[0]["sum_g"], 1);
    assert_eq!(of("send.input_signature").len(), 3);
    assert_eq!(of("send.final")[0]["tx_hex"], hex::encode(bitcoin::consensus::serialize(&signed)));

    // No secret, as lowercase hex, either sign.
    let mut secrets: Vec<(String, Vec<u8>)> = nonces.iter().enumerate().map(|(i, n)| (format!("nonce {i}"), n.clone())).collect();
    assert_eq!(secrets.len(), 2 * 2 * 3, "two nonces per signer and input");
    for k in &keys {
        let i = k.identifier();
        secrets.push((format!("signing share x_{i}"), k.key_package().signing_share().serialize()));
        secrets.push((format!("host secret of {i}"), k.host_secret().secret_bytes().to_vec()));
        for (j, tau) in taus.iter().enumerate() {
            let tweaked = tweak_key_package(k.key_package(), tau).unwrap();
            secrets.push((format!("x_{i} + tau_{j}"), tweaked.signing_share().serialize()));
        }
    }
    secrets.push(("b_scan".into(), env.group.b_scan.secret_bytes().to_vec()));
    let kps: Vec<_> = keys[..2].iter().map(|k| k.key_package().clone()).collect();
    let x = SecretKey::from_slice(&frost::keys::reconstruct(&kps).unwrap().serialize()).unwrap();
    secrets.push(("group secret x".into(), x.secret_bytes().to_vec()));
    for (j, tau) in taus.iter().enumerate() {
        let xt = x.add_tweak(&Scalar::from_be_bytes(*tau).unwrap()).unwrap();
        secrets.push((format!("x + tau_{j}"), xt.secret_bytes().to_vec()));
    }
    for (what, s) in &secrets {
        let neg = SecretKey::from_slice(s).unwrap().negate().secret_bytes();
        for (sign, bytes) in [("", s.as_slice()), ("-", neg.as_slice())] {
            assert!(!text.contains(&hex::encode(bytes)), "{sign}{what} appears in the trace");
        }
    }

    // Off: empty, then removed. Nothing more is written.
    let len = std::fs::metadata(&path).unwrap().len();
    std::env::set_var(trace::ENV, "");
    assert!(!trace::enabled());
    trace::emit("must.not.appear", serde_json::json!({}));
    std::env::remove_var(trace::ENV);
    assert!(!trace::enabled());
    frost_sp_wallet::dkg::keygen(2, 3, &mut rng(63)).unwrap();
    execute_send(&env.coord, &mut env.signers, &set, &plan, &mut r).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), len, "the trace grew while off");
    std::fs::remove_file(&path).unwrap();
}
