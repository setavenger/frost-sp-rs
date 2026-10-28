#![allow(clippy::unwrap_used)]
//! W2: sending to SP addresses from the FROST wallet. T1 (in-process round trip), T3, T4, T5,
//! T6 (nonces), parity guard, exposure counter.
mod common;

use std::collections::BTreeMap;

use bitcoin::{Amount, ScriptBuf, Transaction};
use common::*;
use frost_secp256k1_tr as frost;
use frost_sp_wallet::send::*;
use frost_sp_wallet::Error;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

fn pay_sp(code: &silentpayments::SilentPaymentCode, sat: u64) -> Payment {
    Payment {
        dest: PaymentDest::Sp(*code),
        amount: Amount::from_sat(sat),
    }
}

fn xonly(s: &ScriptBuf) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&s.as_bytes()[2..]).unwrap()
}

// ---------------------------------------------------------------------------------------
// In-process round trip
// ---------------------------------------------------------------------------------------

#[test]
fn round_trip_a_pays_b_and_c_b_pays_c_a_finds_change() {
    let mut a = env(1, &[]);
    let mut b = env(2, &[5]);
    let c = SpdkReceiver::new(3);
    let set = [ident(1), ident(3)];

    // A holds three coins of mixed parity; the payment needs two of them.
    let coins = fund_coins(&a, &[1, 1, -1], None, 100, 60_000);
    let b_labelled = b.address(Some(5));
    let payments = vec![
        pay_sp(&b_labelled, 40_000),
        pay_sp(&b.address(None), 15_000), // second output for B's scan key: k = 1
        pay_sp(&c.code(), 20_000),
        Payment {
            dest: PaymentDest::Script(ScriptBuf::new_p2tr_tweaked(
                bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                    bitcoin::XOnlyPublicKey::from_slice(&[7u8; 32]).unwrap_or_else(|_| {
                        bitcoin::XOnlyPublicKey::from_slice(
                            &sk_from_seed(9, "plain").x_only_public_key(&Secp256k1::new()).0.serialize(),
                        )
                        .unwrap()
                    }),
                ),
            )),
            amount: Amount::from_sat(5_000),
        },
    ];
    let (tx1, plan) = send_payment(&a.coord, &mut a.signers, &set, &coins, &payments, 2, &mut rng(11)).unwrap();
    assert_eq!(plan.coins.len(), 2);
    assert_eq!(tx1.output.len(), 5, "4 payments + change");
    let spks1 = prevout_spks_of(&plan.coins);

    // B and C find their outputs with their own scanners.
    let b_found = b.coord.wallet().scan_tx(&tx1, &spks1).unwrap();
    assert_eq!(b_found.len(), 2);
    assert!(b_found.iter().any(|o| o.label == Some(5)));
    assert_eq!(b_found.iter().map(|o| o.value.to_sat()).sum::<u64>(), 55_000);
    let c_found = c.scan(&tx1, &spks1);
    assert_eq!(c_found, vec![xonly(&tx1.output[2].script_pubkey)]);

    // A finds its own change (label 0).
    let a_found = a.coord.wallet().scan_tx(&tx1, &spks1).unwrap();
    assert_eq!(a_found.len(), 1);
    assert_eq!(a_found[0].label, Some(0));
    let fee = plan.fee.to_sat();
    assert_eq!(a_found[0].value.to_sat(), 120_000 - 80_000 - fee);

    // B spends both received outputs to C (B's own coins have to have sum g != 0 for this).
    let b_coins: Vec<_> = b_found.iter().map(|o| coin_from(&tx1, &spks1, o.outpoint.vout)).collect();
    let gs: Vec<i8> = b_coins
        .iter()
        .map(|k| resolve_input(b.coord.wallet(), &k.source).unwrap().g)
        .collect();
    println!("B's coin parities: {gs:?}");
    let pay = vec![pay_sp(&c.code(), 50_000)];
    let res = send_payment(&b.coord, &mut b.signers, &[ident(1), ident(2)], &b_coins, &pay, 2, &mut rng(12));
    if gs.iter().map(|g| i32::from(*g)).sum::<i32>() == 0 {
        // Opposite parities: the guard must refuse, and it does.
        assert!(res.is_err());
    } else {
        let (tx2, plan2) = res.unwrap();
        assert_eq!(plan2.coins.len(), 2);
        let spks2 = prevout_spks_of(&plan2.coins);
        assert_eq!(c.scan(&tx2, &spks2), vec![xonly(&tx2.output[0].script_pubkey)]);
        let b_change = b.coord.wallet().scan_tx(&tx2, &spks2).unwrap();
        assert_eq!(b_change.len(), 1);
    }
}

#[test]
fn b_spends_received_outputs_to_c_multi_input() {
    // Find a seed pair where B receives two same-parity coins and spends both.
    for seed in 20..60u64 {
        let mut a = env(seed, &[]);
        let mut b = env(seed + 1000, &[]);
        let c = SpdkReceiver::new(seed);
        let coins = fund_coins(&a, &[1], None, seed * 10, 200_000);
        let pays = vec![pay_sp(&b.address(None), 60_000), pay_sp(&b.address(None), 60_000)];
        let (tx1, plan) = send_payment(&a.coord, &mut a.signers, &[ident(1), ident(2)], &coins, &pays, 1, &mut rng(seed)).unwrap();
        let spks1 = prevout_spks_of(&plan.coins);
        let found = b.coord.wallet().scan_tx(&tx1, &spks1).unwrap();
        assert_eq!(found.len(), 2);
        let b_coins: Vec<_> = found.iter().map(|o| coin_from(&tx1, &spks1, o.outpoint.vout)).collect();
        let g: i32 = b_coins.iter().map(|k| i32::from(resolve_input(b.coord.wallet(), &k.source).unwrap().g)).sum();
        if g == 0 {
            continue;
        }
        let (tx2, plan2) = send_payment(&b.coord, &mut b.signers, &[ident(2), ident(3)], &b_coins, &[pay_sp(&c.code(), 100_000)], 1, &mut rng(seed + 5)).unwrap();
        assert_eq!(plan2.coins.len(), 2, "both coins needed");
        let spks2 = prevout_spks_of(&plan2.coins);
        assert_eq!(c.scan(&tx2, &spks2).len(), 1);
        println!("round trip B->C multi-input at seed {seed}, sum g = {g}");
        return;
    }
    panic!("no seed with same-parity coins");
}

// ---------------------------------------------------------------------------------------
// T3: parities, labels, mixed sets
// ---------------------------------------------------------------------------------------

#[test]
fn t3_mixed_parity_and_labelled_inputs() {
    let secp = Secp256k1::new();
    let _ = secp;
    let mut seen = std::collections::BTreeSet::new();
    let cases: Vec<(Vec<i8>, Option<u32>)> = vec![
        (vec![1], None),
        (vec![-1], None),
        (vec![1, 1], None),
        (vec![-1, -1], None),
        (vec![1, 1, -1], None),
        (vec![-1, -1, 1], Some(7)),
        (vec![1, -1, -1, -1], Some(7)),
        (vec![-1], Some(7)),
    ];
    for (n, (par, label)) in cases.into_iter().enumerate() {
        let mut a = env(40 + n as u64, &[7]);
        let c = SpdkReceiver::new(50 + n as u64);
        let coins = fund_coins(&a, &par, label, 1000 * (n as u64 + 1), 50_000);
        let total: u64 = coins.iter().map(|k| k.value.to_sat()).sum();
        let pay = vec![pay_sp(&c.code(), total - 3_000)]; // forces every coin in, leaves ~ fee
        let (tx, plan) = send_payment(&a.coord, &mut a.signers, &[ident(2), ident(3)], &coins, &pay, 1, &mut rng(n as u64)).unwrap();
        assert_eq!(plan.coins.len(), par.len());
        let spks = prevout_spks_of(&plan.coins);
        assert_eq!(c.scan(&tx, &spks), vec![xonly(&tx.output[0].script_pubkey)], "case {par:?}");
        seen.insert((par, label));
    }
    assert_eq!(seen.len(), 8);
}

#[test]
fn t3_every_signing_set_gives_the_same_transaction_outputs() {
    let mut a = env(70, &[]);
    let c = SpdkReceiver::new(71);
    let coins = fund_coins(&a, &[1, 1, -1], None, 777, 40_000);
    let pay = vec![pay_sp(&c.code(), 100_000)];
    let mut outs = vec![];
    for set in [[ident(1), ident(2)], [ident(2), ident(3)], [ident(1), ident(3)]] {
        let (tx, _) = send_payment(&a.coord, &mut a.signers, &set, &coins, &pay, 1, &mut rng(1)).unwrap();
        outs.push(tx.output.iter().map(|o| o.script_pubkey.clone()).collect::<Vec<_>>());
    }
    assert_eq!(outs[0], outs[1]);
    assert_eq!(outs[1], outs[2]);
}

// ---------------------------------------------------------------------------------------
// T4: invalid scan keys
// ---------------------------------------------------------------------------------------

#[test]
fn t4_invalid_scan_keys_are_rejected() {
    let secp = Secp256k1::new();
    let good = sk_from_seed(1, "s").public_key(&secp).serialize();
    assert!(validate_scan_key(&good).is_ok());

    let mut off_curve = vec![0x02];
    off_curve.extend_from_slice(&[0u8; 31]);
    off_curve.push(5); // x = 5 has no y on secp256k1
    assert!(validate_scan_key(&off_curve).is_err(), "off curve");

    let mut ge_p = vec![0x02];
    ge_p.extend_from_slice(&[0xff; 32]); // x >= p
    assert!(validate_scan_key(&ge_p).is_err(), "x >= p");
    let mut eq_p = vec![0x03];
    eq_p.extend_from_slice(&hex::decode("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f").unwrap());
    assert!(validate_scan_key(&eq_p).is_err(), "x == p");

    assert!(validate_scan_key(&[0u8; 33]).is_err(), "infinity as zeros");
    assert!(validate_scan_key(&[0u8]).is_err(), "infinity as single 00");

    for prefix in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff] {
        let mut k = good;
        k[0] = prefix;
        assert!(validate_scan_key(&k).is_err(), "prefix {prefix:#x}");
    }
    assert!(validate_scan_key(&good[..32]).is_err(), "short");
    let mut long = good.to_vec();
    long.push(0);
    assert!(validate_scan_key(&long).is_err(), "long");
    // uncompressed encoding of a valid key is not a 33-byte scan key
    assert!(validate_scan_key(&sk_from_seed(1, "s").public_key(&secp).serialize_uncompressed()).is_err());
}

// ---------------------------------------------------------------------------------------
// Staged session for adversarial tests
// ---------------------------------------------------------------------------------------

struct Stage {
    inputs: Vec<InputSource>,
    plan: SendPlan,
    set: Vec<frost::Identifier>,
    shares: Vec<EcdhShare>,
    tx: Transaction,
    packages: Vec<frost::SigningPackage>,
}

fn stage(env: &mut Env, coins: &[SpendableCoin], payments: &[Payment], seed: u64) -> Stage {
    let set = vec![ident(1), ident(2)];
    let plan = plan_send(env.coord.wallet(), coins, payments, 1).unwrap();
    let inputs: Vec<InputSource> = plan.coins.iter().map(|c| c.source.clone()).collect();
    let req = env.coord.ecdh_request(&inputs, &plan.approved.outputs, set.clone());
    let mut r = rng(seed);
    let mut shares = vec![];
    let mut commitments = BTreeMap::new();
    for s in env.signers.iter_mut().filter(|s| set.contains(&s.identifier())) {
        shares.extend(s.ecdh_shares(&req, &plan.approved, &mut r).unwrap());
        commitments.insert(s.identifier(), s.commit_inputs(inputs.len(), &mut r));
    }
    let tx = env.coord.build_tx(&inputs, &plan.approved.outputs, &shares, &set).unwrap();
    let packages = env.coord.signing_packages(&tx, &inputs, &commitments).unwrap();
    Stage { inputs, plan, set, shares, tx, packages }
}

impl Stage {
    fn request<'a>(&'a self, tx: &'a Transaction, shares: &'a [EcdhShare], packages: &'a [frost::SigningPackage]) -> SendSignRequest<'a> {
        SendSignRequest {
            inputs: &self.inputs,
            tx,
            ecdh_shares: shares,
            signing_packages: packages,
            coordinator_tau_hints: None,
        }
    }
}

/// Every honest signer in the set must refuse; returns the reasons.
fn all_refuse(env: &mut Env, st: &Stage, req: &SendSignRequest) -> Vec<String> {
    let mut reasons = vec![];
    for s in env.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
        match s.sign_send(req, &st.plan.approved) {
            Err(Error::Refused { reason, .. }) => reasons.push(reason),
            Err(e) => panic!("expected a refusal, got {e}"),
            Ok(_) => panic!("signer signed a tampered session"),
        }
    }
    assert_eq!(reasons.len(), 2);
    reasons
}

fn setup_adv(seed: u64) -> (Env, Stage, SpdkReceiver) {
    let mut a = env(seed, &[]);
    let c = SpdkReceiver::new(seed + 1);
    let coins = fund_coins(&a, &[1, 1, -1], None, seed * 100, 50_000);
    let st = stage(&mut a, &coins, &[pay_sp(&c.code(), 100_000)], seed);
    (a, st, c)
}

#[test]
fn honest_session_signs_and_verifies() {
    let (mut a, st, _) = setup_adv(200);
    let req = st.request(&st.tx, &st.shares, &st.packages);
    let mut sigs = BTreeMap::new();
    for s in a.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
        sigs.insert(s.identifier(), s.sign_send(&req, &st.plan.approved).unwrap());
    }
    let tx = a.coord.finalize(&st.tx, &st.inputs, &st.packages, &sigs).unwrap();
    assert_eq!(tx.input.len(), 3);
    assert!(tx.input.iter().all(|i| i.witness.len() == 1));
}

#[test]
fn t5_wrong_d_i_names_the_culprit() {
    let (mut a, st, _) = setup_adv(201);
    let mut shares = st.shares.clone();
    let culprit = shares[0].id;
    // A valid curve point, but not x_i*B: the proof no longer fits.
    shares[0].d = shares[0].d.combine(&sk_from_seed(1, "g").public_key(&Secp256k1::new())).unwrap();
    // The coordinator already names the culprit...
    let e = a.coord.build_tx(&st.inputs, &st.plan.approved.outputs, &shares, &st.set).unwrap_err();
    assert!(matches!(&e, Error::Culprit { who, .. } if *who == format!("{culprit:?}")), "{e}");
    // ...and so does every honest signer.
    let req = st.request(&st.tx, &shares, &st.packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("culprit") && r.contains(&format!("{culprit:?}")), "{r}");
    }
}

#[test]
fn t5_bad_dleq_proof_names_the_culprit() {
    let (mut a, st, _) = setup_adv(202);
    let mut shares = st.shares.clone();
    let culprit = shares[1].id;
    shares[1].proof[10] ^= 1;
    let req = st.request(&st.tx, &shares, &st.packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("DLEQ") && r.contains(&format!("{culprit:?}")), "{r}");
    }
}

#[test]
fn t5_missing_and_foreign_shares_are_refused() {
    let (mut a, st, _) = setup_adv(203);
    let missing: Vec<EcdhShare> = st.shares[1..].to_vec();
    let req = st.request(&st.tx, &missing, &st.packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("missing ECDH share"), "{r}");
    }
    // (nonces were consumed by the refusal above; a new session needs new commitments)
    for s in a.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
        s.commit_inputs(3, &mut rng(6));
    }
    // A share from a signer outside the signing set (id 3), made validly by signer 3 itself.
    let mut shares = st.shares.clone();
    let mut r3 = rng(5);
    let s3 = make_ecdh_share(&a.group.key_packages[&ident(3)], &shares[0].scan_key, &mut r3).unwrap();
    shares.push(s3);
    let req = st.request(&st.tx, &shares, &st.packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("outside the signing set"), "{r}");
    }
}

#[test]
fn t5_swapped_output_script() {
    let (mut a, st, _) = setup_adv(204);
    let mut tx = st.tx.clone();
    tx.output[0].script_pubkey = tx.output[1].script_pubkey.clone();
    // Re-derive the packages for the tampered tx so only the output check can fire.
    let mut commitments = BTreeMap::new();
    for s in a.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
        commitments.insert(s.identifier(), s.commit_inputs(3, &mut rng(8)));
    }
    let packages = a.coord.signing_packages(&tx, &st.inputs, &commitments).unwrap();
    let req = st.request(&tx, &st.shares, &packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("output 0 script"), "{r}");
    }
}

#[test]
fn t5_swapped_recipient_address() {
    let (mut a, st, c) = setup_adv(205);
    // (1) Same scan key, a different spend key (e.g. another label): shares are acceptable, the
    // derived output differs from what the signer recomputes for the approved address.
    let secp = Secp256k1::new();
    let other_spend = c.code().m_pubkey().combine(&sk_from_seed(4, "l").public_key(&secp)).unwrap();
    let swapped = vec![ApprovedOutput {
        dest: ApprovedDest::Sp { scan_key: c.code().scan_key(), spend_key: other_spend },
        amount: st.plan.approved.outputs[0].amount,
    }, st.plan.approved.outputs[1].clone()];
    let tx = a.coord.build_tx(&st.inputs, &swapped, &st.shares, &st.set).unwrap();
    assert_ne!(tx.output[0].script_pubkey, st.tx.output[0].script_pubkey);
    let mut commitments = BTreeMap::new();
    for s in a.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
        commitments.insert(s.identifier(), s.commit_inputs(3, &mut rng(9)));
    }
    let packages = a.coord.signing_packages(&tx, &st.inputs, &commitments).unwrap();
    let req = st.request(&tx, &st.shares, &packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("output 0 script"), "{r}");
    }

    // (2) A different scan key: the signers will not even release D_i for it.
    let d = SpdkReceiver::new(999);
    let mut evil = st.plan.approved.outputs.clone();
    evil[0].dest = ApprovedDest::sp(&d.code());
    let req = a.coord.ecdh_request(&st.inputs, &evil, st.set.clone());
    for s in a.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
        match s.ecdh_shares(&req, &st.plan.approved, &mut rng(1)) {
            Err(Error::Refused { reason, .. }) => assert!(reason.contains("not an approved recipient"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn t5_frost_message_not_the_sighash() {
    let (mut a, st, _) = setup_adv(206);
    let mut commitments = BTreeMap::new();
    for s in a.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
        commitments.insert(s.identifier(), s.commit_inputs(3, &mut rng(10)));
    }
    let mut packages = a.coord.signing_packages(&st.tx, &st.inputs, &commitments).unwrap();
    // input 1 gets the sighash of input 0
    packages[1] = frost::SigningPackage::new(packages[1].signing_commitments().clone(), packages[0].message());
    let req = st.request(&st.tx, &st.shares, &packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("input 1") && r.contains("not the sighash"), "{r}");
    }
}

#[test]
fn t5_wrong_tweak_from_coordinator() {
    let (mut a, st, _) = setup_adv(207);
    let mut hints: Vec<[u8; 32]> = a.coord.resolve(&st.inputs).unwrap().iter().map(|r| r.tau).collect();
    hints[2][31] ^= 1;
    let mut req = st.request(&st.tx, &st.shares, &st.packages);
    req.coordinator_tau_hints = Some(hints);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("tweak for input 2"), "{r}");
    }
}

#[test]
fn t5_other_tampering_amounts_fee_and_coins() {
    // amount changed
    let (mut a, st, _) = setup_adv(208);
    let mut tx = st.tx.clone();
    tx.output[0].value = Amount::from_sat(tx.output[0].value.to_sat() + 1);
    let mut commitments = BTreeMap::new();
    for s in a.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
        commitments.insert(s.identifier(), s.commit_inputs(3, &mut rng(11)));
    }
    let packages = a.coord.signing_packages(&tx, &st.inputs, &commitments).unwrap();
    let req = st.request(&tx, &st.shares, &packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("amount") || r.contains("fee"), "{r}");
    }
    // fee ceiling: approve a smaller max fee than the transaction pays
    let (mut a, mut st, _) = setup_adv(209);
    st.plan.approved.max_fee = Amount::from_sat(st.plan.fee.to_sat() - 1);
    let req = st.request(&st.tx, &st.shares, &st.packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("fee exceeds"), "{r}");
    }
    // different coin order than approved
    let (mut a, mut st, _) = setup_adv(210);
    st.plan.approved.inputs.reverse();
    let req = st.request(&st.tx, &st.shares, &st.packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("approved coins"), "{r}");
    }
}

// ---------------------------------------------------------------------------------------
// Parity guard and the leak it prevents
// ---------------------------------------------------------------------------------------

#[test]
fn parity_guard_refuses_opposite_parity_pairs() {
    let mut a = env(300, &[]);
    let c = SpdkReceiver::new(301);
    let coins = fund_coins(&a, &[1, -1], None, 5000, 60_000);
    // Selection: the pair is needed but sum g = 0, so there is no valid set.
    let r = plan_send(a.coord.wallet(), &coins, &[pay_sp(&c.code(), 100_000)], 1);
    assert!(r.is_err());
    // A coordinator that builds the plan anyway is stopped by every signer in round A.
    let inputs: Vec<InputSource> = coins.iter().map(|k| k.source.clone()).collect();
    let approved = ApprovedSend {
        inputs: a.coord.resolve(&inputs).unwrap().iter().map(|r| r.outpoint).collect(),
        outputs: vec![ApprovedOutput { dest: ApprovedDest::sp(&c.code()), amount: Amount::from_sat(100_000) }],
        max_fee: Amount::from_sat(20_000),
    };
    let req = a.coord.ecdh_request(&inputs, &approved.outputs, vec![ident(1), ident(2)]);
    for s in a.signers.iter_mut().take(2) {
        match s.ecdh_shares(&req, &approved, &mut rng(2)) {
            Err(Error::Refused { reason, .. }) => assert!(reason.contains("sum of parities 0"), "{reason}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(s.exposure().count(), 0, "nothing was released");
    }
    // The coordinator itself refuses too.
    assert!(matches!(
        a.coord.build_tx(&inputs, &approved.outputs, &[], &[ident(1), ident(2)]),
        Err(Error::ParityCancellation)
    ));
}

/// The leak the guard prevents: the payer of two opposite-parity coins knows tau_1, tau_2 and
/// both parities, so with `sum g = 0` it can compute a = sum g_j*tau_j without x, and from it
/// the shared secret of the wallet's outgoing payment to any scan key. With `sum g != 0` the
/// same computation gives the wrong value.
#[test]
fn leak_without_guard_payer_computes_the_outgoing_shared_secret() {
    let secp = Secp256k1::new();
    let a = env(310, &[]);
    let victim_recipient = SpdkReceiver::new(311);
    let b_scan = victim_recipient.code().scan_key();

    for (parities, leaks) in [(vec![1i8, -1], true), (vec![1, 1], false), (vec![-1, -1, 1], false)] {
        let coins = fund_coins(&a, &parities, None, 9000 + parities.len() as u64 * 17, 60_000);
        let inputs: Vec<InputSource> = coins.iter().map(|k| k.source.clone()).collect();
        let resolved = a.coord.resolve(&inputs).unwrap();

        // What the wallet's threshold signers would compute (guard bypassed for the demo).
        let terms: Vec<InputTerm> = resolved
            .iter()
            .map(|r| InputTerm { outpoint: r.outpoint, g: r.g, tau: r.tau, point: r.point })
            .collect();
        let ctx = SenderContext::new(&terms).unwrap();
        let set = [ident(1), ident(3)];
        let lambdas = lagrange_at_zero(&set).unwrap();
        let mut ld = k256::ProjectivePoint::IDENTITY;
        for id in set {
            let sh = make_ecdh_share(&a.group.key_packages[&id], &b_scan, &mut rng(3)).unwrap();
            ld += k256_point(&sh.d) * lambdas[&id];
        }
        let real = ctx.ecdh_from_shares(&b_scan, &ld).unwrap();

        // The payer: knows tau_j (it built the outputs) and g_j (parity of the output keys it
        // created), and the public outpoints. It does not know x or any share.
        let mut acc: Option<SecretKey> = None;
        for r in &resolved {
            let tau = SecretKey::from_slice(&r.tau).unwrap();
            let t = if r.g < 0 { tau.negate() } else { tau };
            acc = Some(match acc {
                None => t,
                Some(s) => s.add_tweak(&Scalar::from_be_bytes(t.secret_bytes()).unwrap()).unwrap(),
            });
        }
        let a_guess = acc.unwrap();
        let a_pub = a_guess.public_key(&secp);
        let min_op = resolved.iter().map(|r| outpoint_bytes(&r.outpoint)).min().unwrap();
        let ih = tagged("BIP0352/Inputs", &[&min_op, &a_pub.serialize()]);
        let payer_view = b_scan
            .mul_tweak(&secp, &Scalar::from_be_bytes(a_guess.mul_tweak(&Scalar::from_be_bytes(ih).unwrap()).unwrap().secret_bytes()).unwrap())
            .unwrap();
        assert_eq!(payer_view == real, leaks, "parities {parities:?}");
    }
}

fn k256_point(p: &PublicKey) -> k256::ProjectivePoint {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let ep = k256::EncodedPoint::from_bytes(p.serialize()).unwrap();
    k256::ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&ep).unwrap())
}

// ---------------------------------------------------------------------------------------
// T6: nonces; exposure counter
// ---------------------------------------------------------------------------------------

#[test]
fn t6_dleq_proofs_use_fresh_aux_randomness_and_frost_nonces_are_per_input() {
    let (mut a, st, _) = setup_adv(400);
    // Same signer, same scan key, two calls: different proofs (fresh aux), both valid.
    let kp = &a.group.key_packages[&ident(1)];
    let b = st.shares[0].scan_key;
    let mut r = rng(77);
    let s1 = make_ecdh_share(kp, &b, &mut r).unwrap();
    let s2 = make_ecdh_share(kp, &b, &mut r).unwrap();
    assert_eq!(s1.d, s2.d);
    assert_ne!(s1.proof, s2.proof);
    let x1 = PublicKey::from_slice(&a.group.public_key_package.verifying_shares()[&ident(1)].serialize().unwrap()).unwrap();
    assert!(dleq_verify(&x1, &b, &s1.d, &s1.proof, None).unwrap());
    assert!(dleq_verify(&x1, &b, &s2.d, &s2.proof, None).unwrap());

    // One distinct FROST nonce pair per input, none reused across sessions.
    let s = &mut a.signers[0];
    let c1 = s.commit_inputs(3, &mut rng(1));
    let c2 = s.commit_inputs(3, &mut rng(2));
    let all: Vec<_> = c1.iter().chain(&c2).map(|c| c.serialize().unwrap()).collect();
    let uniq: std::collections::BTreeSet<_> = all.iter().collect();
    assert_eq!(uniq.len(), 6);
}

#[test]
fn t6_no_nonce_reuse_after_a_refused_or_finished_session() {
    let (mut a, st, _) = setup_adv(401);
    // Refused session: nonces are gone, a retry (even of the honest request) cannot sign.
    let mut bad = st.packages.clone();
    bad[0] = frost::SigningPackage::new(bad[0].signing_commitments().clone(), &[9u8; 32]);
    let req = st.request(&st.tx, &st.shares, &bad);
    all_refuse(&mut a, &st, &req);
    let honest = st.request(&st.tx, &st.shares, &st.packages);
    for s in a.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
        match s.sign_send(&honest, &st.plan.approved) {
            Err(Error::Refused { reason, .. }) => assert!(reason.contains("commit first"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }
    // Finished session: signing the same request a second time is impossible too.
    let (mut a, st, _) = setup_adv(402);
    let req = st.request(&st.tx, &st.shares, &st.packages);
    let s = &mut a.signers[0];
    s.sign_send(&req, &st.plan.approved).unwrap();
    assert!(s.sign_send(&req, &st.plan.approved).is_err());
}

#[test]
fn exposure_counter_counts_distinct_scan_keys_only() {
    let mut a = env(500, &[]);
    let c = SpdkReceiver::new(501);
    let d = SpdkReceiver::new(502);
    let coins = fund_coins(&a, &[1, 1, -1], None, 6000, 50_000);
    // Two distinct recipients, plus change (own scan key: not counted).
    let st = stage(&mut a, &coins, &[pay_sp(&c.code(), 60_000), pay_sp(&d.code(), 60_000)], 1);
    for s in a.signers.iter().filter(|s| st.set.contains(&s.identifier())) {
        assert_eq!(s.exposure().count(), 2);
    }
    // Abort in round B: costs nothing.
    let mut bad = st.packages.clone();
    bad[2] = frost::SigningPackage::new(bad[2].signing_commitments().clone(), &[1u8; 32]);
    let req = st.request(&st.tx, &st.shares, &bad);
    all_refuse(&mut a, &st, &req);
    for s in a.signers.iter().filter(|s| st.set.contains(&s.identifier())) {
        assert_eq!(s.exposure().count(), 2);
    }
    // A session that finishes does not add anything; a repeat recipient is not recounted.
    let coins2 = fund_coins(&a, &[1], None, 7000, 150_000);
    let st2 = stage(&mut a, &coins2, &[pay_sp(&c.code(), 100_000)], 2);
    let req2 = st2.request(&st2.tx, &st2.shares, &st2.packages);
    for s in a.signers.iter_mut().filter(|s| st2.set.contains(&s.identifier())) {
        s.sign_send(&req2, &st2.plan.approved).unwrap();
        assert_eq!(s.exposure().count(), 2);
    }
}

#[test]
fn exposure_limit_blocks_release_until_rotation() {
    use frost_sp_wallet::exposure::*;
    let g1 = sk_from_seed(9001, "g").public_key(&Secp256k1::new()).serialize();
    let g2 = sk_from_seed(9002, "g").public_key(&Secp256k1::new()).serialize();
    let mut e = ExposureCounter::new(RotationThreshold::Thousand).with_group_key(g1);
    let keys: Vec<[u8; 33]> = (0..1000u32)
        .map(|i| sk_from_seed(i as u64, "e").public_key(&Secp256k1::new()).serialize())
        .collect();
    assert!(e.check_release(&keys).is_ok());
    e.record_release(&keys);
    assert_eq!(e.count(), 1000);
    let extra = sk_from_seed(5000, "e").public_key(&Secp256k1::new()).serialize();
    assert!(e.check_release(&[extra]).is_err(), "above the threshold");
    assert!(e.check_release(&keys[..1]).is_ok(), "already counted key is free");
    e.set_threshold(RotationThreshold::Million);
    assert!(e.check_release(&[extra]).is_ok());
    assert_eq!(e.count(), 1000);
    let _ = g2;
    assert_eq!(RotationThreshold::Billion.limit(), 1_000_000_000);
}

#[test]
fn f2_aborts_on_one_scan_key_cost_nothing_distinct_keys_do() {
    use frost_sp_wallet::exposure::*;
    let secp = Secp256k1::new();
    let mut e = ExposureCounter::new(RotationThreshold::Thousand);
    let one = sk_from_seed(1, "k").public_key(&secp).serialize();
    for _ in 0..1000 {
        e.check_release(&[one]).unwrap();
        e.record_release(&[one]);
    }
    assert_eq!(e.count(), 1);
    // And through a real signer: 1000 aborted round-B sessions for one recipient.
    let mut a = env(800, &[]);
    let c = SpdkReceiver::new(801);
    let coins = fund_coins(&a, &[1, 1, -1], None, 9000, 50_000);
    let st = stage(&mut a, &coins, &[pay_sp(&c.code(), 100_000)], 1);
    let mut bad = st.packages.clone();
    bad[0] = frost::SigningPackage::new(bad[0].signing_commitments().clone(), &[1u8; 32]);
    for round in 0..1000u64 {
        let req = st.request(&st.tx, &st.shares, &bad);
        all_refuse(&mut a, &st, &req);
        // Re-request shares for the same key (and fresh nonces) as a new session would.
        let inputs = st.inputs.clone();
        let req_a = a.coord.ecdh_request(&inputs, &st.plan.approved.outputs, st.set.clone());
        let mut r = rng(10_000 + round);
        for s in a.signers.iter_mut().filter(|s| st.set.contains(&s.identifier())) {
            s.ecdh_shares(&req_a, &st.plan.approved, &mut r).unwrap();
            s.commit_inputs(inputs.len(), &mut r);
        }
    }
    for s in a.signers.iter().filter(|s| st.set.contains(&s.identifier())) {
        assert_eq!(s.exposure().count(), 1);
    }
    // Distinct keys do count.
    let e2 = ExposureCounter::new(RotationThreshold::Thousand);
    let keys: Vec<[u8; 33]> = (0..1001u32)
        .map(|i| sk_from_seed(i as u64, "d").public_key(&secp).serialize())
        .collect();
    assert!(e2.check_release(&keys[..1000]).is_ok());
    assert!(e2.check_release(&keys).is_err());
}

#[test]
fn signer_refuses_ecdh_at_the_exposure_limit() {
    let mut a = env(600, &[]);
    let c = SpdkReceiver::new(601);
    let coins = fund_coins(&a, &[1], None, 8000, 100_000);
    let plan = plan_send(a.coord.wallet(), &coins, &[pay_sp(&c.code(), 50_000)], 1).unwrap();
    let inputs: Vec<InputSource> = plan.coins.iter().map(|k| k.source.clone()).collect();
    let req = a.coord.ecdh_request(&inputs, &plan.approved.outputs, vec![ident(1), ident(2)]);
    let s = &mut a.signers[0];
    let fake: Vec<[u8; 33]> = (0..1000u32)
        .map(|i| sk_from_seed(i as u64, "f").public_key(&Secp256k1::new()).serialize())
        .collect();
    s.exposure_mut().record_release(&fake);
    match s.ecdh_shares(&req, &plan.approved, &mut rng(1)) {
        Err(Error::Refused { reason, .. }) => assert!(reason.contains("rotate"), "{reason}"),
        other => panic!("{other:?}"),
    }
    // Same key material: rotation is refused and the signer keeps refusing.
    let kp = a.group.key_packages.values().next().unwrap().clone();
    let wallet = frost_sp_wallet::wallet::SpWallet::new(
        a.group.b_scan,
        a.group.b_spend().unwrap(),
        silentpayments::Network::Regtest,
    )
    .unwrap();
    let pkp = a.group.public_key_package.clone();
    let s = &mut a.signers[0];
    assert!(s.rotate(kp, wallet, pkp).is_err());
    assert!(s.ecdh_shares(&req, &plan.approved, &mut rng(1)).is_err());
    // A genuinely new group: budget restored.
    let g2 = env(601, &[]);
    let kp2 = g2.group.key_packages.get(&ident(1)).unwrap().clone();
    let w2 = frost_sp_wallet::wallet::SpWallet::new(
        g2.group.b_scan,
        g2.group.b_spend().unwrap(),
        silentpayments::Network::Regtest,
    )
    .unwrap();
    s.rotate(kp2, w2, g2.group.public_key_package.clone()).unwrap();
    assert_eq!(s.exposure().count(), 0);
}

#[test]
fn f1_substituted_verifying_share_with_matching_d_is_refused_by_every_signer() {
    use frost_sp_wallet::spend::Signer;
    use frost_sp_wallet::wallet::SpWallet;
    let mut a = env(210, &[]);
    let c = SpdkReceiver::new(211);
    // Attacker key x2' for signer 2: X2' in every signer's package, D2' = x2'*B with a valid proof.
    let x2p = sk_from_seed(77, "x2'");
    let secp = Secp256k1::new();
    let x2p_pub = x2p.public_key(&secp);
    // Substituted package.
    let mut vs = a.group.public_key_package.verifying_shares().clone();
    vs.insert(ident(2), frost::keys::VerifyingShare::deserialize(&x2p_pub.serialize()).unwrap());
    let bad_pkp = frost::keys::PublicKeyPackage::new(vs, *a.group.public_key_package.verifying_key(), Some(2));
    let wallet = |g: &frost_sp_wallet::group::FrostGroup| SpWallet::new(g.b_scan, g.b_spend().unwrap(), silentpayments::Network::Regtest).unwrap();
    let rebuilt: Vec<Signer> = a
        .group
        .key_packages
        .values()
        .map(|kp| Signer::new("s", kp.clone(), wallet(&a.group)).unwrap().with_public_key_package(bad_pkp.clone()))
        .collect();
    a.signers = rebuilt;
    let coins = fund_coins(&a, &[1, 1, -1], None, 21_000, 50_000);
    let st = stage(&mut a, &coins, &[pay_sp(&c.code(), 100_000)], 210);
    let mut shares = st.shares.clone();
    let i = shares.iter().position(|s| s.id == ident(2)).unwrap();
    let b = shares[i].scan_key;
    shares[i].d = b.mul_tweak(&secp, &Scalar::from(x2p)).unwrap();
    shares[i].proof = dleq_prove(&x2p, &b, &[7u8; 32], None).unwrap();
    // The DLEQ itself passes against X2'; only the package check stops it.
    let req = st.request(&st.tx, &shares, &st.packages);
    for r in all_refuse(&mut a, &st, &req) {
        assert!(r.contains("public key package invalid"), "{r}");
    }
}

#[test]
fn f1_package_with_wrong_own_share_or_group_key_is_refused() {
    use frost_sp_wallet::send::validate_public_key_package;
    let a = env(220, &[]);
    let kp = a.group.key_packages.get(&ident(1)).unwrap();
    let good = &a.group.public_key_package;
    let set = [ident(1), ident(2)];
    validate_public_key_package(good, kp, &set).unwrap();
    let secp = Secp256k1::new();
    let fake = frost::keys::VerifyingShare::deserialize(&sk_from_seed(5, "f").public_key(&secp).serialize()).unwrap();
    let mut vs = good.verifying_shares().clone();
    vs.insert(ident(1), fake);
    let own_bad = frost::keys::PublicKeyPackage::new(vs, *good.verifying_key(), Some(2));
    assert!(validate_public_key_package(&own_bad, kp, &set).is_err());
    let other = env(221, &[]);
    assert!(validate_public_key_package(&other.group.public_key_package, kp, &set).is_err());
}

// ---- Codex review of W2 ----

#[test]
fn codex1_more_than_k_max_outputs_per_scan_key_is_refused() {
    let c = SpdkReceiver::new(700);
    let ecdh_dummy = sk_from_seed(1, "d").public_key(&Secp256k1::new());
    let one = ApprovedOutput {
        dest: ApprovedDest::sp(&c.code()),
        amount: Amount::from_sat(500),
    };
    let mut ecdh = BTreeMap::new();
    ecdh.insert(c.code().scan_key().serialize(), ecdh_dummy);
    let at_limit = vec![one.clone(); 2323];
    assert_eq!(derive_scripts(&at_limit, &ecdh).unwrap().len(), 2323);
    let over = vec![one; 2324];
    assert!(derive_scripts(&over, &ecdh).is_err());
}

#[test]
fn codex2_no_change_send_that_exactly_affords_the_fee_is_planned() {
    let a = env(710, &[]);
    let c = SpdkReceiver::new(711);
    let coins = fund_coins(&a, &[1], None, 7100, 100_000);
    let plan = plan_send(a.coord.wallet(), &coins, &[pay_sp(&c.code(), 99_880)], 1).unwrap();
    assert_eq!(plan.approved.outputs.len(), 1, "no change output");
    assert_eq!(plan.fee.to_sat(), 120);
}

#[test]
fn codex3_fee_estimate_matches_the_real_vsize_at_compactsize_boundaries() {
    let mut a = env(720, &[]);
    let c = SpdkReceiver::new(721);
    for n_pay in [3usize, 252, 253] {
        let coins = fund_coins(&a, &[1], None, 7200 + n_pay as u64, 400_000);
        let pays: Vec<Payment> = (0..n_pay).map(|_| pay_sp(&c.code(), 500)).collect();
        let (tx, plan) =
            send_payment(&a.coord, &mut a.signers, &[ident(1), ident(2)], &coins, &pays, 1, &mut rng(3)).unwrap();
        assert!(
            plan.fee.to_sat() >= tx.vsize() as u64,
            "{n_pay} payments: fee {} < vsize {}",
            plan.fee.to_sat(),
            tx.vsize()
        );
    }
}
