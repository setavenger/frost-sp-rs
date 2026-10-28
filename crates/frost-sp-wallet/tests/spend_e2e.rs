#![allow(clippy::unwrap_used)]
//! T2 (BIP 340 + consensus), T3 (parity/tweak matrix), T7 (re-derivation), plus refusals.
mod common;

use std::collections::BTreeMap;

use bitcoin::{Amount, ScriptBuf, TxOut};
use common::*;
use frost_secp256k1_tr as frost;
use frost_sp_wallet::group::FrostGroup;
use frost_sp_wallet::spend::{
    build_spend_tx, verify_consensus, ApprovedSpend, SignRequest, Signer,
};
use frost_sp_wallet::wallet::{OwnedOutput, SpWallet};
use frost_sp_wallet::Error;
use secp256k1::{Scalar, Secp256k1};
use silentpayments::receiving::Label;
use silentpayments::Network;

const NET: Network = Network::Regtest;

struct World {
    group: FrostGroup,
    funding: Funding,
    owned: OwnedOutput,
}

impl World {
    fn labels(&self) -> Vec<u32> {
        self.owned.label.into_iter().filter(|m| *m != 0).collect()
    }
}

fn approval(owned: &OwnedOutput, tx: &bitcoin::Transaction) -> ApprovedSpend {
    ApprovedSpend {
        outpoint: owned.outpoint,
        outputs: tx.output.clone(),
        max_fee: Amount::from_sat(1_000),
    }
}

fn payout() -> ScriptBuf {
    // plain P2TR payout (arbitrary x-only key)
    let secp = Secp256k1::new();
    let (x, _) = sk_from_seed(99, "payout").x_only_public_key(&secp);
    ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
        bitcoin::XOnlyPublicKey::from_slice(&x.serialize()).unwrap(),
    ))
}

/// Fund `label` (None = base address, Some(m) = labelled/change) from the given inputs.
fn world(seed: u64, label: Option<u32>, kinds: &[InputKind]) -> World {
    let b_scan = sk_from_seed(seed, "scan");
    let group = FrostGroup::trusted_dealer(3, 2, b_scan, &mut rng(seed)).unwrap();
    let mut wallet = SpWallet::new(b_scan, group.b_spend().unwrap(), NET).unwrap();
    if let Some(m) = label.filter(|m| *m != 0) {
        wallet.add_label(m).unwrap();
    }
    let addr = wallet.address(label).unwrap();
    let ltweak: Option<Scalar> = label.map(|m| *Label::new(b_scan, m).as_inner());
    let inputs: Vec<FundingInput> = kinds
        .iter()
        .enumerate()
        .map(|(i, k)| FundingInput::new(seed * 10 + i as u64, *k))
        .collect();
    let funding = sp_fund(
        &inputs,
        &[(addr.scan_key(), addr.m_pubkey())],
        &[ltweak],
        100_000,
    );
    let owned = wallet.scan_tx(&funding.tx, &funding.prevout_spks).unwrap();
    assert_eq!(owned.len(), 1, "seed {seed}: wallet must find the payment");
    assert_eq!(
        owned[0].tau, funding.expected_tau[0],
        "seed {seed}: tau = t_k + l_m (independent oracle)"
    );
    assert_eq!(owned[0].label, label);
    let owned = owned[0].clone();
    World {
        group,
        funding,
        owned,
    }
}

fn run_spend(w: &World, ids: [usize; 2], seed: u64) -> Result<bitcoin::Transaction, Error> {
    let mut signers = make_signers(&w.group, NET, &w.labels());
    let coord = coordinator(&w.group);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let funding_txo = w.funding.tx.output[w.owned.outpoint.vout as usize].clone();
    let mut r = rng(seed);
    let mut commitments = BTreeMap::new();
    for i in ids {
        commitments.insert(signers[i].identifier(), signers[i].commit(&mut r));
    }
    let pkg = coord
        .signing_package(&tx, &funding_txo, commitments)
        .unwrap();
    let approved = approval(&w.owned, &tx);
    let mut shares = BTreeMap::new();
    for i in ids {
        let req = SignRequest {
            funding_tx: &w.funding.tx,
            funding_prevout_spks: &w.funding.prevout_spks,
            funding_vout: w.owned.outpoint.vout,
            spend_tx: &tx,
            signing_package: &pkg,
            coordinator_tau_hint: None,
        };
        shares.insert(signers[i].identifier(), signers[i].sign(&req, &approved)?);
    }
    let done = coord.finalize(&tx, &w.owned, &pkg, &shares)?;
    verify_consensus(&done, &funding_txo)?;
    Ok(done)
}

#[test]
fn t2_t3_matrix_parity_and_labels() {
    let (mut p_even, mut p_odd, mut a_even, mut a_odd, mut n) = (0, 0, 0, 0, 0);
    for seed in 1..=24u64 {
        for (label, kinds) in [
            (None, vec![InputKind::P2wpkh]),
            (None, vec![InputKind::P2tr]),
            (Some(5), vec![InputKind::P2wpkh, InputKind::P2tr]),
            (Some(0), vec![InputKind::P2tr, InputKind::P2tr]),
        ] {
            let w = world(seed, label, &kinds);
            let tx = run_spend(&w, [(seed % 3) as usize, ((seed + 1) % 3) as usize], seed)
                .expect("spend");
            assert_eq!(tx.input[0].witness.len(), 1);
            assert_eq!(tx.input[0].witness.nth(0).unwrap().len(), 64);
            n += 1;
            // parity bookkeeping: output key P_k = X + tau*G (full point)
            let pk = frost_sp_wallet::tweak::tweak_public_key_package(
                &w.group.public_key_package,
                &w.owned.tau,
            )
            .unwrap();
            if pk.verifying_key().serialize().unwrap()[0] == 2 {
                p_even += 1
            } else {
                p_odd += 1
            }
            let x = w
                .group
                .public_key_package
                .verifying_key()
                .serialize()
                .unwrap()[0];
            if x == 2 {
                a_even += 1
            } else {
                a_odd += 1
            }
        }
    }
    println!("T2/T3: {n} spends consensus-verified; P_k even/odd = {p_even}/{p_odd}; X even/odd = {a_even}/{a_odd}");
    assert!(
        p_even > 0 && p_odd > 0 && a_even > 0 && a_odd > 0,
        "all parity cases exercised"
    );
}

#[test]
fn t3_odd_taproot_input_keys_are_negated() {
    // At least one funding input of each parity.
    let secp = Secp256k1::new();
    let (mut even, mut odd) = (0, 0);
    for seed in 1..=40u64 {
        let i = FundingInput::new(seed * 10, InputKind::P2tr);
        if i.sk.x_only_public_key(&secp).1 == secp256k1::Parity::Odd {
            odd += 1
        } else {
            even += 1
        }
        let w = world(seed, None, &[InputKind::P2tr]); // asserts tau == oracle (oracle negates odd keys)
        let _ = w;
    }
    assert!(even > 0 && odd > 0);
}

#[test]
fn any_two_of_three_signers_work() {
    let w = world(7, Some(3), &[InputKind::P2wpkh]);
    for ids in [[0, 1], [1, 2], [0, 2]] {
        run_spend(&w, ids, 70).unwrap();
    }
}

// ---------- T7 and refusals ----------

struct Session {
    signers: Vec<Signer>,
    pkg: frost::SigningPackage,
    tx: bitcoin::Transaction,
}

fn session(w: &World, tx: bitcoin::Transaction, msg: Option<[u8; 32]>) -> Session {
    let mut signers = make_signers(&w.group, NET, &w.labels());
    let coord = coordinator(&w.group);
    let funding_txo = w.funding.tx.output[w.owned.outpoint.vout as usize].clone();
    let mut r = rng(5);
    let mut c = BTreeMap::new();
    for i in [0usize, 1] {
        c.insert(signers[i].identifier(), signers[i].commit(&mut r));
    }
    let pkg = match msg {
        None => coord.signing_package(&tx, &funding_txo, c).unwrap(),
        Some(m) => frost::SigningPackage::new(c, &m),
    };
    Session { signers, pkg, tx }
}

fn try_sign(w: &World, s: &mut Session, f: impl FnOnce(&mut SignRequest)) -> Result<(), Error> {
    let approved = approval(
        &w.owned,
        &build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap(),
    );
    let mut req = SignRequest {
        funding_tx: &w.funding.tx,
        funding_prevout_spks: &w.funding.prevout_spks,
        funding_vout: w.owned.outpoint.vout,
        spend_tx: &s.tx,
        signing_package: &s.pkg,
        coordinator_tau_hint: None,
    };
    f(&mut req);
    s.signers[0].sign(&req, &approved).map(|_| ())
}

fn assert_refused(r: Result<(), Error>, needle: &str) {
    match r {
        Err(Error::Refused { who, reason }) => {
            assert_eq!(who, "signer1");
            assert!(
                reason.contains(needle),
                "reason {reason:?} should mention {needle:?}"
            );
        }
        other => panic!("expected refusal ({needle}), got {other:?}"),
    }
}

#[test]
fn t7_wrong_coordinator_tweak_is_refused() {
    let w = world(11, Some(2), &[InputKind::P2wpkh]);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let mut s = session(&w, tx, None);
    let mut wrong = w.owned.tau;
    wrong[31] ^= 1;
    assert_refused(
        try_sign(&w, &mut s, |r| r.coordinator_tau_hint = Some(wrong)),
        "tweak",
    );
}

#[test]
fn t7_correct_hint_is_accepted_but_not_needed() {
    let w = world(11, Some(2), &[InputKind::P2wpkh]);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let mut s = session(&w, tx, None);
    let t = w.owned.tau;
    try_sign(&w, &mut s, |r| r.coordinator_tau_hint = Some(t)).unwrap();
}

#[test]
fn t7_signer_uses_its_own_b_scan() {
    // A signer holding a different b_scan cannot find the output, so it cannot be fed a tweak.
    let w = world(12, None, &[InputKind::P2wpkh]);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let mut s = session(&w, tx, None);
    let wrong_wallet = SpWallet::new(
        sk_from_seed(500, "other-scan"),
        w.group.b_spend().unwrap(),
        NET,
    )
    .unwrap();
    let kp = w.group.key_packages.values().next().unwrap().clone();
    s.signers[0] = Signer::new("signer1", kp, wrong_wallet).unwrap();
    let id = s.signers[0].identifier();
    // new signer needs its own commitment for a valid session; refusal comes first anyway
    let _ = s.signers[0].commit(&mut rng(1));
    let _ = id;
    assert_refused(try_sign(&w, &mut s, |_| {}), "not an SP output");
}

#[test]
fn t7_lying_prevout_scripts_do_not_fool_signer() {
    let w = world(13, None, &[InputKind::P2wpkh]);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let mut s = session(&w, tx, None);
    let fake: &'static [ScriptBuf] = Box::leak(vec![ScriptBuf::new()].into_boxed_slice());
    assert_refused(
        try_sign(&w, &mut s, |r| r.funding_prevout_spks = fake),
        "not an SP output",
    );
}

#[test]
fn refuses_swapped_output() {
    let w = world(14, None, &[InputKind::P2wpkh]);
    let mut tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    tx.output[0] = TxOut {
        value: tx.output[0].value,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                bitcoin::XOnlyPublicKey::from_slice(
                    &sk_from_seed(1, "evil")
                        .x_only_public_key(&Secp256k1::new())
                        .0
                        .serialize(),
                )
                .unwrap(),
            ),
        ),
    };
    let mut s = session(&w, tx, None);
    assert_refused(try_sign(&w, &mut s, |_| {}), "outputs differ");
}

#[test]
fn refuses_frost_message_not_sighash() {
    let w = world(15, None, &[InputKind::P2wpkh]);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let mut s = session(&w, tx, Some([7u8; 32]));
    assert_refused(try_sign(&w, &mut s, |_| {}), "sighash");
}

#[test]
fn nonces_are_single_use_even_after_refusal() {
    let w = world(16, None, &[InputKind::P2wpkh]);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let mut s = session(&w, tx, Some([7u8; 32]));
    assert_refused(try_sign(&w, &mut s, |_| {}), "sighash");
    // Second attempt with the same commitments: nonces are gone.
    assert_refused(try_sign(&w, &mut s, |_| {}), "no pending nonces");
}

#[test]
fn consensus_check_is_not_vacuous() {
    let w = world(21, Some(4), &[InputKind::P2tr]);
    let mut tx = run_spend(&w, [0, 1], 21).unwrap();
    let txo = w.funding.tx.output[w.owned.outpoint.vout as usize].clone();
    verify_consensus(&tx, &txo).unwrap();
    // flip one bit of the signature
    let mut sig = tx.input[0].witness.nth(0).unwrap().to_vec();
    sig[10] ^= 1;
    let mut wit = bitcoin::Witness::new();
    wit.push(sig);
    tx.input[0].witness = wit;
    assert!(verify_consensus(&tx, &txo).is_err());
    // and a different amount in the prevout must also fail (sighash commits to it)
    let mut good = run_spend(&w, [1, 2], 22).unwrap();
    let mut txo2 = txo.clone();
    txo2.value = Amount::from_sat(txo.value.to_sat() + 1);
    assert!(verify_consensus(&good, &txo2).is_err());
    good.input[0].witness = bitcoin::Witness::new();
    assert!(verify_consensus(&good, &txo).is_err());
}

fn req_for<'a>(
    w: &'a World,
    tx: &'a bitcoin::Transaction,
    pkg: &'a frost::SigningPackage,
) -> SignRequest<'a> {
    SignRequest {
        funding_tx: &w.funding.tx,
        funding_prevout_spks: &w.funding.prevout_spks,
        funding_vout: w.owned.outpoint.vout,
        spend_tx: tx,
        signing_package: pkg,
        coordinator_tau_hint: None,
    }
}

#[test]
fn refuses_excess_fee_and_wrong_coin() {
    let w = world(31, None, &[InputKind::P2wpkh]);
    // fee 50_000 > approved ceiling 1_000, outputs equal to what the coordinator built
    let greedy = build_spend_tx(&w.owned, payout(), Amount::from_sat(50_000)).unwrap();
    let mut s = session(&w, greedy.clone(), None);
    let approved = approval(&w.owned, &greedy);
    let req = req_for(&w, &greedy, &s.pkg);
    assert_refused(
        s.signers[0].sign(&req, &approved).map(|_| ()),
        "fee exceeds",
    );

    // approved coin differs from the funding output being spent
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let mut s = session(&w, tx.clone(), None);
    let mut approved = approval(&w.owned, &tx);
    approved.outpoint.vout += 1;
    let req = req_for(&w, &tx, &s.pkg);
    assert_refused(
        s.signers[0].sign(&req, &approved).map(|_| ()),
        "approved coin",
    );
}

#[test]
fn finalize_rejects_a_different_transaction() {
    let w = world(32, None, &[InputKind::P2wpkh]);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let coord = coordinator(&w.group);
    let mut signers = make_signers(&w.group, NET, &[]);
    let funding_txo = w.funding.tx.output[w.owned.outpoint.vout as usize].clone();
    let mut r = rng(3);
    let mut c = BTreeMap::new();
    for i in [0usize, 1] {
        c.insert(signers[i].identifier(), signers[i].commit(&mut r));
    }
    let pkg = coord.signing_package(&tx, &funding_txo, c).unwrap();
    let approved = approval(&w.owned, &tx);
    let mut shares = BTreeMap::new();
    for i in [0usize, 1] {
        let req = req_for(&w, &tx, &pkg);
        shares.insert(
            signers[i].identifier(),
            signers[i].sign(&req, &approved).unwrap(),
        );
    }
    let mut other = tx.clone();
    other.output[0].value = Amount::from_sat(1);
    assert!(coord.finalize(&other, &w.owned, &pkg, &shares).is_err());
    assert!(coord.finalize(&tx, &w.owned, &pkg, &shares).is_ok());
}

#[test]
fn invalid_p2tr_shaped_output_does_not_block_scanning() {
    let mut w = world(33, None, &[InputKind::P2wpkh]);
    // unrelated P2TR-shaped output whose x is not on the curve (32 x 0xff)
    let mut spk = vec![0x51, 0x20];
    spk.extend([0xffu8; 32]);
    w.funding.tx.output.insert(
        0,
        TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(spk),
        },
    );
    let wallet = SpWallet::new(sk_from_seed(33, "scan"), w.group.b_spend().unwrap(), NET).unwrap();
    let owned = wallet
        .scan_tx(&w.funding.tx, &w.funding.prevout_spks)
        .unwrap();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].outpoint.vout, 1);
}

// ---- Opus review of W1, Low findings F1-F4 ----

#[test]
fn f1_approval_binds_locktime_sequence_and_version() {
    let w = world(60, None, &[InputKind::P2wpkh]);
    let base = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let mut variants = vec![];
    let mut t = base.clone();
    t.lock_time = bitcoin::absolute::LockTime::from_height(1_000_000).unwrap();
    variants.push(t);
    let mut t = base.clone();
    t.input[0].sequence = bitcoin::Sequence::from_height(100);
    variants.push(t);
    let mut t = base.clone();
    t.version = bitcoin::transaction::Version::ONE;
    variants.push(t);
    for tx in variants {
        // the package is for the tampered tx, so only the shape check can refuse
        let mut s = session(&w, tx, None);
        assert_refused(try_sign(&w, &mut s, |_| {}), "locktime");
    }
}

#[test]
fn f2_approved_outpoint_is_checked_before_scanning() {
    let w = world(61, None, &[InputKind::P2wpkh]);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let mut other = w.funding.tx.clone();
    other.output[0].value = Amount::from_sat(1);
    let no_spks: Vec<ScriptBuf> = vec![];
    let mut s = session(&w, tx, None);
    // A funding tx that is not the approved coin's, and whose scan would even error out
    // (no prevout scripts): the signer must refuse on the outpoint, never reaching the scan.
    let approved = approval(
        &w.owned,
        &build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap(),
    );
    let mut req = req_for(&w, &s.tx, &s.pkg);
    req.funding_tx = &other;
    req.funding_prevout_spks = &no_spks;
    let r = s.signers[0].sign(&req, &approved).map(|_| ());
    assert_refused(r, "approved coin");
}

#[test]
fn f3_tx_spending_segwit_v2_output_is_not_scanned() {
    let mut w = world(62, None, &[InputKind::P2wpkh]);
    let wallet = SpWallet::new(sk_from_seed(62, "scan"), w.group.b_spend().unwrap(), NET).unwrap();
    assert_eq!(wallet.scan_tx(&w.funding.tx, &w.funding.prevout_spks).unwrap().len(), 1);
    let mut v2 = vec![0x52, 0x20];
    v2.extend([0x42u8; 32]);
    let mut txin = w.funding.tx.input[0].clone();
    txin.previous_output.vout += 1;
    w.funding.tx.input.push(txin);
    w.funding.prevout_spks.push(ScriptBuf::from_bytes(v2));
    assert!(wallet.scan_tx(&w.funding.tx, &w.funding.prevout_spks).unwrap().is_empty());
}

#[test]
fn f4_wrong_tau_is_a_coordinator_error_not_a_cheater_accusation() {
    let w = world(63, Some(2), &[InputKind::P2wpkh]);
    let tx = build_spend_tx(&w.owned, payout(), Amount::from_sat(1_000)).unwrap();
    let coord = coordinator(&w.group);
    let mut signers = make_signers(&w.group, NET, &w.labels());
    let funding_txo = w.funding.tx.output[w.owned.outpoint.vout as usize].clone();
    let mut r = rng(3);
    let mut c = BTreeMap::new();
    for i in [0usize, 1] {
        c.insert(signers[i].identifier(), signers[i].commit(&mut r));
    }
    let pkg = coord.signing_package(&tx, &funding_txo, c).unwrap();
    let approved = approval(&w.owned, &tx);
    let mut shares = BTreeMap::new();
    for i in [0usize, 1] {
        let req = req_for(&w, &tx, &pkg);
        shares.insert(signers[i].identifier(), signers[i].sign(&req, &approved).unwrap());
    }
    let mut bad = w.owned.clone();
    bad.tau[31] ^= 1;
    let e = coord.finalize(&tx, &bad, &pkg, &shares).unwrap_err();
    assert!(matches!(&e, Error::Other(m) if m.contains("coordinator error")), "{e}");
}
