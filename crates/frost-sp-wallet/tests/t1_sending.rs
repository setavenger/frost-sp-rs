#![allow(clippy::unwrap_used)]
//! T1 (sending): the BIP 352 sending vectors through the threshold coordinator math.
//!
//! TEST-ONLY PATH: for each vector whose inputs are all single-key eligible, a random group
//! secret `x` is chosen and test tweaks `tau_j = sk_j - x` are set so that every vector input
//! key equals `g_j*(x + tau_j)`. This bypasses re-derivation of `tau_j` from a funding
//! transaction (that path is covered by `send_e2e.rs`); the threshold ECDH, the DLEQ checks,
//! the Lagrange combination and the output derivation are the production functions.
mod common;

use std::collections::BTreeSet;

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use common::*;
use frost_sp_wallet::group::FrostGroup;
use frost_sp_wallet::send::*;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/bip-0352/send_and_receive_test_vectors.json");

fn pk(h: &str) -> PublicKey {
    PublicKey::from_slice(&hex::decode(h).unwrap()).unwrap()
}

#[test]
fn bip352_sending_vectors_with_threshold_ecdh() {
    let cases: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let secp = Secp256k1::new();
    let (mut ran, mut skipped, mut neg_inputs, mut multi_out) = (0, 0, 0, 0);

    for (ci, case) in cases.iter().enumerate() {
        for (si, snd) in case["sending"].as_array().unwrap().iter().enumerate() {
            let given = &snd["given"];
            let expected = &snd["expected"];
            let want_sets: Vec<Vec<String>> = expected["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| {
                    let mut v: Vec<String> = s
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|o| o.as_str().unwrap().to_string())
                        .collect();
                    v.sort();
                    v
                })
                .collect();
            if want_sets.iter().all(Vec::is_empty) {
                skipped += 1;
                continue;
            }

            // Vector inputs -> (outpoint, sk, taproot?)
            let mut raw = vec![];
            let mut eff_sum: Option<SecretKey> = None;
            for v in given["vin"].as_array().unwrap() {
                let sk = SecretKey::from_slice(
                    &hex::decode(v["private_key"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                let spk = v["prevout"]["scriptPubKey"]["hex"].as_str().unwrap();
                let taproot = spk.starts_with("5120");
                let odd = sk.public_key(&secp).serialize()[0] == 3;
                let g: i8 = if taproot && odd { -1 } else { 1 };
                let eff = if g < 0 { sk.negate() } else { sk };
                eff_sum = Some(match eff_sum {
                    None => eff,
                    Some(a) => a
                        .add_tweak(&Scalar::from_be_bytes(eff.secret_bytes()).unwrap())
                        .unwrap_or(a), // sums to zero: never matches below
                });
                let mut txid = hex::decode(v["txid"].as_str().unwrap()).unwrap();
                txid.reverse();
                raw.push((
                    OutPoint {
                        txid: Txid::from_byte_array(txid.try_into().unwrap()),
                        vout: v["vout"].as_u64().unwrap() as u32,
                    },
                    sk,
                    g,
                ));
            }
            // All inputs eligible iff my sum equals the vector's own sum.
            let vsum = expected["input_private_key_sum"].as_str().unwrap();
            if hex::encode(eff_sum.unwrap().secret_bytes()) != vsum {
                skipped += 1;
                continue;
            }

            // Test-only: random x, tau_j = sk_j - x.
            let x = sk_from_seed(ci as u64 * 31 + si as u64, "x-test");
            let group = FrostGroup::from_secret(&x, 3, 2, sk_from_seed(7, "scan"), &mut rng(ci as u64))
                .unwrap();
            let neg_x = Scalar::from_be_bytes(x.negate().secret_bytes()).unwrap();
            let terms: Vec<InputTerm> = raw
                .iter()
                .map(|(op, sk, g)| {
                    let tau = sk.add_tweak(&neg_x).unwrap();
                    if *g < 0 {
                        neg_inputs += 1;
                    }
                    InputTerm {
                        outpoint: *op,
                        g: *g,
                        tau: tau.secret_bytes(),
                        point: sk.public_key(&secp),
                    }
                })
                .collect();
            let ctx = SenderContext::new(&terms).unwrap();

            let outputs: Vec<ApprovedOutput> = given["recipients"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| ApprovedOutput {
                    dest: ApprovedDest::Sp {
                        scan_key: pk(r["scan_pub_key"].as_str().unwrap()),
                        spend_key: pk(r["spend_pub_key"].as_str().unwrap()),
                    },
                    amount: bitcoin::Amount::from_sat(1000),
                })
                .collect();

            // Two different signer sets across cases.
            let ids: Vec<u16> = [[1u16, 2], [2, 3], [1, 3]][(ci + si) % 3].to_vec();
            let set: Vec<_> = ids
                .iter()
                .map(|i| frost_secp256k1_tr::Identifier::try_from(*i).unwrap())
                .collect();
            let scan_keys: BTreeSet<[u8; 33]> = outputs
                .iter()
                .map(|o| match &o.dest {
                    ApprovedDest::Sp { scan_key, .. } => scan_key.serialize(),
                    _ => unreachable!(),
                })
                .collect();
            let mut r = rng(99 + ci as u64);
            let mut shares = vec![];
            for id in &set {
                for k in &scan_keys {
                    shares.push(
                        make_ecdh_share(&group.key_packages[id], &PublicKey::from_slice(k).unwrap(), &mut r)
                            .unwrap(),
                    );
                }
            }
            let own_scan = sk_from_seed(12345, "unrelated-own-scan");
            let ecdh = ecdh_for_outputs(
                &ctx,
                &outputs,
                &shares,
                &set,
                &group.public_key_package,
                &own_scan,
            )
            .unwrap();
            let scripts = derive_scripts(&outputs, &ecdh).unwrap();
            let mut got: Vec<String> = scripts
                .iter()
                .map(|s| hex::encode(&s.as_bytes()[2..]))
                .collect();
            got.sort();
            assert!(
                want_sets.contains(&got),
                "case {ci}/{si} ({}): outputs {got:?} not in {want_sets:?}",
                case["comment"]
            );
            // The vector's shared secrets are exactly our per-scan-key ECDH values.
            let want_ss: BTreeSet<String> = expected["shared_secrets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect();
            let got_ss: BTreeSet<String> =
                ecdh.values().map(|p| hex::encode(p.serialize())).collect();
            assert_eq!(got_ss, want_ss, "case {ci}/{si}: shared secrets");
            if outputs.len() > 1 {
                multi_out += 1;
            }
            ran += 1;
        }
    }
    println!("T1-send: {ran} vector cases ran ({skipped} skipped as ineligible/failing), {neg_inputs} negated taproot inputs, {multi_out} multi-output");
    assert!(ran >= 15 && neg_inputs > 0 && multi_out > 0);
}
