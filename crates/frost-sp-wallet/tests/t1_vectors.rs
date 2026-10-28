#![allow(clippy::unwrap_used)]
//! T1: BIP 352 receiving vectors, split with a test-only trusted dealer.
mod common;

use std::collections::BTreeSet;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use common::*;
use frost_sp_wallet::group::FrostGroup;
use frost_sp_wallet::wallet::SpWallet;
use secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use serde_json::Value;
use silentpayments::Network;

const VECTORS: &str = include_str!("vectors/bip-0352/send_and_receive_test_vectors.json");

fn compact(bytes: &[u8], pos: &mut usize) -> usize {
    let b = bytes[*pos];
    *pos += 1;
    match b {
        0xfd => {
            let v = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]) as usize;
            *pos += 2;
            v
        }
        0xfe => {
            let v = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().unwrap()) as usize;
            *pos += 4;
            v
        }
        n => n as usize,
    }
}

fn witness_from_hex(h: &str) -> Witness {
    let bytes = hex::decode(h).unwrap();
    let mut w = Witness::new();
    if bytes.is_empty() {
        return w;
    }
    let mut pos = 0;
    let n = compact(&bytes, &mut pos);
    for _ in 0..n {
        let l = compact(&bytes, &mut pos);
        w.push(&bytes[pos..pos + l]);
        pos += l;
    }
    w
}

#[test]
fn bip352_receiving_vectors_with_frost_shares() {
    let cases: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let secp = Secp256k1::new();
    let msg: [u8; 32] = sha256::Hash::hash(b"message").to_byte_array();
    let (mut checked, mut sigs, mut labelled) = (0, 0, 0);

    for (ci, case) in cases.iter().enumerate() {
        for rcv in case["receiving"].as_array().unwrap() {
            let given = &rcv["given"];
            let expected = &rcv["expected"];
            let b_scan = SecretKey::from_slice(
                &hex::decode(given["key_material"]["scan_priv_key"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let b_spend = SecretKey::from_slice(
                &hex::decode(given["key_material"]["spend_priv_key"].as_str().unwrap()).unwrap(),
            )
            .unwrap();

            // Build the transaction from the vector.
            let mut inputs = vec![];
            let mut spks = vec![];
            for v in given["vin"].as_array().unwrap() {
                let mut txid = hex::decode(v["txid"].as_str().unwrap()).unwrap();
                txid.reverse();
                let spk = ScriptBuf::from_bytes(
                    hex::decode(v["prevout"]["scriptPubKey"]["hex"].as_str().unwrap()).unwrap(),
                );
                inputs.push(TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array(txid.try_into().unwrap()),
                        vout: v["vout"].as_u64().unwrap() as u32,
                    },
                    script_sig: ScriptBuf::from_bytes(
                        hex::decode(v["scriptSig"].as_str().unwrap()).unwrap(),
                    ),
                    sequence: Sequence::MAX,
                    witness: witness_from_hex(v["txinwitness"].as_str().unwrap()),
                });
                spks.push(spk);
            }
            let outputs: Vec<TxOut> = given["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| {
                    let mut s = vec![0x51, 0x20];
                    s.extend(hex::decode(o.as_str().unwrap()).unwrap());
                    TxOut {
                        value: Amount::from_sat(10_000),
                        script_pubkey: ScriptBuf::from_bytes(s),
                    }
                })
                .collect();
            let tx = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: inputs,
                output: outputs,
            };

            // Test-only dealer splits the vector's b_spend; nobody holds it afterwards.
            let group =
                FrostGroup::from_secret(&b_spend, 3, 2, b_scan, &mut rng(ci as u64 + 1)).unwrap();
            assert_eq!(
                group.b_spend().unwrap(),
                b_spend.public_key(&secp),
                "case {ci}: group key"
            );
            let mut wallet =
                SpWallet::new(b_scan, group.b_spend().unwrap(), Network::Mainnet).unwrap();
            let label_ints: Vec<u32> = given["labels"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_u64().unwrap() as u32)
                .collect();
            for m in &label_ints {
                wallet.add_label(*m).unwrap();
            }

            // Addresses match (change address only if label 0 was requested).
            let mut got: BTreeSet<String> = BTreeSet::new();
            got.insert(wallet.address(None).unwrap().to_string());
            for m in &label_ints {
                got.insert(wallet.address(Some(*m)).unwrap().to_string());
            }
            let want: BTreeSet<String> = expected["addresses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap().to_string())
                .collect();
            assert_eq!(got, want, "case {ci} ({}): addresses", case["comment"]);

            // Scan finds exactly the vector's outputs, with the vector's tweaks.
            let owned = wallet.scan_tx(&tx, &spks).unwrap();
            if let Some(n) = expected.get("n_outputs") {
                // K_max case: the vector only gives the count (receiver stops at 2323).
                assert_eq!(owned.len() as u64, n.as_u64().unwrap(), "case {ci}: K_max");
                checked += 1;
                continue;
            }
            let want_out: BTreeSet<(String, String)> = expected["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| {
                    (
                        o["pub_key"].as_str().unwrap().to_string(),
                        o["priv_key_tweak"].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            let got_out: BTreeSet<(String, String)> = owned
                .iter()
                .map(|o| {
                    (
                        hex::encode(&o.script_pubkey.as_bytes()[2..]),
                        hex::encode(o.tau),
                    )
                })
                .collect();
            assert_eq!(
                got_out, want_out,
                "case {ci} ({}): outputs",
                case["comment"]
            );
            checked += 1;

            // FROST (2 different signer sets) signs under each output key; BIP 340 verifies.
            for (oi, o) in owned.iter().enumerate() {
                if o.label.is_some() {
                    labelled += 1;
                }
                let xonly = XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..]).unwrap();
                for ids in [[1u16, 2], [2, 3], [1, 3]] {
                    let sig =
                        frost_sign_raw(&group, &o.tau, &msg, &ids, 1000 * ci as u64 + oi as u64);
                    assert!(
                        verify_bip340(&sig, &msg, &xonly),
                        "case {ci}: FROST sig under output {oi} signers {ids:?}"
                    );
                    sigs += 1;
                }
            }
        }
    }
    println!("T1: {checked} receiving cases, {sigs} FROST signatures verified, {labelled} labelled outputs");
    assert!(checked >= 20 && sigs > 0 && labelled > 0);
}
