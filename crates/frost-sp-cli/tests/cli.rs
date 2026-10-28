#![allow(clippy::unwrap_used)]
//! The `frost-sp-signer` binary against the external-signer contract (T2, T3, T5, T7 on the
//! CLI path). The state file is the committed `frost-rs-roundtrip` fixture.
#[path = "../../frost-sp-wallet/tests/common/mod.rs"]
mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use common::*;
use frost_sp_wallet::send::{resolve_input, verify_consensus_all, InputSource, SpendableCoin};
use frost_sp_wallet::wallet::SpWallet;
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use silentpayments::Network;

const STATE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/frost-rs-roundtrip-state.json");

fn fixture() -> Value {
    serde_json::from_str(&std::fs::read_to_string(STATE).unwrap()).unwrap()
}

fn wallet(labels: &[u32]) -> SpWallet {
    let f = fixture();
    let scan = SecretKey::from_slice(&hex::decode(f["scan_secret"].as_str().unwrap()).unwrap()).unwrap();
    let pkp = hex::decode(f["public_key_package"].as_str().unwrap()).unwrap();
    let pkp = frost_secp256k1_tr::keys::PublicKeyPackage::deserialize(&pkp).unwrap();
    let spend = PublicKey::from_slice(&pkp.verifying_key().serialize().unwrap()).unwrap();
    let mut w = SpWallet::new(scan, spend, Network::Testnet).unwrap();
    for m in labels {
        w.add_label(*m).unwrap();
    }
    w
}

/// Coins paid to the fixture wallet with the wanted parities (`g`), as the test kit would offer.
fn coins(w: &SpWallet, parities: &[i8], seed0: u64) -> Vec<SpendableCoin> {
    let code = w.address(None).unwrap();
    let mut out = vec![];
    let mut s = seed0;
    for want in parities {
        loop {
            s += 1;
            let kind = if s.is_multiple_of(2) { InputKind::P2tr } else { InputKind::P2wpkh };
            let f = sp_fund(&[FundingInput::new(s, kind)], &[(code.scan_key(), code.m_pubkey())], &[None], 100_000);
            let src = InputSource { funding_tx: f.tx, funding_prevout_spks: f.prevout_spks, funding_vout: 0 };
            if resolve_input(w, &src).unwrap().g == *want {
                out.push(SpendableCoin { source: src, value: Amount::from_sat(100_000) });
                break;
            }
        }
    }
    out
}

fn utxo(c: &SpendableCoin) -> Value {
    let f = &c.source.funding_tx;
    json!({
        "outpoint": format!("{}:{}", f.compute_txid(), c.source.funding_vout),
        "value_sats": c.value.to_sat(),
        "script_pubkey": hex::encode(f.output[c.source.funding_vout as usize].script_pubkey.as_bytes()),
        "funding_tx_hex": hex::encode(serialize(f)),
        "funding_prevouts": c.source.funding_prevout_spks.iter()
            .map(|s| json!({"script_pubkey": hex::encode(s.as_bytes()), "value_sats": 1_000_000})).collect::<Vec<_>>(),
        // A wrong hint must change nothing: signers re-derive tau themselves (T7).
        "tweak": "11".repeat(32),
    })
}

fn run(args: &[&str], envs: &[(&str, String)], stdin: &str) -> (Value, bool) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_frost-sp-signer"));
    cmd.args(args).env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    // The signer may exit before reading stdin (e.g. no state file): a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {:?}", String::from_utf8_lossy(&out.stdout)));
    (v, out.status.success())
}

fn wallet_env(labels: &str) -> Vec<(&'static str, String)> {
    let f = fixture();
    let w = wallet(&[]);
    vec![
        ("BLINDBIT_SIGNER_NETWORK", "regtest".into()),
        ("BLINDBIT_SIGNER_SCAN_SECRET", f["scan_secret"].as_str().unwrap().into()),
        ("BLINDBIT_SIGNER_SPEND_PUBKEY", hex::encode(w.b_spend().serialize())),
        ("BLINDBIT_SIGNER_LABELS", labels.into()),
    ]
}

fn request(cs: &[SpendableCoin], dests: &[(String, u64)], change: &str) -> String {
    json!({
        "network": "regtest",
        "fee_rate_sat_vb": 5,
        "change_address": change,
        "destinations": dests.iter().map(|(a, v)| json!({"address": a, "amount_sats": v})).collect::<Vec<_>>(),
        "utxos": cs.iter().map(utxo).collect::<Vec<_>>(),
    })
    .to_string()
}

fn tsp(code: &silentpayments::SilentPaymentCode) -> String {
    // The test kit speaks `tsp` on regtest.
    let c = silentpayments::SilentPaymentCode::new_v0(code.scan_key(), code.m_pubkey(), Network::Testnet);
    c.to_string()
}

#[test]
fn spends_exactly_the_given_coins_pays_bob_and_sp_change_to_itself() {
    let w = wallet(&[7]);
    let cs = coins(&w, &[1, 1, -1], 500); // sum g = 1
    let bob = SpdkReceiver::new(42);
    let change = tsp(&w.change_address());
    let (v, ok) = run(
        &["--state", STATE, "--signing-set", "2,3"],
        &wallet_env("7"),
        &request(&cs, &[(tsp(&bob.code()), 150_000)], &change),
    );
    assert!(ok, "{v}");
    let tx: Transaction = deserialize(&hex::decode(v["tx_hex"].as_str().unwrap()).unwrap()).unwrap();
    // exactly the 3 given coins, in order; payment then change
    assert_eq!(tx.input.len(), 3);
    for (i, c) in cs.iter().enumerate() {
        assert_eq!(tx.input[i].previous_output.txid, c.source.funding_tx.compute_txid());
    }
    assert_eq!(tx.output.len(), 2);
    assert_eq!(tx.output[0].value, Amount::from_sat(150_000));
    // consensus-valid (libbitcoinconsensus) for every input
    let prevouts: Vec<TxOut> = cs
        .iter()
        .map(|c| c.source.funding_tx.output[0].clone())
        .collect();
    verify_consensus_all(&tx, &prevouts).unwrap();
    // bob finds his output with an independent spdk receiver
    // the wallet itself finds its change with label m = 0, live and when scanning the tx fresh
    let funding_spks: Vec<ScriptBuf> = cs.iter().map(|c| c.source.funding_tx.output[0].script_pubkey.clone()).collect();
    let mine = w.scan_tx(&tx, &funding_spks).unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].label, Some(0));
    assert_eq!(mine[0].outpoint.vout, 1);
    let fee = 300_000 - 150_000 - mine[0].value.to_sat();
    assert!(fee > 0 && fee <= 5 * 400, "fee {fee}");
    assert_eq!(bob.scan(&tx, &funding_spks).len(), 1);
}

#[test]
fn refuses_inputs_whose_parities_cancel() {
    let w = wallet(&[]);
    let cs = coins(&w, &[1, -1], 900); // sum g = 0
    let bob = SpdkReceiver::new(43);
    let (v, ok) = run(
        &["--state", STATE],
        &wallet_env(""),
        &request(&cs, &[(tsp(&bob.code()), 50_000)], &tsp(&w.change_address())),
    );
    assert!(!ok);
    let err = v["error"].as_str().unwrap();
    assert!(err.contains("sum of parities 0"), "{err}");
    assert!(v.get("tx_hex").is_none());
}

#[test]
fn refuses_a_request_that_misstates_a_coin_or_the_wallet() {
    let w = wallet(&[]);
    let cs = coins(&w, &[1], 1300);
    let bob = SpdkReceiver::new(44);
    let dest = [(tsp(&bob.code()), 10_000)];
    // wrong value claimed
    let mut req: Value = serde_json::from_str(&request(&cs, &dest, &tsp(&w.change_address()))).unwrap();
    req["utxos"][0]["value_sats"] = json!(999_999);
    let (v, ok) = run(&["--state", STATE], &wallet_env(""), &req.to_string());
    assert!(!ok && v["error"].as_str().unwrap().contains("differ from the funding"), "{v}");
    // a different wallet's scan secret
    let mut env = wallet_env("");
    env[1].1 = "01".repeat(32);
    let (v, ok) = run(&["--state", STATE], &env, &request(&cs, &dest, ""));
    assert!(!ok && v["error"].as_str().unwrap().contains("scan secret"), "{v}");
    // a different group key
    let mut env = wallet_env("");
    env[2].1 = hex::encode(SecretKey::from_slice(&[7u8; 32]).unwrap().public_key(&secp256k1::Secp256k1::new()).serialize());
    let (v, ok) = run(&["--state", STATE], &env, &request(&cs, &dest, ""));
    assert!(!ok && v["error"].as_str().unwrap().contains("group key"), "{v}");
}

#[test]
fn no_change_address_pays_exact_fee_but_will_not_burn_a_big_surplus() {
    let w = wallet(&[]);
    let cs = coins(&w, &[1], 1700);
    let bob = SpdkReceiver::new(45);
    // 100_000 - 99_000 = 1_000 sats left: fine as fee for one input, two outputs? (about 2x)
    let (v, ok) = run(&["--state", STATE], &wallet_env(""), &request(&cs, &[(tsp(&bob.code()), 99_000)], ""));
    assert!(ok, "{v}");
    // paying 10_000 with no change would burn 90_000
    let (v, ok) = run(&["--state", STATE], &wallet_env(""), &request(&cs, &[(tsp(&bob.code()), 10_000)], ""));
    assert!(!ok && v["error"].as_str().unwrap().contains("declare a change address"), "{v}");
}

#[test]
fn rejects_garbage_cleanly() {
    let (v, ok) = run(&["--state", STATE], &wallet_env(""), "not json");
    assert!(!ok && v["error"].as_str().unwrap().starts_with("request:"));
    let (v, ok) = run(&[], &wallet_env(""), "{}");
    assert!(!ok && v["error"].as_str().unwrap().contains("no state file"));
}

#[test]
fn dealer_writes_a_state_file_and_prints_the_scenario_constants() {
    let dir = std::env::temp_dir().join(format!("frost-sp-dealer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.json");
    let (v, ok) = run(&["dealer", "--out", path.to_str().unwrap(), "--seed", "9"], &[], "");
    assert!(ok, "{v}");
    assert_eq!(v["scan_secret"].as_str().unwrap().len(), 64);
    assert_eq!(v["spend_pubkey"].as_str().unwrap().len(), 66);
    let state: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(state["warning"].as_str().unwrap().contains("PoC ONLY"));
    assert_eq!(state["key_packages"].as_object().unwrap().len(), 3);
    // same seed, same keys
    let path2 = dir.join("state2.json");
    let (v2, _) = run(&["dealer", "--out", path2.to_str().unwrap(), "--seed", "9"], &[], "");
    assert_eq!(v["spend_pubkey"], v2["spend_pubkey"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The same group address the test kit pins in `scenarios/frost-rs-roundtrip.toml`
/// (`frostRSAddress`): the Go and Rust implementations are held to one derivation.
#[test]
fn the_fixture_wallet_has_the_address_the_testkit_pins() {
    let w = wallet(&[]);
    let want = "tsp1qqg9ck53fx6ajhnpmzsct8ky2pkhvmt2fea7l6459j42jfuzy3470qqhs9h5sy60xp3j8xrxuu6yf0pqkvf4szt2j3s4wgqmjgcaxwudheq9gkjjv";
    assert_eq!(tsp(&w.address(None).unwrap()), want);
    assert_eq!(
        hex::encode(w.b_spend().serialize()),
        "02f02de90269e60c64730cdce688978416626b012d528c2ae40372463a6771b7c8"
    );
}
