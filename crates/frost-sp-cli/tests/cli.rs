#![allow(clippy::unwrap_used)]
//! The `frost-sp-signer` binary against the external-signer contract (T2, T3, T5, T7 on the
//! CLI path) with DKG device files (D1, D9, D10, D11 on files). The fixture is the seeded
//! `keygen --n 3 --t 2 --seed 352` output committed in `tests/fixtures/frost-rs-roundtrip/`.
#[path = "../../frost-sp-wallet/tests/common/mod.rs"]
mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use common::*;
use frost_sp_wallet::send::{resolve_input, verify_consensus_all, InputSource, SpendableCoin};
use frost_sp_wallet::wallet::SpWallet;
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use silentpayments::Network;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/frost-rs-roundtrip");

fn device(i: u16) -> String {
    format!("{FIXTURES}/device-{i}.json")
}

fn read_json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn fixture() -> Value {
    read_json(&device(1))
}

fn wallet(labels: &[u32]) -> SpWallet {
    let f = fixture();
    let scan = SecretKey::from_slice(&hex::decode(f["scan_secret"].as_str().unwrap()).unwrap()).unwrap();
    let spend = PublicKey::from_slice(&hex::decode(f["spend_pubkey"].as_str().unwrap()).unwrap()).unwrap();
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
    vec![
        ("BLINDBIT_SIGNER_NETWORK", "regtest".into()),
        ("BLINDBIT_SIGNER_SCAN_SECRET", f["scan_secret"].as_str().unwrap().into()),
        ("BLINDBIT_SIGNER_SPEND_PUBKEY", f["spend_pubkey"].as_str().unwrap().into()),
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

/// A fresh scratch directory under the target dir, removed first if a previous run left it.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn keygen(dir: &Path, extra: &[&str]) -> (Value, bool) {
    let mut args = vec!["keygen", "--n", "3", "--t", "2", "--out-dir", dir.to_str().unwrap()];
    args.extend_from_slice(extra);
    run(&args, &[], "")
}

fn p(dir: &Path, i: u16) -> String {
    dir.join(format!("device-{i}.json")).to_str().unwrap().to_string()
}

/// Every pair of devices signs (one `--state` per device), and so do all three.
#[test]
fn spends_exactly_the_given_coins_pays_bob_and_sp_change_to_itself() {
    let w = wallet(&[7]);
    let bob = SpdkReceiver::new(42);
    let change = tsp(&w.change_address());
    for (k, set) in [vec![2, 3], vec![1, 2], vec![1, 3], vec![1, 2, 3]].into_iter().enumerate() {
        let cs = coins(&w, &[1, 1, -1], 500 + 100 * k as u64); // sum g = 1
        let paths: Vec<String> = set.iter().map(|i| device(*i)).collect();
        let mut args = vec![];
        for path in &paths {
            args.extend(["--state", path.as_str()]);
        }
        let (v, ok) = run(&args, &wallet_env("7"), &request(&cs, &[(tsp(&bob.code()), 150_000)], &change));
        assert!(ok, "{set:?}: {v}");
        let tx: Transaction = deserialize(&hex::decode(v["tx_hex"].as_str().unwrap()).unwrap()).unwrap();
        // exactly the 3 given coins, in order; payment then change
        assert_eq!(tx.input.len(), 3);
        for (i, c) in cs.iter().enumerate() {
            assert_eq!(tx.input[i].previous_output.txid, c.source.funding_tx.compute_txid());
        }
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value, Amount::from_sat(150_000));
        // consensus-valid (libbitcoinconsensus) for every input
        let prevouts: Vec<TxOut> = cs.iter().map(|c| c.source.funding_tx.output[0].clone()).collect();
        verify_consensus_all(&tx, &prevouts).unwrap();
        // the wallet finds its change with label m = 0; bob finds his output
        let funding_spks: Vec<ScriptBuf> = cs.iter().map(|c| c.source.funding_tx.output[0].script_pubkey.clone()).collect();
        let mine = w.scan_tx(&tx, &funding_spks).unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].label, Some(0));
        assert_eq!(mine[0].outpoint.vout, 1);
        let fee = 300_000 - 150_000 - mine[0].value.to_sat();
        assert!(fee > 0 && fee <= 5 * 400, "fee {fee}");
        assert_eq!(bob.scan(&tx, &funding_spks).len(), 1);
    }
}

#[test]
fn refuses_inputs_whose_parities_cancel() {
    let w = wallet(&[]);
    let cs = coins(&w, &[1, -1], 900); // sum g = 0
    let bob = SpdkReceiver::new(43);
    let (v, ok) = run(
        &["--state", &device(1), "--state", &device(2)],
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
    let state = ["--state", &device(1), "--state", &device(2)];
    // wrong value claimed
    let mut req: Value = serde_json::from_str(&request(&cs, &dest, &tsp(&w.change_address()))).unwrap();
    req["utxos"][0]["value_sats"] = json!(999_999);
    let (v, ok) = run(&state, &wallet_env(""), &req.to_string());
    assert!(!ok && v["error"].as_str().unwrap().contains("differ from the funding"), "{v}");
    // a different wallet's scan secret
    let mut env = wallet_env("");
    env[1].1 = "01".repeat(32);
    let (v, ok) = run(&state, &env, &request(&cs, &dest, ""));
    assert!(!ok && v["error"].as_str().unwrap().contains("scan secret"), "{v}");
    // a different group key
    let mut env = wallet_env("");
    env[2].1 = hex::encode(SecretKey::from_slice(&[7u8; 32]).unwrap().public_key(&secp256k1::Secp256k1::new()).serialize());
    let (v, ok) = run(&state, &env, &request(&cs, &dest, ""));
    assert!(!ok && v["error"].as_str().unwrap().contains("group key"), "{v}");
}

#[test]
fn no_change_address_pays_exact_fee_but_will_not_burn_a_big_surplus() {
    let w = wallet(&[]);
    let cs = coins(&w, &[1], 1700);
    let bob = SpdkReceiver::new(45);
    let state = ["--state", &device(1), "--state", &device(3)];
    let (v, ok) = run(&state, &wallet_env(""), &request(&cs, &[(tsp(&bob.code()), 99_000)], ""));
    assert!(ok, "{v}");
    // paying 10_000 with no change would burn 90_000
    let (v, ok) = run(&state, &wallet_env(""), &request(&cs, &[(tsp(&bob.code()), 10_000)], ""));
    assert!(!ok && v["error"].as_str().unwrap().contains("declare a change address"), "{v}");
}

#[test]
fn rejects_garbage_cleanly() {
    let (v, ok) = run(&["--state", &device(1), "--state", &device(2)], &wallet_env(""), "not json");
    assert!(!ok && v["error"].as_str().unwrap().starts_with("request:"));
    let (v, ok) = run(&[], &wallet_env(""), "{}");
    assert!(!ok && v["error"].as_str().unwrap().contains("no state file"));
    let (v, ok) = run(&["dealer", "--out", "x.json"], &[], "");
    assert!(!ok && v["error"].as_str().unwrap().contains("keygen"), "{v}");
}

/// The same group address the test kit pins in `scenarios/frost-rs-roundtrip.toml`
/// (`frostRSAddress`): the Go and Rust implementations are held to one derivation.
#[test]
fn the_fixture_wallet_has_the_address_the_testkit_pins() {
    let w = wallet(&[]);
    let want = "tsp1qqtyz3zlz4zfns35cwkyp3ru9anem7mm6z7vh934zkjps8cpxytc56qhfy5qxttq5hkalprt8r6ujt0vag9hxdjthphrlk936kytuxvegxywnyvt0";
    assert_eq!(tsp(&w.address(None).unwrap()), want);
    assert_eq!(
        hex::encode(w.b_spend().serialize()),
        "02e9250065ac14bdbbf08d671eb925bd9d416e66c9770dc7fb163ab117c3332831"
    );
}

#[test]
fn refuses_a_mainnet_silent_payment_address_on_regtest() {
    let w = wallet(&[]);
    let cs = coins(&w, &[1], 2100);
    let bob = SpdkReceiver::new(46);
    let c = bob.code();
    let state = ["--state", &device(2), "--state", &device(3)];
    let mainnet = silentpayments::SilentPaymentCode::new_v0(c.scan_key(), c.m_pubkey(), Network::Mainnet).to_string();
    let (v, ok) = run(&state, &wallet_env(""), &request(&cs, &[(mainnet.clone(), 10_000)], &tsp(&w.change_address())));
    assert!(!ok && v["error"].as_str().unwrap().contains("another network"), "{v}");
    let (v, ok) = run(&state, &wallet_env(""), &request(&cs, &[(tsp(&c), 10_000)], &mainnet));
    assert!(!ok && v["error"].as_str().unwrap().contains("another network"), "{v}");
}

#[test]
fn refuses_wrapping_and_zero_amounts_with_an_error_document() {
    let w = wallet(&[]);
    let cs = coins(&w, &[1], 2500);
    let bob = SpdkReceiver::new(47);
    let a = tsp(&bob.code());
    let state = ["--state", &device(1), "--state", &device(2)];
    let (v, ok) = run(
        &state,
        &wallet_env(""),
        &request(&cs, &[(a.clone(), 18446744073709461616), (a.clone(), 100_000)], &tsp(&w.change_address())),
    );
    assert!(!ok && v["error"].as_str().unwrap().contains("monetary range"), "{v}");
    let (v, ok) = run(&state, &wallet_env(""), &request(&cs, &[(a, 0)], &tsp(&w.change_address())));
    assert!(!ok && v["error"].as_str().unwrap().contains("0 sats"), "{v}");
}

// ------------------------------------------------------------------------------------------
// keygen and device files
// ------------------------------------------------------------------------------------------

#[test]
fn keygen_writes_one_owner_only_file_per_device_and_prints_the_constants() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("keygen");
    let (v, ok) = keygen(&dir, &["--seed", "9"]);
    assert!(ok, "{v}");
    assert_eq!(v["spend_pubkey"].as_str().unwrap().len(), 66);
    assert_eq!(v["scan_secret"].as_str().unwrap().len(), 64);
    assert!(v["warning"].as_str().unwrap().contains("TEST ONLY"));
    let code = v["check_code"].as_str().unwrap();
    for (i, d) in v["devices"].as_array().unwrap().iter().enumerate() {
        assert_eq!(d["identifier"], json!(i + 1));
        assert_eq!(d["check_code"].as_str().unwrap(), code);
        assert_eq!(d["sp_address"], v["sp_address"]);
        let path = p(&dir, i as u16 + 1);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let f = read_json(&path);
        assert_eq!(f["check_code"].as_str().unwrap(), code);
        assert_eq!(f["test_only_seed"], json!(9));
    }
    // same seed, same keys; never overwrite a device file
    let (again, ok) = keygen(&dir, &["--seed", "9"]);
    assert!(!ok && again["error"].as_str().unwrap().contains("never overwrites"), "{again}");
    let dir2 = scratch("keygen-again");
    let (v2, ok) = keygen(&dir2, &["--seed", "9"]);
    assert!(ok);
    assert_eq!(v["spend_pubkey"], v2["spend_pubkey"]);
    assert_eq!(v["check_code"], v2["check_code"]);
    // unseeded: fresh keys, no scan secret printed, files not marked test-only
    let dir3 = scratch("keygen-os");
    let (v3, ok) = keygen(&dir3, &[]);
    assert!(ok, "{v3}");
    assert_ne!(v3["spend_pubkey"], v["spend_pubkey"]);
    assert!(v3.get("scan_secret").is_none() && v3.get("warning").is_none());
    assert!(read_json(&p(&dir3, 1)).get("test_only_seed").is_none());
    for d in [dir, dir2, dir3] {
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[test]
fn d10_keygen_refuses_bad_parameters_and_a_seed_on_mainnet() {
    let dir = scratch("keygen-params");
    for (n, t) in [("3", "4"), ("3", "1"), ("3", "0")] {
        let (v, ok) = run(&["keygen", "--n", n, "--t", t, "--out-dir", dir.to_str().unwrap()], &[], "");
        assert!(!ok && v["error"].as_str().unwrap().contains("threshold"), "{v}");
    }
    for n in ["0", "1", "33"] {
        let (v, ok) = run(&["keygen", "--n", n, "--t", "2", "--out-dir", dir.to_str().unwrap()], &[], "");
        assert!(!ok && v["error"].as_str().unwrap().contains("devices: want 2 to 32"), "{v}");
    }
    let (v, ok) = keygen(&dir, &["--seed", "1", "--network", "mainnet"]);
    assert!(!ok && v["error"].as_str().unwrap().contains("refused on mainnet"), "{v}");
    // A flag without its value does not swallow the next flag.
    let (v, ok) = run(&["keygen", "--n", "3", "--t", "2", "--seed", "--out-dir", dir.to_str().unwrap()], &[], "");
    assert!(!ok && v["error"].as_str().unwrap().contains("--seed needs a value"), "{v}");
    assert!(!dir.exists(), "nothing written");
}

#[test]
fn keygen_writes_no_file_unless_it_can_write_all_of_them() {
    let dir = scratch("keygen-partial");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("device-2.json"), "taken").unwrap();
    let (v, ok) = keygen(&dir, &[]);
    assert!(!ok && v["error"].as_str().unwrap().contains("never overwrites"), "{v}");
    assert!(!dir.join("device-1.json").exists() && !dir.join("device-3.json").exists());
    assert_eq!(std::fs::read_to_string(dir.join("device-2.json")).unwrap(), "taken");
    std::fs::remove_dir_all(dir).unwrap();
}

/// The test mark cannot turn a real group into test data, and the signer keeps real device
/// files owner-only and seeded ones off mainnet.
#[test]
fn test_marks_are_checked_and_real_device_files_stay_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("keygen-marks");
    let (_, ok) = keygen(&dir, &[]);
    assert!(ok);
    // Mark a real group's files as seeded: reconstruction re-derives the group and refuses.
    let forged: Vec<String> = (1..=2)
        .map(|i| {
            let mut f = read_json(&p(&dir, i));
            f["test_only_seed"] = json!(352);
            let path = dir.join(format!("forged-{i}.json"));
            std::fs::write(&path, f.to_string()).unwrap();
            path.to_str().unwrap().to_string()
        })
        .collect();
    let (v, ok) = run(&["reconstruct-test-secret", "--state", &forged[0], "--state", &forged[1]], &[], "");
    assert!(!ok && v["error"].as_str().unwrap().contains("do not come from their recorded test seed"), "{v}");
    // A real device file readable by others is refused.
    std::fs::set_permissions(p(&dir, 1), std::fs::Permissions::from_mode(0o644)).unwrap();
    let (v, ok) = run(&["--state", &p(&dir, 1), "--state", &p(&dir, 2)], &wallet_env(""), "{}");
    assert!(!ok && v["error"].as_str().unwrap().contains("readable by others"), "{v}");
    std::fs::remove_dir_all(dir).unwrap();
    // Seeded files on mainnet.
    let mut env = wallet_env("");
    env[0].1 = "mainnet".into();
    let req = json!({"network": "mainnet", "destinations": [], "utxos": []}).to_string();
    let (v, ok) = run(&["--state", &device(1), "--state", &device(2)], &env, &req);
    assert!(!ok && v["error"].as_str().unwrap().contains("refused on mainnet"), "{v}");
}

/// D11: each file holds exactly one signing share, and no other device's share bytes.
#[test]
fn d11_each_device_file_holds_exactly_its_own_signing_share() {
    let dir = scratch("keygen-d11");
    let (v, ok) = keygen(&dir, &["--seed", "11"]);
    assert!(ok, "{v}");
    let texts: Vec<String> = (1..=3).map(|i| std::fs::read_to_string(p(&dir, i)).unwrap()).collect();
    let shares: Vec<String> = texts
        .iter()
        .map(|t| {
            let f: Value = serde_json::from_str(t).unwrap();
            let kp = frost_secp256k1_tr::keys::KeyPackage::deserialize(&hex::decode(f["key_package"].as_str().unwrap()).unwrap()).unwrap();
            hex::encode(kp.signing_share().serialize())
        })
        .collect();
    for (i, t) in texts.iter().enumerate() {
        let f: Value = serde_json::from_str(t).unwrap();
        // one key package field, nothing that could hold more
        assert!(f.get("key_packages").is_none());
        assert_eq!(t.matches("\"key_package\"").count(), 1);
        for (j, share) in shares.iter().enumerate() {
            assert_eq!(t.contains(share.as_str()), i == j, "file {} and share {}", i + 1, j + 1);
        }
    }
    // A file with a second key package is refused (strict format).
    let mut f: Value = serde_json::from_str(&texts[0]).unwrap();
    f["key_packages"] = json!({"2": "00"});
    let bad = dir.join("two-shares.json");
    std::fs::write(&bad, f.to_string()).unwrap();
    let (v, ok) = run(&["--state", bad.to_str().unwrap(), "--state", &p(&dir, 2)], &wallet_env(""), "{}");
    assert!(!ok && v["error"].as_str().unwrap().contains("unknown field"), "{v}");
    std::fs::remove_dir_all(dir).unwrap();
}

/// D9: a state file whose certificate is missing or does not verify is refused.
#[test]
fn d9_signer_refuses_a_state_file_without_a_valid_certificate() {
    let dir = scratch("keygen-d9");
    std::fs::create_dir_all(&dir).unwrap();
    let good: Value = read_json(&device(1));
    let try_file = |name: &str, f: &Value| {
        let path = dir.join(name);
        std::fs::write(&path, f.to_string()).unwrap();
        run(&["--state", path.to_str().unwrap(), "--state", &device(2)], &wallet_env(""), "{}")
    };
    // no certificate at all
    let mut f = good.clone();
    f.as_object_mut().unwrap().remove("certificate");
    let (v, ok) = try_file("no-cert.json", &f);
    assert!(!ok && v["error"].as_str().unwrap().contains("missing field `certificate`"), "{v}");
    // one signature flipped
    let mut f = good.clone();
    let sig = f["certificate"]["signatures"]["3"].as_str().unwrap().to_string();
    let flipped = format!("{}{}", if sig.starts_with('0') { "1" } else { "0" }, &sig[1..]);
    f["certificate"]["signatures"]["3"] = json!(flipped);
    let (v, ok) = try_file("bad-sig.json", &f);
    assert!(!ok && v["error"].as_str().unwrap().contains("certificate"), "{v}");
    // a signature removed
    let mut f = good.clone();
    f["certificate"]["signatures"].as_object_mut().unwrap().remove("2");
    let (v, ok) = try_file("short-cert.json", &f);
    assert!(!ok && v["error"].as_str().unwrap().contains("no signature from [2]"), "{v}");
    // the key package swapped for another device's
    let mut f = good.clone();
    f["key_package"] = read_json(&device(2))["key_package"].clone();
    let (v, ok) = try_file("other-share.json", &f);
    assert!(!ok, "{v}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn signer_refuses_duplicate_devices_mixed_ceremonies_and_too_few_files() {
    let w = wallet(&[]);
    let cs = coins(&w, &[1], 3100);
    let req = request(&cs, &[(tsp(&SpdkReceiver::new(48).code()), 10_000)], &tsp(&w.change_address()));
    // the same device twice
    let (v, ok) = run(&["--state", &device(1), "--state", &device(1)], &wallet_env(""), &req);
    assert!(!ok && v["error"].as_str().unwrap().contains("two state files for device 1"), "{v}");
    // one device only (t = 2)
    let (v, ok) = run(&["--state", &device(2)], &wallet_env(""), &req);
    assert!(!ok && v["error"].as_str().unwrap().contains("threshold of 2"), "{v}");
    // a device of another ceremony
    let dir = scratch("keygen-mixed");
    let (_, ok) = keygen(&dir, &["--seed", "352"]);
    assert!(ok);
    let (v, ok) = run(&["--state", &device(1), "--state", &p(&dir, 2)], &wallet_env(""), &req);
    // seed 352 again: same group, same certificate; that is the fixture itself
    assert!(ok, "{v}");
    let dir2 = scratch("keygen-mixed-2");
    let (_, ok) = keygen(&dir2, &["--seed", "353"]);
    assert!(ok);
    let (v, ok) = run(&["--state", &device(1), "--state", &p(&dir2, 2)], &wallet_env(""), &req);
    assert!(!ok && v["error"].as_str().unwrap().contains("another group key"), "{v}");
    for d in [dir, dir2] {
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[test]
fn reconstruct_test_secret_matches_the_group_key_and_only_for_seeded_groups() {
    let (v, ok) = run(&["reconstruct-test-secret", "--state", &device(1), "--state", &device(3)], &[], "");
    assert!(ok, "{v}");
    let x = SecretKey::from_slice(&hex::decode(v["group_secret_for_mock_signer"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(hex::encode(x.public_key(&secp256k1::Secp256k1::new()).serialize()), fixture()["spend_pubkey"].as_str().unwrap());
    let (v2, _) = run(&["reconstruct-test-secret", "--state", &device(2), "--state", &device(3)], &[], "");
    assert_eq!(v["group_secret_for_mock_signer"], v2["group_secret_for_mock_signer"]);
    let (v, ok) = run(&["reconstruct-test-secret", "--state", &device(2)], &[], "");
    assert!(!ok && v["error"].as_str().unwrap().contains("threshold of 2"), "{v}");
    let dir = scratch("keygen-unseeded");
    let (_, ok) = keygen(&dir, &[]);
    assert!(ok);
    let (v, ok) = run(&["reconstruct-test-secret", "--state", &p(&dir, 1), "--state", &p(&dir, 2)], &[], "");
    assert!(!ok && v["error"].as_str().unwrap().contains("seeded test group"), "{v}");
    std::fs::remove_dir_all(dir).unwrap();
}
