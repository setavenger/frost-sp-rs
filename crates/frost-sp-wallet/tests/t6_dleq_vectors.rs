#![allow(clippy::unwrap_used)]
//! T6: BIP 374 vectors (bitcoin/bips master) against the DLEQ wrappers used by the signers.
//! rust-dleq supports only the standard generator, so vectors with a custom `point_G` are
//! skipped and counted.
use frost_sp_wallet::send::{dleq_prove, dleq_verify};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

const GEN: &str = include_str!("vectors/bip-0374/test_vectors_generate_proof.csv");
const VER: &str = include_str!("vectors/bip-0374/test_vectors_verify_proof.csv");
const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn arr<const N: usize>(h: &str) -> Option<[u8; N]> {
    hex::decode(h).ok()?.try_into().ok()
}
fn msg(h: &str) -> Option<[u8; 32]> {
    if h.is_empty() {
        None
    } else {
        arr::<32>(h)
    }
}

#[test]
fn bip374_generate_vectors() {
    let (mut ok, mut skipped, mut rejected) = (0, 0, 0);
    for line in GEN.lines().skip(1) {
        let f: Vec<&str> = line.split(',').collect();
        if f[1] != G {
            skipped += 1;
            continue;
        }
        let a = hex::decode(f[2]).ok().and_then(|b| SecretKey::from_slice(&b).ok());
        let b = hex::decode(f[3]).ok().and_then(|b| PublicKey::from_slice(&b).ok());
        let aux = arr::<32>(f[4]).unwrap();
        let m = msg(f[5]);
        let res = match (a, b) {
            (Some(a), Some(b)) => dleq_prove(&a, &b, &aux, m.as_ref()).ok(),
            _ => None, // invalid scalar or point: refused before proving
        };
        if f[6] == "INVALID" {
            assert!(res.is_none(), "vector {} must be rejected", f[0]);
            rejected += 1;
        } else {
            assert_eq!(
                res.map(hex::encode).as_deref(),
                Some(f[6]),
                "vector {}: {}",
                f[0],
                f[7]
            );
            ok += 1;
        }
    }
    println!("T6 generate: {ok} proofs reproduced, {rejected} invalid inputs rejected, {skipped} custom-G skipped");
    assert!(ok >= 5 && rejected >= 4);
}

#[test]
fn bip374_verify_vectors() {
    let (mut t, mut f_, mut skipped) = (0, 0, 0);
    for line in VER.lines().skip(1) {
        let f: Vec<&str> = line.split(',').collect();
        if f[1] != G {
            skipped += 1;
            continue;
        }
        let pt = |h: &str| hex::decode(h).ok().and_then(|b| PublicKey::from_slice(&b).ok());
        let want = f[7] == "TRUE";
        let got = match (pt(f[2]), pt(f[3]), pt(f[4]), arr::<64>(f[5])) {
            (Some(a), Some(b), Some(c), Some(p)) => {
                dleq_verify(&a, &b, &c, &p, msg(f[6]).as_ref()).unwrap_or(false)
            }
            _ => false,
        };
        assert_eq!(got, want, "vector {}: {}", f[0], f[8]);
        if want {
            t += 1
        } else {
            f_ += 1
        }
    }
    let _ = Secp256k1::new();
    println!("T6 verify: {t} accepted, {f_} rejected as expected, {skipped} custom-G skipped");
    assert!(t >= 3 && f_ >= 8);
}
