#![allow(dead_code, clippy::unwrap_used)]
//! Test-only helpers: a minimal BIP 352 sender, FROST signing sessions, vector parsing.

use std::collections::BTreeMap;

use bitcoin::hashes::{hash160, sha256, Hash, HashEngine};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use frost_secp256k1_tr as frost;
use frost_sp_wallet::group::FrostGroup;
use frost_sp_wallet::spend::{Coordinator, Signer};
use frost_sp_wallet::tweak::{tweak_key_package, tweak_public_key_package};
use frost_sp_wallet::wallet::SpWallet;
use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use silentpayments::Network;

pub fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

pub fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let th = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(th.as_ref());
    e.input(th.as_ref());
    for p in parts {
        e.input(p);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

pub fn sk_from_seed(seed: u64, tag: &str) -> SecretKey {
    SecretKey::from_slice(&tagged(tag, &[&seed.to_be_bytes()])).unwrap()
}

/// How the funding transaction's input is locked (and so how its key is extracted).
#[derive(Clone, Copy, Debug)]
pub enum InputKind {
    P2wpkh,
    P2tr,
}

pub struct FundingInput {
    pub sk: SecretKey,
    pub kind: InputKind,
    pub outpoint: OutPoint,
}

impl FundingInput {
    pub fn new(seed: u64, kind: InputKind) -> Self {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&tagged("txid", &[&seed.to_be_bytes()]));
        Self {
            sk: sk_from_seed(seed, "input-key"),
            kind,
            outpoint: OutPoint {
                txid: Txid::from_byte_array(txid),
                vout: (seed % 3) as u32,
            },
        }
    }

    /// The scalar BIP 352 sums: negated for taproot inputs with an odd-Y key.
    pub fn effective_secret(&self) -> SecretKey {
        let secp = Secp256k1::new();
        match self.kind {
            InputKind::P2wpkh => self.sk,
            InputKind::P2tr => {
                let (_, parity) = self.sk.x_only_public_key(&secp);
                if parity == secp256k1::Parity::Odd {
                    self.sk.negate()
                } else {
                    self.sk
                }
            }
        }
    }

    pub fn prevout_spk(&self) -> ScriptBuf {
        let secp = Secp256k1::new();
        match self.kind {
            InputKind::P2wpkh => {
                let pk = self.sk.public_key(&secp);
                ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(hash160::Hash::hash(
                    &pk.serialize(),
                )))
            }
            InputKind::P2tr => {
                let (x, _) = self.sk.x_only_public_key(&secp);
                ScriptBuf::new_p2tr_tweaked(
                    bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                        bitcoin::XOnlyPublicKey::from_slice(&x.serialize()).unwrap(),
                    ),
                )
            }
        }
    }

    fn txin(&self) -> TxIn {
        let secp = Secp256k1::new();
        let mut w = Witness::new();
        match self.kind {
            InputKind::P2wpkh => {
                w.push([0x30u8; 71]);
                w.push(self.sk.public_key(&secp).serialize());
            }
            InputKind::P2tr => w.push([0x01u8; 64]),
        }
        TxIn {
            previous_output: self.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: w,
        }
    }
}

pub fn outpoint_bytes(o: &OutPoint) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[..32].copy_from_slice(&o.txid.to_byte_array());
    b[32..].copy_from_slice(&o.vout.to_le_bytes());
    b
}

pub struct Funding {
    pub tx: Transaction,
    pub prevout_spks: Vec<ScriptBuf>,
    /// Independently computed (t_k + l_m) for output k.
    pub expected_tau: Vec<[u8; 32]>,
}

/// Minimal BIP 352 sender (test oracle): pays `recipients[k]` = (B_scan, B_m) with output k.
pub fn sp_fund(
    inputs: &[FundingInput],
    recipients: &[(PublicKey, PublicKey)],
    labels_tweak: &[Option<Scalar>],
    value: u64,
) -> Funding {
    let secp = Secp256k1::new();
    let mut a_sum: Option<SecretKey> = None;
    for i in inputs {
        let s = i.effective_secret();
        a_sum = Some(match a_sum {
            None => s,
            Some(acc) => acc
                .add_tweak(&Scalar::from_be_bytes(s.secret_bytes()).unwrap())
                .unwrap(),
        });
    }
    let a = a_sum.unwrap();
    let a_pub = a.public_key(&secp);
    let min_op = inputs
        .iter()
        .map(|i| outpoint_bytes(&i.outpoint))
        .min()
        .unwrap();
    let input_hash = tagged("BIP0352/Inputs", &[&min_op, &a_pub.serialize()]);
    let a_h = a
        .mul_tweak(&Scalar::from_be_bytes(input_hash).unwrap())
        .unwrap();

    let mut outputs = vec![];
    let mut taus = vec![];
    for (k, (b_scan, b_m)) in recipients.iter().enumerate() {
        let ecdh = b_scan
            .mul_tweak(&secp, &Scalar::from_be_bytes(a_h.secret_bytes()).unwrap())
            .unwrap();
        // one k per distinct scan key; tests use distinct scan keys or increase k manually
        let kk = recipients[..k].iter().filter(|(s, _)| s == b_scan).count() as u32;
        let t_k = tagged(
            "BIP0352/SharedSecret",
            &[&ecdh.serialize(), &kk.to_be_bytes()],
        );
        let t = SecretKey::from_slice(&t_k).unwrap();
        let p = b_m.combine(&t.public_key(&secp)).unwrap();
        let (x, _) = p.x_only_public_key();
        outputs.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(
                bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                    bitcoin::XOnlyPublicKey::from_slice(&x.serialize()).unwrap(),
                ),
            ),
        });
        let tau = match labels_tweak[k] {
            Some(l) => t.add_tweak(&l).unwrap(),
            None => t,
        };
        taus.push(tau.secret_bytes());
    }
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs.iter().map(|i| i.txin()).collect(),
        output: outputs,
    };
    Funding {
        tx,
        prevout_spks: inputs.iter().map(|i| i.prevout_spk()).collect(),
        expected_tau: taus,
    }
}

pub fn make_signers(group: &FrostGroup, net: Network, labels: &[u32]) -> Vec<Signer> {
    group
        .key_packages
        .iter()
        .enumerate()
        .map(|(i, (_, kp))| {
            let mut wallet = SpWallet::new(group.b_scan, group.b_spend().unwrap(), net).unwrap();
            for m in labels {
                wallet.add_label(*m).unwrap();
            }
            Signer::new(format!("signer{}", i + 1), kp.clone(), wallet).unwrap()
        })
        .collect()
}

pub fn coordinator(group: &FrostGroup) -> Coordinator {
    Coordinator::new(group.public_key_package.clone())
}

/// Raw FROST signing of an arbitrary 32-byte message under `X + tau*G`, using signers `ids`
/// (indices into the group). Returns the 64-byte BIP 340 signature.
pub fn frost_sign_raw(
    group: &FrostGroup,
    tau: &[u8; 32],
    msg: &[u8; 32],
    ids: &[u16],
    seed: u64,
) -> [u8; 64] {
    let mut r = rng(seed);
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    let mut kps = BTreeMap::new();
    for i in ids {
        let id = frost::Identifier::try_from(*i).unwrap();
        let kp = tweak_key_package(&group.key_packages[&id], tau).unwrap();
        let (n, c) = frost::round1::commit(kp.signing_share(), &mut r);
        nonces.insert(id, n);
        commitments.insert(id, c);
        kps.insert(id, kp);
    }
    let pkg = frost::SigningPackage::new(commitments, msg);
    let mut shares = BTreeMap::new();
    for (id, kp) in &kps {
        shares.insert(*id, frost::round2::sign(&pkg, &nonces[id], kp).unwrap());
    }
    let pkp = tweak_public_key_package(&group.public_key_package, tau).unwrap();
    let sig = frost::aggregate(&pkg, &shares, &pkp).unwrap();
    let b = sig.serialize().unwrap();
    b.try_into().unwrap()
}

pub fn verify_bip340(sig: &[u8; 64], msg: &[u8; 32], xonly: &XOnlyPublicKey) -> bool {
    let s = secp256k1::schnorr::Signature::from_slice(sig).unwrap();
    Secp256k1::verification_only()
        .verify_schnorr(&s, &Message::from_digest(*msg), xonly)
        .is_ok()
}

pub fn keypair_unused(_: &Keypair) {}
