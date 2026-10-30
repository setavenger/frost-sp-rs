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
            Signer::new(format!("signer{}", i + 1), kp.clone(), wallet)
                .unwrap()
                .with_public_key_package(group.public_key_package.clone())
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


// ---------------------------------------------------------------------------------------
// W2 helpers: whole-wallet environments, funded coins, a single-key spdk receiver
// ---------------------------------------------------------------------------------------

use frost_sp_wallet::send::{InputSource, SendCoordinator, SpendableCoin};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils::receiving::{get_pubkey_from_input, PublicTweakData};
use silentpayments::{SpVersion, TransactionInputs, TransactionSharedSecret};

pub struct Env {
    pub group: FrostGroup,
    pub signers: Vec<Signer>,
    pub coord: SendCoordinator,
    pub labels: Vec<u32>,
}

/// A 2-of-3 group from the simulated DKG (seeded): each share was made on its own device and
/// `b_scan` drawn by device 1. Tests gather the key packages to drive all cosigners at once.
pub fn dkg_group(seed: u64) -> FrostGroup {
    let keys = frost_sp_wallet::dkg::keygen(2, 3, &mut rng(seed)).unwrap();
    FrostGroup::from_device_keys(&keys).unwrap()
}

pub fn env(seed: u64, labels: &[u32]) -> Env {
    let group = dkg_group(seed);
    let signers = make_signers(&group, Network::Regtest, labels);
    let mut w = SpWallet::new(group.b_scan, group.b_spend().unwrap(), Network::Regtest).unwrap();
    for m in labels {
        w.add_label(*m).unwrap();
    }
    let coord = SendCoordinator::new(group.public_key_package.clone(), w);
    Env {
        group,
        signers,
        coord,
        labels: labels.to_vec(),
    }
}

pub fn ident(i: u16) -> frost::Identifier {
    frost::Identifier::try_from(i).unwrap()
}

impl Env {
    pub fn address(&self, label: Option<u32>) -> silentpayments::SilentPaymentCode {
        self.coord.wallet().address(label).unwrap()
    }
}

/// Coins paid to `env` (unlabelled or `label`) by an independent test sender. `parities[i]`
/// is the wanted `g` (+1 even / -1 odd) of coin `i`, found by trying funding seeds.
pub fn fund_coins(env: &Env, parities: &[i8], label: Option<u32>, seed0: u64, value: u64) -> Vec<SpendableCoin> {
    let code = env.address(label);
    let mut out = vec![];
    let mut s = seed0;
    for want in parities {
        loop {
            s += 1;
            let kind = if s.is_multiple_of(2) { InputKind::P2tr } else { InputKind::P2wpkh };
            let f = sp_fund(
                &[FundingInput::new(s, kind)],
                &[(code.scan_key(), code.m_pubkey())],
                &[None],
                value,
            );
            let src = InputSource {
                funding_tx: f.tx,
                funding_prevout_spks: f.prevout_spks,
                funding_vout: 0,
            };
            let r = frost_sp_wallet::send::resolve_input(env.coord.wallet(), &src).unwrap();
            if r.g == *want {
                out.push(SpendableCoin { source: src, value: Amount::from_sat(value) });
                break;
            }
        }
    }
    out
}

/// Ordinary single-key silent payment receiver (spdk), as a payee that is not a FROST wallet.
pub struct SpdkReceiver {
    pub scan: SecretKey,
    pub spend: SecretKey,
    pub receiver: Receiver,
}

impl SpdkReceiver {
    pub fn new(seed: u64) -> Self {
        let secp = Secp256k1::new();
        let scan = sk_from_seed(seed, "c-scan");
        let spend = sk_from_seed(seed, "c-spend");
        let receiver = Receiver::new(
            SpVersion::ZERO,
            scan.public_key(&secp),
            spend.public_key(&secp),
            Label::new(scan, 0),
            Network::Regtest,
        )
        .unwrap();
        Self { scan, spend, receiver }
    }

    pub fn code(&self) -> silentpayments::SilentPaymentCode {
        self.receiver.receiving_code()
    }

    /// x-only output keys of `tx` that belong to this receiver, found with spdk's scanner.
    pub fn scan(&self, tx: &Transaction, prevout_spks: &[ScriptBuf]) -> Vec<XOnlyPublicKey> {
        let secp = Secp256k1::new();
        let mut inputs = TransactionInputs::new();
        for (txin, spk) in tx.input.iter().zip(prevout_spks) {
            let pk = get_pubkey_from_input(txin.script_sig.as_bytes(), &txin.witness.to_vec(), spk.as_bytes()).unwrap();
            let op = silentpayments::utils::OutPoint::from_txid_bytes_and_vout(
                txin.previous_output.txid.to_byte_array(),
                txin.previous_output.vout,
            );
            inputs.push(op, spk.to_bytes(), pk);
        }
        let tweak = PublicTweakData::new(&secp, &inputs).unwrap();
        let ss = TransactionSharedSecret::new_from_public_tweak_data(&secp, &tweak, &self.scan).unwrap();
        let cands: Vec<XOnlyPublicKey> = tx
            .output
            .iter()
            .filter(|o| o.script_pubkey.is_p2tr())
            .map(|o| XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..]).unwrap())
            .collect();
        let found = self.receiver.scan_transaction(&ss, &cands).unwrap();
        found.values().flat_map(|m| m.keys().copied()).collect()
    }
}

pub fn prevout_spks_of(coins: &[SpendableCoin]) -> Vec<ScriptBuf> {
    coins
        .iter()
        .map(|c| c.source.funding_tx.output[c.source.funding_vout as usize].script_pubkey.clone())
        .collect()
}

/// The coin that an output of `tx` becomes once it is confirmed (funding data for the next spend).
pub fn coin_from(tx: &Transaction, spks: &[ScriptBuf], vout: u32) -> SpendableCoin {
    SpendableCoin {
        source: InputSource { funding_tx: tx.clone(), funding_prevout_spks: spks.to_vec(), funding_vout: vout },
        value: tx.output[vout as usize].value,
    }
}
