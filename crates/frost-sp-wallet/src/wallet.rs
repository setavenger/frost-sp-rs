//! Silent Payment addresses, labels and scanning for a FROST group.
//!
//! `B_spend` is the group key `X`; `b_scan` is a plain scalar held by every cosigner. Scanning
//! needs only `b_scan` and `B_spend`, never a spend share.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, Txid};
use std::collections::HashMap;

use bitcoin::hashes::sha256;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use silentpayments::receiving::{Label, Receiver};

/// BIP 352 per-group recipient limit.
pub const K_MAX: u32 = 2323;
use silentpayments::utils::receiving::{get_pubkey_from_input, is_p2tr, PublicTweakData};
use silentpayments::{
    Network, SilentPaymentCode, SpVersion, TransactionInputs, TransactionSharedSecret,
};

use crate::{Error, Result};

/// A received output: enough to spend it with FROST. `tau = t_k + l_m` (or `t_k` unlabelled).
/// The wallet never stores `x + tau`.
#[derive(Clone, Debug)]
pub struct OwnedOutput {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    /// Plain tweak, big-endian. The spend key is `x + tau`; the output key `P_k = X + tau*G`.
    pub tau: [u8; 32],
    /// Label index `m` (`Some(0)` is change), `None` if unlabelled.
    pub label: Option<u32>,
}

pub struct SpWallet {
    receiver: Receiver,
    b_scan: SecretKey,
    b_spend: PublicKey,
    /// m -> label, includes m = 0 (change).
    labels: Vec<(u32, Label)>,
    /// l_m*G -> (m, l_m), for matching `output - P_k`.
    label_points: HashMap<PublicKey, (u32, Scalar)>,
}

impl SpWallet {
    pub fn new(b_scan: SecretKey, b_spend: PublicKey, network: Network) -> Result<Self> {
        let secp = Secp256k1::new();
        let change = Label::new(b_scan, 0);
        let receiver = Receiver::new(
            SpVersion::ZERO,
            b_scan.public_key(&secp),
            b_spend,
            change.clone(),
            network,
        )?;
        let mut w = Self {
            receiver,
            b_scan,
            b_spend,
            labels: vec![],
            label_points: HashMap::new(),
        };
        w.register(0, change)?;
        Ok(w)
    }

    pub fn b_spend(&self) -> &PublicKey {
        &self.b_spend
    }

    pub fn b_scan(&self) -> &SecretKey {
        &self.b_scan
    }

    /// Register label `m` so that outputs paid to its address are found. Returns its address.
    pub fn add_label(&mut self, m: u32) -> Result<SilentPaymentCode> {
        if !self.labels.iter().any(|(k, _)| *k == m) {
            let label = Label::new(self.b_scan, m);
            self.receiver.add_label(label.clone())?;
            self.register(m, label)?;
        }
        self.address(Some(m))
    }

    /// `None`: base address `(B_scan, B_spend)`. `Some(m)`: `B_m = B_spend + l_m*G`.
    /// `Some(0)` is the change address and must not be shown to users.
    pub fn address(&self, m: Option<u32>) -> Result<SilentPaymentCode> {
        match m {
            None => Ok(self.receiver.receiving_code()),
            Some(0) => Ok(self.receiver.change_code()),
            Some(m) => {
                let (_, label) = self
                    .labels
                    .iter()
                    .find(|(k, _)| *k == m)
                    .ok_or_else(|| Error::Other(format!("label {m} not registered")))?;
                Ok(self.receiver.receiving_code_for_label(label)?)
            }
        }
    }

    pub fn change_address(&self) -> SilentPaymentCode {
        self.receiver.change_code()
    }

    fn register(&mut self, m: u32, label: Label) -> Result<()> {
        let secp = Secp256k1::new();
        let l = *label.as_inner();
        let point = SecretKey::from_slice(&l.to_be_bytes())?.public_key(&secp);
        self.label_points.insert(point, (m, l));
        self.labels.push((m, label));
        Ok(())
    }

    /// Scan one transaction. `prevout_spks[i]` is the scriptPubKey spent by input `i`.
    /// Runs the full BIP 352 k-loop (spdk) with every registered label.
    pub fn scan_tx(
        &self,
        tx: &Transaction,
        prevout_spks: &[ScriptBuf],
    ) -> Result<Vec<OwnedOutput>> {
        if prevout_spks.len() != tx.input.len() {
            return Err(Error::Other(
                "need one prevout scriptPubKey per input".into(),
            ));
        }
        // BIP 352: a transaction spending an output with SegWit version > 1 is not scanned.
        if prevout_spks
            .iter()
            .any(|s| s.witness_version().is_some_and(|v| v.to_num() >= 2))
        {
            return Ok(vec![]);
        }
        let secp = Secp256k1::new();
        let mut inputs = TransactionInputs::new();
        for (txin, spk) in tx.input.iter().zip(prevout_spks) {
            let witness = txin.witness.to_vec();
            let pk = get_pubkey_from_input(txin.script_sig.as_bytes(), &witness, spk.as_bytes())?;
            let op = silentpayments::utils::OutPoint::from_txid_bytes_and_vout(
                txin.previous_output.txid.to_byte_array(),
                txin.previous_output.vout,
            );
            inputs.push(op, spk.to_bytes(), pk);
        }
        if inputs.input_pubkeys().iter().all(Option::is_none) {
            return Ok(vec![]);
        }
        // BIP 352: inputs whose keys sum to the point at infinity make the tx unscannable.
        let tweak_data = match PublicTweakData::new(&secp, &inputs) {
            Ok(t) => t,
            Err(silentpayments::Error::Secp256k1Error(secp256k1::Error::InvalidPublicKeySum)) => {
                return Ok(vec![])
            }
            Err(e) => return Err(e.into()),
        };
        let ss =
            TransactionSharedSecret::new_from_public_tweak_data(&secp, &tweak_data, &self.b_scan)?;

        let mut candidates: Vec<(u32, XOnlyPublicKey)> = vec![];
        for (vout, o) in tx.output.iter().enumerate() {
            if is_p2tr(o.script_pubkey.as_bytes()) {
                // An unspendable P2TR-shaped output (x not on the curve) is just not ours.
                if let Ok(k) = XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..]) {
                    candidates.push((vout as u32, k));
                }
            }
        }

        // BIP 352 k-loop (own implementation so K_max is enforced and k is tracked; the
        // spdk loop does neither). Stop at the first k with no match.
        let ecdh = ss.as_ecdh_shared_secret().serialize();
        let txid: Txid = tx.compute_txid();
        let mut out = vec![];
        let mut used = vec![false; candidates.len()];
        for k in 0..K_MAX {
            let t_k = tagged_hash("BIP0352/SharedSecret", &[&ecdh, &k.to_be_bytes()]);
            let t_k_sk = SecretKey::from_slice(&t_k)?;
            let p_k = self.b_spend.combine(&t_k_sk.public_key(&secp))?;
            let mut hit: Option<(usize, Option<u32>, [u8; 32])> = None;
            for (ci, (_, key)) in candidates.iter().enumerate() {
                if used[ci] {
                    continue;
                }
                if *key == p_k.x_only_public_key().0 {
                    hit = Some((ci, None, t_k));
                    break;
                }
                // Labelled: output - P_k must be a known l_m*G (either output parity).
                let neg_pk = p_k.negate(&secp);
                for parity in [secp256k1::Parity::Even, secp256k1::Parity::Odd] {
                    let diff = key.public_key(parity).combine(&neg_pk);
                    if let Ok(diff) = diff {
                        if let Some((m, l)) = self.label_points.get(&diff) {
                            let tau = t_k_sk.add_tweak(l)?;
                            hit = Some((ci, Some(*m), tau.secret_bytes()));
                            break;
                        }
                    }
                }
                if hit.is_some() {
                    break;
                }
            }
            let Some((ci, m, tau)) = hit else { break };
            used[ci] = true;
            let vout = candidates[ci].0;
            let txo = &tx.output[vout as usize];
            out.push(OwnedOutput {
                outpoint: OutPoint { txid, vout },
                value: txo.value,
                script_pubkey: txo.script_pubkey.clone(),
                tau,
                label: m,
            });
        }
        out.sort_by_key(|o| o.outpoint.vout);
        Ok(out)
    }
}

fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    use bitcoin::hashes::HashEngine;
    let th = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(th.as_ref());
    e.input(th.as_ref());
    for p in parts {
        e.input(p);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}
