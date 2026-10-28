//! Spending one received SP output with FROST (single input, plain P2TR payout).
//!
//! Hand-off for W2: the signer API takes the *funding transaction* and the signer's own
//! `b_scan`. It never accepts a tweak. `tau` is re-derived from the funding transaction
//! (T7); a coordinator-supplied hint is compared and refused on mismatch, never used.
//!
//! ASSUMES-SINGLE-INPUT: `Signer::sign` requires `spend_tx.input.len() == 1`, signs input 0
//! against exactly one prevout, and uses one `tau`. See the summary for the full list.

use std::collections::BTreeMap;

use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
use frost_secp256k1_tr::round2::{self, SignatureShare};
use frost_secp256k1_tr::{Identifier, SigningPackage};
use rand::{CryptoRng, RngCore};
use secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};

use crate::exposure::{ExposureCounter, RotationThreshold};
use crate::tweak::{tweak_key_package, tweak_public_key_package};
use crate::wallet::{OwnedOutput, SpWallet};
use crate::{Error, Result};

/// Build an unsigned 1-in-1-out transaction spending `owned` to `dest`.
pub fn build_spend_tx(owned: &OwnedOutput, dest: ScriptBuf, fee: Amount) -> Result<Transaction> {
    let value = owned
        .value
        .checked_sub(fee)
        .ok_or_else(|| Error::Other("fee exceeds output value".into()))?;
    Ok(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: owned.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: dest,
        }],
    })
}

/// BIP 341 key-path sighash (SIGHASH_DEFAULT) of input 0 spending `prevout`.
pub fn key_path_sighash(tx: &Transaction, prevout: &TxOut) -> Result<[u8; 32]> {
    let mut cache = SighashCache::new(tx);
    let h = cache
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(prevout)),
            TapSighashType::Default,
        )
        .map_err(|e| Error::Other(format!("sighash: {e}")))?;
    Ok(*h.as_ref())
}

/// Everything a signer needs to verify a spend; deliberately no tweak field.
pub struct SignRequest<'a> {
    pub funding_tx: &'a Transaction,
    /// scriptPubKey spent by each input of `funding_tx` (needed to find the SP input keys).
    /// Self-authenticating: a lie changes the derived output key and the match fails.
    pub funding_prevout_spks: &'a [ScriptBuf],
    pub funding_vout: u32,
    pub spend_tx: &'a Transaction,
    pub signing_package: &'a SigningPackage,
    /// Untrusted hint from the coordinator. Compared against the signer's own derivation,
    /// refused on mismatch, never used for signing.
    pub coordinator_tau_hint: Option<[u8; 32]>,
}

/// What a signer approved out of band: the exact coin, the exact outputs and a fee ceiling.
pub struct ApprovedSpend {
    pub outpoint: OutPoint,
    pub outputs: Vec<TxOut>,
    pub max_fee: Amount,
}

pub struct Signer {
    pub(crate) name: String,
    pub(crate) key_package: KeyPackage,
    pub(crate) public_key_package: Option<PublicKeyPackage>,
    pub(crate) wallet: SpWallet,
    nonces: Option<SigningNonces>,
    /// One nonce pair per input of the pending multi-input send (see `send.rs`).
    pub(crate) send_nonces: Vec<SigningNonces>,
    pub(crate) exposure: ExposureCounter,
}

impl Signer {
    /// `wallet` carries this signer's own `b_scan` and labels.
    pub fn new(name: impl Into<String>, key_package: KeyPackage, wallet: SpWallet) -> Result<Self> {
        let x = key_package.verifying_key().serialize()?;
        if x.as_slice() != wallet.b_spend().serialize().as_slice() {
            return Err(Error::Other(
                "wallet B_spend is not the group key of this key package".into(),
            ));
        }
        let wallet_group_key: [u8; 33] = x
            .as_slice()
            .try_into()
            .map_err(|_| Error::Other("group key is not 33 bytes".into()))?;
        Ok(Self {
            name: name.into(),
            key_package,
            wallet,
            public_key_package: None,
            nonces: None,
            send_nonces: vec![],
            exposure: ExposureCounter::new(RotationThreshold::Thousand)
                .with_group_key(wallet_group_key),
        })
    }

    /// The public key package (verification shares) is needed to verify other signers' DLEQ
    /// proofs when sending.
    pub fn with_public_key_package(mut self, pkp: PublicKeyPackage) -> Self {
        self.public_key_package = Some(pkp);
        self
    }

    pub fn exposure(&self) -> &ExposureCounter {
        &self.exposure
    }

    pub fn exposure_mut(&mut self) -> &mut ExposureCounter {
        &mut self.exposure
    }

    pub fn identifier(&self) -> Identifier {
        *self.key_package.identifier()
    }

    /// Round 1. Replaces (and drops) any unused nonces: a nonce pair is never used twice.
    pub fn commit<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> SigningCommitments {
        let (nonces, commitments) =
            frost_secp256k1_tr::round1::commit(self.key_package.signing_share(), rng);
        self.nonces = Some(nonces);
        commitments
    }

    pub(crate) fn refusal(&self, reason: impl Into<String>) -> Error {
        Error::Refused {
            who: self.name.clone(),
            reason: reason.into(),
        }
    }

    pub(crate) fn refuse<T>(&self, reason: impl Into<String>) -> Result<T> {
        Err(self.refusal(reason))
    }

    /// Round 2. Nonces are consumed first, so a refused session cannot be retried with them.
    /// `approved` is what this signer agreed to out of band (coin, outputs, fee ceiling).
    pub fn sign(&mut self, req: &SignRequest, approved: &ApprovedSpend) -> Result<SignatureShare> {
        let nonces = match self.nonces.take() {
            Some(n) => n,
            None => return self.refuse("no pending nonces (commit first)"),
        };

        // 0. The funding transaction must be the approved coin's, checked before any expensive
        //    scanning of an unauthenticated transaction (Opus review F2).
        if req.funding_tx.compute_txid() != approved.outpoint.txid
            || req.funding_vout != approved.outpoint.vout
        {
            return self.refuse("funding output is not the approved coin");
        }

        // 1. Re-derive tau from the funding transaction with our own b_scan (T7).
        let owned = self
            .wallet
            .scan_tx(req.funding_tx, req.funding_prevout_spks)?;
        let Some(out) = owned.iter().find(|o| o.outpoint.vout == req.funding_vout) else {
            return self.refuse("funding output is not an SP output of this wallet");
        };
        if let Some(hint) = req.coordinator_tau_hint {
            if hint != out.tau {
                return self
                    .refuse("coordinator supplied a tweak that differs from the derived one");
            }
        }

        // 2. The tweaked group key must be exactly the funding output key.
        let tweaked = tweak_key_package(&self.key_package, &out.tau)?;
        let pk = tweaked.verifying_key().serialize()?;
        let funding_txo = &req.funding_tx.output[req.funding_vout as usize];
        if funding_txo.script_pubkey.as_bytes().get(2..) != Some(&pk[1..]) {
            return self.refuse("X + tau*G does not match the funding output key");
        }

        // 3. The transaction is the one we approved.
        if req.spend_tx.input.len() != 1 {
            return self.refuse("exactly one input supported");
        }
        if let Err(e) = crate::send::check_tx_shape(req.spend_tx) {
            return self.refuse(e.to_string()); // F1: version, locktime, sequence
        }
        let want = OutPoint {
            txid: req.funding_tx.compute_txid(),
            vout: req.funding_vout,
        };
        if req.spend_tx.input[0].previous_output != want {
            return self.refuse("spend does not consume the funding output");
        }
        if want != approved.outpoint {
            return self.refuse("funding output is not the approved coin");
        }
        if req.spend_tx.output.as_slice() != approved.outputs.as_slice() {
            return self.refuse("outputs differ from the approved outputs");
        }
        let out_sum: u64 = req.spend_tx.output.iter().map(|o| o.value.to_sat()).sum();
        match funding_txo.value.to_sat().checked_sub(out_sum) {
            Some(fee) if fee <= approved.max_fee.to_sat() => {}
            _ => return self.refuse("fee exceeds the approved maximum"),
        }

        // 4. FROST message must be the sighash of the tx we just verified.
        let sighash = key_path_sighash(req.spend_tx, funding_txo)?;
        if req.signing_package.message() != sighash.as_slice() {
            return self.refuse("FROST message is not the sighash of the verified transaction");
        }

        Ok(round2::sign(req.signing_package, &nonces, &tweaked)?)
    }
}

pub struct Coordinator {
    public_key_package: PublicKeyPackage,
}

impl Coordinator {
    pub fn new(public_key_package: PublicKeyPackage) -> Self {
        Self { public_key_package }
    }

    pub fn signing_package(
        &self,
        spend_tx: &Transaction,
        funding_txo: &TxOut,
        commitments: BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SigningPackage> {
        let sighash = key_path_sighash(spend_tx, funding_txo)?;
        Ok(SigningPackage::new(commitments, &sighash))
    }

    /// Aggregate shares under `P_k = X + tau*G`, verify as BIP 340, finalise the key path.
    /// `owned.tau` comes from the coordinator's own scan; a wrong value only makes this fail.
    pub fn finalize(
        &self,
        spend_tx: &Transaction,
        owned: &OwnedOutput,
        signing_package: &SigningPackage,
        shares: &BTreeMap<Identifier, SignatureShare>,
    ) -> Result<Transaction> {
        // The returned tx must be the one the shares were produced for.
        if spend_tx.input.len() != 1 || spend_tx.input[0].previous_output != owned.outpoint {
            return Err(Error::Other(
                "spend tx does not consume the owned output".into(),
            ));
        }
        let prevout = TxOut {
            value: owned.value,
            script_pubkey: owned.script_pubkey.clone(),
        };
        if key_path_sighash(spend_tx, &prevout)?.as_slice() != signing_package.message() {
            return Err(Error::Other(
                "spend tx does not match the signing package message".into(),
            ));
        }
        let pkp = tweak_public_key_package(&self.public_key_package, &owned.tau)?;
        // F4: a wrong tau is the coordinator's bug; check it here so that aggregate's cheater
        // detection cannot blame an honest signer.
        let xonly = XOnlyPublicKey::from_slice(&owned.script_pubkey.as_bytes()[2..])?;
        if pkp.verifying_key().serialize()?[1..] != xonly.serialize()[..] {
            return Err(Error::Other(
                "coordinator error: X + tau*G does not match the output key (wrong tau)".into(),
            ));
        }
        let sig = frost_secp256k1_tr::aggregate(signing_package, shares, &pkp)?;
        let bytes = sig.serialize()?;
        let sig = schnorr::Signature::from_slice(&bytes)?;
        let msg = Message::from_digest_slice(signing_package.message())?;
        Secp256k1::verification_only().verify_schnorr(&sig, &msg, &xonly)?;

        let mut tx = spend_tx.clone();
        let mut w = Witness::new();
        w.push(sig.as_ref());
        tx.input[0].witness = w;
        Ok(tx)
    }
}

/// Consensus check with libbitcoinconsensus (Bitcoin Core 26 script + taproot rules) of a
/// finalised single-input spend of `funding_txo`. rust-bitcoin's `Transaction::verify` does
/// not enable taproot (it would accept any witness), so the crate is called directly with the
/// spent outputs.
pub fn verify_consensus(tx: &Transaction, funding_txo: &TxOut) -> Result<()> {
    let spk = funding_txo.script_pubkey.as_bytes();
    let utxo = bitcoinconsensus::Utxo {
        script_pubkey: spk.as_ptr(),
        script_pubkey_len: spk.len() as u32,
        value: funding_txo.value.to_sat() as i64,
    };
    let raw = bitcoin::consensus::serialize(tx);
    bitcoinconsensus::verify(spk, funding_txo.value.to_sat(), &raw, Some(&[utxo]), 0)
        .map_err(|e| Error::Other(format!("consensus verification failed: {e:?}")))
}
