//! Paying BIP 352 Silent Payment addresses from an SP-only FROST wallet (W2).
//!
//! Every input is a received SP output `P_j = X + tau_j*G` spent through its key path. Because
//! all inputs share the group secret `x`, the sender-side ECDH needs one threshold share per
//! distinct recipient scan key `B`:
//!
//! ```text
//! a*B = (sum_j g_j) * sum_{i in S} lambda_i*D_i + (sum_j g_j*tau_j) * B,   D_i = x_i*B
//! ```
//!
//! `g_j = -1` if `P_j` has odd Y (BIP 352 negates such taproot keys), else `+1`. The wallet's
//! own scan key needs no shares: `a*B_scan = b_scan*A` (ECDH symmetry).
//!
//! Message flow (all in memory, typed structs; no PSBT):
//! 1. coordinator -> signers: [`EcdhRequest`]; signers answer [`EcdhShare`]s (`Signer::ecdh_shares`)
//! 2. coordinator builds the transaction ([`SendCoordinator::build_tx`]) and one
//!    `SigningPackage` per input
//! 3. signers verify everything and return one signature share per input (`Signer::sign_send`)
//! 4. coordinator aggregates per input and attaches the witnesses ([`SendCoordinator::finalize`])
//!
//! Nothing here ever forms `x` or `x + tau_j`.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::round1::SigningCommitments;
use frost_secp256k1_tr::round2::{self, SignatureShare};
use frost_secp256k1_tr::{Identifier, SigningPackage};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand::{CryptoRng, RngCore};
use secp256k1::{schnorr, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use silentpayments::SilentPaymentCode;

use crate::spend::Signer;
use crate::tweak::{scalar_from_be, tweak_key_package, tweak_public_key_package};
use crate::wallet::SpWallet;
use crate::{Error, Result};

// ------------------------------------------------------------------------------------------
// Small helpers
// ------------------------------------------------------------------------------------------

fn to_k(p: &PublicKey) -> Result<ProjectivePoint> {
    let ep = EncodedPoint::from_bytes(p.serialize()).map_err(|_| Error::Scalar("point"))?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .map(ProjectivePoint::from)
        .ok_or(Error::Scalar("point not on curve"))
}

fn from_k(p: &ProjectivePoint) -> Result<PublicKey> {
    if *p == ProjectivePoint::IDENTITY {
        return Err(Error::Scalar("point at infinity"));
    }
    Ok(PublicKey::from_slice(
        p.to_affine().to_encoded_point(true).as_bytes(),
    )?)
}

fn sk_to_scalar(sk: &SecretKey) -> Result<Scalar> {
    scalar_from_be(&sk.secret_bytes())
}

fn signed_scalar(g: i64) -> Scalar {
    let s = Scalar::from(g.unsigned_abs());
    if g < 0 {
        -s
    } else {
        s
    }
}

fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let th = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(th.as_ref());
    e.input(th.as_ref());
    for p in parts {
        e.input(p);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

fn id_str(id: &Identifier) -> String {
    format!("{id:?}")
}

fn outpoint_bytes(o: &OutPoint) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[..32].copy_from_slice(&o.txid.to_byte_array());
    b[32..].copy_from_slice(&o.vout.to_le_bytes());
    b
}

fn p2tr_script(xonly: &XOnlyPublicKey) -> Result<ScriptBuf> {
    Ok(ScriptBuf::new_p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            bitcoin::XOnlyPublicKey::from_slice(&xonly.serialize())
                .map_err(|e| Error::Other(format!("xonly: {e}")))?,
        ),
    ))
}

/// T4: validate a recipient scan key from its 33-byte encoding. Rejects wrong length, a prefix
/// other than 0x02/0x03, x >= p, x not on the curve. (The point at infinity has no 33-byte
/// encoding; an all-zero string fails the prefix check.)
pub fn validate_scan_key(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != 33 {
        return Err(Error::InvalidScanKey("length is not 33 bytes"));
    }
    if bytes[0] != 0x02 && bytes[0] != 0x03 {
        return Err(Error::InvalidScanKey("prefix byte is not 0x02 or 0x03"));
    }
    PublicKey::from_slice(bytes)
        .map_err(|_| Error::InvalidScanKey("x is not a valid curve coordinate"))
}

// ------------------------------------------------------------------------------------------
// Sender math (pure; also driven directly by the BIP 352 sending vectors)
// ------------------------------------------------------------------------------------------

/// One input of the sender-side sum. `point` is `P_j = (x + tau_j)*G` *before* parity.
#[derive(Clone, Debug)]
pub struct InputTerm {
    pub outpoint: OutPoint,
    /// +1, or -1 if the input key is negated by BIP 352 (taproot input with odd-Y key).
    pub g: i8,
    pub tau: [u8; 32],
    pub point: PublicKey,
}

/// `sum_j g_j` must not be 0. See `research/parity-cancellation.md`: if it is 0, `x` cancels
/// out of the input key sum, the payer of these inputs knows every `tau_j` and `g_j`, and so
/// it can compute the shared secret of this wallet's outgoing payment.
pub fn check_parity_guard(gs: &[i8]) -> Result<()> {
    let sum: i64 = gs.iter().map(|g| i64::from(*g)).sum();
    if sum == 0 {
        Err(Error::ParityCancellation)
    } else {
        Ok(())
    }
}

/// Everything about the input set that BIP 352 needs: `A`, `input_hash`, `sum g`, `sum g*tau`.
pub struct SenderContext {
    sum_g: i64,
    sum_g_tau: Scalar,
    a_point: ProjectivePoint,
    input_hash: Scalar,
}

impl SenderContext {
    /// Does **not** apply the parity guard (the math is valid for any set; the guard is a
    /// privacy rule enforced by selection and by signers via [`check_parity_guard`]).
    pub fn new(terms: &[InputTerm]) -> Result<Self> {
        if terms.is_empty() {
            return Err(Error::Other("no inputs".into()));
        }
        let mut sum_g = 0i64;
        let mut sum_g_tau = Scalar::ZERO;
        let mut a_point = ProjectivePoint::IDENTITY;
        for t in terms {
            if t.g != 1 && t.g != -1 {
                return Err(Error::Other("g must be +1 or -1".into()));
            }
            let g = i64::from(t.g);
            sum_g += g;
            sum_g_tau += signed_scalar(g) * scalar_from_be(&t.tau)?;
            let p = to_k(&t.point)?;
            a_point += if g < 0 { -p } else { p };
        }
        let a_pub = from_k(&a_point)?; // BIP 352: A = infinity -> fail
        let min_op = terms
            .iter()
            .map(|t| outpoint_bytes(&t.outpoint))
            .min()
            .ok_or_else(|| Error::Other("no inputs".into()))?;
        let input_hash = nonzero_input_hash(scalar_from_be(&tagged_hash(
            "BIP0352/Inputs",
            &[&min_op, &a_pub.serialize()],
        ))?)?;
        Ok(Self {
            sum_g,
            sum_g_tau,
            a_point,
            input_hash,
        })
    }

    pub fn sum_g(&self) -> i64 {
        self.sum_g
    }

    /// `input_hash * a * B` from `lambda_d = sum_{i in S} lambda_i*D_i`.
    pub fn ecdh_from_shares(
        &self,
        scan_key: &PublicKey,
        lambda_d: &ProjectivePoint,
    ) -> Result<PublicKey> {
        let b = to_k(scan_key)?;
        let p = *lambda_d * signed_scalar(self.sum_g) + b * self.sum_g_tau;
        from_k(&(p * self.input_hash))
    }

    /// `input_hash * b_scan * A`: the wallet's own scan key needs no shares.
    pub fn ecdh_self(&self, b_scan: &SecretKey) -> Result<PublicKey> {
        from_k(&(self.a_point * (sk_to_scalar(b_scan)? * self.input_hash)))
    }
}

/// `P = B_m + t_k*G` as a P2TR script, `t_k = H_BIP0352/SharedSecret(ser_P(ecdh) || ser32(k))`.
pub fn sp_output_script(spend_key: &PublicKey, ecdh: &PublicKey, k: u32) -> Result<ScriptBuf> {
    let secp = Secp256k1::new();
    let t = tagged_hash(
        "BIP0352/SharedSecret",
        &[&ecdh.serialize(), &k.to_be_bytes()],
    );
    let t = SecretKey::from_slice(&t)?;
    let p = spend_key.combine(&t.public_key(&secp))?;
    p2tr_script(&p.x_only_public_key().0)
}

/// Lagrange coefficients at 0 for the signing set.
pub fn lagrange_at_zero(ids: &[Identifier]) -> Result<BTreeMap<Identifier, Scalar>> {
    let xs: Vec<Scalar> = ids
        .iter()
        .map(|i| {
            let bytes: [u8; 32] = i
                .serialize()
                .try_into()
                .map_err(|_| Error::Scalar("identifier length"))?;
            scalar_from_be(&bytes)
        })
        .collect::<Result<_>>()?;
    let mut out = BTreeMap::new();
    for (a, id) in ids.iter().enumerate() {
        let (mut num, mut den) = (Scalar::ONE, Scalar::ONE);
        for (b, xb) in xs.iter().enumerate() {
            if a != b {
                num *= xb;
                den *= *xb - xs[a];
            }
        }
        let inv = Option::<Scalar>::from(den.invert())
            .ok_or_else(|| Error::Other("duplicate identifiers in signing set".into()))?;
        out.insert(*id, num * inv);
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------
// Threshold ECDH shares with BIP 374 proofs
// ------------------------------------------------------------------------------------------

/// `D_i = x_i*B` with a BIP 374 proof for `(A = X_i, B, C = D_i)` against the **untweaked**
/// verification share `X_i`.
#[derive(Clone, Debug)]
pub struct EcdhShare {
    pub id: Identifier,
    pub scan_key: PublicKey,
    pub d: PublicKey,
    pub proof: [u8; 64],
}

/// BIP 374 prove. `aux_rand` must be fresh 32 random bytes per proof and is unrelated to any
/// FROST nonce (BIP 374 derives its own nonce from the secret and `aux_rand`).
pub fn dleq_prove(
    secret: &SecretKey,
    b: &PublicKey,
    aux_rand: &[u8; 32],
    msg: Option<&[u8; 32]>,
) -> Result<[u8; 64]> {
    let secp = Secp256k1::new();
    rust_dleq::generate_dleq_proof(&secp, secret, b, aux_rand, msg)
        .map(|p| p.0)
        .map_err(|e| Error::Other(format!("dleq prove: {e}")))
}

/// BIP 374 verify.
pub fn dleq_verify(
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    proof: &[u8; 64],
    msg: Option<&[u8; 32]>,
) -> Result<bool> {
    let secp = Secp256k1::new();
    rust_dleq::verify_dleq_proof(&secp, a, b, c, &rust_dleq::DleqProof(*proof), msg)
        .map_err(|e| Error::Other(format!("dleq verify: {e}")))
}

/// Produce this signer's share for `scan_key`. Fresh `aux_rand` from `rng` per call.
pub fn make_ecdh_share<R: RngCore + CryptoRng>(
    key_package: &KeyPackage,
    scan_key: &PublicKey,
    rng: &mut R,
) -> Result<EcdhShare> {
    let x_i = SecretKey::from_slice(&key_package.signing_share().to_scalar().to_bytes())?;
    let secp = Secp256k1::new();
    let d = scan_key.mul_tweak(&secp, &secp256k1::Scalar::from(x_i))?;
    let mut aux = [0u8; 32];
    rng.fill_bytes(&mut aux);
    let proof = dleq_prove(&x_i, scan_key, &aux, None)?;
    Ok(EcdhShare {
        id: *key_package.identifier(),
        scan_key: *scan_key,
        d,
        proof,
    })
}

// ------------------------------------------------------------------------------------------
// What a signer approved, and the resolved inputs
// ------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovedDest {
    Sp {
        scan_key: PublicKey,
        spend_key: PublicKey,
    },
    Script(ScriptBuf),
}

impl ApprovedDest {
    pub fn sp(code: &SilentPaymentCode) -> Self {
        Self::Sp {
            scan_key: code.scan_key(),
            spend_key: code.m_pubkey(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedOutput {
    pub dest: ApprovedDest,
    pub amount: Amount,
}

/// What a signer approved out of band: exact coins (in transaction order), exact recipients
/// and amounts (in output order) and a fee ceiling. Replaces `ApprovedSpend` for sends.
#[derive(Clone, Debug)]
pub struct ApprovedSend {
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<ApprovedOutput>,
    pub max_fee: Amount,
}

/// One coin to spend, with the funding transaction each signer re-derives `tau_j` from (T7).
#[derive(Clone, Debug)]
pub struct InputSource {
    pub funding_tx: Transaction,
    /// scriptPubKey spent by each input of `funding_tx`.
    pub funding_prevout_spks: Vec<ScriptBuf>,
    pub funding_vout: u32,
}

#[derive(Clone, Debug)]
pub struct ResolvedInput {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub tau: [u8; 32],
    pub g: i8,
    /// `P_j` before parity.
    pub point: PublicKey,
}

impl ResolvedInput {
    fn term(&self) -> InputTerm {
        InputTerm {
            outpoint: self.outpoint,
            g: self.g,
            tau: self.tau,
            point: self.point,
        }
    }
}

/// Re-derive `tau`, `g` and the prevout of one coin from its funding transaction with the
/// wallet's own `b_scan`. Nothing here comes from the coordinator.
pub fn resolve_input(wallet: &SpWallet, src: &InputSource) -> Result<ResolvedInput> {
    let owned = wallet.scan_tx(&src.funding_tx, &src.funding_prevout_spks)?;
    let out = owned
        .iter()
        .find(|o| o.outpoint.vout == src.funding_vout)
        .ok_or_else(|| Error::Other("funding output is not an SP output of this wallet".into()))?;
    let secp = Secp256k1::new();
    let tau_sk = SecretKey::from_slice(&out.tau)?;
    let point = wallet.b_spend().combine(&tau_sk.public_key(&secp))?;
    let (xonly, parity) = point.x_only_public_key();
    if out.script_pubkey.as_bytes().get(2..) != Some(&xonly.serialize()[..]) {
        return Err(Error::Other(
            "X + tau*G does not match the funding output key".into(),
        ));
    }
    Ok(ResolvedInput {
        outpoint: out.outpoint,
        txout: TxOut {
            value: out.value,
            script_pubkey: out.script_pubkey.clone(),
        },
        tau: out.tau,
        g: if parity == secp256k1::Parity::Odd { -1 } else { 1 },
        point,
    })
}

fn resolve_all(wallet: &SpWallet, srcs: &[InputSource]) -> Result<Vec<ResolvedInput>> {
    let r = srcs
        .iter()
        .map(|s| resolve_input(wallet, s))
        .collect::<Result<Vec<_>>>()?;
    let uniq: BTreeSet<_> = r.iter().map(|i| i.outpoint).collect();
    if uniq.len() != r.len() {
        return Err(Error::Other("duplicate input".into()));
    }
    Ok(r)
}

/// Key-path (SIGHASH_DEFAULT) sighash of every input; taproot commits to all prevouts.
pub fn key_path_sighashes(tx: &Transaction, prevouts: &[TxOut]) -> Result<Vec<[u8; 32]>> {
    let mut cache = SighashCache::new(tx);
    (0..tx.input.len())
        .map(|j| {
            cache
                .taproot_key_spend_signature_hash(
                    j,
                    &Prevouts::All(prevouts),
                    TapSighashType::Default,
                )
                .map(|h| *h.as_ref())
                .map_err(|e| Error::Other(format!("sighash: {e}")))
        })
        .collect()
}

/// BIP 352: `input_hash = 0` must fail (negligible probability, but required).
fn nonzero_input_hash(h: Scalar) -> Result<Scalar> {
    if bool::from(h.is_zero()) {
        return Err(Error::Scalar("input_hash is zero"));
    }
    Ok(h)
}

/// Check the public key package before any `D_j`/DLEQ is accepted or anything is signed:
/// its group key is ours, our own `X_i` is our key package's verifying share, and
/// `sum_{i in S} lambda_i*X_i == X` for the actual signing set. With this, the DLEQ proofs
/// against each `X_i` force `sum lambda_i*D_i = x*B` whatever a substituted `X_j'` claims.
pub fn validate_public_key_package(
    pkp: &PublicKeyPackage,
    key_package: &KeyPackage,
    signing_set: &[Identifier],
) -> Result<()> {
    let bad = |m: &str| Error::Other(format!("public key package invalid: {m}"));
    let x = pkp.verifying_key().serialize()?;
    if x != key_package.verifying_key().serialize()? {
        return Err(bad("group key differs from this signer's key package"));
    }
    let own = pkp
        .verifying_shares()
        .get(key_package.identifier())
        .ok_or_else(|| bad("no verifying share for this signer"))?;
    if own.serialize()? != key_package.verifying_share().serialize()? {
        return Err(bad("own verifying share differs from this signer's key package"));
    }
    let lambdas = lagrange_at_zero(signing_set)?;
    let mut sum = ProjectivePoint::IDENTITY;
    for id in signing_set {
        let x_i = pkp
            .verifying_shares()
            .get(id)
            .ok_or_else(|| bad("signing set member has no verifying share"))?;
        sum += to_k(&PublicKey::from_slice(&x_i.serialize()?)?)? * lambdas[id];
    }
    if from_k(&sum).ok() != PublicKey::from_slice(&x).ok() {
        return Err(bad("sum of lambda_i*X_i over the signing set is not the group key"));
    }
    Ok(())
}

/// Verify every ECDH share (BIP 374, against the untweaked `X_i`) and derive the ECDH value of
/// each distinct scan key among the SP outputs. Names the culprit on any failure.
///
/// Culprit ids are unauthenticated: `EcdhShare.id` is self-declared, so when shares are
/// relayed by a coordinator the named culprit is only meaningful over authenticated channels
/// (a relay can attach a bad proof to an honest id or drop an honest share).
///
/// `own_scan`: the wallet's `b_scan`; outputs to that scan key use `b_scan*A`, not shares.
pub fn ecdh_for_outputs(
    ctx: &SenderContext,
    outputs: &[ApprovedOutput],
    shares: &[EcdhShare],
    signing_set: &[Identifier],
    pkp: &PublicKeyPackage,
    own_scan: &SecretKey,
) -> Result<BTreeMap<[u8; 33], PublicKey>> {
    let secp = Secp256k1::new();
    let own_pub = own_scan.public_key(&secp);
    let wanted: BTreeSet<[u8; 33]> = outputs
        .iter()
        .filter_map(|o| match &o.dest {
            ApprovedDest::Sp { scan_key, .. } if *scan_key != own_pub => {
                Some(scan_key.serialize())
            }
            _ => None,
        })
        .collect();
    let set: BTreeSet<Identifier> = signing_set.iter().copied().collect();
    let lambdas = lagrange_at_zero(signing_set)?;

    let mut by_key: BTreeMap<[u8; 33], BTreeMap<Identifier, &EcdhShare>> = BTreeMap::new();
    for s in shares {
        let culprit = |reason: &str| Error::Culprit {
            who: id_str(&s.id),
            reason: reason.into(),
        };
        if !set.contains(&s.id) {
            return Err(culprit("share from outside the signing set"));
        }
        let key = s.scan_key.serialize();
        if !wanted.contains(&key) {
            return Err(culprit("share for a scan key that is not a recipient"));
        }
        let x_i = pkp
            .verifying_shares()
            .get(&s.id)
            .ok_or_else(|| culprit("unknown identifier"))?;
        let x_i = PublicKey::from_slice(&x_i.serialize()?)?;
        if !dleq_verify(&x_i, &s.scan_key, &s.d, &s.proof, None).unwrap_or(false) {
            return Err(culprit("invalid BIP 374 DLEQ proof"));
        }
        if by_key.entry(key).or_default().insert(s.id, s).is_some() {
            return Err(culprit("duplicate share"));
        }
    }

    let mut out = BTreeMap::new();
    for key in &wanted {
        let scan_key = PublicKey::from_slice(key)?;
        let have = by_key.get(key);
        let mut lambda_d = ProjectivePoint::IDENTITY;
        for id in signing_set {
            let s = have.and_then(|m| m.get(id)).ok_or_else(|| Error::Culprit {
                who: id_str(id),
                reason: "missing ECDH share".into(),
            })?;
            lambda_d += to_k(&s.d)? * lambdas[id];
        }
        out.insert(*key, ctx.ecdh_from_shares(&scan_key, &lambda_d)?);
    }
    if wanted.iter().any(|k| !out.contains_key(k)) {
        return Err(Error::Other("missing ECDH value".into()));
    }
    // Own scan key: ECDH symmetry.
    if outputs
        .iter()
        .any(|o| matches!(&o.dest, ApprovedDest::Sp { scan_key, .. } if *scan_key == own_pub))
    {
        out.insert(own_pub.serialize(), ctx.ecdh_self(own_scan)?);
    }
    Ok(out)
}

/// Output scripts for `outputs` (SP outputs derived, `k` counted per scan key in output order).
pub fn derive_scripts(
    outputs: &[ApprovedOutput],
    ecdh: &BTreeMap<[u8; 33], PublicKey>,
) -> Result<Vec<ScriptBuf>> {
    let mut k_of: BTreeMap<[u8; 33], u32> = BTreeMap::new();
    outputs
        .iter()
        .map(|o| match &o.dest {
            ApprovedDest::Script(s) => Ok(s.clone()),
            ApprovedDest::Sp {
                scan_key,
                spend_key,
            } => {
                let key = scan_key.serialize();
                let e = ecdh
                    .get(&key)
                    .ok_or_else(|| Error::Other("no ECDH value for scan key".into()))?;
                let k = k_of.entry(key).or_insert(0);
                // BIP 352: senders fail beyond K_max outputs per scan key (a receiver stops
                // scanning there, so the excess outputs would never be found).
                if *k >= crate::wallet::K_MAX {
                    return Err(Error::Other(format!(
                        "more than K_max = {} outputs for one scan key",
                        crate::wallet::K_MAX
                    )));
                }
                let s = sp_output_script(spend_key, e, *k)?;
                *k += 1;
                Ok(s)
            }
        })
        .collect()
}

pub(crate) fn check_tx_shape(tx: &Transaction) -> Result<()> {
    if tx.version != transaction::Version::TWO
        || tx.lock_time != absolute::LockTime::ZERO
        || tx
            .input
            .iter()
            .any(|i| i.sequence != Sequence::ENABLE_RBF_NO_LOCKTIME)
    {
        return Err(Error::Other(
            "unexpected version, locktime or sequence".into(),
        ));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// Messages
// ------------------------------------------------------------------------------------------

/// Round A: please release `D_i` for these (non-self) recipient scan keys.
pub struct EcdhRequest<'a> {
    pub inputs: &'a [InputSource],
    pub scan_keys: Vec<PublicKey>,
    pub signing_set: Vec<Identifier>,
}

/// Round B: everything a signer needs to verify and sign every input.
pub struct SendSignRequest<'a> {
    pub inputs: &'a [InputSource],
    pub tx: &'a Transaction,
    pub ecdh_shares: &'a [EcdhShare],
    /// One signing package per input, in input order.
    pub signing_packages: &'a [SigningPackage],
    /// Untrusted per-input tweak hints; compared with the derived `tau_j`, never used.
    pub coordinator_tau_hints: Option<Vec<[u8; 32]>>,
}

// ------------------------------------------------------------------------------------------
// Signer side
// ------------------------------------------------------------------------------------------

impl Signer {
    /// Round 1 for a send: one commitment per input (a nonce pair is never shared between
    /// inputs or sessions). Replaces and drops any earlier pending nonces.
    pub fn commit_inputs<R: RngCore + CryptoRng>(
        &mut self,
        n_inputs: usize,
        rng: &mut R,
    ) -> Vec<SigningCommitments> {
        self.send_nonces.clear();
        let mut commitments = Vec::with_capacity(n_inputs);
        for _ in 0..n_inputs {
            let (n, c) =
                frost_secp256k1_tr::round1::commit(self.key_package.signing_share(), rng);
            self.send_nonces.push(n);
            commitments.push(c);
        }
        commitments
    }

    fn own_scan_pub(&self) -> PublicKey {
        self.wallet.b_scan().public_key(&Secp256k1::new())
    }

    /// Checks shared by both rounds: coins, parity guard. Returns the resolved inputs.
    fn check_inputs(
        &self,
        srcs: &[InputSource],
        approved: &ApprovedSend,
    ) -> Result<Vec<ResolvedInput>> {
        // Authenticate the coins before scanning anything (Opus review F2).
        let ops: Vec<OutPoint> = srcs
            .iter()
            .map(|s| OutPoint {
                txid: s.funding_tx.compute_txid(),
                vout: s.funding_vout,
            })
            .collect();
        if ops != approved.inputs {
            return self.refuse("inputs differ from the approved coins");
        }
        let resolved = resolve_all(&self.wallet, srcs)
            .map_err(|e| self.refusal(e.to_string()))?;
        let ops: Vec<OutPoint> = resolved.iter().map(|r| r.outpoint).collect();
        if ops != approved.inputs {
            return self.refuse("inputs differ from the approved coins");
        }
        let gs: Vec<i8> = resolved.iter().map(|r| r.g).collect();
        if check_parity_guard(&gs).is_err() {
            return self.refuse("input set has sum of parities 0 (privacy guard)");
        }
        Ok(resolved)
    }

    /// Round A. Refuses unless every requested scan key is an approved non-self recipient, the
    /// input set passes the parity guard and the exposure limit allows the release.
    pub fn ecdh_shares<R: RngCore + CryptoRng>(
        &mut self,
        req: &EcdhRequest,
        approved: &ApprovedSend,
        rng: &mut R,
    ) -> Result<Vec<EcdhShare>> {
        self.check_inputs(req.inputs, approved)?;
        let own = self.own_scan_pub();
        let approved_keys: BTreeSet<[u8; 33]> = approved
            .outputs
            .iter()
            .filter_map(|o| match &o.dest {
                ApprovedDest::Sp { scan_key, .. } if *scan_key != own => {
                    Some(scan_key.serialize())
                }
                _ => None,
            })
            .collect();
        let mut keys = BTreeSet::new();
        for k in &req.scan_keys {
            let kb = k.serialize();
            if !approved_keys.contains(&kb) {
                return self.refuse("ECDH requested for a scan key that is not an approved recipient");
            }
            if !keys.insert(kb) {
                return self.refuse("duplicate scan key in ECDH request");
            }
        }
        let keys: Vec<[u8; 33]> = keys.into_iter().collect();
        if let Err(e) = self.exposure.check_release(&keys) {
            return self.refuse(e.to_string());
        }
        let shares = req
            .scan_keys
            .iter()
            .map(|k| make_ecdh_share(&self.key_package, k, rng))
            .collect::<Result<Vec<_>>>()?;
        self.exposure.record_release(&keys);
        Ok(shares)
    }

    /// Round B. Nonces are taken out of the signer first, so a refused session cannot reuse
    /// them. Aborted sessions cost nothing in the exposure counter (see `exposure.rs`).
    pub fn sign_send(
        &mut self,
        req: &SendSignRequest,
        approved: &ApprovedSend,
    ) -> Result<Vec<SignatureShare>> {
        let nonces = std::mem::take(&mut self.send_nonces);
        self.sign_send_inner(req, approved, nonces)
    }

    fn sign_send_inner(
        &self,
        req: &SendSignRequest,
        approved: &ApprovedSend,
        nonces: Vec<frost_secp256k1_tr::round1::SigningNonces>,
    ) -> Result<Vec<SignatureShare>> {
        let n = req.inputs.len();
        if nonces.len() != n {
            return self.refuse("no pending nonces for every input (commit first)");
        }
        let Some(pkp) = self.public_key_package.as_ref() else {
            return self.refuse("no public key package (needed to verify DLEQ proofs)");
        };
        if req.signing_packages.len() != n || req.tx.input.len() != n {
            return self.refuse("one signing package and one tx input per coin required");
        }

        // 1. Coins: re-derive tau_j (T7), parity, the approved coin set.
        let resolved = self.check_inputs(req.inputs, approved)?;
        if let Some(hints) = &req.coordinator_tau_hints {
            for (j, (h, r)) in hints.iter().zip(&resolved).enumerate() {
                if *h != r.tau {
                    return self.refuse(format!(
                        "coordinator supplied a tweak for input {j} that differs from the derived one"
                    ));
                }
            }
        }
        for (j, (txin, r)) in req.tx.input.iter().zip(&resolved).enumerate() {
            if txin.previous_output != r.outpoint {
                return self.refuse(format!("tx input {j} is not the approved coin"));
            }
        }
        if let Err(e) = check_tx_shape(req.tx) {
            return self.refuse(e.to_string());
        }

        // 2. Signing set: the same in every package, at least t signers, includes us.
        let set: Vec<Identifier> = req.signing_packages[0]
            .signing_commitments()
            .keys()
            .copied()
            .collect();
        for p in req.signing_packages {
            if p.signing_commitments().keys().copied().collect::<Vec<_>>() != set {
                return self.refuse("signing sets differ between inputs");
            }
        }
        if set.len() < usize::from(*self.key_package.min_signers())
            || !set.contains(self.key_package.identifier())
        {
            return self.refuse("signing set is too small or does not include this signer");
        }

        if let Err(e) = validate_public_key_package(pkp, &self.key_package, &set) {
            return self.refuse(e.to_string());
        }

        // 3. Outputs: DLEQ proofs, recompute every SP output, amounts, fee.
        let terms: Vec<InputTerm> = resolved.iter().map(ResolvedInput::term).collect();
        let ctx = SenderContext::new(&terms)?;
        let ecdh = ecdh_for_outputs(
            &ctx,
            &approved.outputs,
            req.ecdh_shares,
            &set,
            pkp,
            self.wallet.b_scan(),
        )
        .map_err(|e| self.refusal(e.to_string()))?;
        let scripts = derive_scripts(&approved.outputs, &ecdh)?;
        if req.tx.output.len() != approved.outputs.len() {
            return self.refuse("number of outputs differs from the approved outputs");
        }
        for (i, ((txo, want), script)) in req
            .tx
            .output
            .iter()
            .zip(&approved.outputs)
            .zip(&scripts)
            .enumerate()
        {
            if txo.script_pubkey != *script {
                return self.refuse(format!(
                    "output {i} script differs from the recomputed/approved one"
                ));
            }
            if txo.value != want.amount {
                return self.refuse(format!("output {i} amount differs from the approved one"));
            }
        }
        let sum = |vals: Vec<u64>| {
            vals.into_iter().try_fold(0u64, |a, v| a.checked_add(v)).filter(|s| *s <= MAX_MONEY_SATS)
        };
        let (Some(in_sum), Some(out_sum)) = (
            sum(resolved.iter().map(|r| r.txout.value.to_sat()).collect()),
            sum(req.tx.output.iter().map(|o| o.value.to_sat()).collect()),
        ) else {
            return self.refuse("amounts are outside the monetary range");
        };
        match in_sum.checked_sub(out_sum) {
            Some(fee) if fee <= approved.max_fee.to_sat() => {}
            _ => return self.refuse("fee exceeds the approved maximum"),
        }

        // 4. Each FROST message is that input's sighash.
        let prevouts: Vec<TxOut> = resolved.iter().map(|r| r.txout.clone()).collect();
        let sighashes = key_path_sighashes(req.tx, &prevouts)?;
        for (j, (sh, p)) in sighashes.iter().zip(req.signing_packages).enumerate() {
            if p.message() != sh.as_slice() {
                return self.refuse(format!(
                    "FROST message of input {j} is not the sighash of the verified transaction"
                ));
            }
        }

        // 5. Sign every input under its own tweak.
        let mut shares = Vec::with_capacity(n);
        for j in 0..n {
            let kp = tweak_key_package(&self.key_package, &resolved[j].tau)?;
            shares.push(round2::sign(&req.signing_packages[j], &nonces[j], &kp)?);
        }
        Ok(shares)
    }
}

// ------------------------------------------------------------------------------------------
// Coordinator side
// ------------------------------------------------------------------------------------------

pub struct SendCoordinator {
    public_key_package: PublicKeyPackage,
    wallet: SpWallet,
}

impl SendCoordinator {
    /// `wallet` must carry the group's `b_scan` (every cosigner holds it).
    pub fn new(public_key_package: PublicKeyPackage, wallet: SpWallet) -> Self {
        Self {
            public_key_package,
            wallet,
        }
    }

    pub fn wallet(&self) -> &SpWallet {
        &self.wallet
    }

    pub fn resolve(&self, srcs: &[InputSource]) -> Result<Vec<ResolvedInput>> {
        resolve_all(&self.wallet, srcs)
    }

    /// Distinct non-self recipient scan keys of `outputs`.
    pub fn ecdh_request<'a>(
        &self,
        inputs: &'a [InputSource],
        outputs: &[ApprovedOutput],
        signing_set: Vec<Identifier>,
    ) -> EcdhRequest<'a> {
        let own = self.wallet.b_scan().public_key(&Secp256k1::new());
        let mut scan_keys: Vec<PublicKey> = vec![];
        for o in outputs {
            if let ApprovedDest::Sp { scan_key, .. } = &o.dest {
                if *scan_key != own && !scan_keys.contains(scan_key) {
                    scan_keys.push(*scan_key);
                }
            }
        }
        EcdhRequest {
            inputs,
            scan_keys,
            signing_set,
        }
    }

    /// Verify the shares (naming the culprit), derive the SP outputs and build the unsigned tx.
    pub fn build_tx(
        &self,
        inputs: &[InputSource],
        outputs: &[ApprovedOutput],
        shares: &[EcdhShare],
        signing_set: &[Identifier],
    ) -> Result<Transaction> {
        let resolved = self.resolve(inputs)?;
        check_parity_guard(&resolved.iter().map(|r| r.g).collect::<Vec<_>>())?;
        let terms: Vec<InputTerm> = resolved.iter().map(ResolvedInput::term).collect();
        let ctx = SenderContext::new(&terms)?;
        let ecdh = ecdh_for_outputs(
            &ctx,
            outputs,
            shares,
            signing_set,
            &self.public_key_package,
            self.wallet.b_scan(),
        )?;
        let scripts = derive_scripts(outputs, &ecdh)?;
        Ok(Transaction {
            version: transaction::Version::TWO,
            // Privacy fingerprint (review F4, accepted for the PoC): locktime is always 0.
            lock_time: absolute::LockTime::ZERO,
            input: resolved
                .iter()
                .map(|r| TxIn {
                    previous_output: r.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .iter()
                .zip(scripts)
                .map(|(o, script_pubkey)| TxOut {
                    value: o.amount,
                    script_pubkey,
                })
                .collect(),
        })
    }

    /// One signing package per input; the message is that input's sighash.
    /// `commitments[id][j]` is signer `id`'s commitment for input `j`.
    pub fn signing_packages(
        &self,
        tx: &Transaction,
        inputs: &[InputSource],
        commitments: &BTreeMap<Identifier, Vec<SigningCommitments>>,
    ) -> Result<Vec<SigningPackage>> {
        let resolved = self.resolve(inputs)?;
        let prevouts: Vec<TxOut> = resolved.iter().map(|r| r.txout.clone()).collect();
        let sighashes = key_path_sighashes(tx, &prevouts)?;
        sighashes
            .iter()
            .enumerate()
            .map(|(j, sh)| {
                let c = commitments
                    .iter()
                    .map(|(id, v)| {
                        v.get(j)
                            .cloned()
                            .map(|c| (*id, c))
                            .ok_or_else(|| Error::Other("missing commitment".into()))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                Ok(SigningPackage::new(c, sh))
            })
            .collect()
    }

    /// Aggregate each input under `X + tau_j*G`, verify as BIP 340, attach the witnesses and
    /// consensus-verify the whole transaction.
    pub fn finalize(
        &self,
        tx: &Transaction,
        inputs: &[InputSource],
        packages: &[SigningPackage],
        shares: &BTreeMap<Identifier, Vec<SignatureShare>>,
    ) -> Result<Transaction> {
        let resolved = self.resolve(inputs)?;
        let prevouts: Vec<TxOut> = resolved.iter().map(|r| r.txout.clone()).collect();
        let sighashes = key_path_sighashes(tx, &prevouts)?;
        if packages.len() != tx.input.len() || resolved.len() != tx.input.len() {
            return Err(Error::Other("package/input count mismatch".into()));
        }
        let mut signed = tx.clone();
        for (j, r) in resolved.iter().enumerate() {
            if tx.input[j].previous_output != r.outpoint {
                return Err(Error::Other("tx does not consume the given coins".into()));
            }
            if packages[j].message() != sighashes[j].as_slice() {
                return Err(Error::Other(format!(
                    "package {j} does not match the sighash of the transaction"
                )));
            }
            let per: BTreeMap<Identifier, SignatureShare> = shares
                .iter()
                .map(|(id, v)| {
                    v.get(j)
                        .cloned()
                        .map(|s| (*id, s))
                        .ok_or_else(|| Error::Other("missing signature share".into()))
                })
                .collect::<Result<_>>()?;
            let pkp = tweak_public_key_package(&self.public_key_package, &r.tau)?;
            let sig = frost_secp256k1_tr::aggregate(&packages[j], &per, &pkp)?;
            let sig = schnorr::Signature::from_slice(&sig.serialize()?)?;
            let xonly = XOnlyPublicKey::from_slice(&r.txout.script_pubkey.as_bytes()[2..])?;
            let msg = Message::from_digest_slice(packages[j].message())?;
            Secp256k1::verification_only().verify_schnorr(&sig, &msg, &xonly)?;
            let mut w = Witness::new();
            w.push(sig.as_ref());
            signed.input[j].witness = w;
        }
        verify_consensus_all(&signed, &prevouts)?;
        Ok(signed)
    }
}

/// libbitcoinconsensus (Core 26, taproot on) for every input of `tx`, with all spent outputs.
pub fn verify_consensus_all(tx: &Transaction, prevouts: &[TxOut]) -> Result<()> {
    let utxos: Vec<bitcoinconsensus::Utxo> = prevouts
        .iter()
        .map(|p| bitcoinconsensus::Utxo {
            script_pubkey: p.script_pubkey.as_bytes().as_ptr(),
            script_pubkey_len: p.script_pubkey.len() as u32,
            value: p.value.to_sat() as i64,
        })
        .collect();
    let raw = bitcoin::consensus::serialize(tx);
    for (j, p) in prevouts.iter().enumerate() {
        bitcoinconsensus::verify(
            p.script_pubkey.as_bytes(),
            p.value.to_sat(),
            &raw,
            Some(&utxos),
            j,
        )
        .map_err(|e| Error::Other(format!("consensus verification of input {j} failed: {e:?}")))?;
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// Library entry point: coins + destinations + fee rate -> signed transaction
// ------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum PaymentDest {
    Sp(SilentPaymentCode),
    Script(ScriptBuf),
}

#[derive(Clone, Debug)]
pub struct Payment {
    pub dest: PaymentDest,
    pub amount: Amount,
}

/// A coin the wallet owns, with the data signers need to re-derive its tweak.
#[derive(Clone, Debug)]
pub struct SpendableCoin {
    pub source: InputSource,
    pub value: Amount,
}

/// Outputs below this go to fees instead of change.
pub const DUST_CHANGE_SATS: u64 = 330;

fn script_len_of(dest: &PaymentDest) -> usize {
    match dest {
        PaymentDest::Sp(_) => 34,
        PaymentDest::Script(s) => s.len(),
    }
}

fn varint_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        _ => 5,
    }
}

/// vsize of a transaction with `n_in` key-path P2TR inputs (64-byte signature witness) and
/// outputs with the given script lengths, using the real CompactSize lengths.
fn est_vsize(n_in: usize, script_lens: &[usize]) -> u64 {
    let outs: usize = script_lens.iter().map(|l| 8 + varint_len(*l) + l).sum();
    let non_witness = 4 + varint_len(n_in) + n_in * 41 + varint_len(script_lens.len()) + outs + 4;
    let witness = 2 + n_in * 66; // marker+flag, then (item count + length + 64) per input
    (non_witness * 4 + witness).div_ceil(4) as u64
}

/// Result of coin selection: what the signers are asked to approve.
#[derive(Clone, Debug)]
pub struct SendPlan {
    pub coins: Vec<SpendableCoin>,
    pub approved: ApprovedSend,
    pub fee: Amount,
}

/// Pick coins (largest first) that cover the payments and the fee, never an input set with
/// `sum g = 0`, and add change to the wallet's own change address when it is not dust.
pub fn plan_send(
    wallet: &SpWallet,
    candidates: &[SpendableCoin],
    payments: &[Payment],
    fee_rate_sat_vb: u64,
) -> Result<SendPlan> {
    let target: u64 = payments.iter().map(|p| p.amount.to_sat()).sum();
    let mut sorted: Vec<(SpendableCoin, i8)> = candidates
        .iter()
        .map(|c| Ok((c.clone(), resolve_input(wallet, &c.source)?.g)))
        .collect::<Result<_>>()?;
    sorted.sort_by_key(|(c, _)| std::cmp::Reverse(c.value));

    let lens: Vec<usize> = payments.iter().map(|p| script_len_of(&p.dest)).collect();
    let mut picked: Vec<(SpendableCoin, i8)> = vec![];
    for cand in sorted {
        picked.push(cand);
        let sum_g: i64 = picked.iter().map(|(_, g)| i64::from(*g)).sum();
        let have: u64 = picked.iter().map(|(c, _)| c.value.to_sat()).sum();
        let fee_with_change = {
            let mut l = lens.clone();
            l.push(34);
            fee_rate_sat_vb * est_vsize(picked.len(), &l)
        };
        let fee_no_change = fee_rate_sat_vb * est_vsize(picked.len(), &lens);
        if sum_g != 0 && have >= target + fee_no_change {
            // Change only if it pays for itself and is not dust; otherwise the rest is fee.
            let change = have.saturating_sub(target + fee_with_change);
            let mut outputs: Vec<ApprovedOutput> = payments
                .iter()
                .map(|p| ApprovedOutput {
                    dest: match &p.dest {
                        PaymentDest::Sp(c) => ApprovedDest::sp(c),
                        PaymentDest::Script(s) => ApprovedDest::Script(s.clone()),
                    },
                    amount: p.amount,
                })
                .collect();
            let fee = if change >= DUST_CHANGE_SATS {
                // Privacy fingerprint (review F4, accepted for the PoC): change is always last.
                outputs.push(ApprovedOutput {
                    dest: ApprovedDest::sp(&wallet.change_address()),
                    amount: Amount::from_sat(change),
                });
                fee_with_change
            } else {
                have - target
            };
            return Ok(SendPlan {
                approved: ApprovedSend {
                    inputs: picked
                        .iter()
                        .map(|(c, _)| resolve_input(wallet, &c.source).map(|r| r.outpoint))
                        .collect::<Result<_>>()?,
                    outputs,
                    max_fee: Amount::from_sat(fee),
                },
                coins: picked.into_iter().map(|(c, _)| c).collect(),
                fee: Amount::from_sat(fee),
            });
        }
    }
    Err(Error::Other(
        "insufficient funds, or no input set with a non-zero sum of parities".into(),
    ))
}

/// "Spend exactly these coins": every given coin is an input, in the given order, `payments`
/// are paid in order and `change` (when given and not dust) is the last output.
///
/// Refuses when the coins' parities sum to 0 (see [`check_parity_guard`]), when they do not
/// cover payments plus fee, and, with no `change` destination, when the leftover would burn
/// more than `MAX_BURN_FACTOR` times the estimated fee. This is the planner behind the
/// external-signer interface, whose caller chooses the inputs.
pub fn plan_spend_exact(
    wallet: &SpWallet,
    coins: &[SpendableCoin],
    payments: &[Payment],
    change: Option<&PaymentDest>,
    fee_rate_sat_vb: u64,
) -> Result<SendPlan> {
    if coins.is_empty() {
        return Err(Error::Other("no coins to spend".into()));
    }
    let resolved = coins
        .iter()
        .map(|c| resolve_input(wallet, &c.source))
        .collect::<Result<Vec<_>>>()?;
    let uniq: BTreeSet<_> = resolved.iter().map(|r| r.outpoint).collect();
    if uniq.len() != resolved.len() {
        return Err(Error::Other("duplicate input".into()));
    }
    for (c, r) in coins.iter().zip(&resolved) {
        if r.txout.value != c.value {
            return Err(Error::Other(format!(
                "coin {} is worth {} per its funding transaction, not {}",
                r.outpoint, r.txout.value, c.value
            )));
        }
    }
    check_parity_guard(&resolved.iter().map(|r| r.g).collect::<Vec<_>>())?;

    // Monetary validation before anything is signed: positive amounts inside the monetary
    // range, and every sum and product checked (a wrapped sum would sign a negative output).
    let money = |sum: Option<u64>, what: &str| -> Result<u64> {
        sum.filter(|v| *v <= MAX_MONEY_SATS)
            .ok_or_else(|| Error::Other(format!("{what} is outside the monetary range")))
    };
    if payments.iter().any(|p| p.amount.to_sat() == 0) {
        return Err(Error::Other("a payment of 0 sats".into()));
    }
    let have = money(
        coins.iter().try_fold(0u64, |a, c| a.checked_add(c.value.to_sat())),
        "the coins' value",
    )?;
    let target = money(
        payments.iter().try_fold(0u64, |a, p| a.checked_add(p.amount.to_sat())),
        "the payments' sum",
    )?;
    let fee_for = |n_out_lens: &[usize]| -> Result<u64> {
        fee_rate_sat_vb
            .checked_mul(est_vsize(coins.len(), n_out_lens))
            .filter(|f| *f <= MAX_MONEY_SATS)
            .ok_or_else(|| Error::Other("fee rate is outside any sane range".into()))
    };
    let mut lens: Vec<usize> = payments.iter().map(|p| script_len_of(&p.dest)).collect();
    let fee_no_change = fee_for(&lens)?;
    if have < target.saturating_add(fee_no_change) {
        return Err(Error::Other(format!(
            "insufficient funds: coins hold {have} sats, payments {target} plus fee {fee_no_change}"
        )));
    }
    let mut outputs: Vec<ApprovedOutput> = payments
        .iter()
        .map(|p| ApprovedOutput {
            dest: match &p.dest {
                PaymentDest::Sp(c) => ApprovedDest::sp(c),
                PaymentDest::Script(s) => ApprovedDest::Script(s.clone()),
            },
            amount: p.amount,
        })
        .collect();
    let mut fee = have - target;
    if let Some(change) = change {
        lens.push(script_len_of(change));
        let fee_with_change = fee_for(&lens)?;
        let amount = have.saturating_sub(target.saturating_add(fee_with_change));
        if amount >= dust_threshold(change) {
            outputs.push(ApprovedOutput {
                dest: match change {
                    PaymentDest::Sp(c) => ApprovedDest::sp(c),
                    PaymentDest::Script(s) => ApprovedDest::Script(s.clone()),
                },
                amount: Amount::from_sat(amount),
            });
            fee = fee_with_change;
        }
    }
    if fee > fee_no_change.max(1).saturating_mul(MAX_BURN_FACTOR) {
        return Err(Error::Other(format!(
            "the leftover {fee} sats would all go to fees (about {fee_no_change} needed); declare a change address"
        )));
    }
    Ok(SendPlan {
        approved: ApprovedSend {
            inputs: resolved.iter().map(|r| r.outpoint).collect(),
            outputs,
            max_fee: Amount::from_sat(fee),
        },
        coins: coins.to_vec(),
        fee: Amount::from_sat(fee),
    })
}

/// 21 million BTC in sats.
pub const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

/// Smallest change output worth creating for this destination: the relay dust threshold of
/// its script (an SP output is P2TR).
fn dust_threshold(dest: &PaymentDest) -> u64 {
    match dest {
        PaymentDest::Sp(_) => DUST_CHANGE_SATS,
        PaymentDest::Script(s) => s.minimal_non_dust().to_sat(),
    }
}

/// A plan without change may leave at most this many times the estimated fee unspent.
pub const MAX_BURN_FACTOR: u64 = 10;

/// Run both rounds in process: `signers` are the cosigners, `signing_set` the ones used.
pub fn execute_send<R: RngCore + CryptoRng>(
    coordinator: &SendCoordinator,
    signers: &mut [Signer],
    signing_set: &[Identifier],
    plan: &SendPlan,
    rng: &mut R,
) -> Result<Transaction> {
    let inputs: Vec<InputSource> = plan.coins.iter().map(|c| c.source.clone()).collect();
    let req = coordinator.ecdh_request(&inputs, &plan.approved.outputs, signing_set.to_vec());

    let mut shares = vec![];
    let mut commitments = BTreeMap::new();
    for s in signers.iter_mut().filter(|s| signing_set.contains(&s.identifier())) {
        shares.extend(s.ecdh_shares(&req, &plan.approved, rng)?);
        commitments.insert(s.identifier(), s.commit_inputs(inputs.len(), rng));
    }
    let tx = coordinator.build_tx(&inputs, &plan.approved.outputs, &shares, signing_set)?;
    let packages = coordinator.signing_packages(&tx, &inputs, &commitments)?;
    let sign_req = SendSignRequest {
        inputs: &inputs,
        tx: &tx,
        ecdh_shares: &shares,
        signing_packages: &packages,
        coordinator_tau_hints: None,
    };
    let mut sig_shares = BTreeMap::new();
    for s in signers.iter_mut().filter(|s| signing_set.contains(&s.identifier())) {
        sig_shares.insert(s.identifier(), s.sign_send(&sign_req, &plan.approved)?);
    }
    coordinator.finalize(&tx, &inputs, &packages, &sig_shares)
}

/// W4 entry point: owned coins, destinations and a fee rate in; a signed, consensus-verified
/// transaction out. The caller supplies the cosigners (in process) and the signing set.
pub fn send_payment<R: RngCore + CryptoRng>(
    coordinator: &SendCoordinator,
    signers: &mut [Signer],
    signing_set: &[Identifier],
    coins: &[SpendableCoin],
    payments: &[Payment],
    fee_rate_sat_vb: u64,
    rng: &mut R,
) -> Result<(Transaction, SendPlan)> {
    let plan = plan_send(coordinator.wallet(), coins, payments, fee_rate_sat_vb)?;
    let tx = execute_send(coordinator, signers, signing_set, &plan, rng)?;
    Ok((tx, plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_hash_zero_is_rejected() {
        assert!(nonzero_input_hash(Scalar::ZERO).is_err());
        assert!(nonzero_input_hash(Scalar::ONE).is_ok());
    }
}
