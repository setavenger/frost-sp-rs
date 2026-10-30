//! A device's result: its one signing share, the group's public data, `b_scan`, its host key
//! and the certificate binding them to the ceremony. [`DeviceKey::verify`] re-checks all of it
//! from the stored data, so a loaded file is as trustworthy as the ceremony that produced it.

use std::collections::BTreeMap;

use frost_secp256k1_tr::keys::dkg::round1;
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage, Tweak};
use frost_secp256k1_tr::Identifier;
use k256::ProjectivePoint;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::{Network, SilentPaymentCode, SpVersion};

use super::wire::verify_host;
use super::{check_code, frost_err, identifier, transcript_hash, DkgError, Params};
use crate::send::validate_public_key_package;

/// Proof that all `n` devices finished one ceremony with the same transcript `T`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// The coordinator's 32 random bytes; with the participant list they give the session id.
    pub session_nonce: [u8; 32],
    pub session_id: [u8; 32],
    /// Every participant's serialized round-1 package (commitments and proof of knowledge).
    pub round1_packages: BTreeMap<u16, Vec<u8>>,
    /// `T`.
    pub transcript_hash: [u8; 32],
    /// BIP 340 signature on `T` by each participant's host key.
    pub signatures: BTreeMap<u16, [u8; 64]>,
}

/// One device's key material after a certified ceremony. Holds exactly one signing share.
#[derive(Clone)]
pub struct DeviceKey {
    identifier: u16,
    params: Params,
    host_secret: SecretKey,
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
    b_scan: SecretKey,
    certificate: Certificate,
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey")
            .field("identifier", &self.identifier)
            .field("params", &self.params)
            .field("check_code", &self.check_code())
            .finish_non_exhaustive()
    }
}

impl DeviceKey {
    /// Assemble from stored parts. Fails unless [`DeviceKey::verify`] passes.
    pub fn from_parts(
        identifier: u16,
        params: Params,
        host_secret: SecretKey,
        key_package: KeyPackage,
        public_key_package: PublicKeyPackage,
        b_scan: SecretKey,
        certificate: Certificate,
    ) -> Result<Self, DkgError> {
        let k = Self {
            identifier,
            params,
            host_secret,
            key_package,
            public_key_package,
            b_scan,
            certificate,
        };
        k.verify()?;
        Ok(k)
    }

    /// Everything a device checks before it accepts, recomputed from the stored data:
    /// host key and identifier, session id, the public key package from the round-1
    /// commitments, the key material, `T`, and valid signatures on `T` from all `n` hosts.
    pub fn verify(&self) -> Result<(), DkgError> {
        let secp = Secp256k1::new();
        let p = &self.params;
        let cert = &self.certificate;
        if p.host(self.identifier) != Some(&self.host_secret.public_key(&secp)) {
            return Err(DkgError::KeyCheck(format!(
                "host secret is not participant {}'s host key",
                self.identifier
            )));
        }
        if p.session_id(&cert.session_nonce) != cert.session_id {
            return Err(DkgError::Certificate(
                "session id does not match the participant list".into(),
            ));
        }
        let derived = public_key_package_from_round1(p, &cert.round1_packages)?;
        if derived.serialize().map_err(frost_err)?
            != self.public_key_package.serialize().map_err(frost_err)?
        {
            return Err(DkgError::Certificate(
                "public key package does not follow from the round-1 commitments".into(),
            ));
        }
        check_key_material(p, self.identifier, &self.key_package, &self.public_key_package)?;
        let t = transcript_hash(
            &cert.session_id,
            &cert.round1_packages,
            p.t(),
            &self.public_key_package,
            &self.b_scan.public_key(&secp),
        )?;
        if t != cert.transcript_hash {
            return Err(DkgError::Certificate("transcript hash does not match".into()));
        }
        check_signatures(p, &t, &cert.signatures)
    }

    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    /// For persistence only.
    pub fn host_secret(&self) -> &SecretKey {
        &self.host_secret
    }

    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }

    pub fn b_scan(&self) -> &SecretKey {
        &self.b_scan
    }

    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// `B_spend = X`.
    pub fn b_spend(&self) -> Result<PublicKey, DkgError> {
        let x = self
            .public_key_package
            .verifying_key()
            .serialize()
            .map_err(frost_err)?;
        PublicKey::from_slice(&x).map_err(|e| DkgError::KeyCheck(e.to_string()))
    }

    /// The code each device shows for the user to compare.
    pub fn check_code(&self) -> String {
        check_code(&self.certificate.transcript_hash)
    }

    /// The group's base Silent Payment address `(B_scan, B_spend)`.
    pub fn sp_address(&self, network: Network) -> crate::Result<SilentPaymentCode> {
        let secp = Secp256k1::new();
        let receiver = Receiver::new(
            SpVersion::ZERO,
            self.b_scan.public_key(&secp),
            self.b_spend()?,
            Label::new(self.b_scan, 0),
            network,
        )?;
        Ok(receiver.receiving_code())
    }
}

/// The public key package that ZF's `part3` derives from the round-1 commitments of
/// participants `1..=n` (including its BIP 341 `post_dkg` tweak).
pub(crate) fn public_key_package_from_round1(
    params: &Params,
    packages: &BTreeMap<u16, Vec<u8>>,
) -> Result<PublicKeyPackage, DkgError> {
    if !packages.keys().copied().eq(params.ids()) {
        return Err(DkgError::Certificate(
            "round-1 packages are not exactly participants 1..=n".into(),
        ));
    }
    let mut parsed = BTreeMap::new();
    for (id, bytes) in packages {
        let pkg = round1::Package::deserialize(bytes).map_err(|e| DkgError::Malformed {
            sender: Some(*id),
            reason: format!("round-1 package: {e}"),
        })?;
        parsed.insert(identifier(*id)?, pkg);
    }
    let commitments: BTreeMap<Identifier, _> =
        parsed.iter().map(|(id, p)| (*id, p.commitment())).collect();
    Ok(PublicKeyPackage::from_dkg_commitments(&commitments)
        .map_err(frost_err)?
        .tweak::<&[u8]>(None))
}

/// The device's own key material is sound:
/// * its key package is participant `me`'s, threshold `t`, group key `X` of the package;
/// * the package lists exactly `X_1..X_n`, and `X_me == x_me·G` for the device's own share;
/// * all `X_i` lie on one polynomial of degree `t − 1` through `(0, X)`: every set
///   `{1..t−1} ∪ {j}` interpolates to `X` (`n − t + 1` checks).
pub(crate) fn check_key_material(
    params: &Params,
    me: u16,
    kp: &KeyPackage,
    pkp: &PublicKeyPackage,
) -> Result<(), DkgError> {
    let bad = |m: String| Err(DkgError::KeyCheck(m));
    if *kp.identifier() != identifier(me)? {
        return bad(format!("key package is not participant {me}'s"));
    }
    if *kp.min_signers() != params.t() || pkp.min_signers() != Some(params.t()) {
        return bad("threshold differs from t".into());
    }
    let ids: Vec<Identifier> = params.ids().map(identifier).collect::<Result<_, _>>()?;
    if !pkp.verifying_shares().keys().eq(ids.iter()) {
        return bad("public key package does not list exactly participants 1..=n".into());
    }
    if kp.verifying_key() != pkp.verifying_key() {
        return bad("group key differs between key package and public key package".into());
    }
    let x_i_g = ProjectivePoint::GENERATOR * kp.signing_share().to_scalar();
    if x_i_g != kp.verifying_share().to_element()
        || Some(kp.verifying_share()) != pkp.verifying_shares().get(kp.identifier())
    {
        return bad("own X_i is not x_i·G".into());
    }
    let t = usize::from(params.t());
    for j in &ids[t - 1..] {
        let mut set = ids[..t - 1].to_vec();
        set.push(*j);
        validate_public_key_package(pkp, kp, &set)
            .map_err(|e| DkgError::KeyCheck(e.to_string()))?;
    }
    Ok(())
}

/// Valid BIP 340 signatures on `T` from exactly participants `1..=n`.
pub(crate) fn check_signatures(
    params: &Params,
    transcript: &[u8; 32],
    signatures: &BTreeMap<u16, [u8; 64]>,
) -> Result<(), DkgError> {
    let missing: Vec<u16> = params.ids().filter(|i| !signatures.contains_key(i)).collect();
    if !missing.is_empty() {
        return Err(DkgError::Certificate(format!("no signature from {missing:?}")));
    }
    let msg = Message::from_digest(*transcript);
    for (id, sig) in signatures {
        let host = params
            .host(*id)
            .ok_or_else(|| DkgError::Certificate(format!("signature from unknown participant {id}")))?;
        if !verify_host(host, &msg, sig) {
            return Err(DkgError::Certificate(format!(
                "participant {id}'s signature does not verify on this transcript"
            )));
        }
    }
    Ok(())
}
