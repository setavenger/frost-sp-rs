//! Signing under a *plain* tweaked key, with no BIP 341 taproot tweak.
//!
//! `frost-secp256k1-tr` only applies the taproot tweak in `sign_with_tweak` /
//! `aggregate_with_tweak`. The plain `round2::sign` / `aggregate` do not, and they negate for
//! even Y after whatever key material they are given. So adding `tau` to every signing share
//! and `tau*G` to every verification share and the group key is enough: Lagrange weights sum
//! to 1, hence `sum(l_i * (s_i + tau)) = x + tau`. The secret `x + tau` is never formed.

use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare};
use frost_secp256k1_tr::VerifyingKey;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};

use crate::{Error, Result};

/// Convert a big-endian scalar into a k256 scalar, rejecting values >= the group order.
pub fn scalar_from_be(bytes: &[u8; 32]) -> Result<Scalar> {
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
        .ok_or(Error::Scalar("scalar out of range"))
}

/// Add `tau` to a signer's key package (shares and group key).
pub fn tweak_key_package(kp: &KeyPackage, tau: &[u8; 32]) -> Result<KeyPackage> {
    let t = scalar_from_be(tau)?;
    let tg = ProjectivePoint::GENERATOR * t;
    Ok(KeyPackage::new(
        *kp.identifier(),
        SigningShare::new(kp.signing_share().to_scalar() + t),
        VerifyingShare::new(kp.verifying_share().to_element() + tg),
        VerifyingKey::new(kp.verifying_key().to_element() + tg),
        *kp.min_signers(),
    ))
}

/// Add `tau*G` to every verification share and to the group key.
pub fn tweak_public_key_package(
    pkp: &PublicKeyPackage,
    tau: &[u8; 32],
) -> Result<PublicKeyPackage> {
    let t = scalar_from_be(tau)?;
    let tg = ProjectivePoint::GENERATOR * t;
    let shares = pkp
        .verifying_shares()
        .iter()
        .map(|(id, vs)| (*id, VerifyingShare::new(vs.to_element() + tg)))
        .collect();
    Ok(PublicKeyPackage::new(
        shares,
        VerifyingKey::new(pkp.verifying_key().to_element() + tg),
        pkp.min_signers(),
    ))
}
