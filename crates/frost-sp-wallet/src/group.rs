//! Group setup. **Trusted dealer: PoC only.** A deployment needs DKG or an authenticated
//! provisioning ceremony; here the dealer sees the group secret and `b_scan`.

use std::collections::BTreeMap;

use frost_secp256k1_tr::keys::{self, IdentifierList, KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::{Identifier, SigningKey};
use rand::{CryptoRng, RngCore};
use secp256k1::SecretKey;

use crate::{Error, Result};

/// Everything the dealer hands out. `key_packages[i]` goes to signer `i` only.
pub struct FrostGroup {
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub public_key_package: PublicKeyPackage,
    /// Scan key held by every cosigner.
    pub b_scan: SecretKey,
    pub min_signers: u16,
    pub max_signers: u16,
}

impl FrostGroup {
    /// Fresh random group secret `x`.
    pub fn trusted_dealer<R: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        b_scan: SecretKey,
        rng: &mut R,
    ) -> Result<Self> {
        let (shares, pkp) = keys::generate_with_dealer(
            max_signers,
            min_signers,
            IdentifierList::Default,
            &mut *rng,
        )?;
        Self::from_shares(shares, pkp, b_scan, min_signers, max_signers)
    }

    /// Split an existing secret (e.g. a BIP 352 vector's `b_spend`) into shares.
    pub fn from_secret<R: RngCore + CryptoRng>(
        b_spend: &SecretKey,
        max_signers: u16,
        min_signers: u16,
        b_scan: SecretKey,
        rng: &mut R,
    ) -> Result<Self> {
        let signing_key = SigningKey::deserialize(&b_spend.secret_bytes())
            .map_err(|_| Error::Scalar("b_spend rejected by frost"))?;
        let (shares, pkp) = keys::split(
            &signing_key,
            max_signers,
            min_signers,
            IdentifierList::Default,
            rng,
        )?;
        Self::from_shares(shares, pkp, b_scan, min_signers, max_signers)
    }

    fn from_shares(
        shares: BTreeMap<Identifier, keys::SecretShare>,
        public_key_package: PublicKeyPackage,
        b_scan: SecretKey,
        min_signers: u16,
        max_signers: u16,
    ) -> Result<Self> {
        let mut key_packages = BTreeMap::new();
        for (id, share) in shares {
            key_packages.insert(id, KeyPackage::try_from(share)?);
        }
        Ok(Self {
            key_packages,
            public_key_package,
            b_scan,
            min_signers,
            max_signers,
        })
    }

    /// `B_spend`: the 33-byte compressed group key `X`.
    pub fn b_spend(&self) -> Result<secp256k1::PublicKey> {
        let bytes = self.public_key_package.verifying_key().serialize()?;
        Ok(secp256k1::PublicKey::from_slice(&bytes)?)
    }
}

/// Test helper: reconstruct `x` by Lagrange interpolation. **Tests only.**
#[cfg(test)]
pub fn reconstruct_for_tests(g: &FrostGroup, ids: &[Identifier]) -> Result<SecretKey> {
    let kps: Vec<KeyPackage> = ids.iter().map(|i| g.key_packages[i].clone()).collect();
    let sk = keys::reconstruct(&kps)?;
    Ok(SecretKey::from_slice(&sk.serialize())?)
}
