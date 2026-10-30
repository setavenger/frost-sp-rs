//! A whole group's key material in one place. **Tests only.**
//!
//! Real groups come from the distributed key generation in [`crate::dkg`]: each device ends with
//! one [`crate::dkg::DeviceKey`] and nobody sees `x`. This struct gathers every key package so
//! tests can drive all cosigners in one process. The trusted-dealer constructors exist only
//! behind the `test-dealer` feature (or `cfg(test)`), for the BIP 352 vector tests: the vectors
//! fix `b_spend`, which a DKG cannot produce.

use std::collections::BTreeMap;

use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::Identifier;
use secp256k1::SecretKey;

use crate::Result;

/// Every key package of a group. `key_packages[i]` belongs to signer `i` only.
pub struct FrostGroup {
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub public_key_package: PublicKeyPackage,
    /// Scan key held by every cosigner.
    pub b_scan: SecretKey,
    pub min_signers: u16,
    pub max_signers: u16,
}

impl FrostGroup {
    /// Gather the devices of one DKG run (tests drive every cosigner in one process).
    pub fn from_device_keys(keys: &[crate::dkg::DeviceKey]) -> Result<Self> {
        let first = keys
            .first()
            .ok_or_else(|| crate::Error::Other("no device keys".into()))?;
        let mut key_packages = BTreeMap::new();
        for k in keys {
            if k.certificate() != first.certificate() {
                return Err(crate::Error::Other("device keys from different ceremonies".into()));
            }
            key_packages.insert(*k.key_package().identifier(), k.key_package().clone());
        }
        Ok(Self {
            key_packages,
            public_key_package: first.public_key_package().clone(),
            b_scan: *first.b_scan(),
            min_signers: first.params().t(),
            max_signers: first.params().n(),
        })
    }

    /// `B_spend`: the 33-byte compressed group key `X`.
    pub fn b_spend(&self) -> Result<secp256k1::PublicKey> {
        let bytes = self.public_key_package.verifying_key().serialize()?;
        Ok(secp256k1::PublicKey::from_slice(&bytes)?)
    }
}

#[cfg(any(test, feature = "test-dealer"))]
mod dealer {
    use std::collections::BTreeMap;

    use frost_secp256k1_tr::keys::{self, IdentifierList, KeyPackage, PublicKeyPackage};
    use frost_secp256k1_tr::{Identifier, SigningKey};
    use rand::{CryptoRng, RngCore};
    use secp256k1::SecretKey;

    use super::FrostGroup;
    use crate::{Error, Result};

    impl FrostGroup {
        /// **Test-only trusted dealer**: fresh random group secret `x`, seen by the dealer.
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

        /// **Test-only**: split an existing secret (a BIP 352 vector's `b_spend`) into shares.
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
    }

    /// Reconstruct `x` by Lagrange interpolation. **Tests only.**
    pub fn reconstruct_for_tests(g: &FrostGroup, ids: &[Identifier]) -> Result<SecretKey> {
        let kps: Vec<KeyPackage> = ids.iter().map(|i| g.key_packages[i].clone()).collect();
        let sk = keys::reconstruct(&kps)?;
        Ok(SecretKey::from_slice(&sk.serialize())?)
    }
}

#[cfg(any(test, feature = "test-dealer"))]
pub use dealer::reconstruct_for_tests;
