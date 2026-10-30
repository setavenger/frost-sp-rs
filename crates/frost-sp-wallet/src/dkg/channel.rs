//! Round-2 channel: each `round2::Package` (and device 1's `b_scan`) is sealed to its recipient.
//!
//! * Key: HKDF-SHA256 over the static ECDH of the two host keys (`SHA256(ser(sk·PK))`,
//!   libsecp256k1's ECDH), salt = session id, info binds both host keys and identifiers in
//!   sender→recipient order, so each direction of each pair in each session has its own key.
//! * Cipher: ChaCha20-Poly1305, a random 12-byte nonce carried in front of the ciphertext.
//! * AAD: session id ‖ sender ‖ recipient.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::DkgError;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// One direction of one pair in one session.
pub(crate) struct Link<'a> {
    pub session_id: &'a [u8; 32],
    pub sender: u16,
    pub sender_host: &'a PublicKey,
    pub recipient: u16,
    pub recipient_host: &'a PublicKey,
}

impl Link<'_> {
    fn aad(&self) -> Vec<u8> {
        let mut a = self.session_id.to_vec();
        a.extend_from_slice(&self.sender.to_be_bytes());
        a.extend_from_slice(&self.recipient.to_be_bytes());
        a
    }

    /// `own` is the sender's host secret when sealing, the recipient's when opening.
    fn key(&self, own: &SecretKey, peer: &PublicKey) -> Result<Zeroizing<[u8; 32]>, DkgError> {
        let shared = Zeroizing::new(SharedSecret::new(peer, own).secret_bytes());
        let hk = Hkdf::<Sha256>::new(Some(self.session_id), shared.as_ref());
        let mut info = b"FROST-SP/DKG/round2/v1".to_vec();
        info.extend_from_slice(&self.sender_host.serialize());
        info.extend_from_slice(&self.recipient_host.serialize());
        info.extend_from_slice(&self.sender.to_be_bytes());
        info.extend_from_slice(&self.recipient.to_be_bytes());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(&info, okm.as_mut())
            .map_err(|_| DkgError::Protocol("hkdf output length".into()))?;
        Ok(okm)
    }
}

/// Seal `plaintext` from `link.sender` (holding `sender_secret`) to `link.recipient`.
pub(crate) fn seal<R: RngCore + CryptoRng + ?Sized>(
    sender_secret: &SecretKey,
    link: &Link,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, DkgError> {
    let key = link.key(sender_secret, link.recipient_host)?;
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = link.aad();
    let ct = cipher
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| DkgError::Protocol("encryption failed".into()))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed payload at `link.recipient` (holding `recipient_secret`). `None` if it does not
/// authenticate: wrong key (sender, recipient or session), or any bit changed.
pub(crate) fn open(
    recipient_secret: &SecretKey,
    link: &Link,
    sealed: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let key = link.key(recipient_secret, link.sender_host).ok()?;
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let aad = link.aad();
    cipher
        .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad: &aad })
        .ok()
        .map(Zeroizing::new)
}
