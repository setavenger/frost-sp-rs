//! Distributed key generation (DKG): `n` devices end with one FROST signing share each, the
//! same group key `X = B_spend` and the same scan key `b_scan`, and nobody ever holds `x`.
//!
//! The core is ZF's Pedersen DKG with proofs of knowledge (`frost_secp256k1_tr::keys::dkg`,
//! `part1/2/3`). Around it this module adds what ZF leaves to the application:
//!
//! * **Participants and session.** Each device has a static secp256k1 host key. The
//!   participant list is the sorted host public keys plus `t` and `n` ([`Params`]), confirmed
//!   out of band; a device's FROST identifier is its 1-based position in that list. The session
//!   id hashes the list, `t`, `n` and 32 random bytes from the coordinator.
//! * **Authenticated messages.** Every message ([`wire::Envelope`]) carries the session id,
//!   sender and recipient. Plaintext messages are BIP 340-signed by the sender's host key;
//!   round-2 messages are sealed to their recipient (ECDH of the host keys, HKDF-SHA256,
//!   ChaCha20-Poly1305). A device refuses a wrong session, an unknown or forged sender, a
//!   misrouted message, duplicates and missing participants, and aborts.
//! * **Same view (echo round).** Before any share leaves a device, every device sends every
//!   other the hash of all `n` round-1 packages it received; a device continues only if all
//!   `n − 1` echoes equal its own hash (ZF requires a secure broadcast, `dkg.rs:5-35`).
//! * **Scan key.** Device 1 draws `b_scan` and puts it into its sealed round-2 payloads.
//! * **Certificate.** Every device checks its key material, hashes the transcript `T` (session,
//!   all round-1 packages, `X` and every `X_i`, `B_scan`) and signs `T` with its host key. A
//!   device accepts only with valid signatures on *its own* `T` from all `n` host keys.
//!
//! The [`ceremony::Ceremony`] plays coordinator and network: it moves only bytes, logs them, and
//! lets tests read, drop, replace, reorder or misroute any message, or swap in a cheating device.
//!
//! ZF's `part3` adds BIP 341's "unspendable script path" tweak to the DKG key (`post_dkg`), so
//! `X` is `P + H_TapTweak(P)·G` for the Pedersen key `P` (even-Y). All devices compute it
//! identically and SP outputs then use `X` like any other `B_spend` with no further tweak.

pub mod ceremony;
mod channel;
pub mod device;
pub mod key;
pub mod wire;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use frost_secp256k1_tr::keys::PublicKeyPackage;
use frost_secp256k1_tr::Identifier;
use secp256k1::PublicKey;

pub use ceremony::{keygen, Ceremony, Outcome, Outgoing, Participant, Round, Transit};
pub use device::Device;
pub use key::{Certificate, DeviceKey};

use crate::wallet::tagged_hash;

/// Why a device refused to go on. Where a single participant is to blame, it is named.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DkgError {
    #[error("parameters: {0}")]
    Params(String),
    #[error("this device's host key is not in the participant list")]
    UnknownParticipant,
    #[error("malformed message (claimed sender {sender:?}): {reason}")]
    Malformed { sender: Option<u16>, reason: String },
    #[error("message from {sender} belongs to another session")]
    WrongSession { sender: u16 },
    #[error("message claims unknown sender {0}")]
    UnknownSender(u16),
    #[error("message from {sender} is addressed to {recipient}, not this device")]
    Misrouted { sender: u16, recipient: u16 },
    #[error("message claiming sender {claimed_sender} has no valid host-key signature")]
    BadSignature { claimed_sender: u16 },
    #[error("duplicate message from {0}")]
    Duplicate(u16),
    #[error("missing messages from {0:?}")]
    Missing(Vec<u16>),
    #[error("round-1 views differ: echoes from {0:?} do not match this device's view")]
    ViewMismatch(Vec<u16>),
    #[error("culprit {culprit}: invalid proof of knowledge")]
    ProofOfKnowledge { culprit: u16 },
    #[error("culprit {culprit}: secret share inconsistent with its commitments")]
    SecretShare { culprit: u16 },
    #[error("round-2 message from {sender} fails authentication")]
    Decrypt { sender: u16 },
    #[error("scan key from {sender}: {reason}")]
    ScanKey { sender: u16, reason: String },
    #[error("key check: {0}")]
    KeyCheck(String),
    #[error("certificate: {0}")]
    Certificate(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("frost: {0}")]
    Frost(String),
}

impl DkgError {
    /// The participant this error blames, if exactly one is to blame.
    pub fn culprit(&self) -> Option<u16> {
        match self {
            DkgError::ProofOfKnowledge { culprit } | DkgError::SecretShare { culprit } => {
                Some(*culprit)
            }
            DkgError::ScanKey { sender, .. } => Some(*sender),
            _ => None,
        }
    }
}

pub(crate) fn frost_err(e: frost_secp256k1_tr::Error) -> DkgError {
    DkgError::Frost(e.to_string())
}

/// The participant list: `t`, `n` and the host public keys sorted by their 33-byte encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    t: u16,
    n: u16,
    hosts: Vec<PublicKey>,
}

impl Params {
    /// Refuses `t < 2`, `t > n`, a list that is not `n` keys long and duplicate host keys
    /// (also two keys with one x coordinate: they would share BIP 340 signatures).
    pub fn new(t: u16, n: u16, mut hosts: Vec<PublicKey>) -> Result<Self, DkgError> {
        let bad = |m: String| Err(DkgError::Params(m));
        if t < 2 {
            return bad(format!("threshold t = {t} is below 2"));
        }
        if t > n {
            return bad(format!("threshold t = {t} exceeds n = {n}"));
        }
        if hosts.len() != usize::from(n) {
            return bad(format!("{} host keys for n = {n}", hosts.len()));
        }
        let xs: std::collections::BTreeSet<[u8; 32]> =
            hosts.iter().map(|h| h.x_only_public_key().0.serialize()).collect();
        if xs.len() != hosts.len() {
            return bad("duplicate host key".into());
        }
        hosts.sort_by_key(|h| h.serialize());
        Ok(Self { t, n, hosts })
    }

    pub fn t(&self) -> u16 {
        self.t
    }

    pub fn n(&self) -> u16 {
        self.n
    }

    /// Sorted host public keys; index `i` is identifier `i + 1`.
    pub fn hosts(&self) -> &[PublicKey] {
        &self.hosts
    }

    /// Host key of identifier `id` (1-based).
    pub fn host(&self, id: u16) -> Option<&PublicKey> {
        self.hosts.get(usize::from(id).checked_sub(1)?)
    }

    pub fn identifier_of(&self, host: &PublicKey) -> Option<u16> {
        let pos = self.hosts.iter().position(|h| h == host)?;
        u16::try_from(pos + 1).ok()
    }

    pub fn ids(&self) -> impl Iterator<Item = u16> {
        1..=self.n
    }

    /// `H_FROST-SP/DKG/session(t ‖ n ‖ host_1 ‖ … ‖ host_n ‖ nonce)`.
    pub fn session_id(&self, nonce: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(4 + 33 * self.hosts.len() + 32);
        data.extend_from_slice(&self.t.to_be_bytes());
        data.extend_from_slice(&self.n.to_be_bytes());
        for h in &self.hosts {
            data.extend_from_slice(&h.serialize());
        }
        data.extend_from_slice(nonce);
        tagged_hash("FROST-SP/DKG/session", &[&data])
    }
}

pub(crate) fn identifier(id: u16) -> Result<Identifier, DkgError> {
    Identifier::try_from(id).map_err(frost_err)
}

/// Inverse of [`identifier`] for the default identifiers `1..=n`.
pub(crate) fn index_of(id: &Identifier) -> Result<u16, DkgError> {
    let bytes = id.serialize();
    let (head, tail) = bytes.split_at(bytes.len() - 2);
    if head.iter().any(|b| *b != 0) {
        return Err(DkgError::Protocol("identifier out of range".into()));
    }
    Ok(u16::from_be_bytes([tail[0], tail[1]]))
}

fn put_packages(data: &mut Vec<u8>, packages: &BTreeMap<u16, Vec<u8>>) {
    data.extend_from_slice(&(packages.len() as u32).to_be_bytes());
    for (id, bytes) in packages {
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(bytes);
    }
}

/// The echo: hash of the session id and all `n` round-1 packages sorted by identifier.
pub(crate) fn view_hash(session_id: &[u8; 32], packages: &BTreeMap<u16, Vec<u8>>) -> [u8; 32] {
    let mut data = session_id.to_vec();
    put_packages(&mut data, packages);
    tagged_hash("FROST-SP/DKG/echo", &[&data])
}

/// The transcript `T` every device signs: session id, all round-1 packages, `t`, `X`, every
/// `X_i` by identifier, and `B_scan`.
pub(crate) fn transcript_hash(
    session_id: &[u8; 32],
    packages: &BTreeMap<u16, Vec<u8>>,
    t: u16,
    pkp: &PublicKeyPackage,
    b_scan: &PublicKey,
) -> Result<[u8; 32], DkgError> {
    let mut data = session_id.to_vec();
    put_packages(&mut data, packages);
    data.extend_from_slice(&t.to_be_bytes());
    data.extend_from_slice(&pkp.verifying_key().serialize().map_err(frost_err)?);
    data.extend_from_slice(&(pkp.verifying_shares().len() as u32).to_be_bytes());
    for (id, share) in pkp.verifying_shares() {
        data.extend_from_slice(&index_of(id)?.to_be_bytes());
        data.extend_from_slice(&share.serialize().map_err(frost_err)?);
    }
    data.extend_from_slice(&b_scan.serialize());
    Ok(tagged_hash("FROST-SP/DKG/transcript", &[&data]))
}

/// Short code for the user to compare across devices: 48 bits of `H(T)`, `xxxx-xxxx-xxxx`.
pub fn check_code(transcript: &[u8; 32]) -> String {
    let h = tagged_hash("FROST-SP/DKG/check-code", &[transcript]);
    let hex: String = h[..6].iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12])
}
