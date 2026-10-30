//! Byte-level DKG messages.
//!
//! ```text
//! "FSPD" ‖ version (1) ‖ kind (1) ‖ session id (32) ‖ sender (u16) ‖ recipient (u16)
//!        ‖ payload length (u32) ‖ payload ‖ [BIP 340 signature (64), plaintext kinds only]
//! ```
//!
//! Round 1, echo and certificate messages are signed by the sender's host key over
//! `H_FROST-SP/DKG/envelope(everything before the signature)`. Round-2 payloads are sealed to
//! the recipient (`channel.rs`), whose AEAD authenticates them instead.

use secp256k1::{schnorr, Keypair, Message, PublicKey, Secp256k1};

use crate::wallet::tagged_hash;

const MAGIC: &[u8; 4] = b"FSPD";
const VERSION: u8 = 1;
const HEADER: usize = 4 + 1 + 1 + 32 + 2 + 2 + 4;
/// No DKG payload comes near this; refuse anything larger before allocating.
const MAX_PAYLOAD: usize = 1 << 20;

/// BIP 340 signature by a host key. Deterministic nonce (zero aux randomness, allowed by
/// BIP 340): seeded test ceremonies stay reproducible.
pub(crate) fn sign_host(host: &Keypair, msg: &Message) -> [u8; 64] {
    Secp256k1::new().sign_schnorr_no_aux_rand(msg, host).serialize()
}

pub(crate) fn verify_host(host: &PublicKey, msg: &Message, sig: &[u8]) -> bool {
    let Ok(sig) = schnorr::Signature::from_slice(sig) else { return false };
    Secp256k1::verification_only()
        .verify_schnorr(&sig, msg, &host.x_only_public_key().0)
        .is_ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Round1 = 1,
    Echo = 2,
    Round2 = 3,
    CertSig = 4,
}

impl Kind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Kind::Round1),
            2 => Some(Kind::Echo),
            3 => Some(Kind::Round2),
            4 => Some(Kind::CertSig),
            _ => None,
        }
    }

    /// Plaintext kinds carry a host-key signature.
    pub fn is_signed(self) -> bool {
        self != Kind::Round2
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    pub session_id: [u8; 32],
    pub sender: u16,
    pub recipient: u16,
    pub payload: Vec<u8>,
    pub signature: Option<[u8; 64]>,
}

impl Envelope {
    pub fn new(kind: Kind, session_id: [u8; 32], sender: u16, recipient: u16, payload: Vec<u8>) -> Self {
        Self {
            kind,
            session_id,
            sender,
            recipient,
            payload,
            signature: None,
        }
    }

    fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER + self.payload.len() + 64);
        b.extend_from_slice(MAGIC);
        b.push(VERSION);
        b.push(self.kind as u8);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&self.sender.to_be_bytes());
        b.extend_from_slice(&self.recipient.to_be_bytes());
        b.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.payload);
        b
    }

    fn digest(&self) -> Message {
        Message::from_digest(tagged_hash("FROST-SP/DKG/envelope", &[&self.body()]))
    }

    /// Sign with the sender's host key (plaintext kinds).
    pub fn signed(mut self, host: &Keypair) -> Self {
        if self.kind.is_signed() {
            self.signature = Some(sign_host(host, &self.digest()));
        }
        self
    }

    /// The signature verifies under `host` (the claimed sender's host key).
    pub fn verify_signature(&self, host: &PublicKey) -> bool {
        let Some(sig) = self.signature else { return false };
        verify_host(host, &self.digest(), &sig)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        if let Some(sig) = &self.signature {
            b.extend_from_slice(sig);
        }
        b
    }

    /// Strict decoding: magic, version, known kind, exact length.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER {
            return Err("message too short".into());
        }
        if &bytes[0..4] != MAGIC || bytes[4] != VERSION {
            return Err("unknown message format".into());
        }
        let kind = Kind::from_byte(bytes[5]).ok_or("unknown message kind")?;
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&bytes[6..38]);
        let sender = u16::from_be_bytes([bytes[38], bytes[39]]);
        let recipient = u16::from_be_bytes([bytes[40], bytes[41]]);
        let len = u32::from_be_bytes([bytes[42], bytes[43], bytes[44], bytes[45]]) as usize;
        if len > MAX_PAYLOAD {
            return Err("payload too large".into());
        }
        let sig_len = if kind.is_signed() { 64 } else { 0 };
        if bytes.len() != HEADER + len + sig_len {
            return Err("message length does not match its header".into());
        }
        let payload = bytes[HEADER..HEADER + len].to_vec();
        let signature = if kind.is_signed() {
            let mut s = [0u8; 64];
            s.copy_from_slice(&bytes[HEADER + len..]);
            Some(s)
        } else {
            None
        };
        Ok(Self {
            kind,
            session_id,
            sender,
            recipient,
            payload,
            signature,
        })
    }
}
