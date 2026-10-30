//! One DKG participant. A `Device` holds only its own secrets (host key, RNG, ZF's DKG secret
//! packages, finally its [`DeviceKey`]) and talks only in bytes. Any refused message aborts the
//! device for the session; it then refuses every further step with the same error.

use std::collections::BTreeMap;

use frost_secp256k1_tr::keys::dkg::{self as zdkg, round1, round2};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::{Error as FrostError, Identifier};
use rand::{CryptoRng, RngCore};
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use zeroize::Zeroizing;

use super::ceremony::{Outgoing, Participant};
use super::channel::{self, Link};
use super::key::{check_key_material, Certificate, DeviceKey};
use super::wire::{sign_host, verify_host, Envelope, Kind};
use super::{frost_err, identifier, index_of, transcript_hash, view_hash, DkgError, Params};

/// A device's own randomness (one per device, never shared).
pub trait DeviceRng: RngCore + CryptoRng + Send {}
impl<T: RngCore + CryptoRng + Send> DeviceRng for T {}

struct Session {
    params: Params,
    me: u16,
    nonce: [u8; 32],
    id: [u8; 32],
}

impl Session {
    fn host(&self, id: u16) -> Result<&PublicKey, DkgError> {
        self.params.host(id).ok_or(DkgError::UnknownSender(id))
    }
}

// One per device, held for one ceremony: variant sizes do not matter.
#[allow(clippy::large_enum_variant)]
enum Phase {
    Idle,
    Round1 {
        s: Session,
        secret: round1::SecretPackage,
        own: Vec<u8>,
        b_scan: Option<SecretKey>,
    },
    Echo {
        s: Session,
        secret: round1::SecretPackage,
        packages: BTreeMap<u16, Vec<u8>>,
        parsed: BTreeMap<Identifier, round1::Package>,
        view: [u8; 32],
        b_scan: Option<SecretKey>,
    },
    Round2 {
        s: Session,
        secret: round2::SecretPackage,
        packages: BTreeMap<u16, Vec<u8>>,
        parsed: BTreeMap<Identifier, round1::Package>,
        b_scan: Option<SecretKey>,
    },
    Certify {
        s: Session,
        packages: BTreeMap<u16, Vec<u8>>,
        key_package: KeyPackage,
        public_key_package: PublicKeyPackage,
        b_scan: SecretKey,
        transcript: [u8; 32],
        own_sig: [u8; 64],
    },
    Done(Box<DeviceKey>),
    Aborted(DkgError),
}

pub struct Device {
    host: Keypair,
    host_secret: SecretKey,
    rng: Box<dyn DeviceRng>,
    phase: Phase,
    /// Control experiment only (D4): go on although the echoes disagree.
    #[cfg(test)]
    pub(crate) skip_echo_check: bool,
    /// Plaintext round-2 shares this device sealed (D6 looks for them in the log).
    #[cfg(test)]
    pub(crate) sent_shares: Vec<Vec<u8>>,
    /// Group key from `part3`, kept even if the device later aborts (D4 control).
    #[cfg(test)]
    pub(crate) part3_group_key: Option<Vec<u8>>,
}

impl Device {
    pub fn new(host_secret: SecretKey, rng: impl DeviceRng + 'static) -> Self {
        Self {
            host: Keypair::from_secret_key(&Secp256k1::new(), &host_secret),
            host_secret,
            rng: Box::new(rng),
            phase: Phase::Idle,
            #[cfg(test)]
            skip_echo_check: false,
            #[cfg(test)]
            sent_shares: vec![],
            #[cfg(test)]
            part3_group_key: None,
        }
    }

    pub fn host_public_key(&self) -> PublicKey {
        self.host.public_key()
    }

    /// The accepted result, once the certificate is complete.
    pub fn key(&self) -> Option<&DeviceKey> {
        match &self.phase {
            Phase::Done(k) => Some(k),
            _ => None,
        }
    }

    /// Why this device aborted, if it did.
    pub fn error(&self) -> Option<&DkgError> {
        match &self.phase {
            Phase::Aborted(e) => Some(e),
            _ => None,
        }
    }

    /// Run one step; on error the device is aborted for good.
    fn advance<T>(
        &mut self,
        f: impl FnOnce(&mut Self, Phase) -> Result<(Phase, T), DkgError>,
    ) -> Result<T, DkgError> {
        let busy = Phase::Aborted(DkgError::Protocol("step interrupted".into()));
        let phase = std::mem::replace(&mut self.phase, busy);
        if let Phase::Aborted(e) = &phase {
            let e = e.clone();
            self.phase = phase;
            return Err(e);
        }
        match f(self, phase) {
            Ok((next, out)) => {
                self.phase = next;
                Ok(out)
            }
            Err(e) => {
                self.phase = Phase::Aborted(e.clone());
                Err(e)
            }
        }
    }

    /// The same signed plaintext message to every other participant.
    fn broadcast(&self, s: &Session, kind: Kind, payload: &[u8]) -> Vec<Outgoing> {
        s.params
            .ids()
            .filter(|j| *j != s.me)
            .map(|j| Outgoing {
                to: j,
                bytes: Envelope::new(kind, s.id, s.me, j, payload.to_vec())
                    .signed(&self.host)
                    .encode(),
            })
            .collect()
    }

    /// Exactly one authenticated message of `kind` from every other participant, for this
    /// session, addressed to this device.
    fn collect(
        &self,
        s: &Session,
        kind: Kind,
        inbox: Vec<Vec<u8>>,
    ) -> Result<BTreeMap<u16, Envelope>, DkgError> {
        let mut got = BTreeMap::new();
        for bytes in inbox {
            let env = Envelope::decode(&bytes)
                .map_err(|reason| DkgError::Malformed { sender: None, reason })?;
            if env.session_id != s.id {
                return Err(DkgError::WrongSession { sender: env.sender });
            }
            let host = s.params.host(env.sender).ok_or(DkgError::UnknownSender(env.sender))?;
            if env.sender == s.me {
                return Err(DkgError::Malformed {
                    sender: Some(env.sender),
                    reason: "message claims to come from this device".into(),
                });
            }
            if env.recipient != s.me {
                return Err(DkgError::Misrouted { sender: env.sender, recipient: env.recipient });
            }
            if env.kind != kind {
                return Err(DkgError::Malformed {
                    sender: Some(env.sender),
                    reason: format!("{:?} message during {kind:?}", env.kind),
                });
            }
            if kind.is_signed() && !env.verify_signature(host) {
                return Err(DkgError::BadSignature { claimed_sender: env.sender });
            }
            let sender = env.sender;
            if got.insert(sender, env).is_some() {
                return Err(DkgError::Duplicate(sender));
            }
        }
        let missing: Vec<u16> = s
            .params
            .ids()
            .filter(|j| *j != s.me && !got.contains_key(j))
            .collect();
        if !missing.is_empty() {
            return Err(DkgError::Missing(missing));
        }
        Ok(got)
    }

    fn start_inner(&mut self, params: &Params, nonce: [u8; 32]) -> Result<Vec<Outgoing>, DkgError> {
        self.advance(|d, phase| {
            if !matches!(phase, Phase::Idle) {
                return Err(DkgError::Protocol("session already started".into()));
            }
            let me = params
                .identifier_of(&d.host.public_key())
                .ok_or(DkgError::UnknownParticipant)?;
            let s = Session { params: params.clone(), me, nonce, id: params.session_id(&nonce) };
            let (secret, package) =
                zdkg::part1(identifier(me)?, params.n(), params.t(), &mut *d.rng)
                    .map_err(frost_err)?;
            let own = package.serialize().map_err(frost_err)?;
            // Participant 1 draws the scan key and sends it inside its sealed round-2 payloads.
            let b_scan = (me == 1).then(|| SecretKey::new(&mut *d.rng));
            let out = d.broadcast(&s, Kind::Round1, &own);
            Ok((Phase::Round1 { s, secret, own, b_scan }, out))
        })
    }

    fn round1_inner(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError> {
        self.advance(|d, phase| {
            let Phase::Round1 { s, secret, own, b_scan } = phase else {
                return Err(DkgError::Protocol("round-1 packages out of order".into()));
            };
            let got = d.collect(&s, Kind::Round1, inbox)?;
            let mut packages = BTreeMap::from([(s.me, own)]);
            let mut parsed = BTreeMap::new();
            for (j, env) in got {
                let malformed = |reason: String| DkgError::Malformed { sender: Some(j), reason };
                let pkg = round1::Package::deserialize(&env.payload)
                    .map_err(|e| malformed(format!("round-1 package: {e}")))?;
                // The echo and the transcript hash these bytes: they must be the canonical ones.
                if pkg.serialize().map_err(frost_err)? != env.payload {
                    return Err(malformed("round-1 package is not canonically encoded".into()));
                }
                let coefficients = pkg.commitment().serialize().map_err(frost_err)?.len();
                if coefficients != usize::from(s.params.t()) {
                    return Err(malformed(format!("{coefficients} commitments for t = {}", s.params.t())));
                }
                parsed.insert(identifier(j)?, pkg);
                packages.insert(j, env.payload);
            }
            let view = view_hash(&s.id, &packages);
            let out = d.broadcast(&s, Kind::Echo, &view);
            Ok((Phase::Echo { s, secret, packages, parsed, view, b_scan }, out))
        })
    }

    fn echo_inner(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError> {
        self.advance(|d, phase| {
            let Phase::Echo { s, secret, packages, parsed, view, b_scan } = phase else {
                return Err(DkgError::Protocol("echoes out of order".into()));
            };
            let got = d.collect(&s, Kind::Echo, inbox)?;
            let mismatched: Vec<u16> = got
                .iter()
                .filter(|(_, e)| e.payload.as_slice() != view.as_slice())
                .map(|(j, _)| *j)
                .collect();
            #[cfg(test)]
            let skip = d.skip_echo_check;
            #[cfg(not(test))]
            let skip = false;
            if !mismatched.is_empty() && !skip {
                return Err(DkgError::ViewMismatch(mismatched));
            }
            // Same view everywhere: now verify the proofs of knowledge and compute the shares.
            let (secret, shares) = zdkg::part2(secret, &parsed).map_err(|e| match e {
                FrostError::InvalidProofOfKnowledge { culprit } => match index_of(&culprit) {
                    Ok(culprit) => DkgError::ProofOfKnowledge { culprit },
                    Err(e) => e,
                },
                other => frost_err(other),
            })?;
            let mut out = vec![];
            for (id, pkg) in &shares {
                let j = index_of(id)?;
                let share = Zeroizing::new(pkg.serialize().map_err(frost_err)?);
                let scan = b_scan.map(|b| Zeroizing::new(b.secret_bytes()));
                let plain = round2_plaintext(&share, scan.as_deref());
                #[cfg(test)]
                d.sent_shares.push(pkg.signing_share().serialize());
                let link = Link {
                    session_id: &s.id,
                    sender: s.me,
                    sender_host: s.host(s.me)?,
                    recipient: j,
                    recipient_host: s.host(j)?,
                };
                let sealed = channel::seal(&d.host_secret, &link, &plain, &mut *d.rng)?;
                out.push(Outgoing {
                    to: j,
                    bytes: Envelope::new(Kind::Round2, s.id, s.me, j, sealed).encode(),
                });
            }
            Ok((Phase::Round2 { s, secret, packages, parsed, b_scan }, out))
        })
    }

    fn round2_inner(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError> {
        self.advance(|d, phase| {
            let Phase::Round2 { s, secret, packages, parsed, b_scan } = phase else {
                return Err(DkgError::Protocol("round-2 packages out of order".into()));
            };
            let got = d.collect(&s, Kind::Round2, inbox)?;
            let mut shares = BTreeMap::new();
            let mut scan_from_1 = None;
            for (j, env) in got {
                let link = Link {
                    session_id: &s.id,
                    sender: j,
                    sender_host: s.host(j)?,
                    recipient: s.me,
                    recipient_host: s.host(s.me)?,
                };
                let plain = channel::open(&d.host_secret, &link, &env.payload)
                    .ok_or(DkgError::Decrypt { sender: j })?;
                let (share, scan) = parse_round2(&plain)
                    .map_err(|reason| DkgError::Malformed { sender: Some(j), reason })?;
                match (j == 1, scan) {
                    (true, Some(b)) => {
                        scan_from_1 = Some(SecretKey::from_slice(&b[..]).map_err(|_| {
                            DkgError::ScanKey { sender: 1, reason: "not a valid scalar".into() }
                        })?)
                    }
                    (true, None) => {
                        return Err(DkgError::ScanKey { sender: 1, reason: "missing".into() })
                    }
                    (false, Some(_)) => {
                        return Err(DkgError::ScanKey {
                            sender: j,
                            reason: "only participant 1 sends the scan key".into(),
                        })
                    }
                    (false, None) => {}
                }
                shares.insert(identifier(j)?, share);
            }
            let b_scan = b_scan
                .or(scan_from_1)
                .ok_or_else(|| DkgError::Protocol("no scan key".into()))?;
            let (key_package, public_key_package) =
                zdkg::part3(&secret, &parsed, &shares).map_err(|e| match e {
                    FrostError::InvalidSecretShare { culprit: Some(c) } => match index_of(&c) {
                        Ok(culprit) => DkgError::SecretShare { culprit },
                        Err(e) => e,
                    },
                    other => frost_err(other),
                })?;
            #[cfg(test)]
            {
                d.part3_group_key = public_key_package.verifying_key().serialize().ok();
            }
            check_key_material(&s.params, s.me, &key_package, &public_key_package)?;
            let b_scan_pub = b_scan.public_key(&Secp256k1::new());
            let transcript =
                transcript_hash(&s.id, &packages, s.params.t(), &public_key_package, &b_scan_pub)?;
            let own_sig = sign_host(&d.host, &Message::from_digest(transcript));
            let out = d.broadcast(&s, Kind::CertSig, &own_sig);
            Ok((
                Phase::Certify {
                    s,
                    packages,
                    key_package,
                    public_key_package,
                    b_scan,
                    transcript,
                    own_sig,
                },
                out,
            ))
        })
    }

    fn certificates_inner(&mut self, inbox: Vec<Vec<u8>>) -> Result<DeviceKey, DkgError> {
        self.advance(|d, phase| {
            let Phase::Certify {
                s,
                packages,
                key_package,
                public_key_package,
                b_scan,
                transcript,
                own_sig,
            } = phase
            else {
                return Err(DkgError::Protocol("certificate signatures out of order".into()));
            };
            let got = d.collect(&s, Kind::CertSig, inbox)?;
            let msg = Message::from_digest(transcript);
            let mut signatures = BTreeMap::from([(s.me, own_sig)]);
            for (j, env) in got {
                let sig: [u8; 64] = env.payload.as_slice().try_into().map_err(|_| {
                    DkgError::Malformed { sender: Some(j), reason: "signature is not 64 bytes".into() }
                })?;
                if !verify_host(s.host(j)?, &msg, &sig) {
                    return Err(DkgError::Certificate(format!(
                        "participant {j}'s signature does not verify on this device's transcript"
                    )));
                }
                signatures.insert(j, sig);
            }
            let certificate = Certificate {
                session_nonce: s.nonce,
                session_id: s.id,
                round1_packages: packages,
                transcript_hash: transcript,
                signatures,
            };
            // Re-verifies everything from the parts, exactly as a loaded file is checked.
            let key = DeviceKey::from_parts(
                s.me,
                s.params,
                d.host_secret,
                key_package,
                public_key_package,
                b_scan,
                certificate,
            )?;
            Ok((Phase::Done(Box::new(key.clone())), key))
        })
    }
}

/// `share length (u16) ‖ round2::Package ‖ flag (0 | 1) ‖ [b_scan (32) if flag = 1]`.
pub(super) fn round2_plaintext(share: &[u8], b_scan: Option<&[u8; 32]>) -> Zeroizing<Vec<u8>> {
    let mut plain = Zeroizing::new(Vec::with_capacity(share.len() + 35));
    plain.extend_from_slice(&(share.len() as u16).to_be_bytes());
    plain.extend_from_slice(share);
    match b_scan {
        Some(b) => {
            plain.push(1);
            plain.extend_from_slice(b);
        }
        None => plain.push(0),
    }
    plain
}

/// A received round-2 payload: the share and, from participant 1 only, `b_scan`.
pub(super) type Round2Plain = (round2::Package, Option<Zeroizing<[u8; 32]>>);

pub(super) fn parse_round2(plain: &[u8]) -> Result<Round2Plain, String> {
    let short = || "round-2 payload too short".to_string();
    let len = usize::from(u16::from_be_bytes([*plain.first().ok_or_else(short)?, *plain.get(1).ok_or_else(short)?]));
    let share = plain.get(2..2 + len).ok_or_else(short)?;
    let share = round2::Package::deserialize(share).map_err(|e| format!("round-2 package: {e}"))?;
    let flag = *plain.get(2 + len).ok_or_else(short)?;
    let rest = &plain[3 + len..];
    match (flag, rest.len()) {
        (0, 0) => Ok((share, None)),
        (1, 32) => {
            let mut b = Zeroizing::new([0u8; 32]);
            b.copy_from_slice(rest);
            Ok((share, Some(b)))
        }
        _ => Err("bad scan-key field in round-2 payload".into()),
    }
}

impl Participant for Device {
    fn host_public_key(&self) -> PublicKey {
        Device::host_public_key(self)
    }

    fn start(&mut self, params: &Params, nonce: [u8; 32]) -> Result<Vec<Outgoing>, DkgError> {
        self.start_inner(params, nonce)
    }

    fn on_round1(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError> {
        self.round1_inner(inbox)
    }

    fn on_echo(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError> {
        self.echo_inner(inbox)
    }

    fn on_round2(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError> {
        self.round2_inner(inbox)
    }

    fn on_certificates(&mut self, inbox: Vec<Vec<u8>>) -> Result<DeviceKey, DkgError> {
        self.certificates_inner(inbox)
    }

    fn as_device(&self) -> Option<&Device> {
        Some(self)
    }
}
