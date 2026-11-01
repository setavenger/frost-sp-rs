//! The coordinator and network of a simulated ceremony. It moves only bytes between
//! participants, round by round, and keeps the full log. A test hook sees every round's
//! messages before delivery and may read, drop, replace, reorder, add or misroute them; a test
//! may also put a cheating [`Participant`] in any seat.

use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use secp256k1::{PublicKey, SecretKey};

use super::device::Device;
use super::{DeviceKey, DkgError, Params};

/// A message a participant wants sent to participant `to`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub to: u16,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Round {
    /// Round-1 packages (commitments and proof of knowledge), one copy per recipient.
    Round1,
    /// Hashes of each device's view of all round-1 packages.
    Echo,
    /// Sealed shares (and device 1's `b_scan`).
    Round2,
    /// Host-key signatures on the transcript `T`.
    Certify,
}

/// One message as the coordinator handles it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transit {
    pub round: Round,
    /// The seat that handed it to the coordinator (not authenticated; devices check the
    /// envelope's signed or sealed sender).
    pub from: u16,
    pub to: u16,
    pub bytes: Vec<u8>,
}

/// A seat in the ceremony. [`Device`] is the honest implementation.
pub trait Participant {
    fn host_public_key(&self) -> PublicKey;
    fn start(&mut self, params: &Params, nonce: [u8; 32]) -> Result<Vec<Outgoing>, DkgError>;
    fn on_round1(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError>;
    fn on_echo(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError>;
    fn on_round2(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError>;
    fn on_certificates(&mut self, inbox: Vec<Vec<u8>>) -> Result<DeviceKey, DkgError>;
    fn as_device(&self) -> Option<&Device> {
        None
    }
}

/// Each seat's result and everything the coordinator saw.
pub struct Outcome {
    pub results: BTreeMap<u16, Result<DeviceKey, DkgError>>,
    pub log: Vec<Transit>,
}

impl Outcome {
    pub fn accepted(&self) -> Vec<&DeviceKey> {
        self.results.values().filter_map(|r| r.as_ref().ok()).collect()
    }

    pub fn error(&self, id: u16) -> Option<&DkgError> {
        self.results.get(&id).and_then(|r| r.as_ref().err())
    }
}

type Hook<'a> = Box<dyn FnMut(Round, &mut Vec<Transit>) + 'a>;

pub struct Ceremony<'a> {
    params: Params,
    /// Seat `i` is identifier `i + 1`.
    seats: Vec<Box<dyn Participant + 'a>>,
    hook: Option<Hook<'a>>,
}

impl<'a> Ceremony<'a> {
    /// Seats each participant at its identifier. Refuses a participant whose host key is not
    /// in the list, two participants with one host key, and a wrong number of participants.
    pub fn new(params: Params, participants: Vec<Box<dyn Participant + 'a>>) -> Result<Self, DkgError> {
        if participants.len() != usize::from(params.n()) {
            return Err(DkgError::Params(format!(
                "{} participants for n = {}",
                participants.len(),
                params.n()
            )));
        }
        let mut slots: Vec<Option<Box<dyn Participant + 'a>>> =
            (0..params.n()).map(|_| None).collect();
        for p in participants {
            let id = params
                .identifier_of(&p.host_public_key())
                .ok_or(DkgError::UnknownParticipant)?;
            let slot = &mut slots[usize::from(id) - 1];
            if slot.is_some() {
                return Err(DkgError::Params("two participants with one host key".into()));
            }
            *slot = Some(p);
        }
        let seats = slots.into_iter().flatten().collect();
        Ok(Self { params, seats, hook: None })
    }

    /// Called with each round's messages before they are delivered.
    pub fn with_hook(mut self, hook: impl FnMut(Round, &mut Vec<Transit>) + 'a) -> Self {
        self.hook = Some(Box::new(hook));
        self
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    pub fn participant(&self, id: u16) -> Option<&(dyn Participant + 'a)> {
        self.seats.get(usize::from(id).checked_sub(1)?).map(|b| b.as_ref())
    }

    /// Run all rounds with the coordinator's session nonce. A seat that fails sends nothing
    /// more; the others then miss its messages and abort too.
    pub fn run(&mut self, nonce: [u8; 32]) -> Outcome {
        let mut log = vec![];
        let mut failed: BTreeMap<u16, DkgError> = BTreeMap::new();
        let mut outbox = vec![];
        for (id, seat) in (1u16..).zip(self.seats.iter_mut()) {
            match seat.start(&self.params, nonce) {
                Ok(out) => outbox.extend(transits(Round::Round1, id, out)),
                Err(e) => {
                    failed.insert(id, e);
                }
            }
        }
        for (round, next) in [
            (Round::Round1, Round::Echo),
            (Round::Echo, Round::Round2),
            (Round::Round2, Round::Certify),
        ] {
            let mut inboxes = self.deliver(round, std::mem::take(&mut outbox), &mut log);
            for (id, seat) in (1u16..).zip(self.seats.iter_mut()) {
                if failed.contains_key(&id) {
                    continue;
                }
                let inbox = inboxes.remove(&id).unwrap_or_default();
                let step = match round {
                    Round::Round1 => seat.on_round1(inbox),
                    Round::Echo => seat.on_echo(inbox),
                    Round::Round2 => seat.on_round2(inbox),
                    Round::Certify => Err(DkgError::Protocol("no step after certify".into())),
                };
                match step {
                    Ok(out) => outbox.extend(transits(next, id, out)),
                    Err(e) => {
                        failed.insert(id, e);
                    }
                }
            }
        }
        let mut inboxes = self.deliver(Round::Certify, outbox, &mut log);
        let mut results = BTreeMap::new();
        for (id, seat) in (1u16..).zip(self.seats.iter_mut()) {
            let r = match failed.remove(&id) {
                Some(e) => Err(e),
                None => seat.on_certificates(inboxes.remove(&id).unwrap_or_default()),
            };
            results.insert(id, r);
        }
        Outcome { results, log }
    }

    /// Hook, log, then sort into inboxes. Messages to no seat are logged and dropped.
    fn deliver(
        &mut self,
        round: Round,
        mut msgs: Vec<Transit>,
        log: &mut Vec<Transit>,
    ) -> BTreeMap<u16, Vec<Vec<u8>>> {
        if let Some(hook) = self.hook.as_mut() {
            hook(round, &mut msgs);
        }
        log.extend(msgs.iter().cloned());
        let mut inboxes: BTreeMap<u16, Vec<Vec<u8>>> = BTreeMap::new();
        for m in msgs {
            if self.params.host(m.to).is_some() {
                inboxes.entry(m.to).or_default().push(m.bytes);
            }
        }
        inboxes
    }
}

fn transits(round: Round, from: u16, out: Vec<Outgoing>) -> impl Iterator<Item = Transit> {
    out.into_iter().map(move |o| Transit { round, from, to: o.to, bytes: o.bytes })
}

/// Host keys and device RNG seeds for `n` simulated devices, drawn from `rng`.
pub fn simulated_devices<R: RngCore + CryptoRng>(n: u16, rng: &mut R) -> Vec<Device> {
    (0..n)
        .map(|_| {
            let host = SecretKey::new(rng);
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            Device::new(host, StdRng::from_seed(seed))
        })
        .collect()
}

/// An honest simulated ceremony: `n` devices, each with its own host key and its own RNG
/// (a ChaCha12 `StdRng` seeded from `rng`). Returns the devices' keys by identifier.
///
/// With a seeded `rng` every secret follows from the seed: **test constants only.**
pub fn keygen<R: RngCore + CryptoRng>(t: u16, n: u16, rng: &mut R) -> Result<Vec<DeviceKey>, DkgError> {
    let devices = simulated_devices(n, rng);
    let hosts = devices.iter().map(Device::host_public_key).collect();
    let params = Params::new(t, n, hosts)?;
    let seats: Vec<Box<dyn Participant>> =
        devices.into_iter().map(|d| Box::new(d) as Box<dyn Participant>).collect();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let mut ceremony = Ceremony::new(params, seats)?;
    let outcome = ceremony.run(nonce);
    if crate::trace::enabled() {
        trace_keygen(ceremony.params(), &outcome);
    }
    outcome.results.into_values().collect()
}

/// `FROST_SP_TRACE`: the ceremony's public record. `B_scan` is the public scan key; no secret
/// is read here.
fn trace_keygen(params: &Params, outcome: &Outcome) {
    use crate::trace::hex;
    use serde_json::json;
    let count = |r: Round| outcome.log.iter().filter(|m| m.round == r).count();
    let keys = outcome.accepted();
    let first = keys.first().copied();
    let cert = first.map(DeviceKey::certificate);
    let echo = cert.map(|c| super::view_hash(&c.session_id, &c.round1_packages));
    let echoes_matching = outcome
        .log
        .iter()
        .filter(|m| m.round == Round::Echo)
        .filter(|m| super::wire::Envelope::decode(&m.bytes).is_ok_and(|e| Some(e.payload.as_slice()) == echo.as_ref().map(|h| &h[..])))
        .count();
    let shares: serde_json::Map<String, serde_json::Value> = first
        .map(|k| {
            k.public_key_package()
                .verifying_shares()
                .iter()
                .filter_map(|(id, s)| Some((super::index_of(id).ok()?.to_string(), hex(s.serialize().ok()?).into())))
                .collect()
        })
        .unwrap_or_default();
    let secp = secp256k1::Secp256k1::new();
    let devices: Vec<_> = outcome
        .results
        .iter()
        .map(|(id, r)| {
            json!({
                "identifier": id,
                "host_pubkey": params.host(*id).map(|h| hex(h.serialize())),
                "accepted": r.is_ok(),
                "error": r.as_ref().err().map(ToString::to_string),
                "certificate_valid": r.as_ref().is_ok_and(|k| k.verify().is_ok()),
                "check_code": r.as_ref().ok().map(DeviceKey::check_code),
            })
        })
        .collect();
    crate::trace::emit(
        "keygen.dkg",
        json!({
            "n": params.n(),
            "t": params.t(),
            "device_ids": params.ids().collect::<Vec<_>>(),
            "host_pubkeys": params.hosts().iter().map(|h| hex(h.serialize())).collect::<Vec<_>>(),
            "messages_per_round": {
                "round1": count(Round::Round1),
                "echo": count(Round::Echo),
                "round2_sealed": count(Round::Round2),
                "certify": count(Round::Certify),
            },
            "session_id": cert.map(|c| hex(c.session_id)),
            "echo_digest": echo.map(hex),
            "echo_messages_matching_digest": echoes_matching,
            "all_devices_same_certificate": keys.windows(2).all(|w| w[0].certificate() == w[1].certificate()),
            "verification_shares": shares,
            "group_key": first.and_then(|k| k.b_spend().ok()).map(|x| hex(x.serialize())),
            "b_scan_pub": first.map(|k| hex(k.b_scan().public_key(&secp).serialize())),
            "transcript_hash": cert.map(|c| hex(c.transcript_hash)),
            "certificate_signatures": cert.map(|c| c.signatures.len()),
            "check_code": first.map(DeviceKey::check_code),
            "devices": devices,
        }),
    );
}
