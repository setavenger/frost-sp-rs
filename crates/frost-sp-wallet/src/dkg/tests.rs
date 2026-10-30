//! D1–D11 (`run/W5-dkg.md`): honest ceremonies and every attack the brief names, run through
//! the byte-level coordinator. Cheating devices are played by the coordinator hook (holding the
//! cheater's host key) or by a custom [`Participant`].
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use frost::keys::dkg::{self as zdkg, round1, round2};
use frost::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifiableSecretSharingCommitment};
use frost::Identifier;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};

use super::ceremony::{Outgoing, Participant};
use super::channel::{self, Link};
use super::device::{parse_round2, round2_plaintext};
use super::wire::{Envelope, Kind};
use super::*;
use crate::tweak::{tweak_key_package, tweak_public_key_package};

// ------------------------------------------------------------------------------------------
// Harness
// ------------------------------------------------------------------------------------------

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Host secrets in identifier order (`hosts[id - 1]`) and each device's RNG seed.
struct Setup {
    params: Params,
    hosts: Vec<SecretKey>,
    seeds: Vec<[u8; 32]>,
}

fn setup(t: u16, n: u16, seed: u64) -> Setup {
    let secp = Secp256k1::new();
    let mut r = rng(seed);
    let mut pairs: Vec<(SecretKey, [u8; 32])> = (0..n)
        .map(|_| {
            let sk = SecretKey::new(&mut r);
            let mut s = [0u8; 32];
            r.fill_bytes(&mut s);
            (sk, s)
        })
        .collect();
    pairs.sort_by_key(|(sk, _)| sk.public_key(&secp).serialize());
    let params = Params::new(t, n, pairs.iter().map(|(sk, _)| sk.public_key(&secp)).collect()).unwrap();
    Setup {
        params,
        hosts: pairs.iter().map(|p| p.0).collect(),
        seeds: pairs.iter().map(|p| p.1).collect(),
    }
}

impl Setup {
    fn device(&self, id: u16) -> Device {
        let i = usize::from(id) - 1;
        Device::new(self.hosts[i], StdRng::from_seed(self.seeds[i]))
    }

    fn honest_seats(&self) -> Vec<Box<dyn Participant>> {
        self.params.ids().map(|id| Box::new(self.device(id)) as Box<dyn Participant>).collect()
    }

    fn host(&self, id: u16) -> SecretKey {
        self.hosts[usize::from(id) - 1]
    }
}

fn nonce(seed: u64) -> [u8; 32] {
    let mut n = [0u8; 32];
    rng(seed ^ 0x5eed).fill_bytes(&mut n);
    n
}

fn run_with<'a>(s: &Setup, hook: impl FnMut(Round, &mut Vec<Transit>) + 'a) -> Outcome {
    Ceremony::new(s.params.clone(), s.honest_seats())
        .unwrap()
        .with_hook(hook)
        .run(nonce(1))
}

fn run_honest(t: u16, n: u16, seed: u64) -> Outcome {
    run_with(&setup(t, n, seed), |_, _| {})
}

fn decode(b: &[u8]) -> Envelope {
    Envelope::decode(b).unwrap()
}

/// Re-sign an edited plaintext envelope with `host` (the cheater's own host key).
fn resign(env: Envelope, host: &SecretKey) -> Vec<u8> {
    let kp = Keypair::from_secret_key(&Secp256k1::new(), host);
    Envelope { signature: None, ..env }.signed(&kp).encode()
}

/// Re-seal a round-2 message after `edit` changed its plaintext, as its sender would.
fn reseal(
    s: &Setup,
    bytes: &[u8],
    edit: impl FnOnce(&mut round2::Package, &mut Option<[u8; 32]>),
) -> Vec<u8> {
    let env = decode(bytes);
    let link = Link {
        session_id: &env.session_id,
        sender: env.sender,
        sender_host: s.params.host(env.sender).unwrap(),
        recipient: env.recipient,
        recipient_host: s.params.host(env.recipient).unwrap(),
    };
    let plain = channel::open(&s.host(env.recipient), &link, &env.payload).unwrap();
    let (mut share, scan) = parse_round2(&plain).unwrap();
    let mut scan = scan.map(|z| *z);
    edit(&mut share, &mut scan);
    let plain = round2_plaintext(&share.serialize().unwrap(), scan.as_ref());
    let sealed = channel::seal(&s.host(env.sender), &link, &plain, &mut rng(99)).unwrap();
    Envelope { payload: sealed, ..env }.encode()
}

fn keys(out: Outcome) -> Vec<DeviceKey> {
    out.results.into_values().map(|r| r.unwrap()).collect()
}

fn none_accepted(out: &Outcome) {
    assert!(out.accepted().is_empty(), "a device accepted: {:?}", out.results);
}

fn sent_in(out: &Outcome, round: Round) -> usize {
    out.log.iter().filter(|m| m.round == round).count()
}

fn combinations(n: u16, t: u16) -> Vec<Vec<u16>> {
    fn go(start: u16, n: u16, t: u16, cur: &mut Vec<u16>, out: &mut Vec<Vec<u16>>) {
        if cur.len() == usize::from(t) {
            out.push(cur.clone());
            return;
        }
        for i in start..=n {
            cur.push(i);
            go(i + 1, n, t, cur, out);
            cur.pop();
        }
    }
    let mut out = vec![];
    go(1, n, t, &mut vec![], &mut out);
    out
}

/// Plain FROST (BIP 340) signing by the given key packages.
fn frost_sign(kps: &[KeyPackage], pkp: &PublicKeyPackage, msg: &[u8; 32], r: &mut StdRng) -> [u8; 64] {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for kp in kps {
        let (n, c) = frost::round1::commit(kp.signing_share(), &mut *r);
        nonces.insert(*kp.identifier(), n);
        commitments.insert(*kp.identifier(), c);
    }
    let pkg = frost::SigningPackage::new(commitments, msg);
    let mut shares = BTreeMap::new();
    for kp in kps {
        shares.insert(*kp.identifier(), frost::round2::sign(&pkg, &nonces[kp.identifier()], kp).unwrap());
    }
    let sig = frost::aggregate(&pkg, &shares, pkp).unwrap();
    sig.serialize().unwrap().try_into().unwrap()
}

fn verify_bip340(sig: &[u8; 64], msg: &[u8; 32], key: &PublicKey) -> bool {
    let s = secp256k1::schnorr::Signature::from_slice(sig).unwrap();
    Secp256k1::verification_only()
        .verify_schnorr(&s, &Message::from_digest(*msg), &key.x_only_public_key().0)
        .is_ok()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A device that sends one round-1 package to everyone, but a package of the hook's making,
/// and keeps its echo consistent with it (so only the package itself is wrong). `make` sees
/// the other devices' packages first (a rushing adversary) and the cheater's honest one.
fn consistent_round1_cheat<'a>(
    cheater: u16,
    host: SecretKey,
    mut make: impl FnMut(&BTreeMap<u16, Vec<u8>>, &[u8]) -> Vec<u8> + 'a,
) -> impl FnMut(Round, &mut Vec<Transit>) + 'a {
    let mut view = BTreeMap::new();
    let mut session = [0u8; 32];
    move |round, msgs| match round {
        Round::Round1 => {
            let mut own = vec![];
            for m in msgs.iter() {
                let e = decode(&m.bytes);
                session = e.session_id;
                if m.from == cheater {
                    own = e.payload;
                } else {
                    view.insert(m.from, e.payload);
                }
            }
            let bad = make(&view, &own);
            view.insert(cheater, bad.clone());
            for m in msgs.iter_mut().filter(|m| m.from == cheater) {
                let e = decode(&m.bytes);
                m.bytes = resign(Envelope { payload: bad.clone(), ..e }, &host);
            }
        }
        Round::Echo => {
            let h = view_hash(&session, &view);
            for m in msgs.iter_mut().filter(|m| m.from == cheater) {
                let e = decode(&m.bytes);
                m.bytes = resign(Envelope { payload: h.to_vec(), ..e }, &host);
            }
        }
        _ => {}
    }
}

// ------------------------------------------------------------------------------------------
// D1: honest ceremonies
// ------------------------------------------------------------------------------------------

fn honest(t: u16, n: u16, seed: u64) {
    let out = run_honest(t, n, seed);
    assert_eq!(sent_in(&out, Round::Round2), usize::from(n) * usize::from(n - 1));
    let keys = keys(out);
    assert_eq!(keys.len(), usize::from(n));
    let k0 = &keys[0];
    let x = k0.b_spend().unwrap();
    for (i, k) in keys.iter().enumerate() {
        assert_eq!(usize::from(k.identifier()), i + 1);
        assert_eq!(k.b_spend().unwrap(), x);
        assert_eq!(k.b_scan(), k0.b_scan());
        assert_eq!(k.check_code(), k0.check_code());
        assert_eq!(k.certificate(), k0.certificate());
        assert_eq!(k.public_key_package().serialize().unwrap(), k0.public_key_package().serialize().unwrap());
        assert_eq!(k.certificate().signatures.len(), usize::from(n));
        k.verify().unwrap();
    }
    assert_eq!(k0.check_code().len(), 14);

    // Every t-subset signs under X, and under X + tau*G (the SP spend path).
    let mut r = rng(seed + 100);
    let tau = SecretKey::new(&mut r);
    let p = x.add_exp_tweak(&Secp256k1::new(), &tau.into()).unwrap();
    let tpkp = tweak_public_key_package(k0.public_key_package(), &tau.secret_bytes()).unwrap();
    assert_eq!(tpkp.verifying_key().serialize().unwrap(), p.serialize().to_vec());
    for set in combinations(n, t) {
        let msg = crate::wallet::tagged_hash("test", &[&format!("{set:?}").into_bytes()]);
        let kps: Vec<KeyPackage> = set.iter().map(|i| keys[usize::from(*i) - 1].key_package().clone()).collect();
        let sig = frost_sign(&kps, k0.public_key_package(), &msg, &mut r);
        assert!(verify_bip340(&sig, &msg, &x), "plain signature by {set:?}");
        let tkps: Vec<KeyPackage> = kps.iter().map(|kp| tweak_key_package(kp, &tau.secret_bytes()).unwrap()).collect();
        let sig = frost_sign(&tkps, &tpkp, &msg, &mut r);
        assert!(verify_bip340(&sig, &msg, &p), "tweaked signature by {set:?}");
    }

    // Test-only reconstruction from any t shares gives x with x*G == X.
    for set in [combinations(n, t).first().unwrap().clone(), combinations(n, t).last().unwrap().clone()] {
        let kps: Vec<KeyPackage> = set.iter().map(|i| keys[usize::from(*i) - 1].key_package().clone()).collect();
        let secret = frost::keys::reconstruct(&kps).unwrap();
        let sk = SecretKey::from_slice(&secret.serialize()).unwrap();
        assert_eq!(sk.public_key(&Secp256k1::new()), x);
    }
}

#[test]
fn d1_honest_2_of_3() {
    honest(2, 3, 1);
}

#[test]
fn d1_honest_3_of_5() {
    honest(3, 5, 2);
}

#[test]
fn d1_keygen_is_reproducible_only_with_the_same_seed() {
    let a = keygen(2, 3, &mut rng(7)).unwrap();
    let b = keygen(2, 3, &mut rng(7)).unwrap();
    let c = keygen(2, 3, &mut rng(8)).unwrap();
    assert_eq!(a[0].b_spend().unwrap(), b[0].b_spend().unwrap());
    assert_eq!(a[0].certificate(), b[0].certificate());
    assert_ne!(a[0].b_spend().unwrap(), c[0].b_spend().unwrap());
}

// ------------------------------------------------------------------------------------------
// D2: proof of knowledge
// ------------------------------------------------------------------------------------------

#[test]
fn d2_bad_proof_of_knowledge_names_the_culprit() {
    let s = setup(2, 3, 10);
    let out = run_with(
        &s,
        consistent_round1_cheat(2, s.host(2), |_, own| {
            let pkg = round1::Package::deserialize(own).unwrap();
            let mut sig = pkg.proof_of_knowledge().serialize().unwrap();
            *sig.last_mut().unwrap() ^= 1;
            let sig = frost::Signature::deserialize(&sig).unwrap();
            round1::Package::new(pkg.commitment().clone(), sig).serialize().unwrap()
        }),
    );
    for id in [1, 3] {
        assert_eq!(out.error(id), Some(&DkgError::ProofOfKnowledge { culprit: 2 }));
        assert_eq!(out.error(id).unwrap().culprit(), Some(2));
    }
    assert!(!out.log.iter().any(|m| m.round == Round::Round2 && m.from != 2), "an honest share left");
    none_accepted(&out);
}

#[test]
fn d2_rogue_key_attempt_is_caught_by_the_proof_of_knowledge() {
    let secp = Secp256k1::new();
    let s = setup(3, 4, 11);
    // The group key the attacker wants: a point whose discrete log nobody uses.
    let target = SecretKey::from_slice(&crate::wallet::tagged_hash("rogue target", &[])).unwrap().public_key(&secp);
    let mut sum_c0 = None;
    let out = run_with(
        &s,
        consistent_round1_cheat(4, s.host(4), |others, own| {
            // C_0' = target - sum of the others' C_0, other coefficients kept; the cheater
            // cannot prove knowledge of log C_0' and reuses its old proof.
            let c0 = |bytes: &[u8]| {
                let pkg = round1::Package::deserialize(bytes).unwrap();
                PublicKey::from_slice(&pkg.commitment().serialize().unwrap()[0]).unwrap()
            };
            let neg: Vec<PublicKey> = others.values().map(|b| c0(b).negate(&secp)).collect();
            let mut parts: Vec<&PublicKey> = neg.iter().collect();
            parts.push(&target);
            let rogue = PublicKey::combine_keys(&parts).unwrap();
            let pkg = round1::Package::deserialize(own).unwrap();
            let mut coeffs = pkg.commitment().serialize().unwrap();
            coeffs[0] = rogue.serialize().to_vec();
            let commitment = VerifiableSecretSharingCommitment::deserialize(coeffs).unwrap();
            let mut all: Vec<PublicKey> = others.values().map(|b| c0(b)).collect();
            all.push(rogue);
            sum_c0 = Some(PublicKey::combine_keys(&all.iter().collect::<Vec<_>>()).unwrap());
            round1::Package::new(commitment, *pkg.proof_of_knowledge()).serialize().unwrap()
        }),
    );
    // Unchecked, the group's Pedersen key would have been the attacker's target.
    assert_eq!(sum_c0, Some(target));
    for id in 1..=3 {
        assert_eq!(out.error(id), Some(&DkgError::ProofOfKnowledge { culprit: 4 }));
    }
    assert_eq!(sent_in(&out, Round::Round2), 0);
    none_accepted(&out);
}

// ------------------------------------------------------------------------------------------
// D3: share inconsistent with the sender's commitments
// ------------------------------------------------------------------------------------------

#[test]
fn d3_inconsistent_share_names_the_culprit_and_nobody_accepts() {
    let s = setup(2, 3, 20);
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round2 {
            for m in msgs.iter_mut().filter(|m| m.from == 2 && m.to == 3) {
                m.bytes = reseal(&s, &m.bytes, |share, _| {
                    let bumped = share.signing_share().to_scalar() + k256::Scalar::ONE;
                    *share = round2::Package::new(SigningShare::new(bumped));
                });
            }
        }
    });
    assert_eq!(out.error(3), Some(&DkgError::SecretShare { culprit: 2 }));
    for id in [1, 2] {
        assert_eq!(out.error(id), Some(&DkgError::Missing(vec![3])));
    }
    none_accepted(&out);
}

// ------------------------------------------------------------------------------------------
// D4: equivocation and the echo round
// ------------------------------------------------------------------------------------------

#[test]
fn d4_equivocation_is_caught_by_the_echo_before_any_share_is_sent() {
    let s = setup(2, 3, 30);
    let mut alt = rng(31);
    let cheater = s.host(2);
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round1 {
            for m in msgs.iter_mut().filter(|m| m.from == 2 && m.to == 3) {
                let (_, other) = zdkg::part1(identifier(2).unwrap(), 3, 2, &mut alt).unwrap();
                let e = decode(&m.bytes);
                m.bytes = resign(Envelope { payload: other.serialize().unwrap(), ..e }, &cheater);
            }
        }
    });
    for id in 1..=3 {
        assert!(matches!(out.error(id), Some(DkgError::ViewMismatch(_))), "{id}: {:?}", out.error(id));
    }
    assert_eq!(out.error(1), Some(&DkgError::ViewMismatch(vec![3])));
    assert_eq!(sent_in(&out, Round::Round2), 0, "a share was sent");
    none_accepted(&out);
}

/// Participant 2 sends package A to participant 1 and package B to everyone else, and shares
/// from the matching polynomial: what a device can do when there is no echo round.
struct Equivocator {
    host: SecretKey,
    rng: StdRng,
    s: Option<(Params, u16, [u8; 32])>,
    secrets: Vec<round1::SecretPackage>,
    others: BTreeMap<Identifier, round1::Package>,
}

impl Equivocator {
    fn env(&self, kind: Kind, to: u16, payload: Vec<u8>) -> Vec<u8> {
        let (_, me, id) = self.s.as_ref().unwrap();
        let kp = Keypair::from_secret_key(&Secp256k1::new(), &self.host);
        Envelope::new(kind, *id, *me, to, payload).signed(&kp).encode()
    }
}

impl Participant for Equivocator {
    fn host_public_key(&self) -> PublicKey {
        self.host.public_key(&Secp256k1::new())
    }

    fn start(&mut self, params: &Params, nonce: [u8; 32]) -> Result<Vec<Outgoing>, DkgError> {
        let me = params.identifier_of(&self.host_public_key()).unwrap();
        self.s = Some((params.clone(), me, params.session_id(&nonce)));
        let mut pkgs = vec![];
        for _ in 0..2 {
            let (sec, pkg) = zdkg::part1(identifier(me)?, params.n(), params.t(), &mut self.rng).unwrap();
            self.secrets.push(sec);
            pkgs.push(pkg.serialize().unwrap());
        }
        Ok(params
            .ids()
            .filter(|j| *j != me)
            .map(|j| Outgoing { to: j, bytes: self.env(Kind::Round1, j, pkgs[usize::from(j != 1)].clone()) })
            .collect())
    }

    fn on_round1(&mut self, inbox: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError> {
        for b in inbox {
            let e = decode(&b);
            self.others.insert(identifier(e.sender)?, round1::Package::deserialize(&e.payload).unwrap());
        }
        let (params, me, _) = self.s.clone().unwrap();
        Ok(params
            .ids()
            .filter(|j| *j != me)
            .map(|j| Outgoing { to: j, bytes: self.env(Kind::Echo, j, vec![0; 32]) })
            .collect())
    }

    fn on_echo(&mut self, _: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError> {
        let (params, me, id) = self.s.clone().unwrap();
        let b = self.secrets.pop().unwrap();
        let a = self.secrets.pop().unwrap();
        let (_, shares_a) = zdkg::part2(a, &self.others).unwrap();
        let (_, shares_b) = zdkg::part2(b, &self.others).unwrap();
        let mut out = vec![];
        for j in params.ids().filter(|j| *j != me) {
            let shares = if j == 1 { &shares_a } else { &shares_b };
            let plain = round2_plaintext(&shares[&identifier(j)?].serialize().unwrap(), None);
            let link = Link {
                session_id: &id,
                sender: me,
                sender_host: params.host(me).unwrap(),
                recipient: j,
                recipient_host: params.host(j).unwrap(),
            };
            let sealed = channel::seal(&self.host, &link, &plain, &mut self.rng)?;
            out.push(Outgoing { to: j, bytes: Envelope::new(Kind::Round2, id, me, j, sealed).encode() });
        }
        Ok(out)
    }

    fn on_round2(&mut self, _: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, DkgError> {
        Err(DkgError::Protocol("equivocator stops".into()))
    }

    fn on_certificates(&mut self, _: Vec<Vec<u8>>) -> Result<DeviceKey, DkgError> {
        Err(DkgError::Protocol("equivocator stops".into()))
    }
}

#[test]
fn d4_control_without_the_echo_check_devices_end_with_different_group_keys() {
    let s = setup(2, 3, 30);
    let mut seats: Vec<Box<dyn Participant>> = vec![];
    for id in [1, 3] {
        let mut d = s.device(id);
        d.skip_echo_check = true;
        seats.push(Box::new(d));
    }
    seats.push(Box::new(Equivocator {
        host: s.host(2),
        rng: rng(32),
        s: None,
        secrets: vec![],
        others: BTreeMap::new(),
    }));
    let mut c = Ceremony::new(s.params.clone(), seats).unwrap();
    let out = c.run(nonce(1));
    let key = |id| c.participant(id).unwrap().as_device().unwrap().part3_group_key.clone().unwrap();
    // Shares were sent, both honest devices finished part 3, and their group keys differ.
    assert!(sent_in(&out, Round::Round2) > 0);
    assert_ne!(key(1), key(3), "the equivocation went unnoticed: devices disagree on X");
    // The certificate still stops them from accepting.
    none_accepted(&out);
}

// ------------------------------------------------------------------------------------------
// D5: tampered ciphertext
// ------------------------------------------------------------------------------------------

#[test]
fn d5_flipped_ciphertext_bit_fails_authentication() {
    let s = setup(2, 3, 40);
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round2 {
            for m in msgs.iter_mut().filter(|m| m.from == 1 && m.to == 2) {
                *m.bytes.last_mut().unwrap() ^= 0x01;
            }
        }
    });
    assert_eq!(out.error(2), Some(&DkgError::Decrypt { sender: 1 }));
    assert!(!out.log.iter().any(|m| m.round == Round::Certify && m.from == 2));
    none_accepted(&out);
}

// ------------------------------------------------------------------------------------------
// D6: the coordinator never sees a secret
// ------------------------------------------------------------------------------------------

fn no_secrets_in_log(t: u16, n: u16, seed: u64) {
    let s = setup(t, n, seed);
    let mut c = Ceremony::new(s.params.clone(), s.honest_seats()).unwrap();
    let out = c.run(nonce(seed));
    assert!(sent_in(&out, Round::Round2) > 0);
    let mut secrets: Vec<(String, Vec<u8>)> = vec![];
    for id in s.params.ids() {
        let d = c.participant(id).unwrap().as_device().unwrap();
        for (i, share) in d.sent_shares.iter().enumerate() {
            secrets.push((format!("share {i} sent by {id}"), share.clone()));
        }
        let k = d.key().unwrap();
        secrets.push((format!("signing share of {id}"), k.key_package().signing_share().serialize()));
        secrets.push((format!("host secret of {id}"), s.host(id).secret_bytes().to_vec()));
        secrets.push(("b_scan".into(), k.b_scan().secret_bytes().to_vec()));
    }
    assert_eq!(secrets.len(), usize::from(n) * (usize::from(n) - 1 + 3));
    for m in &out.log {
        for (what, bytes) in &secrets {
            assert_eq!(bytes.len(), 32);
            assert!(!contains(&m.bytes, bytes), "{what} appears in a {:?} message", m.round);
        }
    }
}

#[test]
fn d6_log_holds_no_share_and_no_scan_key_2_of_3() {
    no_secrets_in_log(2, 3, 50);
}

#[test]
fn d6_log_holds_no_share_and_no_scan_key_3_of_5() {
    no_secrets_in_log(3, 5, 51);
}

// ------------------------------------------------------------------------------------------
// D7: replay, swapped sender, misrouting
// ------------------------------------------------------------------------------------------

#[test]
fn d7_replay_from_another_session_is_refused() {
    let s = setup(2, 3, 60);
    let first = Ceremony::new(s.params.clone(), s.honest_seats()).unwrap().run(nonce(1));
    let old = first.log.iter().find(|m| m.round == Round::Round1 && m.from == 2 && m.to == 1).unwrap().clone();
    let out = Ceremony::new(s.params.clone(), s.honest_seats())
        .unwrap()
        .with_hook(|round, msgs: &mut Vec<Transit>| {
            if round == Round::Round1 {
                for m in msgs.iter_mut().filter(|m| m.from == 2 && m.to == 1) {
                    m.bytes = old.bytes.clone();
                }
            }
        })
        .run(nonce(2));
    assert_eq!(out.error(1), Some(&DkgError::WrongSession { sender: 2 }));
    none_accepted(&out);
}

#[test]
fn d7_swapped_sender_is_refused_in_round_1_and_round_2() {
    let s = setup(2, 3, 61);
    // Round 1: the signature is 2's, the claimed sender 3.
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round1 {
            for m in msgs.iter_mut().filter(|m| m.from == 2 && m.to == 1) {
                let mut e = decode(&m.bytes);
                e.sender = 3;
                m.bytes = e.encode();
            }
        }
    });
    assert_eq!(out.error(1), Some(&DkgError::BadSignature { claimed_sender: 3 }));
    none_accepted(&out);
    // Round 2: the coordinator swaps the sender labels of two sealed messages.
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round2 {
            for m in msgs.iter_mut().filter(|m| m.to == 1) {
                let mut e = decode(&m.bytes);
                e.sender = if e.sender == 2 { 3 } else { 2 };
                m.bytes = e.encode();
            }
        }
    });
    assert_eq!(out.error(1), Some(&DkgError::Decrypt { sender: 2 }));
    none_accepted(&out);
}

#[test]
fn d7_misrouted_message_is_refused() {
    let s = setup(2, 3, 62);
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round1 {
            for m in msgs.iter_mut().filter(|m| m.from == 2 && m.to == 1) {
                m.to = 3;
            }
        }
    });
    assert_eq!(out.error(3), Some(&DkgError::Misrouted { sender: 2, recipient: 1 }));
    assert_eq!(out.error(1), Some(&DkgError::Missing(vec![2])));
    none_accepted(&out);
    // The same in round 2: a sealed share delivered to the wrong device.
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round2 {
            for m in msgs.iter_mut().filter(|m| m.from == 1 && m.to == 2) {
                m.to = 3;
            }
        }
    });
    assert_eq!(out.error(3), Some(&DkgError::Misrouted { sender: 1, recipient: 2 }));
    none_accepted(&out);
}

#[test]
fn d7_duplicates_and_missing_participants_are_refused() {
    let s = setup(2, 3, 63);
    let out = run_with(&s, |round, msgs| {
        if round == Round::Echo {
            let dup = msgs.iter().find(|m| m.from == 2 && m.to == 1).unwrap().clone();
            msgs.push(dup);
        }
    });
    assert_eq!(out.error(1), Some(&DkgError::Duplicate(2)));
    none_accepted(&out);
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round1 {
            msgs.retain(|m| !(m.from == 3 && m.to == 2));
        }
    });
    assert_eq!(out.error(2), Some(&DkgError::Missing(vec![3])));
    none_accepted(&out);
}

// ------------------------------------------------------------------------------------------
// D8: device 1 hands out different scan keys
// ------------------------------------------------------------------------------------------

#[test]
fn d8_different_scan_keys_break_the_transcript_and_nobody_accepts() {
    let s = setup(2, 3, 70);
    let other = SecretKey::new(&mut rng(71)).secret_bytes();
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round2 {
            for m in msgs.iter_mut().filter(|m| m.from == 1 && m.to == 3) {
                m.bytes = reseal(&s, &m.bytes, |_, scan| *scan = Some(other));
            }
        }
    });
    // Everyone finished part 3 and signed its own T; no T gathered all n signatures.
    assert_eq!(sent_in(&out, Round::Certify), 6);
    for id in 1..=3 {
        assert!(matches!(out.error(id), Some(DkgError::Certificate(_))), "{id}: {:?}", out.error(id));
    }
    none_accepted(&out);
}

#[test]
fn d8_scan_key_from_anyone_but_device_1_is_refused() {
    let s = setup(2, 3, 72);
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round2 {
            for m in msgs.iter_mut().filter(|m| m.from == 2 && m.to == 3) {
                m.bytes = reseal(&s, &m.bytes, |_, scan| *scan = Some([7; 32]));
            }
        }
    });
    assert_eq!(out.error(3), Some(&DkgError::ScanKey { sender: 2, reason: "only participant 1 sends the scan key".into() }));
    none_accepted(&out);
}

// ------------------------------------------------------------------------------------------
// D9: certificate
// ------------------------------------------------------------------------------------------

#[test]
fn d9_missing_or_forged_certificate_signature_means_no_acceptance() {
    let s = setup(2, 3, 80);
    let out = run_with(&s, |round, msgs| {
        if round == Round::Certify {
            msgs.retain(|m| !(m.from == 2 && m.to == 1));
        }
    });
    assert_eq!(out.error(1), Some(&DkgError::Missing(vec![2])));
    // Device 3 signs some other transcript (a well-formed, host-signed message).
    let cheater = s.host(3);
    let out = run_with(&s, |round, msgs| {
        if round == Round::Certify {
            for m in msgs.iter_mut().filter(|m| m.from == 3 && m.to == 1) {
                let e = decode(&m.bytes);
                let kp = Keypair::from_secret_key(&Secp256k1::new(), &cheater);
                let forged = super::wire::sign_host(&kp, &Message::from_digest([9; 32]));
                m.bytes = resign(Envelope { payload: forged.to_vec(), ..e }, &cheater);
            }
        }
    });
    assert!(matches!(out.error(1), Some(DkgError::Certificate(_))), "{:?}", out.error(1));
    assert!(out.results[&1].is_err());
}

#[test]
fn d9_a_stored_key_with_a_bad_certificate_does_not_load() {
    let ks = keys(run_honest(2, 3, 81));
    let other = keys(run_honest(2, 3, 82));
    let k = &ks[1];
    let rebuild = |cert: Certificate, pkp: &PublicKeyPackage| {
        DeviceKey::from_parts(
            k.identifier(),
            k.params().clone(),
            *k.host_secret(),
            k.key_package().clone(),
            pkp.clone(),
            *k.b_scan(),
            cert,
        )
    };
    rebuild(k.certificate().clone(), k.public_key_package()).unwrap();
    let mut c = k.certificate().clone();
    c.signatures.get_mut(&3).unwrap()[10] ^= 1;
    assert!(matches!(rebuild(c, k.public_key_package()), Err(DkgError::Certificate(_))));
    let mut c = k.certificate().clone();
    c.signatures.remove(&1);
    assert!(matches!(rebuild(c, k.public_key_package()), Err(DkgError::Certificate(_))));
    let mut c = k.certificate().clone();
    c.transcript_hash[0] ^= 1;
    assert!(matches!(rebuild(c, k.public_key_package()), Err(DkgError::Certificate(_))));
    let mut c = k.certificate().clone();
    c.session_nonce[0] ^= 1;
    assert!(matches!(rebuild(c, k.public_key_package()), Err(DkgError::Certificate(_))));
    // Another ceremony's public key package or certificate.
    assert!(rebuild(k.certificate().clone(), other[1].public_key_package()).is_err());
    assert!(rebuild(other[1].certificate().clone(), k.public_key_package()).is_err());
    // Another device's host key.
    let wrong_host = DeviceKey::from_parts(
        k.identifier(),
        k.params().clone(),
        *ks[0].host_secret(),
        k.key_package().clone(),
        k.public_key_package().clone(),
        *k.b_scan(),
        k.certificate().clone(),
    );
    assert!(matches!(wrong_host, Err(DkgError::KeyCheck(_))));
    // A different scan key.
    let wrong_scan = DeviceKey::from_parts(
        k.identifier(),
        k.params().clone(),
        *k.host_secret(),
        k.key_package().clone(),
        k.public_key_package().clone(),
        *other[1].b_scan(),
        k.certificate().clone(),
    );
    assert!(matches!(wrong_scan, Err(DkgError::Certificate(_))));
}

// ------------------------------------------------------------------------------------------
// D10: parameters and participants
// ------------------------------------------------------------------------------------------

#[test]
fn d10_bad_parameters_and_unknown_participants_are_refused() {
    let secp = Secp256k1::new();
    let pk = |i: u8| SecretKey::from_slice(&[i; 32]).unwrap().public_key(&secp);
    let three = vec![pk(1), pk(2), pk(3)];
    assert!(matches!(Params::new(4, 3, three.clone()), Err(DkgError::Params(_))));
    assert!(matches!(Params::new(1, 3, three.clone()), Err(DkgError::Params(_))));
    assert!(matches!(Params::new(0, 3, three.clone()), Err(DkgError::Params(_))));
    assert!(matches!(Params::new(2, 3, vec![pk(1), pk(2)]), Err(DkgError::Params(_))));
    assert!(matches!(Params::new(2, 1, vec![pk(1)]), Err(DkgError::Params(_))));
    let many: Vec<PublicKey> = (1..=33).map(pk).collect();
    assert!(matches!(Params::new(2, 33, many.clone()), Err(DkgError::Params(_))));
    assert!(Params::new(2, 32, many[..32].to_vec()).is_ok());
    assert!(matches!(Params::new(2, 3, vec![pk(1), pk(2), pk(1)]), Err(DkgError::Params(_))));
    // Same x coordinate, other parity: one BIP 340 identity.
    assert!(matches!(Params::new(2, 3, vec![pk(1), pk(2), pk(1).negate(&secp)]), Err(DkgError::Params(_))));
    assert!(Params::new(2, 3, three.clone()).is_ok());

    // A device whose host key is not in the list refuses to start; the coordinator refuses it.
    let s = setup(2, 3, 90);
    let mut outsider = Device::new(SecretKey::from_slice(&[9; 32]).unwrap(), rng(91));
    assert_eq!(Participant::start(&mut outsider, &s.params, nonce(1)), Err(DkgError::UnknownParticipant));
    let mut seats = s.honest_seats();
    seats[0] = Box::new(Device::new(SecretKey::from_slice(&[9; 32]).unwrap(), rng(91)));
    assert!(matches!(Ceremony::new(s.params.clone(), seats), Err(DkgError::UnknownParticipant)));
    let mut seats = s.honest_seats();
    seats[0] = Box::new(s.device(2));
    assert!(matches!(Ceremony::new(s.params.clone(), seats), Err(DkgError::Params(_))));

    // A message from an identifier outside 1..=n.
    let out = run_with(&s, |round, msgs| {
        if round == Round::Round1 {
            for m in msgs.iter_mut().filter(|m| m.from == 2 && m.to == 1) {
                let mut e = decode(&m.bytes);
                e.sender = 9;
                m.bytes = e.encode();
            }
        }
    });
    assert_eq!(out.error(1), Some(&DkgError::UnknownSender(9)));
    none_accepted(&out);
}

#[test]
fn a_device_refuses_steps_out_of_order_and_stays_aborted() {
    let s = setup(2, 3, 95);
    let mut d = s.device(1);
    assert!(matches!(Participant::on_echo(&mut d, vec![]), Err(DkgError::Protocol(_))));
    let e = d.error().cloned().unwrap();
    assert_eq!(Participant::start(&mut d, &s.params, nonce(1)), Err(e));
}

// ------------------------------------------------------------------------------------------
// D11 (library side): a device's key holds one signing share; its debug output none
// ------------------------------------------------------------------------------------------

#[test]
fn d11_a_device_key_debug_print_shows_no_secret() {
    let ks = keys(run_honest(2, 3, 96));
    let text = format!("{:?}", ks[0]);
    for k in &ks {
        assert!(!text.contains(&hex_of(&k.key_package().signing_share().serialize())));
    }
    assert!(!text.contains(&hex_of(&ks[0].b_scan().secret_bytes())));
    assert!(!text.contains(&hex_of(&ks[0].host_secret().secret_bytes())));
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
