//! `frost-sp-signer`: the external signer of `docs/external-signer.md` (BlindBit test kit) for
//! a FROST Silent Payment wallet.
//!
//! Keys come from a distributed key generation (`frost_sp_wallet::dkg`): `keygen` runs a
//! simulated ceremony between `n` devices and writes one file per device, each holding that
//! device's single signing share, the group's public data, `b_scan`, its host key and the
//! ceremony certificate. The signer loads one file per participating device into its own
//! [`Signer`]. **PoC:** the devices of `keygen` and the cosigners of one signing run share a
//! process; their state, secrets and messages are separate. Nothing here reconstructs the group
//! secret except the test-only `reconstruct-test-secret` subcommand, which the signer never uses.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Transaction, Txid};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::Identifier;
use frost_sp_wallet::dkg::{keygen, Certificate, DeviceKey, Params};
use frost_sp_wallet::send::{
    execute_send, plan_spend_exact, InputSource, Payment, PaymentDest, SendCoordinator,
    SpendableCoin,
};
use frost_sp_wallet::spend::Signer;
use frost_sp_wallet::wallet::SpWallet;
use rand::rngs::{OsRng, StdRng};
use rand::{CryptoRng, RngCore, SeedableRng};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use silentpayments::{Network as SpNetwork, SilentPaymentCode};

pub const DEVICE_FORMAT: &str = "frost-sp-device/1";
pub const DEVICE_WARNING: &str = "One FROST cosigner device: this file holds exactly one signing \
share of the group, the group's scan key and this device's host key. Keep it on that device only.";
pub const SEEDED_WARNING: &str = "TEST ONLY: made with keygen --seed. Every secret in this file \
follows from the seed. Never use it for real funds.";

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| format!("{what}: {e}"))?
        .try_into()
        .map_err(|_| format!("{what}: want 32 bytes"))
}

// ------------------------------------------------------------------------------------------
// Device files
// ------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateFile {
    pub session_nonce: String,
    pub session_id: String,
    /// Identifier -> hex of the serialized round-1 package (commitments, proof of knowledge).
    pub round1_packages: BTreeMap<u16, String>,
    pub transcript_hash: String,
    /// Identifier -> hex BIP 340 signature on the transcript hash by that host key.
    pub signatures: BTreeMap<u16, String>,
}

/// One device's state file. Strict: unknown fields are refused, so a file cannot smuggle in a
/// second key package.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFile {
    pub format: String,
    pub warning: String,
    /// Set by `keygen --seed`: every secret follows from this seed. `reconstruct-test-secret`
    /// re-derives the group from it before trusting it; elsewhere it is an advisory mark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_only_seed: Option<u64>,
    pub identifier: u16,
    pub min_signers: u16,
    pub max_signers: u16,
    /// The participant list: host public keys sorted, identifier `i` at index `i - 1`.
    pub host_pubkeys: Vec<String>,
    pub host_secret: String,
    /// Hex of `KeyPackage::serialize`: this device's one signing share.
    pub key_package: String,
    /// Hex of `PublicKeyPackage::serialize`: `X` and every `X_i`.
    pub public_key_package: String,
    /// `b_scan`, held by every cosigner.
    pub scan_secret: String,
    pub certificate: CertificateFile,
    /// Shown for comparison; recomputed and checked on load.
    pub check_code: String,
    pub spend_pubkey: String,
}

impl DeviceFile {
    pub fn from_key(k: &DeviceKey, seed: Option<u64>) -> Result<Self, String> {
        let e = |x: &dyn std::fmt::Display| x.to_string();
        let c = k.certificate();
        Ok(Self {
            format: DEVICE_FORMAT.into(),
            warning: if seed.is_some() { SEEDED_WARNING } else { DEVICE_WARNING }.into(),
            test_only_seed: seed,
            identifier: k.identifier(),
            min_signers: k.params().t(),
            max_signers: k.params().n(),
            host_pubkeys: k.params().hosts().iter().map(|h| hex::encode(h.serialize())).collect(),
            host_secret: hex::encode(k.host_secret().secret_bytes()),
            key_package: hex::encode(k.key_package().serialize().map_err(|x| e(&x))?),
            public_key_package: hex::encode(k.public_key_package().serialize().map_err(|x| e(&x))?),
            scan_secret: hex::encode(k.b_scan().secret_bytes()),
            certificate: CertificateFile {
                session_nonce: hex::encode(c.session_nonce),
                session_id: hex::encode(c.session_id),
                round1_packages: c.round1_packages.iter().map(|(i, p)| (*i, hex::encode(p))).collect(),
                transcript_hash: hex::encode(c.transcript_hash),
                signatures: c.signatures.iter().map(|(i, s)| (*i, hex::encode(s))).collect(),
            },
            check_code: k.check_code(),
            spend_pubkey: hex::encode(k.b_spend().map_err(|x| e(&x))?.serialize()),
        })
    }

    /// Parse and verify: the certificate, the key material and the shown values must all check
    /// out (`DeviceKey::verify`).
    pub fn load(&self) -> Result<DeviceKey, String> {
        let e = |x: &dyn std::fmt::Display| x.to_string();
        if self.format != DEVICE_FORMAT {
            return Err(format!("unknown device file format {:?}", self.format));
        }
        let hosts = self
            .host_pubkeys
            .iter()
            .map(|h| PublicKey::from_slice(&hex::decode(h).map_err(|x| e(&x))?).map_err(|x| e(&x)))
            .collect::<Result<Vec<_>, _>>()?;
        let params = Params::new(self.min_signers, self.max_signers, hosts.clone()).map_err(|x| e(&x))?;
        if params.hosts() != hosts.as_slice() {
            return Err("host_pubkeys are not sorted".into());
        }
        let c = &self.certificate;
        let certificate = Certificate {
            session_nonce: hex32(&c.session_nonce, "session_nonce")?,
            session_id: hex32(&c.session_id, "session_id")?,
            round1_packages: c
                .round1_packages
                .iter()
                .map(|(i, p)| Ok((*i, hex::decode(p).map_err(|x| e(&x))?)))
                .collect::<Result<_, String>>()?,
            transcript_hash: hex32(&c.transcript_hash, "transcript_hash")?,
            signatures: c
                .signatures
                .iter()
                .map(|(i, s)| {
                    let b: [u8; 64] = hex::decode(s)
                        .map_err(|x| e(&x))?
                        .try_into()
                        .map_err(|_| "signature: want 64 bytes".to_string())?;
                    Ok((*i, b))
                })
                .collect::<Result<_, String>>()?,
        };
        let key = DeviceKey::from_parts(
            self.identifier,
            params,
            SecretKey::from_slice(&hex32(&self.host_secret, "host_secret")?).map_err(|x| e(&x))?,
            KeyPackage::deserialize(&hex::decode(&self.key_package).map_err(|x| e(&x))?).map_err(|x| e(&x))?,
            PublicKeyPackage::deserialize(&hex::decode(&self.public_key_package).map_err(|x| e(&x))?)
                .map_err(|x| e(&x))?,
            SecretKey::from_slice(&hex32(&self.scan_secret, "scan_secret")?).map_err(|x| e(&x))?,
            certificate,
        )
        .map_err(|x| format!("device {}: {x}", self.identifier))?;
        if key.check_code() != self.check_code
            || hex::encode(key.b_spend().map_err(|x| e(&x))?.serialize()) != self.spend_pubkey
        {
            return Err("check_code/spend_pubkey do not match the key material".into());
        }
        Ok(key)
    }
}

/// What `keygen` prints. `scan_secret` only for seeded (test) runs.
#[derive(Serialize, Deserialize)]
pub struct KeygenOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    pub min_signers: u16,
    pub max_signers: u16,
    pub spend_pubkey: String,
    pub sp_address: String,
    pub check_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_secret: Option<String>,
    pub devices: Vec<KeygenDevice>,
}

/// What each device shows the user: compare the check code and address across devices.
#[derive(Serialize, Deserialize)]
pub struct KeygenDevice {
    pub identifier: u16,
    pub file: String,
    pub check_code: String,
    pub sp_address: String,
}

pub fn networks(name: &str) -> Result<(SpNetwork, bitcoin::Network), String> {
    // BIP 352: `tsp` serves testnet, signet and regtest alike.
    match name {
        "mainnet" => Ok((SpNetwork::Mainnet, bitcoin::Network::Bitcoin)),
        "signet" => Ok((SpNetwork::Testnet, bitcoin::Network::Signet)),
        "regtest" => Ok((SpNetwork::Testnet, bitcoin::Network::Regtest)),
        other => Err(format!("unknown network {other:?}")),
    }
}

/// The simulated ceremony: fresh randomness, or (test only) everything from `seed`.
fn ceremony(t: u16, n: u16, seed: Option<u64>) -> Result<Vec<DeviceKey>, String> {
    match seed {
        Some(s) => keygen(t, n, &mut StdRng::seed_from_u64(s)),
        None => keygen(t, n, &mut OsRng),
    }
    .map_err(|x| format!("key generation failed: {x}"))
}

/// Run the simulated ceremony and describe its result. A `seed` marks the files test-only.
pub fn run_keygen(
    t: u16,
    n: u16,
    network: &str,
    seed: Option<u64>,
) -> Result<(Vec<DeviceFile>, KeygenOutput), String> {
    let e = |x: &dyn std::fmt::Display| x.to_string();
    let seeded = seed.is_some();
    let (sp_net, _) = networks(network)?;
    if seeded && sp_net == SpNetwork::Mainnet {
        return Err("--seed is test-only and refused on mainnet".into());
    }
    let keys = ceremony(t, n, seed)?;
    let mut files = vec![];
    let mut devices = vec![];
    for k in &keys {
        files.push(DeviceFile::from_key(k, seed)?);
        devices.push(KeygenDevice {
            identifier: k.identifier(),
            file: format!("device-{}.json", k.identifier()),
            check_code: k.check_code(),
            sp_address: k.sp_address(sp_net).map_err(|x| e(&x))?.to_string(),
        });
    }
    let first = keys.first().ok_or("no devices")?;
    let out = KeygenOutput {
        warning: seeded.then(|| SEEDED_WARNING.to_string()),
        min_signers: t,
        max_signers: n,
        spend_pubkey: hex::encode(first.b_spend().map_err(|x| e(&x))?.serialize()),
        sp_address: devices[0].sp_address.clone(),
        check_code: first.check_code(),
        scan_secret: seeded.then(|| hex::encode(first.b_scan().secret_bytes())),
        devices,
    };
    Ok((files, out))
}

/// Load the devices taking part in one run (at least `t`). Refuses duplicate identifiers and
/// devices from different ceremonies (group key or certificate differ).
pub fn load_devices(files: &[DeviceFile]) -> Result<Vec<DeviceKey>, String> {
    let keys = load_each(files)?;
    let t = keys.first().map_or(0, |k| k.params().t());
    if keys.len() < usize::from(t) {
        return Err(format!("{} device files for a threshold of {t}", keys.len()));
    }
    Ok(keys)
}

fn load_each(files: &[DeviceFile]) -> Result<Vec<DeviceKey>, String> {
    let mut keys: Vec<DeviceKey> = vec![];
    for f in files {
        let k = f.load()?;
        if let Some(first) = keys.first() {
            if k.public_key_package().verifying_key() != first.public_key_package().verifying_key() {
                return Err(format!("device {} has another group key", k.identifier()));
            }
            if k.certificate() != first.certificate() {
                return Err(format!("device {} has another certificate", k.identifier()));
            }
        }
        if keys.iter().any(|o| o.identifier() == k.identifier()) {
            return Err(format!("two state files for device {}", k.identifier()));
        }
        keys.push(k);
    }
    Ok(keys)
}

/// What `reconstruct-test-secret` prints: constants for the test kit's single-key mock signer.
#[derive(Serialize, Deserialize)]
pub struct TestSecretOutput {
    pub warning: String,
    pub spend_pubkey: String,
    pub scan_secret: String,
    pub group_secret_for_mock_signer: String,
}

/// **Test only.** Reconstruct `x` from `t` device files of a *seeded* (test) group and check
/// `x·G == X`. The group must re-derive from the recorded seed, so a real group's files cannot
/// be passed off as test data by editing the mark. Never used by the signer.
pub fn reconstruct_test_secret(files: &[DeviceFile]) -> Result<TestSecretOutput, String> {
    let e = |x: &dyn std::fmt::Display| x.to_string();
    let keys = load_devices(files)?;
    let first = keys.first().ok_or("no device files")?;
    let seed = files[0].test_only_seed;
    if seed.is_none() || files.iter().any(|f| f.test_only_seed != seed) {
        return Err("reconstruct-test-secret only accepts device files of one seeded test group".into());
    }
    let again = ceremony(first.params().t(), first.params().n(), seed)?;
    if again.first().map(DeviceKey::certificate) != Some(first.certificate()) {
        return Err("these device files do not come from their recorded test seed".into());
    }
    let kps: Vec<KeyPackage> = keys.iter().map(|k| k.key_package().clone()).collect();
    let x = frost_secp256k1_tr::keys::reconstruct(&kps).map_err(|x| e(&x))?;
    let sk = SecretKey::from_slice(&x.serialize()).map_err(|x| e(&x))?;
    let spend = first.b_spend().map_err(|x| e(&x))?;
    if sk.public_key(&secp256k1::Secp256k1::new()) != spend {
        return Err("reconstruction does not match the group key".into());
    }
    Ok(TestSecretOutput {
        warning: "TEST ONLY: the reconstructed group secret of a seeded test group.".into(),
        spend_pubkey: hex::encode(spend.serialize()),
        scan_secret: hex::encode(first.b_scan().secret_bytes()),
        group_secret_for_mock_signer: hex::encode(sk.secret_bytes()),
    })
}

// ------------------------------------------------------------------------------------------
// Wire types (docs/external-signer.md)
// ------------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct Request {
    pub network: String,
    #[serde(default)]
    pub fee_rate_sat_vb: u64,
    #[serde(default)]
    pub change_address: String,
    pub destinations: Vec<Destination>,
    pub utxos: Vec<Utxo>,
}

#[derive(Deserialize)]
pub struct Destination {
    pub address: String,
    pub amount_sats: u64,
}

#[derive(Deserialize)]
pub struct Prevout {
    pub script_pubkey: String,
    #[allow(dead_code)]
    pub value_sats: u64,
}

#[derive(Deserialize)]
pub struct Utxo {
    pub outpoint: String,
    pub value_sats: u64,
    pub script_pubkey: String,
    pub funding_tx_hex: String,
    #[serde(default)]
    pub funding_prevouts: Vec<Prevout>,
    /// Informational only. Never used: every signer re-derives the tweak from the funding
    /// transaction with its own `b_scan`.
    #[serde(default)]
    #[allow(dead_code)]
    pub tweak: String,
}

/// The wallet configuration the test kit passes in the environment.
pub struct WalletEnv {
    pub network: String,
    pub scan_secret: SecretKey,
    pub spend_pubkey: PublicKey,
    pub labels: Vec<u32>,
}

impl WalletEnv {
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let need = |k: &str| get(k).ok_or_else(|| format!("environment variable {k} is not set"));
        let scan = hex::decode(need("BLINDBIT_SIGNER_SCAN_SECRET")?.trim())
            .map_err(|e| format!("BLINDBIT_SIGNER_SCAN_SECRET: {e}"))?;
        let spend = hex::decode(need("BLINDBIT_SIGNER_SPEND_PUBKEY")?.trim())
            .map_err(|e| format!("BLINDBIT_SIGNER_SPEND_PUBKEY: {e}"))?;
        let labels = get("BLINDBIT_SIGNER_LABELS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.trim()
                    .parse::<u32>()
                    .map_err(|e| format!("BLINDBIT_SIGNER_LABELS: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            network: need("BLINDBIT_SIGNER_NETWORK")?,
            scan_secret: SecretKey::from_slice(&scan)
                .map_err(|e| format!("BLINDBIT_SIGNER_SCAN_SECRET: {e}"))?,
            spend_pubkey: PublicKey::from_slice(&spend)
                .map_err(|e| format!("BLINDBIT_SIGNER_SPEND_PUBKEY: {e}"))?,
            labels,
        })
    }
}

// ------------------------------------------------------------------------------------------
// The signing session
// ------------------------------------------------------------------------------------------

/// Run one spend with the loaded devices (one [`Signer`] each; all of them sign). Returns the
/// signed transaction in witness serialisation, hex.
pub fn sign_request<R: RngCore + CryptoRng>(
    devices: &[DeviceKey],
    seeded: bool,
    env: &WalletEnv,
    request: &Request,
    rng: &mut R,
) -> Result<String, String> {
    let e = |x: &dyn std::fmt::Display| x.to_string();
    if request.network != env.network {
        return Err(format!(
            "request network {:?} differs from the wallet's {:?}",
            request.network, env.network
        ));
    }
    let (sp_net, btc_net) = networks(&env.network)?;
    if seeded && sp_net == SpNetwork::Mainnet {
        return Err("a seeded (test-only) device file is refused on mainnet".into());
    }
    let first = devices.first().ok_or("no device state files")?;
    let t = first.params().t();
    if devices.len() < usize::from(t) {
        return Err(format!("{} device files for a threshold of {t}", devices.len()));
    }

    // Key material: the devices must be this wallet.
    let pkp = first.public_key_package().clone();
    if first.b_spend().map_err(|x| e(&x))? != env.spend_pubkey {
        return Err("the state files' group key is not BLINDBIT_SIGNER_SPEND_PUBKEY".into());
    }
    if *first.b_scan() != env.scan_secret {
        return Err("the state files' scan secret is not BLINDBIT_SIGNER_SCAN_SECRET".into());
    }

    let make_wallet = |b_scan: SecretKey| -> Result<SpWallet, String> {
        let mut w = SpWallet::new(b_scan, env.spend_pubkey, sp_net).map_err(|x| e(&x))?;
        for m in &env.labels {
            if *m != 0 {
                w.add_label(*m).map_err(|x| e(&x))?;
            }
        }
        Ok(w)
    };
    let coordinator = SendCoordinator::new(pkp.clone(), make_wallet(env.scan_secret)?);
    let mut signers = vec![];
    let mut signing_set: Vec<Identifier> = vec![];
    for d in devices {
        // Each signer gets only its own device's key package and scan key.
        let signer = Signer::new(
            format!("device-{}", d.identifier()),
            d.key_package().clone(),
            make_wallet(*d.b_scan())?,
        )
        .map_err(|x| e(&x))?
        .with_public_key_package(d.public_key_package().clone());
        signing_set.push(*d.key_package().identifier());
        signers.push(signer);
    }

    // Coins.
    let mut coins = vec![];
    for u in &request.utxos {
        coins.push(parse_coin(u)?);
    }

    // Destinations and change.
    let mut payments = vec![];
    for d in &request.destinations {
        payments.push(Payment {
            dest: parse_dest(&d.address, btc_net)?,
            amount: Amount::from_sat(d.amount_sats),
        });
    }
    let change = if request.change_address.is_empty() {
        None
    } else {
        Some(parse_dest(&request.change_address, btc_net)?)
    };

    // Spend exactly these coins; refuses sum g = 0 before any share is released.
    let plan = plan_spend_exact(
        coordinator.wallet(),
        &coins,
        &payments,
        change.as_ref(),
        request.fee_rate_sat_vb,
    )
    .map_err(|x| e(&x))?;
    let tx = execute_send(&coordinator, &mut signers, &signing_set, &plan, rng)
        .map_err(|x| e(&x))?;
    Ok(hex::encode(serialize(&tx)))
}

fn parse_dest(address: &str, net: bitcoin::Network) -> Result<PaymentDest, String> {
    if let Ok(code) = SilentPaymentCode::try_from(address) {
        // `tsp` serves testnet, signet and regtest alike; `sp` only mainnet.
        let want = if net == bitcoin::Network::Bitcoin { SpNetwork::Mainnet } else { SpNetwork::Testnet };
        if code.network() != want {
            return Err(format!("destination {address:?}: silent payment address is for another network"));
        }
        return Ok(PaymentDest::Sp(code));
    }
    let a = Address::from_str(address)
        .map_err(|x| format!("destination {address:?}: not a silent payment or plain address: {x}"))?
        .require_network(net)
        .map_err(|x| format!("destination {address:?}: {x}"))?;
    Ok(PaymentDest::Script(a.script_pubkey()))
}

fn parse_coin(u: &Utxo) -> Result<SpendableCoin, String> {
    let (txid, vout) = u
        .outpoint
        .split_once(':')
        .ok_or_else(|| format!("outpoint {:?}: want txid:vout", u.outpoint))?;
    let outpoint = OutPoint {
        txid: Txid::from_str(txid).map_err(|x| format!("outpoint {:?}: {x}", u.outpoint))?,
        vout: vout.parse().map_err(|x| format!("outpoint {:?}: {x}", u.outpoint))?,
    };
    let funding_tx: Transaction = deserialize(
        &hex::decode(&u.funding_tx_hex).map_err(|x| format!("funding_tx_hex: {x}"))?,
    )
    .map_err(|x| format!("funding_tx_hex: {x}"))?;
    if funding_tx.compute_txid() != outpoint.txid {
        return Err(format!("{}: funding_tx_hex is not the transaction {}", u.outpoint, outpoint.txid));
    }
    let out = funding_tx
        .output
        .get(outpoint.vout as usize)
        .ok_or_else(|| format!("{}: the funding transaction has no such output", u.outpoint))?;
    // The request's claims are cross-checked against the funding transaction, never trusted.
    let spk = ScriptBuf::from_hex(&u.script_pubkey).map_err(|x| format!("script_pubkey: {x}"))?;
    if out.script_pubkey != spk || out.value.to_sat() != u.value_sats {
        return Err(format!(
            "{}: script_pubkey/value_sats differ from the funding transaction's output",
            u.outpoint
        ));
    }
    let prevout_spks = u
        .funding_prevouts
        .iter()
        .map(|p| ScriptBuf::from_hex(&p.script_pubkey).map_err(|x| format!("funding_prevouts: {x}")))
        .collect::<Result<Vec<_>, _>>()?;
    if prevout_spks.len() != funding_tx.input.len() {
        return Err(format!(
            "{}: {} funding_prevouts for {} inputs of the funding transaction",
            u.outpoint,
            prevout_spks.len(),
            funding_tx.input.len()
        ));
    }
    let value = out.value;
    Ok(SpendableCoin {
        source: InputSource {
            funding_tx,
            funding_prevout_spks: prevout_spks,
            funding_vout: outpoint.vout,
        },
        value,
    })
}
