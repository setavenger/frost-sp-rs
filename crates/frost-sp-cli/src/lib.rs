//! `frost-sp-signer`: the external signer of `docs/external-signer.md` (BlindBit test kit) for
//! a FROST Silent Payment wallet.
//!
//! **PoC ONLY.** The state file holds *every* key package of the `t`-of-`n` group (trusted
//! dealer), and one process plays all cosigners. A real deployment has one key package per
//! machine and runs the rounds over a network; the protocol code (`frost-sp-wallet::send`)
//! is the same. Nothing here ever reconstructs the group secret.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Transaction, Txid};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::Identifier;
use frost_sp_wallet::group::FrostGroup;
use frost_sp_wallet::send::{
    execute_send, plan_spend_exact, InputSource, Payment, PaymentDest, SendCoordinator,
    SpendableCoin,
};
use frost_sp_wallet::spend::Signer;
use frost_sp_wallet::wallet::SpWallet;
use rand::{CryptoRng, RngCore};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use silentpayments::{Network as SpNetwork, SilentPaymentCode};

pub const POC_WARNING: &str = "PoC ONLY: this file holds every key package of the group. \
A real FROST wallet keeps one key package per cosigner and never the group secret.";

// ------------------------------------------------------------------------------------------
// State file
// ------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct State {
    pub warning: String,
    pub min_signers: u16,
    pub max_signers: u16,
    /// 32-byte hex scan secret, held by every cosigner.
    pub scan_secret: String,
    /// Hex of `PublicKeyPackage::serialize`.
    pub public_key_package: String,
    /// Signer index (1-based) -> hex of `KeyPackage::serialize`.
    pub key_packages: BTreeMap<u16, String>,
}

/// What `dealer` prints, and what scenarios take as constants.
#[derive(Serialize, Deserialize)]
pub struct DealerOutput {
    pub scan_secret: String,
    pub spend_pubkey: String,
    pub min_signers: u16,
    pub max_signers: u16,
    /// Only with `--print-group-secret`: the reconstructed group secret `x`, so a scenario
    /// can also run against the test kit's single-key mock signer. **Test constants only.**
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_secret_for_mock_signer: Option<String>,
}

pub fn deal<R: RngCore + CryptoRng>(
    max: u16,
    min: u16,
    scan_secret: SecretKey,
    print_group_secret: bool,
    rng: &mut R,
) -> Result<(State, DealerOutput), String> {
    let group = FrostGroup::trusted_dealer(max, min, scan_secret, rng).map_err(|e| e.to_string())?;
    let mut key_packages = BTreeMap::new();
    for (id, kp) in &group.key_packages {
        let idx = identifier_index(id)?;
        key_packages.insert(idx, hex::encode(kp.serialize().map_err(|e| e.to_string())?));
    }
    let spend = group.b_spend().map_err(|e| e.to_string())?;
    let state = State {
        warning: POC_WARNING.into(),
        min_signers: min,
        max_signers: max,
        scan_secret: hex::encode(scan_secret.secret_bytes()),
        public_key_package: hex::encode(
            group.public_key_package.serialize().map_err(|e| e.to_string())?,
        ),
        key_packages,
    };
    let out = DealerOutput {
        scan_secret: state.scan_secret.clone(),
        spend_pubkey: hex::encode(spend.serialize()),
        min_signers: min,
        max_signers: max,
        group_secret_for_mock_signer: if print_group_secret {
            let kps: Vec<KeyPackage> = group.key_packages.values().take(usize::from(min)).cloned().collect();
            let x = frost_secp256k1_tr::keys::reconstruct(&kps).map_err(|e| e.to_string())?;
            Some(hex::encode(x.serialize()))
        } else {
            None
        },
    };
    Ok((state, out))
}

fn identifier_index(id: &Identifier) -> Result<u16, String> {
    // Default identifiers are 1..=n; their scalar serialisation is big-endian.
    let bytes = id.serialize();
    let (head, tail) = bytes.split_at(bytes.len() - 2);
    if head.iter().any(|b| *b != 0) {
        return Err("identifier out of range".into());
    }
    Ok(u16::from_be_bytes([tail[0], tail[1]]))
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

fn networks(name: &str) -> Result<(SpNetwork, bitcoin::Network), String> {
    // BIP 352: `tsp` serves testnet, signet and regtest alike.
    match name {
        "mainnet" => Ok((SpNetwork::Mainnet, bitcoin::Network::Bitcoin)),
        "signet" => Ok((SpNetwork::Testnet, bitcoin::Network::Signet)),
        "regtest" => Ok((SpNetwork::Testnet, bitcoin::Network::Regtest)),
        other => Err(format!("unknown network {other:?}")),
    }
}

// ------------------------------------------------------------------------------------------
// The signing session
// ------------------------------------------------------------------------------------------

pub struct Config {
    /// Cosigners that take part, default the first `min_signers`.
    pub signing_set: Option<Vec<u16>>,
}

/// Run one spend. Returns the signed transaction in witness serialisation, hex.
pub fn sign_request<R: RngCore + CryptoRng>(
    state: &State,
    env: &WalletEnv,
    request: &Request,
    config: &Config,
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

    // Key material: the state file must be this wallet.
    let pkp = PublicKeyPackage::deserialize(
        &hex::decode(&state.public_key_package).map_err(|x| e(&x))?,
    )
    .map_err(|x| e(&x))?;
    let group_key = pkp.verifying_key().serialize().map_err(|x| e(&x))?;
    if group_key.as_slice() != env.spend_pubkey.serialize().as_slice() {
        return Err("the state file's group key is not BLINDBIT_SIGNER_SPEND_PUBKEY".into());
    }
    if hex::encode(env.scan_secret.secret_bytes()) != state.scan_secret {
        return Err("the state file's scan secret is not BLINDBIT_SIGNER_SCAN_SECRET".into());
    }

    let make_wallet = || -> Result<SpWallet, String> {
        let mut w =
            SpWallet::new(env.scan_secret, env.spend_pubkey, sp_net).map_err(|x| e(&x))?;
        for m in &env.labels {
            if *m != 0 {
                w.add_label(*m).map_err(|x| e(&x))?;
            }
        }
        Ok(w)
    };
    let coordinator = SendCoordinator::new(pkp.clone(), make_wallet()?);
    let mut signers = vec![];
    for (idx, kp_hex) in &state.key_packages {
        let kp = KeyPackage::deserialize(&hex::decode(kp_hex).map_err(|x| e(&x))?)
            .map_err(|x| e(&x))?;
        let signer = Signer::new(format!("signer-{idx}"), kp, make_wallet()?)
            .map_err(|x| e(&x))?
            .with_public_key_package(pkp.clone());
        signers.push(signer);
    }
    let signing_set: Vec<Identifier> = match &config.signing_set {
        Some(ids) => ids.clone(),
        None => (1..=state.min_signers).collect(),
    }
    .into_iter()
    .map(|i| Identifier::try_from(i).map_err(|x| e(&x)))
    .collect::<Result<_, _>>()?;
    if signing_set.len() < usize::from(state.min_signers) {
        return Err(format!("signing set smaller than the threshold {}", state.min_signers));
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
