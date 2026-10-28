//! `frost-sp-signer`: PoC external signer for the BlindBit test kit. See `lib.rs`.
//!
//! ```text
//! frost-sp-signer dealer --out state.json [--max 3] [--min 2] [--scan-secret HEX] [--seed N]
//!                         [--print-group-secret]   # test constants only: lets the mock signer run too
//! frost-sp-signer [--state state.json] [--signing-set 1,3]      # stdin JSON -> stdout JSON
//! ```
//!
//! The state file may also come from `FROST_SP_STATE`. Wallet configuration is read from the
//! `BLINDBIT_SIGNER_*` environment variables, the request from stdin.

use std::io::Read;
use std::process::ExitCode;

use frost_sp_cli::{deal, sign_request, Config, Request, State, WalletEnv};
use rand::rngs::{OsRng, StdRng};
use rand::{RngCore, SeedableRng};
use secp256k1::SecretKey;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.first().map(String::as_str) == Some("dealer") {
        dealer(&args[1..])
    } else {
        sign(&args)
    };
    match result {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{}", serde_json::json!({ "error": e }));
            ExitCode::FAILURE
        }
    }
}

const VALUE_FLAGS: [&str; 7] = ["--out", "--max", "--min", "--scan-secret", "--seed", "--state", "--signing-set"];
const BOOL_FLAGS: [&str; 1] = ["--print-group-secret"];

/// Value of `--name value`; a boolean flag yields `Some("")` when present.
fn flag(args: &[String], name: &str) -> Result<Option<String>, String> {
    let mut found = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let is_value = VALUE_FLAGS.contains(&a.as_str());
        if !is_value && !BOOL_FLAGS.contains(&a.as_str()) {
            return Err(format!("unexpected argument {a:?}"));
        }
        let value = if is_value {
            it.next().ok_or_else(|| format!("{a} needs a value"))?.clone()
        } else {
            String::new()
        };
        if a == name {
            found = Some(value);
        }
    }
    Ok(found)
}

fn dealer(args: &[String]) -> Result<String, String> {
    let out = flag(args, "--out")?.ok_or("dealer needs --out <state file>")?;
    let max: u16 = flag(args, "--max")?.map_or(Ok(3), |s| s.parse().map_err(|e| format!("--max: {e}")))?;
    let min: u16 = flag(args, "--min")?.map_or(Ok(2), |s| s.parse().map_err(|e| format!("--min: {e}")))?;
    // --seed makes the scenario constants reproducible. PoC only: a seeded dealer is not secret.
    let mut rng: Box<dyn RngCore> = match flag(args, "--seed")? {
        Some(s) => Box::new(StdRng::seed_from_u64(s.parse().map_err(|e| format!("--seed: {e}"))?)),
        None => Box::new(OsRng),
    };
    let scan = match flag(args, "--scan-secret")? {
        Some(h) => SecretKey::from_slice(&hex::decode(h).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
        None => loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            if let Ok(k) = SecretKey::from_slice(&b) {
                break k;
            }
        },
    };
    struct Dyn<'a>(&'a mut dyn RngCore);
    impl RngCore for Dyn<'_> {
        fn next_u32(&mut self) -> u32 { self.0.next_u32() }
        fn next_u64(&mut self) -> u64 { self.0.next_u64() }
        fn fill_bytes(&mut self, d: &mut [u8]) { self.0.fill_bytes(d) }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand::Error> { self.0.try_fill_bytes(d) }
    }
    impl rand::CryptoRng for Dyn<'_> {}
    let (state, printed) = deal(max, min, scan, flag(args, "--print-group-secret")?.is_some(), &mut Dyn(rng.as_mut()))?;
    let json = serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?;
    std::fs::write(&out, json + "\n").map_err(|e| format!("{out}: {e}"))?;
    serde_json::to_string_pretty(&printed).map_err(|e| e.to_string())
}

fn sign(args: &[String]) -> Result<String, String> {
    let path = flag(args, "--state")?
        .or_else(|| std::env::var("FROST_SP_STATE").ok())
        .ok_or("no state file: pass --state <file> or set FROST_SP_STATE")?;
    let signing_set = flag(args, "--signing-set")?
        .map(|s| {
            s.split(',')
                .map(|i| i.trim().parse::<u16>().map_err(|e| format!("--signing-set: {e}")))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let state: State = serde_json::from_str(
        &std::fs::read_to_string(&path).map_err(|e| format!("state file {path}: {e}"))?,
    )
    .map_err(|e| format!("state file {path}: {e}"))?;
    let env = WalletEnv::from_env(|k| std::env::var(k).ok())?;
    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin).map_err(|e| format!("stdin: {e}"))?;
    let request: Request = serde_json::from_str(&stdin).map_err(|e| format!("request: {e}"))?;
    let tx_hex = sign_request(&state, &env, &request, &Config { signing_set }, &mut OsRng)?;
    Ok(serde_json::json!({ "tx_hex": tx_hex }).to_string())
}
