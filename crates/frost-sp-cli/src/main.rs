//! `frost-sp-signer`: PoC external signer for the BlindBit test kit. See `lib.rs`.
//!
//! ```text
//! frost-sp-signer keygen --n 3 --t 2 --out-dir DIR [--network regtest] [--seed N]
//!     # simulated DKG ceremony; writes DIR/device-<i>.json (one signing share each).
//!     # --seed: reproducible TEST constants, refused on mainnet.
//! frost-sp-signer --state device-1.json --state device-3.json     # stdin JSON -> stdout JSON
//!     # one --state per participating device (at least t); all of them sign.
//! frost-sp-signer reconstruct-test-secret --state device-1.json --state device-2.json
//!     # TEST ONLY: x from t files of a seeded group, for the test kit's mock signer.
//! ```
//!
//! `FROST_SP_STATE` (paths separated by `:`) may replace the `--state` flags. Wallet
//! configuration is read from the `BLINDBIT_SIGNER_*` environment variables, the request from
//! stdin.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use frost_sp_cli::{
    load_devices, reconstruct_test_secret, run_keygen, sign_request, DeviceFile, Request,
    WalletEnv,
};
use rand::rngs::{OsRng, StdRng};
use rand::{RngCore, SeedableRng};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("reconstruct-test-secret") => reconstruct(&args[1..]),
        Some("dealer") => Err("the trusted dealer is gone: use `keygen` (distributed key generation)".into()),
        _ => sign(&args),
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

/// `--name value` pairs; every argument must be one of `allowed`.
fn parse(args: &[String], allowed: &[&str]) -> Result<Vec<(String, String)>, String> {
    let mut out = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if !allowed.contains(&a.as_str()) {
            return Err(format!("unexpected argument {a:?}"));
        }
        let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
        out.push((a.clone(), v.clone()));
    }
    Ok(out)
}

/// The value of a flag given at most once.
fn one(pairs: &[(String, String)], name: &str) -> Result<Option<String>, String> {
    let mut vals = pairs.iter().filter(|(k, _)| k == name).map(|(_, v)| v.clone());
    let first = vals.next();
    if vals.next().is_some() {
        return Err(format!("{name} given twice"));
    }
    Ok(first)
}

fn number<T: std::str::FromStr>(pairs: &[(String, String)], name: &str) -> Result<Option<T>, String>
where
    T::Err: std::fmt::Display,
{
    one(pairs, name)?
        .map(|s| s.parse::<T>().map_err(|e| format!("{name}: {e}")))
        .transpose()
}

fn keygen(args: &[String]) -> Result<String, String> {
    let p = parse(args, &["--n", "--t", "--out-dir", "--seed", "--network"])?;
    let n: u16 = number(&p, "--n")?.ok_or("keygen needs --n <devices>")?;
    let t: u16 = number(&p, "--t")?.ok_or("keygen needs --t <threshold>")?;
    let dir = one(&p, "--out-dir")?.ok_or("keygen needs --out-dir <dir>")?;
    let network = one(&p, "--network")?.unwrap_or_else(|| "regtest".into());
    let seed: Option<u64> = number(&p, "--seed")?;
    // --seed: reproducible test constants. Every secret then follows from the seed.
    let mut rng: Box<dyn RngCore> = match seed {
        Some(s) => Box::new(StdRng::seed_from_u64(s)),
        None => Box::new(OsRng),
    };
    struct Dyn<'a>(&'a mut dyn RngCore);
    impl RngCore for Dyn<'_> {
        fn next_u32(&mut self) -> u32 { self.0.next_u32() }
        fn next_u64(&mut self) -> u64 { self.0.next_u64() }
        fn fill_bytes(&mut self, d: &mut [u8]) { self.0.fill_bytes(d) }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand::Error> { self.0.try_fill_bytes(d) }
    }
    impl rand::CryptoRng for Dyn<'_> {}
    let (files, out) = run_keygen(t, n, &network, seed.is_some(), &mut Dyn(rng.as_mut()))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{dir}: {e}"))?;
    for (f, d) in files.iter().zip(&out.devices) {
        let json = serde_json::to_string_pretty(f).map_err(|e| e.to_string())?;
        write_private(&Path::new(&dir).join(&d.file), &(json + "\n"))?;
    }
    serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
}

/// Owner-only (0600), and never overwrite: a device file holds a signing share.
fn write_private(path: &Path, content: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let shown = path.display();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{shown}: {e} (keygen never overwrites a device file)"))?;
    f.write_all(content.as_bytes()).map_err(|e| format!("{shown}: {e}"))
}

/// The `--state` files (or `FROST_SP_STATE`), parsed but not yet verified.
fn state_files(p: &[(String, String)]) -> Result<Vec<DeviceFile>, String> {
    let mut paths: Vec<String> = p.iter().filter(|(k, _)| k == "--state").map(|(_, v)| v.clone()).collect();
    if paths.is_empty() {
        if let Ok(v) = std::env::var("FROST_SP_STATE") {
            paths = v.split(':').filter(|s| !s.is_empty()).map(String::from).collect();
        }
    }
    if paths.is_empty() {
        return Err("no state file: pass --state <device file> once per device, or set FROST_SP_STATE".into());
    }
    paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path).map_err(|e| format!("state file {path}: {e}"))?;
            serde_json::from_str(&text).map_err(|e| format!("state file {path}: {e}"))
        })
        .collect()
}

fn reconstruct(args: &[String]) -> Result<String, String> {
    let p = parse(args, &["--state"])?;
    let files = state_files(&p)?;
    if !files.iter().all(|f| f.test_only_seeded) {
        return Err("reconstruct-test-secret only accepts device files of a seeded test group".into());
    }
    let keys = load_devices(&files)?;
    serde_json::to_string_pretty(&reconstruct_test_secret(&keys)?).map_err(|e| e.to_string())
}

fn sign(args: &[String]) -> Result<String, String> {
    let p = parse(args, &["--state"])?;
    let files = state_files(&p)?;
    let seeded = files.iter().any(|f| f.test_only_seeded);
    let devices = load_devices(&files)?;
    let env = WalletEnv::from_env(|k| std::env::var(k).ok())?;
    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin).map_err(|e| format!("stdin: {e}"))?;
    let request: Request = serde_json::from_str(&stdin).map_err(|e| format!("request: {e}"))?;
    let tx_hex = sign_request(&devices, seeded, &env, &request, &mut OsRng)?;
    Ok(serde_json::json!({ "tx_hex": tx_hex }).to_string())
}
