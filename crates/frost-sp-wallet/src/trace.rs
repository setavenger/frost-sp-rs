//! Opt-in trace for demo runs. With `FROST_SP_TRACE=<path>` set, [`emit`] appends one JSON
//! object per line (`{"step": "...", ...}`) to that file. Unset or empty: nothing is written and
//! nothing else changes. Append mode and one write per line, because the CLI signer is a new
//! process for every spend and all of them share the file.
//!
//! Records hold public values and wallet-private test values (tweaks, the combined ECDH point).
//! Never pass a signing share, a nonce, `b_scan`, the group secret, a host secret or a channel
//! key to [`emit`].

use std::io::Write;

/// The environment variable naming the trace file.
pub const ENV: &str = "FROST_SP_TRACE";

fn path() -> Option<std::ffi::OsString> {
    std::env::var_os(ENV).filter(|p| !p.is_empty())
}

/// Is the trace on? Guard work that only feeds the trace with this.
pub fn enabled() -> bool {
    path().is_some()
}

/// Append `{"step": step, ...fields}` as one line. A no-op when the trace is off. A file that
/// cannot be opened is reported on stderr and otherwise ignored: the trace never changes what
/// the wallet does.
pub fn emit(step: &str, fields: serde_json::Value) {
    let Some(path) = path() else { return };
    let step = serde_json::Value::from(step).to_string();
    let body = fields.to_string();
    let line = match body.strip_prefix('{').filter(|rest| *rest != "}") {
        Some(rest) => format!("{{\"step\":{step},{rest}\n"),
        None => format!("{{\"step\":{step}}}\n"),
    };
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(&path) {
        Ok(mut f) => {
            let _ = f.write_all(line.as_bytes());
        }
        Err(e) => eprintln!("{ENV}={}: {e}", path.to_string_lossy()),
    }
}

/// Lowercase hex.
pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
