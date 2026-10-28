//! FROST wallet that receives and spends BIP 352 Silent Payment outputs (W1 of the PoC).
//!
//! * [`tweak`]: FROST signing under a plain-tweaked key `P = X + tau*G`.
//! * [`group`]: trusted-dealer group setup (PoC only).
//! * [`wallet`]: SP addresses, labels and scanning into owned outputs.
//! * [`spend`]: signer/coordinator for spending one received output (single input).

pub mod group;
pub mod spend;
pub mod tweak;
pub mod wallet;

mod error;
pub use error::{Error, Result};
