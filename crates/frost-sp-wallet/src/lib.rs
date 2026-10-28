//! FROST wallet that receives and spends BIP 352 Silent Payment outputs (W1 of the PoC).
//!
//! * [`tweak`]: FROST signing under a plain-tweaked key `P = X + tau*G`.
//! * [`group`]: trusted-dealer group setup (PoC only).
//! * [`wallet`]: SP addresses, labels and scanning into owned outputs.
//! * [`send`]: multi-input spends that pay SP addresses (threshold ECDH + DLEQ).
//! * [`exposure`]: share-release counter and rotation threshold.
//! * [`spend`]: signer/coordinator for spending one received output (single input).

pub mod exposure;
pub mod group;
pub mod send;
pub mod spend;
pub mod tweak;
pub mod wallet;

mod error;
pub use error::{Error, Result};
