use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid scalar: {0}")]
    Scalar(&'static str),
    #[error("frost: {0}")]
    Frost(#[from] frost_secp256k1_tr::Error),
    #[error("secp256k1: {0}")]
    Secp(#[from] secp256k1::Error),
    #[error("silent payments: {0}")]
    Sp(#[from] silentpayments::Error),
    #[error("transaction does not pay this wallet")]
    NoOwnedOutput,
    #[error("signer {who} refuses: {reason}")]
    Refused { who: String, reason: String },
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
