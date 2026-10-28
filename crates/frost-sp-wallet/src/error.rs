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
    #[error("culprit {who}: {reason}")]
    Culprit { who: String, reason: String },
    #[error("input set has sum of parities 0: the input key sum would not contain the group key")]
    ParityCancellation,
    #[error("invalid scan key: {0}")]
    InvalidScanKey(&'static str),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
