//! Exposure counter: how many times this group's key has been used as a DH oracle.
//!
//! Every non-self recipient scan key `B` makes each cosigner release `D_i = x_i*B` with a
//! proof. Releases are bounded per group key; above the rotation threshold the signer refuses
//! to release more until the key has been rotated. Counted: distinct non-self scan keys, plus
//! sessions that released shares and then aborted. Kept in memory only (PoC).

use std::collections::BTreeSet;

use crate::{Error, Result};

/// Rotation thresholds offered by the PoC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationThreshold {
    Thousand,
    Million,
    Billion,
}

impl RotationThreshold {
    pub fn limit(self) -> u64 {
        match self {
            Self::Thousand => 1_000,
            Self::Million => 1_000_000,
            Self::Billion => 1_000_000_000,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExposureCounter {
    threshold: RotationThreshold,
    scan_keys: BTreeSet<[u8; 33]>,
    aborted_sessions: u64,
}

impl ExposureCounter {
    pub fn new(threshold: RotationThreshold) -> Self {
        Self {
            threshold,
            scan_keys: BTreeSet::new(),
            aborted_sessions: 0,
        }
    }

    pub fn set_threshold(&mut self, threshold: RotationThreshold) {
        self.threshold = threshold;
    }

    pub fn count(&self) -> u64 {
        self.scan_keys.len() as u64 + self.aborted_sessions
    }

    pub fn aborted_sessions(&self) -> u64 {
        self.aborted_sessions
    }

    /// Refuse if releasing shares for `new_keys` would push the count above the threshold.
    pub fn check_release(&self, new_keys: &[[u8; 33]]) -> Result<()> {
        let fresh = new_keys
            .iter()
            .filter(|k| !self.scan_keys.contains(*k))
            .count() as u64;
        if self.count() + fresh > self.threshold.limit() {
            return Err(Error::Other(format!(
                "exposure limit {} reached: rotate the group key before releasing more shares",
                self.threshold.limit()
            )));
        }
        Ok(())
    }

    pub fn record_release(&mut self, keys: &[[u8; 33]]) {
        self.scan_keys.extend(keys.iter().copied());
    }

    pub fn record_abort(&mut self) {
        self.aborted_sessions += 1;
    }

    /// Call after the group key has been rotated: the new key starts at zero.
    pub fn reset_after_rotation(&mut self) {
        self.scan_keys.clear();
        self.aborted_sessions = 0;
    }
}
