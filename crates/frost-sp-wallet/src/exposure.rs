//! Exposure counter: how many times this group's key has been used as a DH oracle.
//!
//! Every non-self recipient scan key `B` makes each cosigner release `D_i = x_i*B` with a
//! proof. Releases are bounded per group key; above the rotation threshold the signer refuses
//! to release more until the key has been rotated. Counted: distinct non-self scan keys only.
//! `D_i = x_i*B` is deterministic in `B`, so re-requesting a counted key, or aborting a
//! session, reveals nothing new and costs nothing.
//!
//! The counter is in memory only (PoC): a restart resets it. A reset otherwise happens only
//! through `Signer::rotate`, which swaps in the new key material together with the reset.

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
    /// The group key this counter belongs to; a reset needs a different one.
    group_key: Option<[u8; 33]>,
}

impl ExposureCounter {
    pub fn new(threshold: RotationThreshold) -> Self {
        Self {
            threshold,
            scan_keys: BTreeSet::new(),
            group_key: None,
        }
    }

    /// Bind the counter to the group key it counts for.
    pub fn with_group_key(mut self, group_key: [u8; 33]) -> Self {
        self.group_key = Some(group_key);
        self
    }

    pub fn set_threshold(&mut self, threshold: RotationThreshold) {
        self.threshold = threshold;
    }

    pub fn count(&self) -> u64 {
        self.scan_keys.len() as u64
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

    /// Rotation to `new_group_key`: the new key starts at zero. Refuses the key the counter
    /// is already bound to (or any reset on an unbound counter), so the count cannot be
    /// cleared without an actual key change.
    pub(crate) fn reset_for_rotation(&mut self, new_group_key: [u8; 33]) -> Result<()> {
        match self.group_key {
            None => return Err(Error::Other("exposure counter has no group key bound".into())),
            Some(k) if k == new_group_key => {
                return Err(Error::Other(
                    "exposure counter reset refused: the group key is unchanged".into(),
                ))
            }
            Some(_) => {}
        }
        self.scan_keys.clear();
        self.group_key = Some(new_group_key);
        Ok(())
    }
}
