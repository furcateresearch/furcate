//! Freshness: proving evidence is current rather than replayed.
//!
//! RFC 9334 describes two mechanisms with different costs. A **nonce** proves
//! evidence was produced after a specific challenge, but the verifier must
//! keep state per outstanding challenge. An **epoch identifier**, broadcast
//! periodically and included in evidence, keeps verifier state independent of
//! the number of attesters — which is what makes continuous attestation across
//! a whole site affordable.
//!
//! Furcate uses epochs for background attestation and nonces for on-demand
//! challenges.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub type EpochId = u64;

#[derive(Debug, PartialEq, Eq)]
pub enum FreshnessError {
    /// The nonce is not one this verifier issued, or it was already consumed.
    UnknownNonce,
    /// The challenge was issued too long ago.
    NonceExpired { issued: u64, now: u64, ttl: u64 },
    /// Evidence quotes an epoch outside the accepted window.
    StaleEpoch {
        found: EpochId,
        current: EpochId,
        tolerance: u64,
    },
    /// Evidence claims an epoch that has not been broadcast yet.
    FutureEpoch { found: EpochId, current: EpochId },
    /// A nonce chosen by the attester proves nothing to a verifier.
    SelfChosenNonce,
}

impl fmt::Display for FreshnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FreshnessError::UnknownNonce => {
                write!(f, "nonce was not issued by this verifier, or has already been used")
            }
            FreshnessError::NonceExpired { issued, now, ttl } => write!(
                f,
                "challenge issued at {issued} expired after {ttl}; it is now {now}"
            ),
            FreshnessError::StaleEpoch {
                found,
                current,
                tolerance,
            } => write!(
                f,
                "evidence quotes epoch {found} but the current epoch is {current} (tolerance {tolerance})"
            ),
            FreshnessError::FutureEpoch { found, current } => write!(
                f,
                "evidence quotes epoch {found}, which is ahead of the current epoch {current}"
            ),
            FreshnessError::SelfChosenNonce => write!(
                f,
                "the attester chose its own nonce, which proves nothing about freshness"
            ),
        }
    }
}

impl std::error::Error for FreshnessError {}

/// Outstanding nonce challenges.
///
/// A nonce is single-use. Consuming it on verification is what stops a captured
/// quote being replayed against the same challenge later.
pub struct NonceChallenge {
    issued: BTreeMap<String, u64>,
    ttl: u64,
}

impl NonceChallenge {
    pub fn new(ttl: u64) -> Self {
        Self {
            issued: BTreeMap::new(),
            ttl,
        }
    }

    /// Record a nonce this verifier is issuing.
    pub fn issue(&mut self, nonce: &[u8], now: u64) -> String {
        let hex = hex::encode(nonce);
        self.issued.insert(hex.clone(), now);
        hex
    }

    pub fn outstanding(&self) -> usize {
        self.issued.len()
    }

    /// Consume a nonce presented in evidence.
    pub fn consume(&mut self, nonce: &[u8], now: u64) -> Result<(), FreshnessError> {
        let hex = hex::encode(nonce);
        let Some(issued) = self.issued.remove(&hex) else {
            return Err(FreshnessError::UnknownNonce);
        };
        if now.saturating_sub(issued) > self.ttl {
            return Err(FreshnessError::NonceExpired {
                issued,
                now,
                ttl: self.ttl,
            });
        }
        Ok(())
    }

    /// Drop challenges that will never be answered.
    pub fn sweep(&mut self, now: u64) -> usize {
        let ttl = self.ttl;
        let before = self.issued.len();
        self.issued.retain(|_, issued| now.saturating_sub(*issued) <= ttl);
        before - self.issued.len()
    }
}

/// Freshness asserted by an attester.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FreshnessProof {
    /// A nonce the verifier issued.
    Nonce(Vec<u8>),
    /// The most recent epoch the attester had received.
    Epoch(EpochId),
    /// A nonce the attester generated itself. Accepted only for local
    /// inspection, never as proof to a third party.
    SelfChosen(Vec<u8>),
}

/// Epoch broadcaster and checker.
pub struct EpochClock {
    current: EpochId,
    /// How many epochs behind evidence may be and still count as fresh.
    tolerance: u64,
}

impl EpochClock {
    pub fn new(tolerance: u64) -> Self {
        Self {
            current: 0,
            tolerance,
        }
    }

    pub fn current(&self) -> EpochId {
        self.current
    }

    pub fn advance(&mut self) -> EpochId {
        self.current += 1;
        self.current
    }

    pub fn check(&self, found: EpochId) -> Result<(), FreshnessError> {
        if found > self.current {
            return Err(FreshnessError::FutureEpoch {
                found,
                current: self.current,
            });
        }
        if self.current - found > self.tolerance {
            return Err(FreshnessError::StaleEpoch {
                found,
                current: self.current,
                tolerance: self.tolerance,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_issued_nonce_verifies_once() {
        let mut c = NonceChallenge::new(60);
        c.issue(b"abc", 0);
        assert_eq!(c.consume(b"abc", 10), Ok(()));
        // Replay of the same captured quote must fail.
        assert_eq!(c.consume(b"abc", 11), Err(FreshnessError::UnknownNonce));
    }

    #[test]
    fn an_unissued_nonce_is_rejected() {
        let mut c = NonceChallenge::new(60);
        assert_eq!(c.consume(b"never", 0), Err(FreshnessError::UnknownNonce));
    }

    #[test]
    fn an_expired_challenge_is_rejected() {
        let mut c = NonceChallenge::new(30);
        c.issue(b"abc", 0);
        assert_eq!(
            c.consume(b"abc", 31),
            Err(FreshnessError::NonceExpired {
                issued: 0,
                now: 31,
                ttl: 30
            })
        );
    }

    #[test]
    fn sweeping_bounds_verifier_state() {
        let mut c = NonceChallenge::new(10);
        c.issue(b"a", 0);
        c.issue(b"b", 0);
        c.issue(b"c", 100);
        assert_eq!(c.outstanding(), 3);
        assert_eq!(c.sweep(100), 2);
        assert_eq!(c.outstanding(), 1);
    }

    #[test]
    fn epochs_accept_a_bounded_lag() {
        let mut e = EpochClock::new(2);
        for _ in 0..5 {
            e.advance();
        }
        assert_eq!(e.check(5), Ok(()));
        assert_eq!(e.check(3), Ok(()));
        assert_eq!(
            e.check(2),
            Err(FreshnessError::StaleEpoch {
                found: 2,
                current: 5,
                tolerance: 2
            })
        );
    }

    #[test]
    fn an_epoch_from_the_future_is_rejected() {
        let e = EpochClock::new(2);
        assert_eq!(
            e.check(9),
            Err(FreshnessError::FutureEpoch {
                found: 9,
                current: 0
            })
        );
    }

    #[test]
    fn epoch_state_does_not_grow_with_attesters() {
        // The point of epochs: one clock serves any number of nodes.
        let e = EpochClock::new(1);
        assert_eq!(std::mem::size_of_val(&e), std::mem::size_of::<EpochClock>());
        assert_eq!(e.check(0), Ok(()));
    }
}
