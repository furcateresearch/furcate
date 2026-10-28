//! Leaf firmware core.
//!
//! `no_std` and allocation-free, so it can be compiled into ESP32-class
//! firmware where there is no operating system, no heap worth relying on, and
//! no trustworthy clock.
//!
//! Three constraints shape everything here. A microcontroller cannot run
//! gossip or consensus, so a leaf attaches to a parent instead of joining the
//! cluster. It has no clock it can prove, so freshness comes from a monotonic
//! counter rather than a timestamp. And it holds its key in whatever its
//! silicon offers, which the firmware does not get to grade: the leaf
//! describes how its key is held, and the parent derives the class from that
//! description (`furcate_identity::LeafKeyCustody`). Nothing here names a
//! class.

#![no_std]

use sha2::{Digest, Sha256};

/// Maximum readings a leaf batches before publishing. Fixed so the whole
/// module is allocation-free.
pub const MAX_BATCH: usize = 8;

/// A measurement taken by a leaf.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    /// Index into the leaf's own sensor table, rather than a string, because
    /// a microcontroller should not be moving names around.
    pub sensor: u8,
    pub value: f32,
    /// Monotonic, never reset except by re-attachment.
    pub seq: u32,
}

/// A fixed-capacity batch of samples awaiting publication.
pub struct Batch {
    samples: [Option<Sample>; MAX_BATCH],
    len: usize,
}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

impl Batch {
    pub const fn new() -> Self {
        Self {
            samples: [None; MAX_BATCH],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_full(&self) -> bool {
        self.len == MAX_BATCH
    }

    /// Add a sample.
    ///
    /// A full batch drops the *oldest* sample rather than refusing the newest:
    /// on a sensor node the current reading is almost always more useful than
    /// a stale one, and blocking is not an option in an interrupt handler.
    pub fn push(&mut self, s: Sample) -> Option<Sample> {
        if self.len < MAX_BATCH {
            self.samples[self.len] = Some(s);
            self.len += 1;
            None
        } else {
            let dropped = self.samples[0];
            self.samples.rotate_left(1);
            self.samples[MAX_BATCH - 1] = Some(s);
            dropped
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Sample> {
        self.samples[..self.len].iter().flatten()
    }

    pub fn clear(&mut self) {
        self.samples = [None; MAX_BATCH];
        self.len = 0;
    }
}

/// A leaf's monotonic counter and signing payload construction.
pub struct LeafState {
    /// Incremented for every sample. Survives reboot by being persisted to
    /// non-volatile storage; a counter that resets would let a reboot replay
    /// old readings.
    counter: u32,
    /// Generation, incremented on every re-attachment so a parent can tell a
    /// reattached leaf from a replayed one.
    generation: u16,
}

impl Default for LeafState {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl LeafState {
    pub const fn new(counter: u32, generation: u16) -> Self {
        Self {
            counter,
            generation,
        }
    }

    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn generation(&self) -> u16 {
        self.generation
    }

    /// Take the next sequence number.
    ///
    /// Saturates rather than wrapping. A wrapped counter would silently
    /// re-enable replay, so exhaustion is treated as a condition requiring
    /// re-attachment instead.
    pub fn next_seq(&mut self) -> Option<u32> {
        if self.counter == u32::MAX {
            return None;
        }
        self.counter += 1;
        Some(self.counter)
    }

    pub fn exhausted(&self) -> bool {
        self.counter == u32::MAX
    }

    /// Begin a new attachment: bump the generation and reset the counter.
    pub fn reattach(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.counter = 0;
    }

    /// Bytes a leaf signs for a sample.
    ///
    /// Includes the device identifier and generation so a signature from one
    /// leaf cannot be presented as coming from another, or from an earlier
    /// attachment of the same one.
    pub fn payload(&self, device_id: &[u8; 8], s: &Sample) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"furcate/leaf/sample/v1");
        h.update(device_id);
        h.update(self.generation.to_be_bytes());
        h.update([s.sensor]);
        h.update(s.value.to_be_bytes());
        h.update(s.seq.to_be_bytes());
        h.finalize().into()
    }
}

/// Length of the model hash bound into a reading.
pub const MODEL_HASH_LEN: usize = 32;

impl LeafState {
    /// Bytes a leaf signs for a sample that also names the model, if any,
    /// that stood between the sensor and the number.
    ///
    /// `model` is the SHA-256 of the signed model artifact active when the
    /// reading was taken, or all zero bytes when no model is active. The
    /// firmware computes the same bytes; the vector in the tests is shared
    /// with its host test. Readings forwarded through further nodes keep this
    /// payload: each node signs over the signature below it rather than
    /// changing what the origin signed.
    pub fn bound_payload(&self, device_id: &[u8; 8], s: &Sample, model: &[u8; MODEL_HASH_LEN]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"furcate/leaf/sample/v2");
        h.update(device_id);
        h.update(self.generation.to_be_bytes());
        h.update([s.sensor]);
        h.update(s.value.to_be_bytes());
        h.update(s.seq.to_be_bytes());
        h.update(model);
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_fills_and_then_drops_the_oldest() {
        let mut b = Batch::new();
        for i in 0..MAX_BATCH {
            assert!(b
                .push(Sample {
                    sensor: 0,
                    value: i as f32,
                    seq: i as u32
                })
                .is_none());
        }
        assert!(b.is_full());
        let dropped = b.push(Sample {
            sensor: 0,
            value: 99.0,
            seq: 99,
        });
        assert_eq!(dropped.unwrap().value, 0.0);
        assert_eq!(b.len(), MAX_BATCH);
        // The newest sample survived.
        assert!(b.iter().any(|s| s.value == 99.0));
    }

    #[test]
    fn sequences_advance_monotonically() {
        let mut s = LeafState::default();
        assert_eq!(s.next_seq(), Some(1));
        assert_eq!(s.next_seq(), Some(2));
        assert_eq!(s.counter(), 2);
    }

    #[test]
    fn an_exhausted_counter_stops_rather_than_wrapping() {
        // Wrapping would silently re-enable replay.
        let mut s = LeafState::new(u32::MAX, 0);
        assert!(s.exhausted());
        assert_eq!(s.next_seq(), None);
    }

    #[test]
    fn reattachment_bumps_the_generation_and_resets_the_counter() {
        let mut s = LeafState::new(500, 3);
        s.reattach();
        assert_eq!(s.generation(), 4);
        assert_eq!(s.counter(), 0);
    }

    #[test]
    fn a_payload_binds_the_device() {
        let s = LeafState::default();
        let sample = Sample {
            sensor: 1,
            value: 21.5,
            seq: 7,
        };
        assert_ne!(s.payload(b"device01", &sample), s.payload(b"device02", &sample));
    }

    #[test]
    fn a_payload_binds_the_generation() {
        // A reading from a previous attachment must not verify against the
        // current one.
        let a = LeafState::new(0, 1);
        let b = LeafState::new(0, 2);
        let sample = Sample {
            sensor: 1,
            value: 21.5,
            seq: 7,
        };
        assert_ne!(a.payload(b"device01", &sample), b.payload(b"device01", &sample));
    }

    #[test]
    fn a_payload_binds_the_value() {
        let s = LeafState::default();
        let a = Sample { sensor: 1, value: 21.5, seq: 7 };
        let b = Sample { sensor: 1, value: 90.0, seq: 7 };
        assert_ne!(s.payload(b"device01", &a), s.payload(b"device01", &b));
    }

    #[test]
    fn clearing_a_batch_empties_it() {
        let mut b = Batch::new();
        b.push(Sample { sensor: 0, value: 1.0, seq: 1 });
        b.clear();
        assert!(b.is_empty());
        assert_eq!(b.iter().count(), 0);
    }

    #[test]
    fn the_bound_payload_matches_the_firmware_vector() {
        // The same vectors as the leaf firmware's host test.
        let st = LeafState::new(0, 3);
        let sample = Sample { sensor: 0, value: 21.5, seq: 7 };
        let dev = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut model = [0u8; MODEL_HASH_LEN];
        for (i, b) in model.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            hex::encode(st.bound_payload(&dev, &sample, &model)),
            "e9f6dae460a5c7af5134556ad39d651aaa61dbbee5e239e167506670987ff3fb"
        );
        assert_eq!(
            hex::encode(st.bound_payload(&dev, &sample, &[0u8; MODEL_HASH_LEN])),
            "716948ddde3cd1ea6edcebf712dc76344c6e70fc2d4a37a4f2cf014d57a9e174"
        );
    }

    #[test]
    fn the_bound_payload_binds_the_model() {
        let st = LeafState::default();
        let sample = Sample { sensor: 1, value: 21.5, seq: 7 };
        let a = st.bound_payload(b"device01", &sample, &[1u8; MODEL_HASH_LEN]);
        let b = st.bound_payload(b"device01", &sample, &[2u8; MODEL_HASH_LEN]);
        assert_ne!(a, b);
        // And it is not the unbound payload.
        assert_ne!(a, st.payload(b"device01", &sample));
    }
}
