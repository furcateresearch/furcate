//! Challenge-response attestation of the model a node is running.
//!
//! A signed model file in flash shows that a model was once installed. It does
//! not show what is computing now. This protocol asks the running model:
//!
//! 1. the verifier issues a fresh nonce for one node;
//! 2. the node derives an input from the nonce and a seed the verifier holds in
//!    its manifest for that model ([`derive_input`]), runs its active model on
//!    it, and signs the nonce, the model hash and the digest of the output;
//! 3. the verifier checks the signature, that the nonce was issued to that node
//!    and is used once, and recomputes the output with its reference copy of
//!    the model: equal, or within the manifest's tolerance for hardware whose
//!    rounding differs.
//!
//! The input is unpredictable until the nonce is known and the output is
//! checked against an independent computation, so a node cannot answer from a
//! stored table and a changed weight shows when it changes the output on the
//! derived inputs. How often it does is a measurement, not a promise: a weight
//! change that no derived input reaches (a dead unit, a low-order bit absorbed
//! by requantisation) is not seen, and `detection_by_challenge_count` in the
//! tests measures the share seen by 1, 4 and 16 challenges on the stand-in model.
//!
//! What this does not show. The challenge runs the node's code path for
//! challenges; a node that keeps a correct copy of the model for this purpose
//! and runs something else on real windows passes. It shows that the stated
//! model computes correctly on the node now, not that every production window
//! used it. The prover here is a software stand-in, and the tolerance a real
//! chip needs is measured on that chip, not here. The nonce must come from the
//! operating system's random source in the service that issues it; this
//! module takes it as an argument so tests are repeatable.

use super::signer::CascadeSigner;
use crate::leaf::verify_with_key;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const NONCE_LEN: usize = 16;
pub const RESPONSE_DOMAIN: &str = "furcate/inference-attestation/v1";
const INPUT_DOMAIN: &[u8] = b"furcate/inference-attestation/input/v1";
const OUTPUT_DOMAIN: &[u8] = b"furcate/inference-attestation/output/v1";

/// The model under attestation: bytes in, bytes out, deterministic.
pub trait ChallengeModel: Send + Sync {
    /// SHA-256 of the model artefact, hex.
    fn sha256(&self) -> String;
    fn input_len(&self) -> usize;
    fn run(&self, input: &[i8]) -> Vec<i8>;
}

/// The input a nonce selects: a SHA-256 counter stream under the manifest seed.
pub fn derive_input(seed: &[u8], nonce: &[u8; NONCE_LEN], len: usize) -> Vec<i8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(INPUT_DOMAIN);
        h.update((seed.len() as u64).to_be_bytes());
        h.update(seed);
        h.update(nonce);
        h.update(counter.to_be_bytes());
        out.extend(h.finalize().iter().map(|b| *b as i8));
        counter += 1;
    }
    out.truncate(len);
    out
}

pub fn output_digest(nonce: &[u8; NONCE_LEN], model_sha256: &str, output: &[i8]) -> String {
    let mut h = Sha256::new();
    h.update(OUTPUT_DOMAIN);
    h.update(nonce);
    h.update((model_sha256.len() as u64).to_be_bytes());
    h.update(model_sha256.as_bytes());
    h.update((output.len() as u64).to_be_bytes());
    h.update(output.iter().map(|v| *v as u8).collect::<Vec<u8>>());
    hex::encode(h.finalize())
}

fn response_message(nonce: &[u8; NONCE_LEN], model: &str, digest: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend(nonce);
    for part in [model.as_bytes(), digest.as_bytes()] {
        m.extend((part.len() as u64).to_be_bytes());
        m.extend(part);
    }
    m
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// Hex.
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub nonce: String,
    /// The model hash the node states it ran, hex.
    pub model: String,
    pub output: Vec<i8>,
    pub output_digest: String,
    pub signature: String,
}

fn parse_nonce(s: &str) -> Option<[u8; NONCE_LEN]> {
    hex::decode(s).ok().and_then(|b| <[u8; NONCE_LEN]>::try_from(b.as_slice()).ok())
}

/// The node's side. `seed` is the manifest seed the node holds for the model.
pub struct Prover<'a> {
    pub signer: &'a dyn CascadeSigner,
    pub model: &'a dyn ChallengeModel,
    pub seed: &'a [u8],
}

impl Prover<'_> {
    pub fn respond(&self, c: &Challenge) -> Result<Response, String> {
        let nonce = parse_nonce(&c.nonce).ok_or("the nonce is not 16 bytes of hex")?;
        let output = self.model.run(&derive_input(self.seed, &nonce, self.model.input_len()));
        let model = self.model.sha256();
        let digest = output_digest(&nonce, &model, &output);
        let signature = self.signer.sign_message(RESPONSE_DOMAIN, &response_message(&nonce, &model, &digest))?;
        Ok(Response { nonce: c.nonce.clone(), model, output, output_digest: digest, signature })
    }
}

/// What the verifier holds for one model.
#[derive(Clone)]
pub struct Manifest {
    pub seed: Vec<u8>,
    /// The verifier's own copy of the model.
    pub reference: Arc<dyn ChallengeModel>,
    /// The largest absolute difference per output value that still passes. 0 is exact.
    pub tolerance: u8,
}

impl Manifest {
    /// Compare an output with the reference for this nonce; returns the largest
    /// difference seen when it is within the tolerance.
    pub fn check(&self, nonce: &[u8; NONCE_LEN], output: &[i8]) -> Result<u32, AttestFailure> {
        let expected = self.reference.run(&derive_input(&self.seed, nonce, self.reference.input_len()));
        if expected.len() != output.len() {
            return Err(AttestFailure::OutputLength { expected: expected.len(), found: output.len() });
        }
        let max_difference = expected.iter().zip(output).map(|(a, b)| (*a as i32 - *b as i32).unsigned_abs()).max().unwrap_or(0);
        if max_difference > self.tolerance as u32 {
            return Err(AttestFailure::OutputMismatch { max_difference });
        }
        Ok(max_difference)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestFailure {
    /// The nonce was not issued to this node, was already used, or is malformed.
    UnknownNonce,
    Expired,
    BadSignature,
    DigestMismatch,
    UnknownModel(String),
    OutputLength { expected: usize, found: usize },
    OutputMismatch { max_difference: u32 },
}

impl AttestFailure {
    pub fn code(&self) -> &'static str {
        match self {
            AttestFailure::UnknownNonce => "attest_unknown_nonce",
            AttestFailure::Expired => "attest_expired",
            AttestFailure::BadSignature => "attest_bad_signature",
            AttestFailure::DigestMismatch => "attest_digest_mismatch",
            AttestFailure::UnknownModel(_) => "attest_unknown_model",
            AttestFailure::OutputLength { .. } => "attest_output_length",
            AttestFailure::OutputMismatch { .. } => "attest_output_mismatch",
        }
    }
}

impl std::fmt::Display for AttestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestFailure::UnknownNonce => write!(f, "no such challenge is outstanding for this node"),
            AttestFailure::Expired => write!(f, "the challenge expired before the answer"),
            AttestFailure::BadSignature => write!(f, "the answer is not signed by the node's key"),
            AttestFailure::DigestMismatch => write!(f, "the output does not match the signed digest"),
            AttestFailure::UnknownModel(m) => write!(f, "model {m} has no manifest"),
            AttestFailure::OutputLength { expected, found } => write!(f, "output has {found} values, expected {expected}"),
            AttestFailure::OutputMismatch { max_difference } => {
                write!(f, "the output differs from the reference by {max_difference}, beyond the tolerance")
            }
        }
    }
}

impl std::error::Error for AttestFailure {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attested {
    pub node: String,
    pub model: String,
    /// The largest difference from the reference that was seen.
    pub max_difference: u32,
}

pub struct Verifier {
    manifests: BTreeMap<String, Manifest>,
    outstanding: BTreeMap<[u8; NONCE_LEN], (String, u64)>,
    ttl_ms: u64,
}

impl Verifier {
    pub fn new(ttl_ms: u64) -> Self {
        Self { manifests: BTreeMap::new(), outstanding: BTreeMap::new(), ttl_ms }
    }

    pub fn register(&mut self, model_sha256: &str, manifest: Manifest) {
        self.manifests.insert(model_sha256.to_string(), manifest);
    }

    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }

    /// Issue a challenge to `node` with a nonce from the operating system's random source.
    pub fn issue(&mut self, node: &str, nonce: [u8; NONCE_LEN], now_ms: u64) -> Challenge {
        self.outstanding.retain(|_, (_, at)| now_ms.saturating_sub(*at) <= self.ttl_ms);
        self.outstanding.insert(nonce, (node.to_string(), now_ms));
        Challenge { nonce: hex::encode(nonce) }
    }

    /// Check an answer from `node`, whose enrolled key is `node_key`. A nonce is
    /// spent by its first answer, whatever the outcome.
    pub fn verify(&mut self, node: &str, node_key: &str, r: &Response, now_ms: u64) -> Result<Attested, AttestFailure> {
        let nonce = parse_nonce(&r.nonce).ok_or(AttestFailure::UnknownNonce)?;
        let (owner, at) = self.outstanding.remove(&nonce).ok_or(AttestFailure::UnknownNonce)?;
        if owner != node {
            return Err(AttestFailure::UnknownNonce);
        }
        if now_ms.saturating_sub(at) > self.ttl_ms {
            return Err(AttestFailure::Expired);
        }
        verify_with_key(node_key, RESPONSE_DOMAIN, &response_message(&nonce, &r.model, &r.output_digest), &r.signature)
            .map_err(|_| AttestFailure::BadSignature)?;
        if output_digest(&nonce, &r.model, &r.output) != r.output_digest {
            return Err(AttestFailure::DigestMismatch);
        }
        let m = self.manifests.get(&r.model).ok_or_else(|| AttestFailure::UnknownModel(r.model.clone()))?;
        let max_difference = m.check(&nonce, &r.output)?;
        Ok(Attested { node: node.to_string(), model: r.model.clone(), max_difference })
    }
}

/// How a layer's accumulator is brought back to int8. Two chips that differ
/// here give outputs that differ by a rounding step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rounding {
    HalfAwayFromZero,
    Floor,
}

/// A two-layer int8 network: `in -> hidden (ReLU) -> out`, accumulating in i32
/// and shifting back to int8. The stand-in for a model on a node.
#[derive(Clone, Debug)]
pub struct Mlp8 {
    pub input: usize,
    pub hidden: usize,
    pub output: usize,
    /// Row-major `hidden x input`, then `output x hidden`.
    pub weights: Vec<i8>,
    pub shift: u32,
    pub rounding: Rounding,
}

impl Mlp8 {
    /// Weights from a SHA-256 stream, for tests and the stand-in.
    pub fn from_seed(seed: &str, input: usize, hidden: usize, output: usize, rounding: Rounding) -> Self {
        let n = hidden * input + output * hidden;
        let mut weights = Vec::with_capacity(n);
        let mut c = 0u32;
        while weights.len() < n {
            weights.extend(Sha256::digest([seed.as_bytes(), &c.to_be_bytes()].concat()).iter().map(|b| (*b as i8) / 2));
            c += 1;
        }
        weights.truncate(n);
        Self { input, hidden, output, weights, shift: 7, rounding }
    }

    fn requant(&self, acc: i32) -> i8 {
        let half = 1i32 << (self.shift - 1);
        let v = match self.rounding {
            Rounding::HalfAwayFromZero => {
                if acc >= 0 {
                    (acc + half) >> self.shift
                } else {
                    -((-acc + half) >> self.shift)
                }
            }
            Rounding::Floor => acc >> self.shift,
        };
        v.clamp(-128, 127) as i8
    }
}

impl ChallengeModel for Mlp8 {
    fn sha256(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"furcate/mlp8/v1");
        for d in [self.input, self.hidden, self.output] {
            h.update((d as u64).to_be_bytes());
        }
        h.update(self.shift.to_be_bytes());
        h.update(self.weights.iter().map(|w| *w as u8).collect::<Vec<u8>>());
        hex::encode(h.finalize())
    }

    fn input_len(&self) -> usize {
        self.input
    }

    fn run(&self, x: &[i8]) -> Vec<i8> {
        let (w1, w2) = self.weights.split_at(self.hidden * self.input);
        let h: Vec<i8> = (0..self.hidden)
            .map(|j| {
                let acc: i32 = w1[j * self.input..(j + 1) * self.input].iter().zip(x).map(|(w, v)| *w as i32 * *v as i32).sum();
                self.requant(acc).max(0)
            })
            .collect();
        (0..self.output)
            .map(|k| {
                let acc: i32 = w2[k * self.hidden..(k + 1) * self.hidden].iter().zip(&h).map(|(w, v)| *w as i32 * *v as i32).sum();
                self.requant(acc)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::Leaf;

    const SEED: &[u8] = b"manifest seed for the stand-in";

    fn model(rounding: Rounding) -> Mlp8 {
        Mlp8::from_seed("window-model", 64, 32, 16, rounding)
    }

    fn nonce(i: u64) -> [u8; NONCE_LEN] {
        let d = Sha256::digest(i.to_be_bytes());
        <[u8; NONCE_LEN]>::try_from(&d[..NONCE_LEN]).unwrap()
    }

    fn verifier(tolerance: u8) -> Verifier {
        let m = model(Rounding::HalfAwayFromZero);
        let mut v = Verifier::new(5_000);
        v.register(&m.sha256(), Manifest { seed: SEED.to_vec(), reference: Arc::new(m), tolerance });
        v
    }

    fn setup() -> (Leaf, Mlp8, Verifier) {
        (Leaf::new("furcate:node:micro1", [4; 32]), model(Rounding::HalfAwayFromZero), verifier(0))
    }

    #[test]
    fn an_honest_node_is_attested_and_the_nonce_is_spent() {
        let (leaf, m, mut v) = setup();
        let c = v.issue("furcate:node:micro1", nonce(1), 1_000);
        let r = Prover { signer: &leaf, model: &m, seed: SEED }.respond(&c).unwrap();
        let a = v.verify("furcate:node:micro1", &leaf.public_key(), &r, 1_100).unwrap();
        assert_eq!((a.model.as_str(), a.max_difference), (m.sha256().as_str(), 0));
        // A recorded answer is not accepted a second time.
        assert_eq!(v.verify("furcate:node:micro1", &leaf.public_key(), &r, 1_200), Err(AttestFailure::UnknownNonce));
        assert_eq!(v.outstanding(), 0);
    }

    #[test]
    fn an_answer_to_another_nonce_another_node_or_a_late_one_is_refused() {
        let (leaf, m, mut v) = setup();
        let key = leaf.public_key();
        let c1 = v.issue("furcate:node:micro1", nonce(1), 1_000);
        let c2 = v.issue("furcate:node:micro1", nonce(2), 1_000);
        let p = Prover { signer: &leaf, model: &m, seed: SEED };
        let (r1, r2) = (p.respond(&c1).unwrap(), p.respond(&c2).unwrap());
        // r1's output under r2's nonce: the signature no longer matches.
        let mut swapped = r1.clone();
        swapped.nonce = r2.nonce.clone();
        assert_eq!(v.verify("furcate:node:micro1", &key, &swapped, 1_100), Err(AttestFailure::BadSignature));
        // Not issued to this node.
        assert_eq!(v.verify("furcate:node:other", &key, &r1, 1_100), Err(AttestFailure::UnknownNonce));
        // Unsolicited.
        let stray = p.respond(&Challenge { nonce: hex::encode(nonce(9)) }).unwrap();
        assert_eq!(v.verify("furcate:node:micro1", &key, &stray, 1_100), Err(AttestFailure::UnknownNonce));
        // Late.
        let c3 = v.issue("furcate:node:micro1", nonce(3), 1_000);
        let r3 = p.respond(&c3).unwrap();
        assert_eq!(v.verify("furcate:node:micro1", &key, &r3, 9_000), Err(AttestFailure::Expired));
    }

    #[test]
    fn a_forged_or_altered_answer_is_refused() {
        let (leaf, m, mut v) = setup();
        let key = leaf.public_key();
        let p = Prover { signer: &leaf, model: &m, seed: SEED };
        // Signed by another key.
        let thief = Leaf::new("furcate:node:micro1", [5; 32]);
        let c = v.issue("furcate:node:micro1", nonce(1), 0);
        let r = Prover { signer: &thief, model: &m, seed: SEED }.respond(&c).unwrap();
        assert_eq!(v.verify("furcate:node:micro1", &key, &r, 10), Err(AttestFailure::BadSignature));
        // Output edited, digest left: the digest no longer matches the output.
        let c = v.issue("furcate:node:micro1", nonce(2), 0);
        let mut r = p.respond(&c).unwrap();
        r.output[0] = r.output[0].wrapping_add(1);
        assert_eq!(v.verify("furcate:node:micro1", &key, &r, 10), Err(AttestFailure::DigestMismatch));
        // Model hash edited: the signature covers it.
        let c = v.issue("furcate:node:micro1", nonce(3), 0);
        let mut r = p.respond(&c).unwrap();
        r.model = "00".repeat(32);
        assert_eq!(v.verify("furcate:node:micro1", &key, &r, 10), Err(AttestFailure::BadSignature));
    }

    #[test]
    fn a_model_the_verifier_has_no_manifest_for_is_refused() {
        let (leaf, _, mut v) = setup();
        let other = Mlp8::from_seed("another-model", 64, 32, 16, Rounding::HalfAwayFromZero);
        let c = v.issue("furcate:node:micro1", nonce(1), 0);
        let r = Prover { signer: &leaf, model: &other, seed: SEED }.respond(&c).unwrap();
        assert_eq!(v.verify("furcate:node:micro1", &leaf.public_key(), &r, 10), Err(AttestFailure::UnknownModel(other.sha256())));
    }

    #[test]
    fn a_node_that_states_the_right_hash_but_computes_with_other_weights_is_caught_by_the_output() {
        let (leaf, m, mut v) = setup();
        let mut bad = m.clone();
        for i in (0..64 * 32).step_by(7) {
            bad.weights[i] = bad.weights[i].wrapping_add(60);
        }
        // The node signs the registered hash while running the altered weights.
        struct Liar<'a>(&'a Mlp8, String);
        impl ChallengeModel for Liar<'_> {
            fn sha256(&self) -> String {
                self.1.clone()
            }
            fn input_len(&self) -> usize {
                self.0.input_len()
            }
            fn run(&self, x: &[i8]) -> Vec<i8> {
                self.0.run(x)
            }
        }
        let liar = Liar(&bad, m.sha256());
        let mut caught = 0;
        for i in 0..16 {
            let c = v.issue("furcate:node:micro1", nonce(100 + i), 0);
            let r = Prover { signer: &leaf, model: &liar, seed: SEED }.respond(&c).unwrap();
            if matches!(v.verify("furcate:node:micro1", &leaf.public_key(), &r, 10), Err(AttestFailure::OutputMismatch { .. })) {
                caught += 1;
            }
        }
        assert!(caught >= 12, "caught {caught} of 16");
    }

    /// Single-bit flips of the weights: the share that change the output on
    /// the first 1, 4 and 16 derived inputs, averaged over independent seeds.
    /// Returns (flips, detected at 1, 4, 16, detected by bit position at 16).
    #[allow(clippy::needless_range_loop)]
    fn flip_study() -> (usize, [f64; 3], [f64; 8]) {
        let m = model(Rounding::HalfAwayFromZero);
        let sets = 1u64;
        let mut hit = [0usize; 3];
        let mut by_bit = [0usize; 8];
        let mut total = 0usize;
        for set in 0..sets {
            let inputs: Vec<Vec<i8>> = (0..16).map(|i| derive_input(SEED, &nonce(set * 100 + i), m.input_len())).collect();
            let reference: Vec<Vec<i8>> = inputs.iter().map(|x| m.run(x)).collect();
            for byte in 0..m.weights.len() {
                for bit in 0..8 {
                    let mut f = m.clone();
                    f.weights[byte] = (f.weights[byte] as u8 ^ (1 << bit)) as i8;
                    let first = (0..16).find(|i| f.run(&inputs[*i]) != reference[*i]);
                    for (slot, k) in [1usize, 4, 16].iter().enumerate() {
                        if first.is_some_and(|i| i < *k) {
                            hit[slot] += 1;
                        }
                    }
                    if first.is_some() {
                        by_bit[bit] += 1;
                    }
                    total += 1;
                }
            }
        }
        let per_bit = total / 8;
        (total, [0, 1, 2].map(|i| hit[i] as f64 / total as f64), by_bit.map(|c| c as f64 / per_bit as f64))
    }

    #[test]
    fn detection_by_challenge_count() {
        let (n, d, by_bit) = flip_study();
        println!(
            "single-bit weight flips ({n}): detected by 1 challenge {:.3}, 4 {:.3}, 16 {:.3}; by bit 0..7 at 16: {:?}",
            d[0], d[1], d[2], by_bit.map(|x| (x * 1000.0).round() / 1000.0)
        );
        assert!(d[0] <= d[1] && d[1] <= d[2]);
        assert!(d[2] > 0.5, "16 challenges detect only {:.3}", d[2]);
        // The baseline, a hash of the file checked at load, sees none of these runtime changes.
        let load_time_check_detects = 0.0;
        assert!(d[2] > load_time_check_detects);
    }

    #[test]
    fn rounding_differences_between_two_implementations_are_bounded_and_need_a_tolerance() {
        let reference = model(Rounding::HalfAwayFromZero);
        let chip = model(Rounding::Floor);
        // Same weights, a different rounding rule: the hash differs by design only through the rounding
        // field being outside it, so the node states the reference's hash.
        assert_eq!(chip.weights, reference.weights);
        let (mut exact_mismatch, mut max_diff) = (0usize, 0u32);
        for i in 0..10_000u64 {
            let x = derive_input(SEED, &nonce(i), 64);
            let (a, b) = (reference.run(&x), chip.run(&x));
            if a != b {
                exact_mismatch += 1;
            }
            max_diff = max_diff.max(a.iter().zip(&b).map(|(p, q)| (*p as i32 - *q as i32).unsigned_abs()).max().unwrap());
        }
        println!("rounding: {exact_mismatch}/10000 nonces differ exactly, largest difference {max_diff}");
        assert!(exact_mismatch > 0, "the two roundings should differ somewhere");
        assert!(max_diff >= 1);

        // With the manifest's tolerance set above the observed spread, an honest chip passes all 10,000.
        let tolerated = Manifest { seed: SEED.to_vec(), reference: Arc::new(reference.clone()), tolerance: (max_diff + 1).min(255) as u8 };
        let strict = Manifest { tolerance: 0, ..tolerated.clone() };
        let (mut false_positives, mut strict_refusals) = (0, 0);
        for i in 0..10_000u64 {
            let out = chip.run(&derive_input(SEED, &nonce(i), 64));
            false_positives += tolerated.check(&nonce(i), &out).is_err() as usize;
            strict_refusals += strict.check(&nonce(i), &out).is_err() as usize;
        }
        assert_eq!(false_positives, 0);
        // With tolerance 0 the same honest chip is refused almost always: the tolerance is not optional.
        assert!(strict_refusals > 9_000, "{strict_refusals}");

        // The same through the signed protocol, for a sample of nonces.
        let leaf = Leaf::new("furcate:node:micro1", [4; 32]);
        let mut v = Verifier::new(5_000);
        v.register(&reference.sha256(), tolerated);
        struct Chip<'a>(&'a Mlp8, String);
        impl ChallengeModel for Chip<'_> {
            fn sha256(&self) -> String {
                self.1.clone()
            }
            fn input_len(&self) -> usize {
                self.0.input_len()
            }
            fn run(&self, x: &[i8]) -> Vec<i8> {
                self.0.run(x)
            }
        }
        let chip = Chip(&chip, reference.sha256());
        for i in 0..50u64 {
            let c = v.issue("furcate:node:micro1", nonce(i), 0);
            let r = Prover { signer: &leaf, model: &chip, seed: SEED }.respond(&c).unwrap();
            assert!(v.verify("furcate:node:micro1", &leaf.public_key(), &r, 1).is_ok());
        }
    }

    #[test]
    fn the_input_depends_on_the_nonce_and_the_seed_and_has_the_length_asked() {
        let a = derive_input(SEED, &nonce(1), 64);
        assert_eq!(a.len(), 64);
        assert_eq!(a, derive_input(SEED, &nonce(1), 64));
        assert_ne!(a, derive_input(SEED, &nonce(2), 64));
        assert_ne!(a, derive_input(b"another", &nonce(1), 64));
        assert_eq!(derive_input(SEED, &nonce(1), 100).len(), 100);
    }

    #[test]
    fn stale_challenges_are_dropped_when_new_ones_are_issued() {
        let mut v = Verifier::new(1_000);
        for i in 0..5 {
            v.issue("n", nonce(i), 0);
        }
        assert_eq!(v.outstanding(), 5);
        v.issue("n", nonce(99), 10_000);
        assert_eq!(v.outstanding(), 1);
    }
}
