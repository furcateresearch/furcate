//! The hook for a model run on received embeddings, and a reference model.
//!
//! A [`WindowModel`] takes the int8 embedding a micro processing node sent and
//! returns a label with a margin. It names itself with a [`ModelRef`], the id
//! and the SHA-256 of its parameters, and that reference goes into the hop the
//! small processing node adds to the chain, so the next rung can tell which
//! model produced a value. The hash is computed from the parameters held, never
//! stated.
//!
//! [`NearestCentroid`] is the reference model: one mean vector per label and
//! the label of the nearest. It exists to exercise the path end to end. Its
//! margin is a distance ratio and is not a calibrated probability, and nothing
//! here claims an accuracy for any data.

use crate::nicla::ModelRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Inference {
    pub label: String,
    /// How much nearer the best label is than the second: 0 when the two are
    /// equally near or there is only one, towards 1 when the second is far.
    /// Uncalibrated.
    pub margin: f64,
    pub model: ModelRef,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ModelError {
    WrongDimension { expected: usize, found: usize },
    NoCentroids,
    Invalid(&'static str),
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelError::WrongDimension { expected, found } => {
                write!(f, "embedding has {found} values, the model takes {expected}")
            }
            ModelError::NoCentroids => write!(f, "the model has no labels"),
            ModelError::Invalid(w) => write!(f, "{w}"),
        }
    }
}

impl std::error::Error for ModelError {}

pub trait WindowModel: Send + Sync {
    fn model_ref(&self) -> &ModelRef;
    /// The embedding length the model takes.
    fn dimension(&self) -> usize;
    fn infer(&self, embedding: &[i8]) -> Result<Inference, ModelError>;
}

/// One mean vector per label; the nearest wins.
#[derive(Clone, Debug)]
pub struct NearestCentroid {
    model: ModelRef,
    dim: usize,
    centroids: Vec<(String, Vec<f32>)>,
}

#[derive(Serialize, Deserialize)]
pub struct CentroidFile {
    pub id: String,
    pub centroids: Vec<(String, Vec<f32>)>,
}

impl NearestCentroid {
    pub fn new(id: &str, centroids: Vec<(String, Vec<f32>)>) -> Result<Self, ModelError> {
        let dim = centroids.first().ok_or(ModelError::NoCentroids)?.1.len();
        if dim == 0 || centroids.iter().any(|(_, c)| c.len() != dim) {
            return Err(ModelError::Invalid("centroids must share one non-zero dimension"));
        }
        if centroids.iter().any(|(_, c)| c.iter().any(|v| !v.is_finite())) {
            return Err(ModelError::Invalid("centroids must be finite"));
        }
        let mut h = Sha256::new();
        h.update(b"furcate/nearest-centroid/v1");
        h.update((dim as u64).to_be_bytes());
        for (label, c) in &centroids {
            h.update((label.len() as u64).to_be_bytes());
            h.update(label.as_bytes());
            for v in c {
                h.update(v.to_le_bytes());
            }
        }
        let model = ModelRef { id: id.to_string(), sha256: hex::encode(h.finalize()) };
        Ok(Self { model, dim, centroids })
    }

    /// The mean embedding of each label in `samples`.
    pub fn fit(id: &str, samples: &[(String, Vec<i8>)]) -> Result<Self, ModelError> {
        let dim = samples.first().ok_or(ModelError::NoCentroids)?.1.len();
        let mut sums: std::collections::BTreeMap<&str, (Vec<f64>, u64)> = Default::default();
        for (label, v) in samples {
            if v.len() != dim {
                return Err(ModelError::WrongDimension { expected: dim, found: v.len() });
            }
            let e = sums.entry(label).or_insert_with(|| (vec![0.0; dim], 0));
            for (s, x) in e.0.iter_mut().zip(v) {
                *s += *x as f64;
            }
            e.1 += 1;
        }
        Self::new(id, sums.into_iter().map(|(l, (s, n))| (l.to_string(), s.iter().map(|x| (x / n as f64) as f32).collect())).collect())
    }

    pub fn from_file(f: CentroidFile) -> Result<Self, ModelError> {
        Self::new(&f.id, f.centroids)
    }

    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.centroids.iter().map(|(l, _)| l.as_str())
    }
}

impl WindowModel for NearestCentroid {
    fn model_ref(&self) -> &ModelRef {
        &self.model
    }

    fn dimension(&self) -> usize {
        self.dim
    }

    fn infer(&self, embedding: &[i8]) -> Result<Inference, ModelError> {
        if embedding.len() != self.dim {
            return Err(ModelError::WrongDimension { expected: self.dim, found: embedding.len() });
        }
        let mut ranked: Vec<(f64, &str)> = self
            .centroids
            .iter()
            .map(|(l, c)| {
                let d2: f64 = c.iter().zip(embedding).map(|(a, b)| (*a as f64 - *b as f64).powi(2)).sum();
                (d2.sqrt(), l.as_str())
            })
            .collect();
        ranked.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(b.1)));
        let margin = match ranked.get(1) {
            Some((d2, _)) if d2 + ranked[0].0 > 0.0 => (d2 - ranked[0].0) / (d2 + ranked[0].0),
            _ => 0.0,
        };
        Ok(Inference { label: ranked[0].1.to_string(), margin, model: self.model.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<(String, Vec<i8>)> {
        let mut v = Vec::new();
        for i in 0..10i8 {
            v.push(("low".to_string(), vec![i % 3, 0, 1]));
            v.push(("high".to_string(), vec![100 + i % 3, 50, 90]));
        }
        v
    }

    #[test]
    fn the_nearest_label_wins_and_the_margin_is_larger_for_clearer_inputs() {
        let m = NearestCentroid::fit("ref", &samples()).unwrap();
        let near = m.infer(&[1, 0, 1]).unwrap();
        let between = m.infer(&[50, 25, 45]).unwrap();
        assert_eq!(near.label, "low");
        assert_eq!(m.infer(&[101, 50, 90]).unwrap().label, "high");
        assert!(near.margin > between.margin);
        assert!(between.margin < 0.1);
    }

    #[test]
    fn the_hash_is_of_the_parameters_and_changes_with_them() {
        let a = NearestCentroid::fit("ref", &samples()).unwrap();
        let b = NearestCentroid::fit("ref", &samples()).unwrap();
        assert_eq!(a.model_ref(), b.model_ref());
        assert_eq!(a.model_ref().sha256.len(), 64);
        let mut s = samples();
        s.push(("low".into(), vec![9, 9, 9]));
        assert_ne!(a.model_ref().sha256, NearestCentroid::fit("ref", &s).unwrap().model_ref().sha256);
    }

    #[test]
    fn bad_input_is_an_error_not_a_guess() {
        let m = NearestCentroid::fit("ref", &samples()).unwrap();
        assert_eq!(m.infer(&[1, 2]), Err(ModelError::WrongDimension { expected: 3, found: 2 }));
        assert_eq!(NearestCentroid::new("x", vec![]).unwrap_err(), ModelError::NoCentroids);
        assert!(NearestCentroid::new("x", vec![("a".into(), vec![1.0]), ("b".into(), vec![1.0, 2.0])]).is_err());
        assert!(NearestCentroid::new("x", vec![("a".into(), vec![f32::NAN])]).is_err());
    }

    #[test]
    fn one_label_has_no_margin() {
        let m = NearestCentroid::new("one", vec![("only".into(), vec![0.0, 0.0])]).unwrap();
        assert_eq!(m.infer(&[5, 5]).unwrap().margin, 0.0);
    }
}
