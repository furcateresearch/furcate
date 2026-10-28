//! Embedding-space drift, tracked per sensing node on the small processing node.
//!
//! Embeddings already flow up, so watching them costs the node below nothing.
//! For each sensing node the tracker freezes a reference (mean and variance of
//! its first `reference_windows` embeddings), then compares what follows:
//!
//! * a **mean-shift score**: the distance of the recent mean from the reference
//!   mean in units of the reference spread, scaled so it is about 1 when nothing
//!   changed. It sees a step change;
//! * a **Page-Hinkley** statistic on the squared distance of each window from
//!   the reference. It sees a slow ramp that the mean-shift score reaches late.
//!
//! Either raises the node's alarm, which stays raised until [`FleetDrift::rebase`].
//! The cause is then read across nodes, from what each node reports about its own
//! model:
//!
//! | what the alarmed nodes look like | cause |
//! |---|---|
//! | the model hash they report is not the reference's | [`Cause::ModelChange`] |
//! | at least `site_fraction` of the nodes that kept their model, and their shifts point the same way | [`Cause::SiteWide`] |
//! | fewer than that, or shifts that disagree | [`Cause::SensorDrift`], per node |
//! | none | [`Cause::Stable`] |
//!
//! Limits. The attribution is a heuristic over a small fleet: a site-wide change
//! that reaches only some nodes yet is read as per-node drift, and a node whose
//! model changed while its sensor drifted is read as a model change. With two
//! nodes both alarmed, a site-wide cause cannot be told from two sensor drifts
//! that happen to align. The score assumes windows are about independent;
//! `autocorrelation` widens it for overlapping windows and is a setting, not a
//! measurement. The synthetic detection delays and attribution accuracy are in
//! the tests below and use the same settings as the defaults.

use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DriftConfig {
    /// Embeddings that form the reference.
    pub reference_windows: usize,
    /// Most recent embeddings the mean-shift score uses.
    pub recent_windows: usize,
    /// Fewest recent embeddings before the mean-shift score is read.
    pub min_recent: usize,
    /// Mean-shift score at which a node alarms.
    pub shift_alarm: f64,
    /// Windows per independent sample; 1 for independent windows.
    pub autocorrelation: f64,
    /// Page-Hinkley allowance and alarm level, on the squared distance minus 1.
    pub ph_allowance: f64,
    pub ph_alarm: f64,
    /// Share of the nodes that kept their model that must alarm for a site-wide cause.
    pub site_fraction: f64,
    /// Mean pairwise cosine of the shifts for a site-wide cause.
    pub min_alignment: f64,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            reference_windows: 200,
            recent_windows: 40,
            min_recent: 20,
            shift_alarm: 3.0,
            autocorrelation: 1.0,
            ph_allowance: 0.25,
            ph_alarm: 30.0,
            site_fraction: 0.5,
            min_alignment: 0.5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    Stable,
    SiteWide,
    SensorDrift,
    ModelChange,
}

impl Cause {
    pub fn code(&self) -> &'static str {
        match self {
            Cause::Stable => "stable",
            Cause::SiteWide => "site_wide",
            Cause::SensorDrift => "sensor_drift",
            Cause::ModelChange => "model_change",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Attribution {
    pub node: String,
    pub cause: Cause,
    pub shift_score: f64,
    pub ph: f64,
    /// Windows seen after the reference froze when the alarm first rose.
    pub alarmed_at: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DriftError {
    Dimension { expected: usize, found: usize },
    Empty,
}

impl std::fmt::Display for DriftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriftError::Dimension { expected, found } => write!(f, "embedding has {found} values, this node has sent {expected}"),
            DriftError::Empty => write!(f, "an embedding has no values"),
        }
    }
}

impl std::error::Error for DriftError {}

struct Reference {
    mean: Vec<f64>,
    var: Vec<f64>,
    model: String,
}

struct Track {
    dim: usize,
    count: usize,
    sum: Vec<f64>,
    sum_sq: Vec<f64>,
    model_at_start: String,
    reference: Option<Reference>,
    recent: VecDeque<(Vec<f64>, bool)>,
    after: u64,
    ph_sum: f64,
    ph_min: f64,
    alarmed_at: Option<u64>,
}

impl Track {
    fn new(dim: usize, model: &str) -> Self {
        Self {
            dim,
            count: 0,
            sum: vec![0.0; dim],
            sum_sq: vec![0.0; dim],
            model_at_start: model.to_string(),
            reference: None,
            recent: VecDeque::new(),
            after: 0,
            ph_sum: 0.0,
            ph_min: 0.0,
            alarmed_at: None,
        }
    }
}

pub struct FleetDrift {
    cfg: DriftConfig,
    tracks: BTreeMap<String, Track>,
}

/// Variance floor: an int8 embedding carries at least quantisation noise.
const VAR_FLOOR: f64 = 1.0 / 12.0;

impl FleetDrift {
    pub fn new(cfg: DriftConfig) -> Self {
        Self { cfg, tracks: BTreeMap::new() }
    }

    pub fn nodes(&self) -> impl Iterator<Item = &str> {
        self.tracks.keys().map(String::as_str)
    }

    /// Whether the node has a frozen reference.
    pub fn has_reference(&self, node: &str) -> bool {
        self.tracks.get(node).is_some_and(|t| t.reference.is_some())
    }

    /// Record one embedding from `node`, made by the model whose hash starts `model`.
    pub fn observe(&mut self, node: &str, model: &str, embedding: &[i8]) -> Result<(), DriftError> {
        if embedding.is_empty() {
            return Err(DriftError::Empty);
        }
        let cfg = self.cfg;
        let t = self.tracks.entry(node.to_string()).or_insert_with(|| Track::new(embedding.len(), model));
        if t.dim != embedding.len() {
            return Err(DriftError::Dimension { expected: t.dim, found: embedding.len() });
        }
        let x: Vec<f64> = embedding.iter().map(|v| *v as f64).collect();
        match &t.reference {
            None => {
                t.count += 1;
                for (j, v) in x.iter().enumerate() {
                    t.sum[j] += v;
                    t.sum_sq[j] += v * v;
                }
                if t.count >= cfg.reference_windows {
                    let n = t.count as f64;
                    let mean: Vec<f64> = t.sum.iter().map(|s| s / n).collect();
                    let var: Vec<f64> =
                        (0..t.dim).map(|j| ((t.sum_sq[j] / n - mean[j] * mean[j]) * n / (n - 1.0)).max(VAR_FLOOR)).collect();
                    t.reference = Some(Reference { mean, var, model: t.model_at_start.clone() });
                }
            }
            Some(r) => {
                t.after += 1;
                let d2 = (0..t.dim).map(|j| (x[j] - r.mean[j]).powi(2) / r.var[j]).sum::<f64>() / t.dim as f64;
                t.ph_sum += d2 - 1.0 - cfg.ph_allowance;
                t.ph_min = t.ph_min.min(t.ph_sum);
                let changed = !model.is_empty() && model != r.model;
                t.recent.push_back((x, changed));
                if t.recent.len() > cfg.recent_windows {
                    t.recent.pop_front();
                }
                if t.alarmed_at.is_none() {
                    let (s, ph) = Self::scores(&cfg, t);
                    if s.unwrap_or(0.0) >= cfg.shift_alarm || ph >= cfg.ph_alarm {
                        t.alarmed_at = Some(t.after);
                    }
                }
            }
        }
        Ok(())
    }

    fn scores(cfg: &DriftConfig, t: &Track) -> (Option<f64>, f64) {
        let ph = t.ph_sum - t.ph_min;
        let Some(r) = &t.reference else { return (None, 0.0) };
        if t.recent.len() < cfg.min_recent {
            return (None, ph);
        }
        let n = t.recent.len() as f64;
        let mut acc = 0.0;
        for j in 0..t.dim {
            let m = t.recent.iter().map(|(x, _)| x[j]).sum::<f64>() / n;
            acc += (m - r.mean[j]).powi(2) * (n / cfg.autocorrelation) / r.var[j];
        }
        (Some((acc / t.dim as f64).sqrt()), ph)
    }

    /// The shift of the recent mean from the reference, in reference spreads.
    fn shift(t: &Track) -> Option<Vec<f64>> {
        let r = t.reference.as_ref()?;
        if t.recent.is_empty() {
            return None;
        }
        let n = t.recent.len() as f64;
        Some((0..t.dim).map(|j| (t.recent.iter().map(|(x, _)| x[j]).sum::<f64>() / n - r.mean[j]) / r.var[j].sqrt()).collect())
    }

    fn model_changed(t: &Track) -> bool {
        !t.recent.is_empty() && t.recent.iter().filter(|(_, c)| *c).count() * 2 >= t.recent.len()
    }

    /// Accept the node's current behaviour as the new reference, after the
    /// operator has acted on an alarm. The node re-learns its reference.
    pub fn rebase(&mut self, node: &str) {
        self.tracks.remove(node);
    }

    /// The cause for every node with a reference.
    pub fn attribute(&self) -> Vec<Attribution> {
        let cfg = self.cfg;
        struct Row<'a> {
            node: &'a str,
            track: &'a Track,
            score: f64,
            ph: f64,
            alarm: bool,
            model: bool,
            shift: Option<Vec<f64>>,
        }
        let rows: Vec<Row> = self
            .tracks
            .iter()
            .filter(|(_, t)| t.reference.is_some())
            .map(|(n, t)| {
                let (s, ph) = Self::scores(&cfg, t);
                Row {
                    node: n,
                    track: t,
                    score: s.unwrap_or(0.0),
                    ph,
                    alarm: t.alarmed_at.is_some(),
                    model: Self::model_changed(t),
                    shift: Self::shift(t),
                }
            })
            .collect();

        let kept_model: Vec<&Row> = rows.iter().filter(|r| !r.model).collect();
        let alarmed: Vec<&&Row> = kept_model.iter().filter(|r| r.alarm).collect();
        let site = if alarmed.len() >= 2 && alarmed.len() as f64 / kept_model.len() as f64 >= cfg.site_fraction {
            let mut cos = Vec::new();
            for (i, a) in alarmed.iter().enumerate() {
                for b in alarmed.iter().skip(i + 1) {
                    if let (Some(x), Some(y)) = (&a.shift, &b.shift) {
                        let (dot, nx, ny) = (
                            x.iter().zip(y).map(|(p, q)| p * q).sum::<f64>(),
                            x.iter().map(|p| p * p).sum::<f64>().sqrt(),
                            y.iter().map(|p| p * p).sum::<f64>().sqrt(),
                        );
                        if nx > 0.0 && ny > 0.0 {
                            cos.push(dot / (nx * ny));
                        }
                    }
                }
            }
            !cos.is_empty() && cos.iter().sum::<f64>() / cos.len() as f64 >= cfg.min_alignment
        } else {
            false
        };

        rows.iter()
            .map(|r| {
                let cause = if !r.alarm {
                    Cause::Stable
                } else if r.model {
                    Cause::ModelChange
                } else if site {
                    Cause::SiteWide
                } else {
                    Cause::SensorDrift
                };
                Attribution { node: r.node.to_string(), cause, shift_score: r.score, ph: r.ph, alarmed_at: r.track.alarmed_at }
            })
            .collect()
    }

    pub fn cause_of(&self, node: &str) -> Option<Cause> {
        self.attribute().into_iter().find(|a| a.node == node).map(|a| a.cause)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);

    impl Rng {
        fn u(&mut self) -> f64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 11) as f64 / (1u64 << 53) as f64
        }
        fn normal(&mut self) -> f64 {
            let (a, b) = (self.u().max(1e-12), self.u());
            (-2.0 * a.ln()).sqrt() * (2.0 * std::f64::consts::PI * b).cos()
        }
    }

    const D: usize = 8;
    const LEAVES: usize = 6;
    const SIGMA: f64 = 6.0;

    fn base(leaf: usize, j: usize) -> f64 {
        ((leaf * 17 + j * 29) % 61) as f64 - 30.0
    }

    /// A fleet with a reference of 200 windows already frozen.
    struct Fleet {
        f: FleetDrift,
        rng: Rng,
        t: usize,
    }

    fn model() -> &'static str {
        "aaaaaaaaaaaaaaaa"
    }

    fn fleet(seed: u64) -> Fleet {
        let mut fl = Fleet { f: FleetDrift::new(DriftConfig::default()), rng: Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1), t: 0 };
        for _ in 0..200 {
            fl.step(&|_, _| 0.0, &|_| model());
        }
        fl
    }

    impl Fleet {
        /// One window per leaf. `offset(leaf, j)` is added to the mean; `model(leaf)` is the hash reported.
        fn step(&mut self, offset: &dyn Fn(usize, usize) -> f64, model: &dyn Fn(usize) -> &'static str) {
            for l in 0..LEAVES {
                let v: Vec<i8> = (0..D)
                    .map(|j| (base(l, j) + offset(l, j) + SIGMA * self.rng.normal()).round().clamp(-128.0, 127.0) as i8)
                    .collect();
                self.f.observe(&format!("leaf{l}"), model(l), &v).unwrap();
            }
            self.t += 1;
        }

        fn run(&mut self, n: usize, offset: &dyn Fn(usize, usize) -> f64, model: &dyn Fn(usize) -> &'static str) {
            for _ in 0..n {
                self.step(offset, model);
            }
        }

        fn causes(&self) -> Vec<Cause> {
            (0..LEAVES).map(|l| self.f.cause_of(&format!("leaf{l}")).unwrap()).collect()
        }
    }

    #[test]
    fn a_fleet_that_does_not_change_raises_no_alarm_over_many_windows() {
        let mut alarms = 0;
        for seed in 1..=20 {
            let mut fl = fleet(seed);
            fl.run(3000, &|_, _| 0.0, &|_| model());
            alarms += fl.causes().iter().filter(|c| **c != Cause::Stable).count();
        }
        // 20 fleets x 6 nodes x 3000 windows.
        assert_eq!(alarms, 0);
    }

    #[test]
    fn a_site_wide_common_shift_is_read_as_site_wide_for_every_node() {
        let mut right = 0;
        let mut delays = Vec::new();
        for seed in 1..=20 {
            let mut fl = fleet(seed);
            let common = |_: usize, j: usize| if j.is_multiple_of(2) { 5.0 } else { -3.0 };
            fl.run(80, &common, &|_| model());
            if fl.causes().iter().all(|c| *c == Cause::SiteWide) {
                right += 1;
            }
            delays.extend(fl.f.attribute().iter().filter_map(|a| a.alarmed_at));
        }
        let worst = *delays.iter().max().unwrap();
        println!("site-wide: attributed correctly {right}/20, worst alarm delay {worst} windows");
        assert_eq!(right, 20);
        assert!(worst <= 40);
    }

    #[test]
    fn one_node_drifting_alone_is_read_as_sensor_drift_and_the_rest_stable() {
        let mut right = 0;
        let mut worst = 0;
        for seed in 1..=20 {
            let mut fl = fleet(seed);
            // A step on one node's channels, different direction from any common mode.
            let one = |l: usize, j: usize| if l == 3 && j < 4 { 6.0 } else { 0.0 };
            fl.run(80, &one, &|_| model());
            let c = fl.causes();
            if c[3] == Cause::SensorDrift && c.iter().enumerate().all(|(i, x)| i == 3 || *x == Cause::Stable) {
                right += 1;
            }
            worst = worst.max(fl.f.attribute().iter().find(|a| a.node == "leaf3").unwrap().alarmed_at.unwrap_or(999));
        }
        println!("single node: attributed correctly {right}/20, worst alarm delay {worst} windows");
        assert_eq!(right, 20);
        assert!(worst <= 40);
    }

    #[test]
    fn a_slow_ramp_on_one_node_is_found_by_page_hinkley() {
        let mut right = 0;
        let mut delays = Vec::new();
        for seed in 1..=20 {
            let mut fl = fleet(seed);
            // 0.04 reference spreads per window on four channels, reaching 4 spreads at 100 windows.
            for k in 0..300 {
                let amp = 0.04 * SIGMA * k as f64;
                fl.step(&move |l, j| if l == 1 && j < 4 { amp } else { 0.0 }, &|_| model());
                if fl.f.cause_of("leaf1") == Some(Cause::SensorDrift) {
                    delays.push(k);
                    right += 1;
                    break;
                }
            }
        }
        let worst = *delays.iter().max().unwrap();
        println!("ramp: found {right}/20, worst delay {worst} windows");
        assert_eq!(right, 20);
        assert!(worst <= 120);
    }

    #[test]
    fn every_node_changing_model_and_shifting_is_read_as_a_model_change_and_never_as_the_site() {
        let mut right = 0;
        for seed in 1..=20 {
            let mut fl = fleet(seed);
            fl.run(80, &|l, j| if (j + l) % 2 == 0 { 7.0 } else { -4.0 }, &|_| "bbbbbbbbbbbbbbbb");
            if fl.causes().iter().all(|c| *c == Cause::ModelChange) {
                right += 1;
            }
        }
        println!("model change: attributed correctly {right}/20");
        assert_eq!(right, 20);
    }

    #[test]
    fn a_staged_rollout_to_one_node_is_a_model_change_there_and_the_rest_stay_stable() {
        let mut fl = fleet(5);
        fl.run(80, &|l, j| if l == 2 && j < 4 { 7.0 } else { 0.0 }, &|l| if l == 2 { "cccccccccccccccc" } else { model() });
        let c = fl.causes();
        assert_eq!(c[2], Cause::ModelChange);
        assert!(c.iter().enumerate().all(|(i, x)| i == 2 || *x == Cause::Stable), "{c:?}");
    }

    #[test]
    fn a_model_change_that_leaves_the_embeddings_alone_raises_no_alarm() {
        let mut fl = fleet(6);
        fl.run(300, &|_, _| 0.0, &|_| "dddddddddddddddd");
        assert!(fl.causes().iter().all(|c| *c == Cause::Stable));
    }

    #[test]
    fn two_nodes_drifting_in_different_directions_are_not_read_as_the_site() {
        let mut right = 0;
        for seed in 1..=20 {
            let mut fl = fleet(seed);
            // Opposite signs, so the shifts do not align. Two of six nodes: below the site fraction anyway.
            fl.run(80, &|l, j| match l {
                0 if j < 4 => 6.0,
                4 if j < 4 => -6.0,
                _ => 0.0,
            }, &|_| model());
            let c = fl.causes();
            if c[0] == Cause::SensorDrift && c[4] == Cause::SensorDrift && c.iter().filter(|x| **x == Cause::Stable).count() == 4 {
                right += 1;
            }
        }
        assert_eq!(right, 20);
    }

    #[test]
    fn rebase_clears_an_alarm_after_the_operator_acts() {
        let mut fl = fleet(7);
        fl.run(80, &|l, j| if l == 0 && j < 4 { 8.0 } else { 0.0 }, &|_| model());
        assert_eq!(fl.f.cause_of("leaf0"), Some(Cause::SensorDrift));
        fl.f.rebase("leaf0");
        assert_eq!(fl.f.cause_of("leaf0"), None);
        fl.run(250, &|l, j| if l == 0 && j < 4 { 8.0 } else { 0.0 }, &|_| model());
        assert_eq!(fl.f.cause_of("leaf0"), Some(Cause::Stable), "the shifted behaviour is the new reference");
    }

    #[test]
    fn bad_embeddings_are_errors() {
        let mut f = FleetDrift::new(DriftConfig::default());
        assert_eq!(f.observe("a", "m", &[]), Err(DriftError::Empty));
        f.observe("a", "m", &[1, 2, 3]).unwrap();
        assert_eq!(f.observe("a", "m", &[1, 2]), Err(DriftError::Dimension { expected: 3, found: 2 }));
        assert!(!f.has_reference("a"));
    }
}
