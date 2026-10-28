//! Cross-checks between the sources on one sensing node, as flags.
//!
//! The Nicla's sensor hub reports an accelerometer, a gyroscope and a fused
//! rotation vector. They are separate outputs of one physical motion, so they
//! must agree with each other, and a decoding error, a wrong range, a swapped
//! axis or a stuck channel breaks the agreement. [`CoherenceMonitor`] reads the
//! samples as they are decoded and raises a [`Flag`] when a pair disagrees:
//!
//! | check | when | flags |
//! |---|---|---|
//! | gravity magnitude | the gyroscope says the node is at rest | `|a|` is not about 1 g |
//! | gravity direction | at rest, with a rotation vector | the accelerometer's direction is not the one the rotation vector predicts for gravity |
//! | gyroscope against rotation | two rotation vectors with gyroscope samples between | the angle the rotation vector turned through is not what the gyroscope integrated to |
//! | rotation vector norm | every rotation vector | the quaternion is not a unit quaternion |
//!
//! This is a monitor that flags, not an identity: agreement shows the sources
//! are mutually consistent, not that the node is the one that was enrolled, and
//! a node whose three outputs are all wrong in a consistent way (a replayed
//! recording) passes. It also cannot say which of two disagreeing sources is
//! wrong; the flag names the pair. A magnitude flag carries the scale that
//! would make the vector one g, which is a hint to look at the range setting,
//! not a correction applied to anything.
//!
//! Frame convention, checked against the recorded capture: the rotation vector
//! `(x, y, z, w)` rotates the sensor frame into the world frame, so gravity as
//! the accelerometer sees it at rest is the world up axis rotated back into the
//! sensor frame.

use crate::nicla::Sample;

pub const STANDARD_GRAVITY: f64 = 9.80665;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CoherenceConfig {
    /// The node is at rest when the gyroscope magnitude is below this, in degrees per second.
    pub rest_dps: f64,
    /// Allowed deviation of the rest magnitude from 1 g, as a fraction.
    pub gravity_tolerance: f64,
    /// Allowed angle between measured and predicted gravity, in degrees.
    pub direction_tolerance_deg: f64,
    /// Allowed disagreement between the integrated gyroscope and the rotation
    /// vector's angle: absolute radians, plus a fraction of the larger angle.
    pub rotation_abs_rad: f64,
    pub rotation_rel: f64,
    /// Rotation vectors further apart than this in time are not compared, in seconds.
    pub max_gap_s: f64,
    /// Allowed deviation of the quaternion norm from 1.
    pub norm_tolerance: f64,
}

impl Default for CoherenceConfig {
    fn default() -> Self {
        Self {
            rest_dps: 5.0,
            gravity_tolerance: 0.10,
            direction_tolerance_deg: 10.0,
            rotation_abs_rad: 0.03,
            rotation_rel: 0.25,
            max_gap_s: 2.0,
            norm_tolerance: 0.02,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Flag {
    /// At rest the acceleration is `measured_g` g. `scale_to_one_g` is the factor that would make it 1.
    GravityMagnitude { measured_g: f64, scale_to_one_g: f64 },
    GravityDirection { angle_deg: f64 },
    GyroRotationMismatch { gyro_rad: f64, rotation_rad: f64 },
    QuaternionNorm { norm: f64 },
    /// A value that is not a finite number.
    NotFinite(&'static str),
}

impl Flag {
    pub fn code(&self) -> &'static str {
        match self {
            Flag::GravityMagnitude { .. } => "coherence_gravity_magnitude",
            Flag::GravityDirection { .. } => "coherence_gravity_direction",
            Flag::GyroRotationMismatch { .. } => "coherence_gyro_rotation",
            Flag::QuaternionNorm { .. } => "coherence_quaternion_norm",
            Flag::NotFinite(_) => "coherence_not_finite",
        }
    }
}

impl std::fmt::Display for Flag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Flag::GravityMagnitude { measured_g, scale_to_one_g } => write!(
                f,
                "at rest the acceleration is {measured_g:.2} g; a scale of {scale_to_one_g:.3} would make it 1 g (check the accelerometer range)"
            ),
            Flag::GravityDirection { angle_deg } => {
                write!(f, "the accelerometer and the rotation vector disagree on which way is down by {angle_deg:.1} degrees")
            }
            Flag::GyroRotationMismatch { gyro_rad, rotation_rad } => {
                write!(f, "the gyroscope integrates to {gyro_rad:.3} rad but the rotation vector turned {rotation_rad:.3} rad")
            }
            Flag::QuaternionNorm { norm } => write!(f, "the rotation vector has norm {norm:.3}"),
            Flag::NotFinite(w) => write!(f, "{w} is not a finite number"),
        }
    }
}

type Quat = [f64; 4]; // x, y, z, w

/// Hamilton product `a * b`.
pub fn quat_mul(a: Quat, b: Quat) -> Quat {
    let ([ax, ay, az, aw], [bx, by, bz, bw]) = (a, b);
    [
        aw * bx + ax * bw + ay * bz - az * by,
        aw * by - ax * bz + ay * bw + az * bx,
        aw * bz + ax * by - ay * bx + az * bw,
        aw * bw - ax * bx - ay * by - az * bz,
    ]
}

fn norm3(v: [f64; 3]) -> f64 {
    (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt()
}

/// The world up axis expressed in the sensor frame, for a unit rotation vector.
pub fn gravity_direction_in_sensor_frame(q: Quat) -> [f64; 3] {
    let [x, y, z, w] = q;
    [2.0 * (x * z - w * y), 2.0 * (y * z + w * x), 1.0 - 2.0 * (x * x + y * y)]
}

/// The angle between two unit rotation vectors, in radians.
pub fn rotation_angle(a: Quat, b: Quat) -> f64 {
    let dot = (a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3]).abs().min(1.0);
    2.0 * dot.acos()
}

#[derive(Default)]
pub struct CoherenceMonitor {
    cfg: CoherenceConfig,
    accel: Option<[f64; 3]>,
    gyro: Option<[f64; 3]>,
    rotation: Option<Quat>,
    last_rotation: Option<(Quat, f64)>,
    gyro_since_rotation: Vec<f64>,
    pending_magnitude: bool,
    pending_direction: bool,
    /// Flags raised so far, by code.
    pub raised: std::collections::BTreeMap<&'static str, u64>,
}

impl CoherenceMonitor {
    pub fn new(cfg: CoherenceConfig) -> Self {
        Self { cfg, ..Default::default() }
    }

    fn at_rest(&self) -> bool {
        self.gyro.is_some_and(|g| norm3(g).to_degrees() < self.cfg.rest_dps)
    }

    /// Each new acceleration is checked once for magnitude, and each new
    /// acceleration or rotation vector once for direction, as soon as the node
    /// is known to be at rest and the other source is present.
    fn check_gravity(&mut self, out: &mut Vec<Flag>) {
        let Some(a) = self.accel else { return };
        if !self.at_rest() {
            return;
        }
        if std::mem::take(&mut self.pending_magnitude) {
            let g = norm3(a) / STANDARD_GRAVITY;
            if (g - 1.0).abs() > self.cfg.gravity_tolerance {
                out.push(Flag::GravityMagnitude { measured_g: g, scale_to_one_g: if g > 0.0 { 1.0 / g } else { f64::INFINITY } });
            }
        }
        if let (Some(q), true) = (self.rotation, self.pending_direction) {
            self.pending_direction = false;
            let up = gravity_direction_in_sensor_frame(q);
            let (na, nu) = (norm3(a), norm3(up));
            if na > 0.0 && nu > 0.0 {
                let cos = ((a[0] * up[0] + a[1] * up[1] + a[2] * up[2]) / (na * nu)).clamp(-1.0, 1.0);
                let angle = cos.acos().to_degrees();
                if angle > self.cfg.direction_tolerance_deg {
                    out.push(Flag::GravityDirection { angle_deg: angle });
                }
            }
        }
    }

    /// Feed one decoded sample taken at `t_s` seconds; returns the flags it raised.
    pub fn observe(&mut self, sample: &Sample, t_s: f64) -> Vec<Flag> {
        let mut out = Vec::new();
        match sample {
            Sample::Acceleration { x, y, z } => {
                if ![x, y, z].iter().all(|v| v.is_finite()) {
                    out.push(Flag::NotFinite("acceleration"));
                } else {
                    self.accel = Some([*x, *y, *z]);
                    self.pending_magnitude = true;
                    self.pending_direction = true;
                    self.check_gravity(&mut out);
                }
            }
            Sample::AngularRate { x, y, z } => {
                if ![x, y, z].iter().all(|v| v.is_finite()) {
                    out.push(Flag::NotFinite("angular rate"));
                } else {
                    self.gyro = Some([*x, *y, *z]);
                    self.gyro_since_rotation.push(norm3([*x, *y, *z]));
                    self.check_gravity(&mut out);
                }
            }
            Sample::Rotation { x, y, z, w, .. } => {
                if ![x, y, z, w].iter().all(|v| v.is_finite()) {
                    out.push(Flag::NotFinite("rotation vector"));
                } else {
                    let q = [*x, *y, *z, *w];
                    let norm = (q.iter().map(|v| v * v).sum::<f64>()).sqrt();
                    if (norm - 1.0).abs() > self.cfg.norm_tolerance {
                        out.push(Flag::QuaternionNorm { norm });
                    } else {
                        let q = q.map(|v| v / norm);
                        if let Some((prev, t0)) = self.last_rotation {
                            let dt = t_s - t0;
                            if dt > 0.0 && dt <= self.cfg.max_gap_s && !self.gyro_since_rotation.is_empty() {
                                let mean = self.gyro_since_rotation.iter().sum::<f64>() / self.gyro_since_rotation.len() as f64;
                                let (gyro_rad, rotation_rad) = (mean * dt, rotation_angle(prev, q));
                                let allowed = self.cfg.rotation_abs_rad + self.cfg.rotation_rel * gyro_rad.max(rotation_rad);
                                if (gyro_rad - rotation_rad).abs() > allowed {
                                    out.push(Flag::GyroRotationMismatch { gyro_rad, rotation_rad });
                                }
                            }
                        }
                        self.last_rotation = Some((q, t_s));
                        self.gyro_since_rotation.clear();
                        self.rotation = Some(q);
                        self.pending_direction = true;
                        self.check_gravity(&mut out);
                    }
                }
            }
            _ => {}
        }
        for f in &out {
            *self.raised.entry(f.code()).or_insert(0) += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_COUNTS: [f64; 3] = [5807.0, 1622.0, 15767.0];
    const FIXTURE_Q: Quat = [0.048, -0.176, 0.003, 0.983];

    fn accel_at(range_g: f64) -> Sample {
        let k = range_g / 32768.0 * STANDARD_GRAVITY;
        Sample::Acceleration { x: FIXTURE_COUNTS[0] * k, y: FIXTURE_COUNTS[1] * k, z: FIXTURE_COUNTS[2] * k }
    }

    fn still() -> Sample {
        let k = 2000.0 / 32768.0_f64.to_radians().recip();
        let _ = k;
        let s = 2000.0 / 32768.0 * std::f64::consts::PI / 180.0;
        Sample::AngularRate { x: 7.0 * s, y: -4.0 * s, z: 2.0 * s }
    }

    fn rot(q: Quat) -> Sample {
        Sample::Rotation { x: q[0], y: q[1], z: q[2], w: q[3], accuracy: Some(3.1) }
    }

    #[test]
    fn the_recorded_capture_has_one_g_at_2g_scale_and_four_g_at_8g_scale_and_the_direction_agrees() {
        // At the scale that makes the vector one g, nothing is flagged.
        let mut m = CoherenceMonitor::new(CoherenceConfig::default());
        let mut flags = Vec::new();
        for (t, s) in [(0.0, accel_at(2.0)), (0.1, still()), (0.2, rot(FIXTURE_Q))] {
            flags.extend(m.observe(&s, t));
        }
        assert!(flags.is_empty(), "{flags:?}");

        // At the printed 8 g scale the magnitude is flagged and the hint is the factor of four.
        let mut m = CoherenceMonitor::new(CoherenceConfig::default());
        let mut flags = Vec::new();
        for (t, s) in [(0.0, accel_at(8.0)), (0.1, still()), (0.2, rot(FIXTURE_Q))] {
            flags.extend(m.observe(&s, t));
        }
        let [Flag::GravityMagnitude { measured_g, scale_to_one_g }] = flags.as_slice() else { panic!("{flags:?}") };
        assert!((measured_g - 4.13).abs() < 0.05, "{measured_g}");
        assert!((scale_to_one_g - 0.2424).abs() < 0.01, "{scale_to_one_g}");
        // The direction check passes at either scale: the vectors point the same way.
        assert!(flags.iter().all(|f| !matches!(f, Flag::GravityDirection { .. })));
    }

    // A body turning at a constant rate about a fixed axis of its own frame,
    // starting from the fixture's attitude, with the accelerometer at rest in
    // the world (so it reads gravity rotated into the body frame).
    struct Trajectory {
        axis: [f64; 3],
        rate: f64,
        q0: Quat,
    }

    impl Trajectory {
        fn q(&self, t: f64) -> Quat {
            let h = self.rate * t / 2.0;
            let s = h.sin();
            let dq = [self.axis[0] * s, self.axis[1] * s, self.axis[2] * s, h.cos()];
            quat_mul(self.q0, dq)
        }
        fn accel(&self, t: f64) -> [f64; 3] {
            let u = gravity_direction_in_sensor_frame(self.q(t));
            [u[0] * STANDARD_GRAVITY, u[1] * STANDARD_GRAVITY, u[2] * STANDARD_GRAVITY]
        }
        fn gyro(&self) -> [f64; 3] {
            [self.axis[0] * self.rate, self.axis[1] * self.rate, self.axis[2] * self.rate]
        }
    }

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

    fn random_trajectory(r: &mut Rng, still: bool) -> Trajectory {
        let v = [r.normal(), r.normal(), r.normal()];
        let n = norm3(v);
        let q0 = {
            let q = [r.normal(), r.normal(), r.normal(), r.normal()];
            let n = (q.iter().map(|x| x * x).sum::<f64>()).sqrt();
            q.map(|x| x / n)
        };
        Trajectory { axis: [v[0] / n, v[1] / n, v[2] / n], rate: if still { 0.0 } else { 0.3 + 2.0 * r.u() }, q0 }
    }

    /// Run a trajectory for 20 s at 50 Hz with sensor noise; `tamper` edits each sample.
    fn run(tr: &Trajectory, r: &mut Rng, tamper: &dyn Fn(Sample) -> Sample) -> Vec<Flag> {
        let mut m = CoherenceMonitor::new(CoherenceConfig::default());
        let mut flags = Vec::new();
        for i in 0..1000 {
            let t = i as f64 * 0.02;
            let a = tr.accel(t);
            let g = tr.gyro();
            let noise = |v: f64, sd: f64, r: &mut Rng| v + sd * r.normal();
            let samples = [
                Sample::Acceleration { x: noise(a[0], 0.05, r), y: noise(a[1], 0.05, r), z: noise(a[2], 0.05, r) },
                Sample::AngularRate { x: noise(g[0], 0.005, r), y: noise(g[1], 0.005, r), z: noise(g[2], 0.005, r) },
            ];
            for s in samples {
                flags.extend(m.observe(&tamper(s), t));
            }
            // The fused rotation vector arrives at 10 Hz.
            if i % 5 == 0 {
                let q = tr.q(t);
                let qn = [noise(q[0], 0.0005, r), noise(q[1], 0.0005, r), noise(q[2], 0.0005, r), noise(q[3], 0.0005, r)];
                let n = (qn.iter().map(|x| x * x).sum::<f64>()).sqrt();
                flags.extend(m.observe(&tamper(rot(qn.map(|x| x / n))), t));
            }
        }
        flags
    }

    #[test]
    fn consistent_motion_raises_no_flag_at_rest_or_turning() {
        let mut r = Rng(0xC0FFEE);
        let mut flagged = 0;
        for k in 0..60 {
            let tr = random_trajectory(&mut r, k % 2 == 0);
            flagged += run(&tr, &mut r, &|s| s).len();
        }
        assert_eq!(flagged, 0, "false flags over 60 trajectories x 1000 windows");
    }

    #[test]
    fn each_injected_fault_is_flagged_in_every_trial() {
        let mut r = Rng(0xFEED);
        // (name, an accelerometer scale error, swapped axes, a gyroscope scale error, a rotation vector with the wrong sign)
        type Fault = (&'static str, bool, fn(Sample) -> Sample, &'static str);
        let faults: [Fault; 4] = [
            ("accelerometer scaled by 4", true, |s| match s {
                Sample::Acceleration { x, y, z } => Sample::Acceleration { x: x * 4.0, y: y * 4.0, z: z * 4.0 },
                o => o,
            }, "coherence_gravity_magnitude"),
            ("accelerometer x and y swapped", true, |s| match s {
                Sample::Acceleration { x, y, z } => Sample::Acceleration { x: y, y: x, z },
                o => o,
            }, "coherence_gravity_direction"),
            ("gyroscope scaled by 3", false, |s| match s {
                Sample::AngularRate { x, y, z } => Sample::AngularRate { x: x * 3.0, y: y * 3.0, z: z * 3.0 },
                o => o,
            }, "coherence_gyro_rotation"),
            ("rotation vector scaled off the unit sphere", true, |s| match s {
                Sample::Rotation { x, y, z, w, accuracy } => Sample::Rotation { x: x * 1.3, y: y * 1.3, z: z * 1.3, w: w * 1.3, accuracy },
                o => o,
            }, "coherence_quaternion_norm"),
        ];
        for (name, at_rest, tamper, code) in faults {
            let (mut detected, mut counted) = (0, 0);
            for _ in 0..80 {
                let tr = random_trajectory(&mut r, at_rest);
                // Swapping x and y changes nothing where gravity has equal x and y; a trial is only
                // counted for that fault where the swap moves the vector by more than twice the tolerance.
                if name.contains("swapped") {
                    let u = gravity_direction_in_sensor_frame(tr.q0);
                    let swapped = [u[1], u[0], u[2]];
                    let cos = (u[0] * swapped[0] + u[1] * swapped[1] + u[2] * swapped[2]) / (norm3(u) * norm3(swapped));
                    if cos.clamp(-1.0, 1.0).acos().to_degrees() < 2.0 * CoherenceConfig::default().direction_tolerance_deg {
                        continue;
                    }
                    counted += 1;
                } else {
                    counted += 1;
                }
                let flags = run(&tr, &mut r, &tamper);
                if flags.iter().any(|f| f.code() == code) {
                    detected += 1;
                }
            }
            println!("{name}: flagged in {detected}/{counted} counted trials");
            assert!(counted >= 20, "{name}: only {counted} counted");
            assert_eq!(detected, counted, "{name}");
        }
    }

    #[test]
    fn a_node_that_is_turning_is_not_flagged_for_a_gravity_magnitude() {
        // The same gravity check must stay quiet in motion: a fast spin with a large acceleration reading.
        let mut m = CoherenceMonitor::new(CoherenceConfig::default());
        let fast = Sample::AngularRate { x: 5.0, y: 0.0, z: 0.0 };
        assert!(m.observe(&fast, 0.0).is_empty());
        assert!(m.observe(&Sample::Acceleration { x: 30.0, y: 0.0, z: 0.0 }, 0.01).is_empty());
    }

    #[test]
    fn non_finite_values_and_gaps_are_handled() {
        let mut m = CoherenceMonitor::new(CoherenceConfig::default());
        let f = m.observe(&Sample::Acceleration { x: f64::NAN, y: 0.0, z: 0.0 }, 0.0);
        assert_eq!(f, vec![Flag::NotFinite("acceleration")]);
        // Two rotation vectors further apart than the gap limit are not compared.
        m.observe(&Sample::AngularRate { x: 1.0, y: 0.0, z: 0.0 }, 0.0);
        m.observe(&rot([0.0, 0.0, 0.0, 1.0]), 0.0);
        assert!(m.observe(&rot([0.0, 0.0, std::f64::consts::FRAC_1_SQRT_2, std::f64::consts::FRAC_1_SQRT_2]), 10.0).is_empty());
        assert_eq!(m.raised.get("coherence_not_finite"), Some(&1));
    }
}
