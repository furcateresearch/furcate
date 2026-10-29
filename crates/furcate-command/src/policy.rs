//! What the site decides for itself. Nothing here is read from a command.

#[derive(Clone, Debug)]
pub struct SiteLimit {
    pub actuator_id: String,
    pub quantity: String,
    pub unit: String,
    pub min: f64,
    pub max: f64,
    /// Largest change per second between two accepted setpoints on this actuator and quantity.
    pub max_rate_per_s: f64,
}

/// What the gate does with a chunk that has a violating step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkOverrun {
    /// Refuse the whole chunk.
    Veto,
    /// Keep the longest prefix that is inside every limit, provided it has at least `min_steps` steps (at least 1);
    /// otherwise veto. Violations of the chunk as a whole (step period, length, interval, continuity, degrees of
    /// freedom, missing members) always veto.
    Truncate { min_steps: usize },
}

/// The stop a stop request asks a safety controller for, by IEC 60204-1 stop category. A request only names a
/// category; the safety controller decides and executes, and a request is never an emergency stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestedStop {
    /// Category 0, safe torque off.
    Sto,
    /// Category 1, controlled stop then power removal (SS1).
    Ss1,
    /// Category 2, controlled stop with power kept (SS2).
    Ss2,
}

impl RequestedStop {
    pub fn as_str(&self) -> &'static str {
        match self {
            RequestedStop::Sto => "sto",
            RequestedStop::Ss1 => "ss1",
            RequestedStop::Ss2 => "ss2",
        }
    }
}

/// Limits for trajectory commands on one actuator (an arm, a leg, a mobile base). Vectors have `dof` entries.
#[derive(Clone, Debug)]
pub struct TrajectoryLimit {
    pub actuator_id: String,
    pub dof: usize,
    pub q_min: Vec<f64>,
    pub q_max: Vec<f64>,
    /// Largest speed, acceleration and jerk magnitude per joint.
    pub dq_max: Vec<f64>,
    pub ddq_max: Vec<f64>,
    pub dddq_max: Vec<f64>,
    /// Largest effort magnitude per joint. When set, a chunk must carry `tau` for every step.
    pub tau_max: Option<Vec<f64>>,
    /// Workspace box (min, max) of the end effector. When set, a chunk must carry `xyz` for every step.
    pub xyz: Option<([f64; 3], [f64; 3])>,
    /// Accepted step period range, longest chunk and shortest time between two accepted chunks.
    pub min_step_ms: u64,
    pub max_step_ms: u64,
    pub max_steps: usize,
    pub min_chunk_interval_ms: u64,
    /// Largest joint position gap between the end of the last accepted chunk and the start of the next.
    pub join_tolerance: f64,
    pub overrun: ChunkOverrun,
    /// The safety controller a stop request is addressed to, and the category asked for.
    pub safety_controller_id: String,
    pub requested_stop: RequestedStop,
}

#[derive(Clone, Debug)]
pub struct SitePolicy {
    pub site_id: String,
    pub tenant: String,
    /// SHA-256 (hex) of the signed operator policy in force. A command must name exactly this.
    pub policy_sha256: String,
    /// Enrolled simulation-platform signing keys, `ed25519:<hex>`.
    pub signers: Vec<String>,
    /// Approved model hashes.
    pub approved_models: Vec<String>,
    pub require_birth_record: bool,
    pub approved_birth_records: Vec<String>,
    /// Longest `expires_at - issued_at` the site accepts.
    pub max_ttl_ms: u64,
    /// Oldest `now - issued_at` the site accepts.
    pub max_age_ms: u64,
    /// How far in the future `issued_at` may be (clock skew).
    pub max_skew_ms: u64,
    /// Lowest twin fidelity score the site accepts.
    pub min_fidelity: f64,
    /// Limits per actuator and quantity. No limit for a pair means deny.
    pub limits: Vec<SiteLimit>,
    /// Limits per actuator for trajectory commands. No limit for an actuator means deny.
    pub trajectory_limits: Vec<TrajectoryLimit>,
}
