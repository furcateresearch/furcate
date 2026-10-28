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
}
