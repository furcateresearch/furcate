//! What a long-running service saves so a restart keeps replay protection and the ledger chain.

use crate::actuation::ApprovalError;
use crate::chunk::EndState;
use furcate_ledger::Chain;
use serde::{Deserialize, Serialize};

/// Version of the saved state layout.
pub const STATE_VERSION: u32 = 1;

/// The last accepted setpoint of one actuator and quantity, for the rate check.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppliedEntry {
    pub actuator_id: String,
    pub quantity: String,
    pub value: f64,
    pub at_ms: u64,
}

/// The gate's state. Written by [`crate::Gate::export_state`], read by [`crate::Gate::restore`], which refuses a state
/// whose chain does not verify. It holds no key and no secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateState {
    pub v: u32,
    pub site_id: String,
    pub tenant: String,
    /// Highest accepted command sequence number (replay protection).
    pub last_seq: u64,
    pub last_applied: Vec<AppliedEntry>,
    /// Per actuator, where the last accepted chunk ended.
    pub last_chunk: Vec<(String, EndState)>,
    /// How many receipts have been made.
    pub receipts: u64,
    /// Installed approvals, canonical record text exactly as installed.
    pub approvals: Vec<String>,
    /// Ids of revoked approvals, which stay uninstallable.
    pub revoked_approvals: Vec<String>,
    pub chain: Chain,
}

/// Why a saved state was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreError {
    /// Another layout version.
    Version,
    /// The state is for another site.
    WrongSite,
    /// The state is for another tenant.
    WrongTenant,
    /// The ledger chain does not verify.
    Chain(String),
    /// An installed approval does not verify.
    Approval(ApprovalError),
    /// An approval or revocation the state lists has no matching entry in the chain, or an installed approval is
    /// revoked in the chain.
    ApprovalNotInChain(String),
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RestoreError::Version => write!(f, "state version not supported"),
            RestoreError::WrongSite => write!(f, "state is for another site"),
            RestoreError::WrongTenant => write!(f, "state is for another tenant"),
            RestoreError::Chain(e) => write!(f, "ledger chain does not verify: {e}"),
            RestoreError::Approval(e) => write!(f, "installed approval does not verify: {e}"),
            RestoreError::ApprovalNotInChain(id) => write!(f, "approval {id} does not match the ledger chain"),
        }
    }
}
impl std::error::Error for RestoreError {}
