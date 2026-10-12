//! What an edition adds to the console.
//!
//! The open console shows everything it measures and does not editorialise on
//! it. An edition that derives findings from those readings implements
//! [`Console`] and passes it to [`register`] before calling [`crate::main`].
//! Nothing here names what implements it.

use serde_json::Value;
use std::sync::OnceLock;

/// What an edition adds to the console. Every method has a default that adds
/// nothing.
pub trait Console: Send + Sync + 'static {
    /// Findings derived from the `/cooling` and `/hardware` readings the
    /// panes already show, as rendered lines. Usually empty.
    fn insight(&self, _cooling: Option<&Value>, _hardware: Option<&Value>) -> Vec<String> {
        Vec::new()
    }
}

/// The open console: adds nothing.
struct Open;

impl Console for Open {}

static REGISTERED: OnceLock<Box<dyn Console>> = OnceLock::new();

/// Register this process's console extension. Returns false, and changes
/// nothing, if one is already registered.
pub fn register(console: impl Console) -> bool {
    REGISTERED.set(Box::new(console)).is_ok()
}

/// The registered extension, or the open console's.
pub(crate) fn get() -> &'static dyn Console {
    match REGISTERED.get() {
        Some(c) => c.as_ref(),
        None => &Open,
    }
}
