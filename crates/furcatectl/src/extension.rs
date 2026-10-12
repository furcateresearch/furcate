//! What an edition adds to the operator's tool.
//!
//! The open tool is complete on its own. An edition that adds commands
//! implements [`Commands`] and passes it to [`register`] before calling
//! [`crate::main`]. Nothing here names what implements it: with nothing
//! registered, a command the open tool does not know is an unknown command.
//!
//! The open commands are matched first, so an edition adds commands and can
//! never change what an open one does.

use std::sync::OnceLock;

/// Commands an edition adds.
pub trait Commands: Send + Sync + 'static {
    /// Run `args` if this edition has the command, or `None` if it does not.
    fn run(&self, args: &[&str]) -> Option<anyhow::Result<()>>;

    /// Usage text for the added commands, printed after the open tool's.
    fn usage(&self) -> &'static str {
        ""
    }
}

/// The open tool: adds nothing.
struct Open;

impl Commands for Open {
    fn run(&self, _args: &[&str]) -> Option<anyhow::Result<()>> {
        None
    }
}

static REGISTERED: OnceLock<Box<dyn Commands>> = OnceLock::new();

/// Register this process's commands. Returns false, and changes nothing, if
/// some are already registered.
pub fn register(commands: impl Commands) -> bool {
    REGISTERED.set(Box::new(commands)).is_ok()
}

/// The registered commands, or the open tool's.
pub(crate) fn get() -> &'static dyn Commands {
    match REGISTERED.get() {
        Some(c) => c.as_ref(),
        None => &Open,
    }
}
