//! Carrying out what was approved.
//!
//! Approval and execution are deliberately separate. The controller records
//! that a person said yes; it cannot act on that, because it holds no operator
//! key — and a controller that could carry out its own proposals would be a
//! network-facing process able to change machines on its own say-so.
//!
//! This is where the signature is spent. It runs where the operator is, reads
//! what was approved, shows it again in the words they agreed to, and performs
//! exactly that.
//!
//! Nothing here decides anything. It refuses a proposal that was not approved,
//! one that has expired, and one whose action it cannot name — the vocabulary
//! is closed, so an approved thing that is not in it is not performed on the
//! strength of having been approved.

use anyhow::{bail, Context, Result};
use furcate_policy::action::Action;

/// What the controller holds, read back.
fn fetch(site: &str, id: &str) -> Result<serde_json::Value> {
    let all = furcate_api::get_json(site, "/proposals", 8_000)
        .with_context(|| format!("reading proposals from {site}"))?;
    let list = all
        .get("proposals")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    list.into_iter()
        .find(|p| p.get("id").and_then(|v| v.as_str()) == Some(id))
        .ok_or_else(|| anyhow::anyhow!("no proposal `{id}` on {site}"))
}

/// The action a proposal carries, if this build knows how to perform it.
///
/// A proposal records a policy request — a capability and a resource — and the
/// typed action is carried alongside it. Reconstructing the action from the
/// capability alone would be guessing at arguments nobody approved.
fn action_of(p: &serde_json::Value) -> Result<Action> {
    let a = p
        .get("action")
        .ok_or_else(|| anyhow::anyhow!(
            "this proposal carries no typed action, so there is nothing to perform. \
             It was recorded for a person to act on by hand"
        ))?;
    serde_json::from_value(a.clone()).context("the action on this proposal is not one this build knows")
}

/// Perform an approved proposal.
pub fn act(key_path: &str, site: &str, id: &str, yes: bool) -> Result<()> {
    let p = fetch(site, id)?;
    // `status` is a tagged enum, so it arrives as either a bare string
    // ("open") or an object ({"approved": {"by": ...}}). Reading only the
    // string form made every approved proposal look like "?" and refused the
    // one case this command exists for.
    let status = p.get("status");
    let approved_by = status
        .and_then(|v| v.get("approved"))
        .and_then(|a| a.get("by"))
        .and_then(|v| v.as_str());
    if approved_by.is_none() {
        let shown = status
            .and_then(|v| v.as_str().map(String::from))
            .or_else(|| status.and_then(|v| v.as_object()).and_then(|o| o.keys().next().cloned()))
            .unwrap_or_else(|| "unknown".into());
        bail!("proposal `{id}` is {shown}, not approved; nothing is performed");
    }

    let action = action_of(&p)?;
    // Checked again here, not because the controller did not, but because this
    // is the last moment before a signature is spent and the cost of checking
    // twice is nothing next to the cost of being wrong once.
    action.check().map_err(|e| anyhow::anyhow!("{e}"))?;

    let who = p.get("proposer").and_then(|v| v.as_str()).unwrap_or("?");
    let by = approved_by.unwrap_or("an operator");

    // Shown in the words the approval was given in, rather than as a payload.
    // Somebody confirming at this prompt should be agreeing to the same
    // sentence they agreed to before.
    println!("{}", action.describe());
    println!("  proposed by {who}, approved by {by}");
    if !action.reversal().is_reversible() {
        println!("  this cannot be undone");
    }

    if !yes {
        println!();
        println!("not performed. Add --yes to carry it out.");
        return Ok(());
    }

    let (path, body) = action.route();
    let node = action.node().to_string();
    // The action names a machine; the call goes to that machine.
    let addr = endpoint_of(site, &node)
        .ok_or_else(|| anyhow::anyhow!("{node} is not answering, so nothing was performed"))?;

    let reply = crate::signed_post(key_path, &addr, path, &body)?;
    if let Some(e) = reply.get("error").and_then(|v| v.as_str()) {
        bail!("{node} refused: {e}");
    }
    println!();
    println!("done on {node}.");
    Ok(())
}

/// Where a machine answers, by handle or by node id.
fn endpoint_of(site: &str, name: &str) -> Option<String> {
    let fleet = furcate_api::get_json(site, "/fleet", 8_000).ok()?;
    let nodes = fleet.get("nodes")?.as_array()?;
    let want = name.trim_start_matches('@');
    nodes
        .iter()
        .find(|n| {
            n.get("handle").and_then(|v| v.as_str()) == Some(want)
                || n.get("topology").and_then(|v| v.as_str()) == Some(want)
                || n.get("node_id").and_then(|v| v.as_str()) == Some(name)
        })
        .and_then(|n| n.get("endpoint")?.as_str())
        .map(String::from)
}
