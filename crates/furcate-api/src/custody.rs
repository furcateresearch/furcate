//! A node's key custody, read only.
//!
//! `GET /custody/keys` answers who holds this site's keys as this node sees
//! it: the mode, this node's class, whether it holds custody, the elected or
//! designated holders with their classes, and the reason whenever something
//! was refused. It is open for the same reason the site view is: it changes
//! nothing and states only what an operator needs to see to trust the answer.
//! Custody changes go through a signed order, never through this route.

use crate::{Request, Response, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The path the status is served on.
pub const PATH: &str = "/custody/keys";

/// One machine holding custody, and the class it holds it with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderStatus {
    pub id: String,
    pub class: String,
}

/// This node's account of the site's key custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyStatus {
    /// `elected`, `designated` or `self`.
    pub mode: String,
    pub node: String,
    /// This node's appraised class.
    pub class: String,
    pub holds_custody: bool,
    pub holders: Vec<HolderStatus>,
    /// Why this node holds nothing, or why no holder could be chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    /// The lowest class the settings admit.
    pub floor: String,
    pub tpm_less: bool,
    pub allow_soft: bool,
    /// `operator` or `passkeys`: what authorised the settings in force;
    /// `none` when the site has no custody record, `default` when its record
    /// was refused.
    pub settings_from: String,
    /// The custody mode material already sealed to this node opens under.
    /// With no custody record it is `self`: the node sealed it to its own TPM
    /// before custody existed, and new placement still follows `mode`.
    #[serde(default)]
    pub existing_material: String,
    /// Why this node may not open material already sealed to it, when it may
    /// not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_material_refused: Option<String>,
    /// The epoch of the change in force, when one is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// Why a stored custody record was not used, when it was not. The node is
    /// then on the strict default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings_refused: Option<String>,
}

/// Whatever can state a node's custody.
pub trait CustodySource: Send + Sync {
    fn status(&self) -> CustodyStatus;
}

/// Register the read-only custody route.
pub fn mount(router: Router, source: Arc<dyn CustodySource>) -> Router {
    router.route("GET", PATH, move |_: &Request| match serde_json::to_value(source.status()) {
        Ok(v) => Response::ok(v),
        Err(e) => Response::error(500, format!("custody status did not serialise: {e}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;

    impl CustodySource for Fixed {
        fn status(&self) -> CustodyStatus {
            CustodyStatus {
                mode: "elected".into(),
                node: "pi-1".into(),
                class: "tee".into(),
                holds_custody: false,
                holders: vec![],
                refused: Some("custody.tpm_less is off".into()),
                floor: "dice".into(),
                tpm_less: false,
                allow_soft: false,
                settings_from: "default".into(),
                existing_material: "elected".into(),
                existing_material_refused: None,
                epoch: None,
                settings_refused: None,
            }
        }
    }

    #[test]
    fn the_status_is_served_open_and_read_only() {
        let r = mount(Router::new(), Arc::new(Fixed));
        assert!(r.guarded_paths().is_empty());
        let req = Request {
            method: "GET".into(),
            path: PATH.into(),
            ..Default::default()
        };
        let resp = r.dispatch(&req);
        assert_eq!(resp.status, 200);
        let body = resp.body;
        assert_eq!(body["holds_custody"], false);
        assert_eq!(body["class"], "tee");
        assert!(body["refused"].as_str().unwrap().contains("tpm_less"));
        let post = Request { method: "POST".into(), path: PATH.into(), ..Default::default() };
        assert_ne!(r.dispatch(&post).status, 200);
    }
}
