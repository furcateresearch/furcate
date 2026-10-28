//! The site as its cells: `GET /cells` and the page at `GET /cells/view`.
//!
//! The same readings as the rest of this crate, arranged as the tree the
//! signed chain describes: the core cluster's controllers, then each cell with
//! its head, edge machine and leaves, and the cells inside it. Per tier, what
//! matters there: machines show cores, power and workloads; leaves show
//! sensors, models, streams, battery and signal; each cell sums to one line.
//!
//! ## Scoped by the caller's own link
//!
//! Unlike `/site`, these routes are guarded, and what they answer depends on
//! who asks. The operator sees the whole tree. Anyone else sees the cell their
//! own signed link names and the cells inside it, and nothing beside or above
//! it: no sibling, no controller list, no core machine. The filtering is done
//! here, on the node, from the caller's proved identity and the chain, so a
//! page cannot be talked into showing more by asking it differently. A caller
//! with no link on this site is refused, with the reason.

use furcate_api::{Request, Response, Router};
use furcate_topology::cell::{roll_up, Cell, CellTree, Member, Readings};
use serde_json::{json, Value};

use crate::web::{esc, ABSENT};

/// What the routes read on each request.
pub type Source = dyn Fn(u64) -> Result<(CellTree, Readings), String> + Send + Sync;

/// `"not measured"` for an absent figure, so a gap never reads as a zero.
const NOT_MEASURED: &str = "not measured";

fn or_absent<T: serde::Serialize>(v: Option<T>) -> Value {
    match v {
        Some(x) => json!(x),
        None => json!(NOT_MEASURED),
    }
}

fn machine(m: &Member, r: &Readings) -> Value {
    let x = r.machine(m);
    json!({
        "name": m.name,
        "key": m.holder,
        "endpoint": m.endpoint,
        "assurance": m.assurance,
        "up": x.map(|x| x.up),
        "cores": or_absent(x.and_then(|x| x.cores)),
        "power_w": or_absent(x.and_then(|x| x.power_w)),
        "workloads": or_absent(x.and_then(|x| x.workloads)),
        "supply": or_absent(x.and_then(|x| x.supply)),
    })
}

/// A cell's head, as this node reads it, with what the head said of itself
/// filled in only where this node measured nothing.
///
/// The parent does not poll a head it only hears from, so its own reading of
/// the head's supply is empty. The head's signed roll-up carries it, and a
/// fresh one stands in for it, labelled as reported. A stale report, or one
/// that names no supply, leaves it not measured.
fn head(c: &Cell, r: &Readings, now: u64) -> Value {
    let mut v = machine(&c.head, r);
    let own = r.machine(&c.head).and_then(|x| x.supply);
    let said = fresh_report(c, r, now).and_then(|(x, _)| x.head_supply);
    v["supply_source"] = match (own, said) {
        (Some(_), _) => json!("measured here"),
        (None, Some(s)) => {
            v["supply"] = json!(s);
            json!("reported by its head")
        }
        (None, None) => json!(NOT_MEASURED),
    };
    v
}

/// The cell's last report from its own head, when recent enough to describe
/// it now.
fn fresh_report<'a>(c: &Cell, r: &'a Readings, now: u64) -> Option<(&'a furcate_topology::RollUp, u64)> {
    let (x, at) = r.reported.get(&c.id)?;
    let age = now.saturating_sub(*at);
    (age <= crate::STALE_SECS).then_some((x, age))
}

fn leaf(m: &Member, r: &Readings) -> Value {
    let x = r.leaves.get(&m.holder).or_else(|| r.leaves.get(&m.name));
    let sensors: Vec<&str> = r
        .sensors
        .iter()
        .filter(|s| s.host == m.name || s.host == m.holder)
        .map(|s| s.id.as_str())
        .collect();
    json!({
        "name": m.name,
        "key": m.holder,
        "assurance": m.assurance,
        "sensors": if sensors.is_empty() { json!(NOT_MEASURED) } else { json!(sensors) },
        "models": or_absent(x.filter(|x| !x.models.is_empty()).map(|x| &x.models)),
        "streams": or_absent(x.filter(|x| !x.streams.is_empty()).map(|x| &x.streams)),
        "battery_pct": or_absent(x.and_then(|x| x.battery_pct)),
        "signal_dbm": or_absent(x.and_then(|x| x.signal_dbm)),
        "last_seen": or_absent(x.and_then(|x| x.last_seen)),
    })
}

fn cell(c: &Cell, r: &Readings, now: u64) -> Value {
    let roll = roll_up(c, r, now);
    json!({
        "id": c.id,
        "scale": c.scale,
        "depth": c.depth,
        "health": roll.health,
        "line": roll.line(),
        // The lowest class a leaf may hold to attach here, from the head's
        // signed link.
        "leaf_min_class": c.leaf_min_class,
        // What the cell's own head last said about it, which can know more
        // than this node measures from outside.
        "reported": r.reported.get(&c.id).map(|(x, at)| {
            let fresh = fresh_report(c, r, now).is_some();
            json!({
                "line": x.line(),
                "health": x.health,
                "as_of_secs_ago": now.saturating_sub(*at),
                "stale": !fresh,
                "machines": x.machines,
                "machines_up": x.machines_up,
                "leaves": x.leaves,
                "leaves_reporting": x.leaves_reporting,
                "power_w": or_absent(x.power_w.filter(|_| fresh)),
                "head_supply": or_absent(x.head_supply.filter(|_| fresh)),
            })
        }),
        "head": head(c, r, now),
        "parent": c.parent,
        "edge_ai": c.edge_ai.iter().map(|m| machine(m, r)).collect::<Vec<_>>(),
        "leaves": c.leaves.iter().map(|m| leaf(m, r)).collect::<Vec<_>>(),
        "managers": c.managers,
        "cells": c.cells.iter().map(|s| cell(s, r, now)).collect::<Vec<_>>(),
    })
}

/// The tree a caller may see, as JSON.
pub fn tree_json(tree: &CellTree, r: &Readings, now: u64) -> Value {
    json!({
        "site": tree.site,
        "controllers": tree.controllers.iter().map(|m| machine(m, r)).collect::<Vec<_>>(),
        "managers": tree.managers,
        "cells": tree.cells.iter().map(|c| cell(c, r, now)).collect::<Vec<_>>(),
        "refused": tree.refused,
        "authority": "none: the tree is read back from signed links; every order is checked by the node it concerns",
    })
}

/// Resolve the caller's scope and cut the tree to it.
fn scoped(req: &Request, source: &Source, now: u64) -> Result<(CellTree, Readings), Response> {
    let Some(p) = req.principal.as_ref() else {
        return Err(Response::refused("the cell tree is shown only to a proved caller"));
    };
    let (tree, readings) = source(now).map_err(|why| Response::error(503, why))?;
    let mut scope = tree.scope_for(p).map_err(Response::refused)?;
    // A passkey read token names the scope it was issued for, and reaches no
    // further than that or than the manager's link does now.
    if let Some(asked) = furcate_topology::read_token::principal_scope(p) {
        if !asked.within(&scope) {
            return Err(Response::refused(format!(
                "the read token is for {}, outside {}, the cell {} manages now",
                asked.as_string(),
                scope.as_string(),
                p.id
            )));
        }
        scope = asked;
    }
    Ok((tree.visible_to(&scope), readings))
}

/// Answer one request for the tree, as JSON or as the page.
pub fn answer(req: &Request, source: &Source, now: u64, page_wanted: bool) -> Response {
    match scoped(req, source, now) {
        Ok((t, r)) if page_wanted => Response::html(page(&t, &r, now)),
        Ok((t, r)) => Response::ok(tree_json(&t, &r, now)),
        Err(resp) => resp,
    }
}

/// Mount `GET /cells` and `GET /cells/view`, both guarded.
pub fn routes(router: Router, source: std::sync::Arc<Source>) -> Router {
    let page_source = std::sync::Arc::clone(&source);
    router
        .guarded("GET", "/cells", move |req: &Request| answer(req, &*source, crate::now_s(), false))
        .guarded("GET", "/cells/view", move |req: &Request| {
            answer(req, &*page_source, crate::now_s(), true)
        })
}

fn machine_row(role: &str, m: &Member, r: &Readings) -> String {
    machine_row_of(role, m, machine(m, r))
}

fn machine_row_of(role: &str, m: &Member, v: Value) -> String {
    let cell = |k: &str| match &v[k] {
        Value::String(s) if s == NOT_MEASURED => format!("<span class=dim>{NOT_MEASURED}</span>"),
        Value::Null => format!("<span class=dim>{ABSENT}</span>"),
        x => esc(&x.to_string()),
    };
    format!(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}{}</td></tr>",
        esc(role),
        esc(&m.name),
        cell("up"),
        cell("cores"),
        cell("power_w"),
        cell("workloads"),
        cell("supply"),
        match v["supply_source"].as_str() {
            Some("reported by its head") => " <span class=dim>(reported by its head)</span>",
            _ => "",
        }
    )
}

fn leaf_row(m: &Member, r: &Readings) -> String {
    let v = leaf(m, r);
    let cell = |k: &str| match &v[k] {
        Value::String(s) if s == NOT_MEASURED => format!("<span class=dim>{NOT_MEASURED}</span>"),
        Value::Array(a) => esc(&a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")),
        x => esc(&x.to_string()),
    };
    // The class the leaf's key custody earned, as its head recorded it.
    let class = m.assurance.map(|a| a.to_string()).unwrap_or_else(|| "unstated".into());
    format!(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        esc(&m.name),
        esc(&class),
        cell("sensors"),
        cell("models"),
        cell("streams"),
        cell("battery_pct"),
        cell("signal_dbm")
    )
}

fn cell_html(c: &Cell, r: &Readings, now: u64, s: &mut String) {
    let roll = roll_up(c, r, now);
    s.push_str(&format!(
        "<section class=cell style='margin-left:{}px'><h2>{} <span class=dim>{}</span></h2><p class=sub>{}; leaf floor {}</p>",
        (c.depth.saturating_sub(1)) * 24,
        esc(&c.id),
        esc(c.scale.as_str()),
        esc(&roll.line()),
        esc(c.leaf_min_class.as_str())
    ));
    s.push_str("<table><thead><tr><th>machine</th><th>name</th><th>up</th><th>cores</th><th>power W</th><th>workloads</th><th>supply</th></tr></thead><tbody>");
    s.push_str(&machine_row_of("head", &c.head, head(c, r, now)));
    for m in &c.edge_ai {
        s.push_str(&machine_row("edge ai", m, r));
    }
    s.push_str("</tbody></table>");
    if !c.leaves.is_empty() {
        s.push_str("<table><thead><tr><th>leaf</th><th>class</th><th>sensors</th><th>models</th><th>streams</th><th>battery %</th><th>signal dBm</th></tr></thead><tbody>");
        for m in &c.leaves {
            s.push_str(&leaf_row(m, r));
        }
        s.push_str("</tbody></table>");
    }
    s.push_str("</section>");
    for sub in &c.cells {
        cell_html(sub, r, now, s);
    }
}

/// The read-only page.
pub fn page(tree: &CellTree, r: &Readings, now: u64) -> String {
    let mut s = crate::web::head(&format!("{} — cells", tree.site));
    s.push_str(&format!(
        "<header><h1>{} <span class=dim>cells</span></h1>\
         <p class=sub>Read-only, and cut to what your own signed link reaches. \
         The tree is read back from the chain of links, so it shows what was \
         delegated, not what anyone typed.</p></header>",
        esc(&tree.site)
    ));
    if !tree.controllers.is_empty() {
        s.push_str("<h2>core cluster</h2><table><thead><tr><th>machine</th><th>name</th><th>up</th><th>cores</th><th>power W</th><th>workloads</th><th>supply</th></tr></thead><tbody>");
        for m in &tree.controllers {
            s.push_str(&machine_row("controller", m, r));
        }
        s.push_str("</tbody></table>");
    }
    if tree.cells.is_empty() {
        s.push_str("<p class=sub>No cells here yet.</p>");
    }
    for c in &tree.cells {
        cell_html(c, r, now, &mut s);
    }
    if !tree.refused.is_empty() {
        s.push_str("<h2>links not taken</h2><table><thead><tr><th>holder</th><th>scope</th><th>why</th></tr></thead><tbody>");
        for x in &tree.refused {
            s.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&x.holder),
                esc(&x.scope.as_string()),
                esc(&x.why)
            ));
        }
        s.push_str("</tbody></table>");
    }
    s.push_str("</div></body></html>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use furcate_authn::{Class, Evidence, Principal};
    use furcate_identity::AssuranceClass;
    use furcate_topology::cell::{ed25519_id, CellDelegation, MachineReading, Role, Root, Scale, Scope, SupplyState};
    use std::sync::Arc;

    const NOW: u64 = 1_786_838_400;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn link(by: u8, above: Option<&CellDelegation>, holder: String, role: Role, scope: &str, name: &str) -> CellDelegation {
        let k = key(by);
        CellDelegation {
            site: "home".into(),
            issuer: ed25519_id(&k.verifying_key()),
            holder,
            role,
            scope: Scope::parse(scope).unwrap(),
            scale: (role == Role::Head).then_some(Scale::Business),
            assurance: match role {
                Role::Manager => None,
                Role::Leaf => Some(AssuranceClass::Soft),
                _ => Some(AssuranceClass::Device),
            },
            leaf_min_class: (role == Role::Head).then_some(AssuranceClass::Soft),
            endpoint: String::new(),
            name: name.into(),
            parent: above.map(|a| a.digest()),
            not_before: NOW - 10,
            not_after: NOW + 86_400,
            signature: String::new(),
        }
        .signed_by(|m| Ok(k.sign(m).to_bytes().to_vec()))
        .unwrap()
    }

    fn id(n: u8) -> String {
        ed25519_id(&key(n).verifying_key())
    }

    fn source() -> Arc<Source> {
        Arc::new(|now| {
            let ctl = link(1, None, id(2), Role::Controller, "site", "core-1");
            let a = link(2, Some(&ctl), id(3), Role::Head, "cell:shop", "pi-shop");
            let b = link(2, Some(&ctl), id(4), Role::Head, "cell:flat", "pi-flat");
            let leaf = link(3, Some(&a), id(5), Role::Leaf, "cell:shop", "esp-shop");
            let mgr = link(3, Some(&a), "passkey:example.org:cred-shop".into(), Role::Manager, "cell:shop", "");
            let tree = CellTree::derive("home", &Root::Operator(id(1)), &[ctl, a, b, leaf, mgr], now);
            let mut r = Readings::default();
            r.machines.insert("pi-shop".into(), MachineReading { up: true, cores: Some(4), power_w: None, workloads: Some(3), supply: None });
            Ok((tree, r))
        })
    }

    fn get(path: &str, who: Option<Principal>) -> Response {
        let req = Request { method: "GET".into(), path: path.into(), principal: who, ..Default::default() };
        answer(&req, &*source(), NOW, path.ends_with("/view"))
    }

    fn json(r: &Response) -> Value {
        assert_eq!(r.status, 200, "{:?}", r.body);
        r.body.clone()
    }

    fn text(r: &Response) -> String {
        r.text.clone().unwrap_or_else(|| r.body.to_string())
    }

    fn manager(id: &str) -> Principal {
        Principal {
            id: id.into(),
            class: Class::Person,
            evidence: Evidence::Delegated { root: id.into(), depth: 1 },
            expires_at: None,
            task: None,
            needs_approval_for: vec![],
            roles: vec![],
        }
    }

    #[test]
    fn both_routes_are_guarded() {
        let r = routes(Router::new(), source());
        let g = r.guarded_paths();
        assert!(g.contains(&"GET /cells".to_string()), "{g:?}");
        assert!(g.contains(&"GET /cells/view".to_string()), "{g:?}");
        assert!(r.paths().iter().all(|p| !p.contains("cells") || g.contains(p)));
    }

    #[test]
    fn the_operator_sees_the_whole_tree_and_a_manager_only_their_cell() {
        let all = get("/cells", Some(Principal::operator("op")));
        let v = json(&all);
        assert_eq!(v["cells"].as_array().unwrap().len(), 2);
        assert_eq!(v["controllers"].as_array().unwrap().len(), 1);

        let mine = get("/cells", Some(manager("passkey:example.org:cred-shop")));
        let v = json(&mine);
        let cells = v["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0]["id"], "shop");
        assert!(v["controllers"].as_array().unwrap().is_empty());
        assert!(!v.to_string().contains("flat"), "a sibling leaked: {v}");
        assert_eq!(cells[0]["head"]["cores"], 4);
        assert_eq!(cells[0]["head"]["power_w"], NOT_MEASURED);
        assert_eq!(cells[0]["leaves"][0]["battery_pct"], NOT_MEASURED);
        assert_eq!(cells[0]["leaves"][0]["assurance"], "soft", "the class the head recorded, as it is");
        assert!(cells[0]["line"].as_str().unwrap().starts_with("shop: "));
        assert!(cells[0]["line"].as_str().unwrap().contains("(1 soft)"), "{}", cells[0]["line"]);

        let page = get("/cells/view", Some(manager("passkey:example.org:cred-shop")));
        let html = text(&page);
        assert!(html.contains("esp-shop") && !html.contains("pi-flat"), "{html}");
        assert!(html.contains("<td>esp-shop</td><td>soft</td>"), "{html}");
        assert!(html.contains("leaf floor soft"), "{html}");
        assert_eq!(cells[0]["leaf_min_class"], "soft");
    }

    fn with_report(age: u64, supply: Option<SupplyState>) -> Arc<Source> {
        let base = source();
        Arc::new(move |now| {
            let (tree, mut r) = base(now)?;
            r.machines.clear();
            let cell = tree.find("shop").expect("shop").clone();
            let mut roll = roll_up(&cell, &r, now);
            roll.head_supply = supply;
            roll.power_w = Some(7.5);
            r.reported.insert("shop".into(), (roll, now - age));
            Ok((tree, r))
        })
    }

    fn head_of(src: &Arc<Source>) -> Value {
        let req = Request { method: "GET".into(), path: "/cells".into(), principal: Some(Principal::operator("op")), ..Default::default() };
        let v = json(&answer(&req, &**src, NOW, false));
        v["cells"].as_array().unwrap().iter().find(|c| c["id"] == "shop").unwrap().clone()
    }

    #[test]
    fn a_fresh_report_from_the_head_gives_its_supply_and_says_where_it_came_from() {
        let c = head_of(&with_report(10, Some(SupplyState::Ok)));
        assert_eq!(c["head"]["supply"], "ok");
        assert_eq!(c["head"]["supply_source"], "reported by its head");
        assert_eq!(c["head"]["up"], Value::Null, "what this node did not measure stays unmeasured");
        assert_eq!(c["reported"]["head_supply"], "ok");
        assert_eq!(c["reported"]["power_w"], 7.5);
        assert_eq!(c["reported"]["stale"], false);
    }

    #[test]
    fn a_stale_or_empty_report_is_not_measured_never_invented() {
        let stale = head_of(&with_report(crate::STALE_SECS + 1, Some(SupplyState::Ok)));
        assert_eq!(stale["head"]["supply"], NOT_MEASURED);
        assert_eq!(stale["reported"]["stale"], true);
        assert_eq!(stale["reported"]["head_supply"], NOT_MEASURED);
        let silent = head_of(&with_report(5, None));
        assert_eq!(silent["head"]["supply"], NOT_MEASURED);
        assert_eq!(silent["reported"]["head_supply"], NOT_MEASURED);
    }

    #[test]
    fn this_nodes_own_reading_of_the_head_wins_over_the_report() {
        let base = with_report(5, Some(SupplyState::Ok));
        let src: Arc<Source> = Arc::new(move |now| {
            let (t, mut r) = base(now)?;
            r.machines.insert("pi-shop".into(), MachineReading { up: true, cores: Some(4), power_w: None, workloads: None, supply: Some(SupplyState::Undervoltage) });
            Ok((t, r))
        });
        let c = head_of(&src);
        assert_eq!(c["head"]["supply"], "undervoltage");
        assert_eq!(c["head"]["supply_source"], "measured here");
    }

    #[test]
    fn a_caller_with_no_link_is_refused_with_the_reason() {
        let r = get("/cells", Some(manager("passkey:example.org:nobody")));
        assert_eq!(r.status, 403);
        assert!(text(&r).contains("holds no cell link"), "{}", text(&r));
        let nobody = get("/cells", None);
        assert_eq!(nobody.status, 403);
    }
}
