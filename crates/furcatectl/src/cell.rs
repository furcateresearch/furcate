//! `furcatectl cell`: the operator's side of edge cells.
//!
//! The chain of cells starts with a link the operator signs for each
//! controller. This module signs that link, drives a controller to enrol a
//! gateway as a cell's head and a head to name a leaf, renews and revokes
//! links, and shows the tree this machine's files describe.
//!
//! The operator key is only ever read from its sealed directory, through the
//! same two-step unseal and custody grant every other operator command uses,
//! and only for as long as one signature takes. Everything written is first
//! read back through the code the nodes themselves run, so a file this
//! command writes is one a node will take.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use furcate_topology::cell::{
    ed25519_id, CellDelegation, CellFile, CellKey, CellRevocation, CellTree, HeadEnrolment, Role,
    Root, Scale, Scope, Upstream,
};
use std::collections::BTreeMap;
use std::path::Path;

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `--name value` pairs. A flag given twice, or one with no value, is refused
/// rather than resolved by position.
fn flags(args: &[&str], known: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(name) = a.strip_prefix("--") else {
            bail!("`{a}` is not a flag; every argument here is `--name value`");
        };
        if !known.contains(&name) {
            bail!("--{name} is not a flag of this command; it takes {}", known.join(", --"));
        }
        let Some(v) = it.next() else { bail!("--{name} needs a value") };
        if out.insert(name.to_string(), v.to_string()).is_some() {
            bail!("--{name} is given twice");
        }
    }
    Ok(out)
}

fn need<'a>(f: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    f.get(name).map(|s| s.as_str()).with_context(|| format!("--{name} is required"))
}

/// `90s`, `30m`, `12h`, `30d`.
pub(crate) fn parse_ttl(s: &str) -> Result<u64> {
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n.parse().with_context(|| format!("`{s}` is not a duration such as 30d or 12h"))?;
    let secs = match unit {
        "s" | "" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => bail!("`{s}`: the unit is s, m, h or d"),
    };
    if secs == 0 {
        bail!("a link that lasts no time is no link");
    }
    Ok(secs)
}

fn parse_scale(s: &str) -> Result<Scale> {
    Scale::parse(s).with_context(|| format!("`{s}` is not a scale; it is home, business, city or other"))
}

/// A key as cell links name it: `ed25519:<hex>` (bare hex is taken as
/// Ed25519), or `p256:<hex>` holding a SEC1 point, compressed or not, or a
/// DER SubjectPublicKeyInfo. A P-256 key comes back as its compressed point,
/// the one way a link names it.
fn key_id(s: &str) -> Result<String> {
    CellKey::normalise(s).map_err(|e| anyhow::anyhow!("{e}"))
}

/// The operator key, from its sealed directory only.
///
/// A plaintext key file is refused here, though other commands still take
/// one: a cell link is authority that outlives the command, and the key that
/// signs it should never have been readable from a disk.
fn sealed_operator_key(dir: &str) -> Result<SigningKey> {
    if !Path::new(dir).is_dir() {
        bail!(
            "{dir} is not a sealed operator key directory; cell links are signed only with the \
             sealed key, opened through the custody grant, never a key file"
        );
    }
    super::operator_signing_key(dir)
}

fn operator_dir(f: &BTreeMap<String, String>) -> Result<String> {
    match f.get("key") {
        Some(k) => Ok(k.clone()),
        None => std::env::var("FURCATE_OPERATOR_KEY")
            .context("--key (the sealed operator key directory) or FURCATE_OPERATOR_KEY is required"),
    }
}

fn load_or_new(path: &Path, site: &str) -> Result<CellFile> {
    let file = CellFile::load(path)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .unwrap_or_else(|| CellFile { site: site.to_string(), links: Vec::new(), revoked: Vec::new() });
    if !file.links.is_empty() && file.site != site {
        bail!("{} holds site {}, not {site}; one file is one site", path.display(), file.site);
    }
    Ok(CellFile { site: site.to_string(), ..file })
}

fn write_file(path: &Path, file: &CellFile) -> Result<()> {
    let text = serde_json::to_string_pretty(file)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text.as_bytes()).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}


/// The operator key named in `operator.pub`, when this machine holds one.
/// Signing with a different key would write links every node refuses.
fn check_operator_pub(f: &BTreeMap<String, String>, signer: &str) -> Result<()> {
    let path = f
        .get("operator-pub")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| furcate_paths::config("operator.pub"));
    match furcate_topology::cell::operator_root(&path) {
        Ok(k) if k == signer => Ok(()),
        Ok(k) => bail!(
            "{} names {k} as the operator, and the sealed key is {signer}; the nodes check \
             links against operator.pub, so they would refuse this one",
            path.display()
        ),
        Err(_) if f.contains_key("operator-pub") => bail!("{} cannot be read as the operator key", path.display()),
        Err(_) => Ok(()),
    }
}

/// The controller's root link, signed with the operator key, added to `file`
/// and read back the way a core node reads it. Refused unless the derived
/// tree takes the new link.
pub(crate) fn controller_link(
    file: &mut CellFile,
    operator: &SigningKey,
    controller: &str,
    endpoint: &str,
    name: &str,
    ttl: u64,
    now: u64,
) -> Result<CellDelegation> {
    if endpoint.is_empty() {
        bail!("the controller's endpoint is how the cells below it reach upward; it is required");
    }
    let link = CellDelegation {
        site: file.site.clone(),
        issuer: ed25519_id(&operator.verifying_key()),
        holder: controller.to_string(),
        role: Role::Controller,
        scope: Scope::Site,
        scale: None,
        assurance: None,
        leaf_min_class: None,
        endpoint: endpoint.to_string(),
        name: name.to_string(),
        parent: None,
        not_before: now,
        not_after: now + ttl,
        signature: String::new(),
    }
    .signed_by(|m| Ok(operator.sign(m).to_bytes().to_vec()))
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut next = file.clone();
    next.links.push(link.clone());
    let tree = furcate_topology::cell::derive_revoking(
        &next,
        &Root::Operator(link.issuer.clone()),
        Some(&link.issuer),
        now,
    );
    if let Some(r) = tree.refused.iter().find(|r| r.holder == controller) {
        bail!("a core node would refuse this link: {}", r.why);
    }
    if !tree.controllers.iter().any(|m| m.holder == controller && m.until == link.not_after) {
        bail!("a core node reading the file back does not find {controller} as a controller");
    }
    *file = next;
    Ok(link)
}

/// The anchor a head installs, as `POST /cells/enrol` answers it, checked as
/// the head itself will check it, and against what was asked for.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Anchor {
    pub own: CellDelegation,
    pub parent_endpoint: String,
}

pub(crate) fn verify_anchor(
    a: &Anchor,
    head: &str,
    cell: &Scope,
    scale: Scale,
    enroller: Option<&CellDelegation>,
    now: u64,
) -> Result<()> {
    let up = Upstream::new(a.own.clone(), &a.parent_endpoint, now)
        .map_err(|why| anyhow::anyhow!("the head would refuse its anchor: {why}"))?;
    if up.own.holder != head {
        bail!("the anchor names {} as head, not {head}", up.own.holder);
    }
    if &up.own.scope != cell {
        bail!("the anchor is for {}, not {}", up.own.scope.as_string(), cell.as_string());
    }
    if up.own.scale != Some(scale) {
        bail!("the anchor gives the cell another scale than the one asked for");
    }
    if a.parent_endpoint.is_empty() {
        bail!("the anchor names no parent endpoint, so the head could not report upward");
    }
    if let Some(above) = enroller {
        up.own
            .check(Some(above), "", &above.site, now)
            .map_err(|why| anyhow::anyhow!("a core node would refuse the head's link: {why}"))?;
    }
    Ok(())
}

fn node_addr(f: &BTreeMap<String, String>, flag: &str) -> Result<String> {
    need(f, flag).map(str::to_string)
}

/// The enroller's own link, when this machine's files hold it: then the head's
/// link is checked against it, as a core node will.
fn enroller_link(f: &BTreeMap<String, String>, endpoint: &str, now: u64) -> Option<CellDelegation> {
    let files = [furcate_paths::config("cells.json"), furcate_paths::state("cells-issued.json")];
    let path = f.get("cells").map(std::path::PathBuf::from);
    let files: Vec<std::path::PathBuf> = match path {
        Some(p) => vec![p],
        None => files.to_vec(),
    };
    let op = f
        .get("operator-pub")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| furcate_paths::config("operator.pub"));
    let file = furcate_topology::cell::merge_files(&files, None).ok()?;
    let root = furcate_topology::cell::operator_root(&op).ok()?;
    let tree = furcate_topology::cell::derive_revoking(&file, &Root::Operator(root.clone()), Some(&root), now);
    file.links
        .iter()
        .find(|l| l.endpoint == endpoint && tree.link_of(&l.holder).map(|t| t.digest()) == Some(l.digest()))
        .cloned()
}

fn enrol_once(
    f: &BTreeMap<String, String>,
    key: &str,
    head: &str,
    cell: &Scope,
    scale: Scale,
    until: u64,
    controller: &str,
) -> Result<Anchor> {
    let path = cell.path().context("a head runs one cell; give --cell as a path")?;
    let (_, segment) = path.rsplit_once('/').unwrap_or(("", path));
    let assurance: furcate_identity::AssuranceClass =
        serde_json::from_value(serde_json::json!(f.get("assurance").map(String::as_str).unwrap_or("device")))
            .context("--assurance is how the head holds its key: device or tpm")?;
    let leaf_min_class = leaf_floor(f)?;
    let body = serde_json::to_value(HeadEnrolment {
        gateway: head.to_string(),
        assurance,
        endpoint: f.get("head-endpoint").cloned().unwrap_or_default(),
        name: f.get("name").cloned().unwrap_or_else(|| segment.to_string()),
        cell: segment.to_string(),
        scale,
        until,
        leaf_min_class,
    })?;
    let reply = super::signed_post(key, controller, "/cells/enrol", &body)?;
    if let Some(why) = super::refusal(&reply) {
        bail!("{controller} refused the enrolment: {why}");
    }
    let anchor: Anchor = serde_json::from_value(reply.get("anchor").cloned().unwrap_or_default())
        .context("the controller's answer holds no anchor")?;
    let now = now_s();
    verify_anchor(&anchor, head, cell, scale, enroller_link(f, controller, now).as_ref(), now)?;
    if anchor.own.leaf_min_class != leaf_min_class {
        bail!(
            "asked for leaf floor {:?} and the controller signed {:?}; the anchor is not written",
            leaf_min_class,
            anchor.own.leaf_min_class
        );
    }
    Ok(anchor)
}

/// `--leaf-min-class`: the lowest class a leaf may hold to attach to the
/// cell. Absent is the default, `device`.
fn leaf_floor(f: &BTreeMap<String, String>) -> Result<Option<furcate_identity::AssuranceClass>> {
    f.get("leaf-min-class")
        .map(|c| {
            furcate_identity::AssuranceClass::from_tag(c)
                .with_context(|| format!("--leaf-min-class `{c}` is not a class: soft, device, se, tee, dice or tpm"))
        })
        .transpose()
}

/// A head's link signed afresh by its controller from the anchor it runs on,
/// keeping its name, endpoint, class and leaf floor unless `f` changes them.
fn reenrol_head(f: &BTreeMap<String, String>, anchor: &str, until: Option<u64>, now: u64) -> Result<()> {
    let a: Anchor = serde_json::from_str(&std::fs::read_to_string(anchor).with_context(|| format!("reading {anchor}"))?)
        .with_context(|| format!("{anchor} is not a cell anchor"))?;
    let controller = node_addr(f, "controller")?;
    let key = operator_dir(f)?;
    sealed_operator_key(&key).map(drop)?;
    let mut f2 = f.clone();
    f2.insert("name".into(), a.own.name.clone());
    f2.insert("head-endpoint".into(), a.own.endpoint.clone());
    let assurance = serde_json::to_value(a.own.assurance).ok().and_then(|v| v.as_str().map(str::to_string));
    f2.insert("assurance".into(), assurance.unwrap_or_else(|| "device".into()));
    if !f2.contains_key("leaf-min-class") {
        if let Some(floor) = a.own.leaf_min_class {
            f2.insert("leaf-min-class".into(), floor.as_str().to_string());
        }
    }
    let scale = a.own.scale.context("the anchor's link names no scale")?;
    let until = until.unwrap_or(a.own.not_after);
    // Keeping the old expiry is only right while it is still ahead: re-signing a link that has already run
    // out would hand the gateway an anchor that is dead on arrival. Ask for a new lifetime instead.
    if until <= now {
        bail!("the anchor's link ran out at {until} (now {now}); re-enrol with a new lifetime (--ttl) to give it one");
    }
    let next = enrol_once(&f2, &key, &a.own.holder, &a.own.scope, scale, until, &controller)?;
    write_anchor(f.get("out").map(String::as_str).unwrap_or(anchor), &next)
}

fn write_anchor(path: &str, a: &Anchor) -> Result<()> {
    let text = serde_json::to_string_pretty(a)?;
    std::fs::write(path, text).with_context(|| format!("writing {path}"))?;
    println!(
        "{path}: head {} of {}, until {}; install it as cell-anchor.json in the gateway's config directory",
        a.own.holder,
        a.own.scope.as_string(),
        a.own.not_after
    );
    Ok(())
}

/// Find a link by digest or, when it names exactly one, by holder.
fn find_link<'a>(links: &'a [CellDelegation], which: &str) -> Result<&'a CellDelegation> {
    if let Some(l) = links.iter().find(|l| l.digest() == which) {
        return Ok(l);
    }
    let by_holder: Vec<&CellDelegation> = links.iter().filter(|l| l.holder == which).collect();
    match by_holder.as_slice() {
        [one] => Ok(one),
        [] => bail!("no link here has digest or holder {which}"),
        many => bail!(
            "{which} holds {} links here; name the one to act on by digest: {}",
            many.len(),
            many.iter().map(|l| l.digest()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// A signed revocation of `link`, added to `file` and read back: refused
/// unless a node reading the result no longer takes the link.
pub(crate) fn revoke(
    file: &mut CellFile,
    operator: &SigningKey,
    link: &CellDelegation,
    reason: &str,
    now: u64,
) -> Result<CellRevocation> {
    if reason.trim().is_empty() {
        bail!("a revocation says why; --reason is required");
    }
    let issuer = ed25519_id(&operator.verifying_key());
    let r = CellRevocation {
        site: file.site.clone(),
        link: link.digest(),
        reason: reason.to_string(),
        at: now,
        issuer: issuer.clone(),
        signature: String::new(),
    }
    .signed_by(|m| Ok(operator.sign(m).to_bytes().to_vec()))
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut next = file.clone();
    next.revoked.push(r.clone());
    let (kept, _, unapplied) = furcate_topology::cell::apply_revocations(&next, Some(&issuer));
    if let Some(why) = unapplied.first() {
        bail!("{why}");
    }
    if kept.iter().any(|l| l.digest() == r.link) {
        bail!("a node reading the file back still takes the link");
    }
    *file = next;
    Ok(r)
}

/// The tree this machine's own files describe, cut to `scope`.
pub(crate) fn local_tree(files: &[std::path::PathBuf], operator_pub: &Path, anchor: &Path, now: u64) -> Result<CellTree> {
    let op = furcate_topology::cell::operator_root(operator_pub).ok();
    if let Ok(text) = std::fs::read_to_string(anchor) {
        let a: Anchor = serde_json::from_str(&text).with_context(|| format!("{} is not a cell anchor", anchor.display()))?;
        let file = furcate_topology::cell::merge_files(files, Some(&a.own.site)).map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Some(why) = furcate_topology::cell::revoked_reason(&file, op.as_deref(), &a.own.digest()) {
            bail!("the operator revoked this cell's own link: {why}");
        }
        return Ok(furcate_topology::cell::derive_revoking(&file, &Root::Anchor(a.own), op.as_deref(), now));
    }
    let file = furcate_topology::cell::merge_files(files, None).map_err(|e| anyhow::anyhow!("{e}"))?;
    if file.links.is_empty() {
        return Ok(CellTree::default());
    }
    let op = op.with_context(|| format!("{} cannot be read, so no link can be checked", operator_pub.display()))?;
    Ok(furcate_topology::cell::derive_revoking(&file, &Root::Operator(op.clone()), Some(&op), now))
}

/// `furcatectl cell ...`
/// The domain an operator signs a list of receipt keys under.
const RECEIPT_KEYS_DOMAIN: &[u8] = b"furcate-receipt-keys-v1";

/// What the operator signs: the domain, a zero byte, and the payload as
/// canonical JSON (keys sorted, no whitespace).
fn receipt_keys_message(payload: &serde_json::Value) -> Vec<u8> {
    let mut m = RECEIPT_KEYS_DOMAIN.to_vec();
    m.push(0);
    m.extend(serde_json::to_vec(payload).expect("JSON"));
    m
}

/// Each node's receipt key, read from the node itself, as one list the operator
/// signs. A verifier that settles or checks receipts builds its allowlist from
/// this, never from the key a receipt names. Run again when a node's key
/// changes (a lost seal, a re-enrolment): the newest list is the one to use.
fn receipt_keys(endpoints: &[&str], key: &SigningKey, ttl: u64, now: u64) -> Result<serde_json::Value> {
    let mut nodes = Vec::new();
    for ep in endpoints {
        let id = furcate_api::get_json(ep, "/identity", 5_000).with_context(|| format!("{ep}: /identity"))?;
        let rk = furcate_api::get_json(ep, "/receipt-key", 5_000).with_context(|| format!("{ep}: /receipt-key"))?;
        let node_id = id.get("node_id").and_then(|v| v.as_str()).with_context(|| format!("{ep} reports no node id"))?;
        let Some(k) = rk.get("key").and_then(|v| v.as_str()) else {
            bail!("{ep} ({node_id}) has no key to sign receipts with; it is left out by refusing the whole list");
        };
        nodes.push(serde_json::json!({
            "node_id": node_id,
            "endpoint": ep,
            "key_id": key_id(k)?,
            "held_by": rk.get("held_by").cloned().unwrap_or(serde_json::Value::Null),
            // soft, device, tpm, se...: a verifier may accept only hardware-held keys
            "assurance": id.get("assurance").cloned().unwrap_or(serde_json::Value::Null),
            "endorsed": id.get("endorsed").cloned().unwrap_or(serde_json::Value::Null),
        }));
    }
    let payload = serde_json::json!({
        "kind": "furcate-receipt-keys-v1",
        "issued_at": now,
        "not_after": now + ttl,
        "nodes": nodes,
    });
    use ed25519_dalek::Signer as _;
    let sig = key.sign(&receipt_keys_message(&payload));
    Ok(serde_json::json!({
        "payload": payload,
        "operator": ed25519_id(&key.verifying_key()),
        "signature": hex::encode(sig.to_bytes()),
    }))
}

/// Check a list against the operator key the verifier already holds, and its term.
fn verify_receipt_keys(file: &serde_json::Value, operator: &str, now: u64) -> Result<usize> {
    if file.get("operator").and_then(|v| v.as_str()) != Some(operator) {
        bail!("the list is signed by {}, not {operator}", file.get("operator").and_then(|v| v.as_str()).unwrap_or("(none)"));
    }
    let payload = file.get("payload").context("no payload")?;
    let sig = file.get("signature").and_then(|v| v.as_str()).context("no signature")?;
    CellKey::parse(operator)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .verify_hex(&receipt_keys_message(payload), sig)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let not_after = payload.get("not_after").and_then(|v| v.as_u64()).context("no not_after")?;
    if now > not_after {
        bail!("the list expired at {not_after}");
    }
    Ok(payload.get("nodes").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0))
}

pub fn run(args: &[&str]) -> Result<()> {
    let (verb, rest) = args.split_first().context(USAGE)?;
    let now = now_s();
    match *verb {
        "receipt-keys" => {
            let f = flags(rest, &["key", "endpoint", "ttl", "out"])?;
            let endpoints: Vec<&str> = need(&f, "endpoint")?.split(',').filter(|e| !e.is_empty()).collect();
            let ttl = parse_ttl(need(&f, "ttl")?)?;
            let out = f.get("out").map(String::as_str).unwrap_or("receipt-keys.json");
            let key = sealed_operator_key(&operator_dir(&f)?)?;
            let list = receipt_keys(&endpoints, &key, ttl, now)?;
            drop(key);
            std::fs::write(out, serde_json::to_string_pretty(&list)? + "\n")?;
            println!("{out}: {} nodes, signed by {}, until {}", endpoints.len(), list["operator"].as_str().unwrap_or(""), now + ttl);
            Ok(())
        }
        "receipt-keys-verify" => {
            let f = flags(rest, &["file", "operator"])?;
            let file: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(need(&f, "file")?)?)?;
            let n = verify_receipt_keys(&file, &key_id(need(&f, "operator")?)?, now)?;
            println!("good: {n} nodes, signed by {}", need(&f, "operator")?);
            Ok(())
        }
        "controller-link" => {
            let f = flags(rest, &["key", "site", "controller", "endpoint", "scale", "ttl", "out", "name", "operator-pub"])?;
            if f.contains_key("scale") {
                bail!(
                    "a controller's link carries no scale: it parents cells of any scale, and \
                     each head's link says its own (give --scale to `cell enrol`)"
                );
            }
            let site = need(&f, "site")?;
            let endpoint = need(&f, "endpoint")?;
            let controller = resolve_controller(need(&f, "controller")?, endpoint)?;
            let ttl = parse_ttl(need(&f, "ttl")?)?;
            let out = f.get("out").map(String::as_str).unwrap_or("cells.json");
            let mut file = load_or_new(Path::new(out), site)?;
            let key = sealed_operator_key(&operator_dir(&f)?)?;
            check_operator_pub(&f, &ed25519_id(&key.verifying_key()))?;
            let name = f.get("name").cloned().unwrap_or_default();
            let link = controller_link(&mut file, &key, &controller, endpoint, &name, ttl, now)?;
            drop(key);
            write_file(Path::new(out), &file)?;
            println!(
                "{out}: controller {controller} at {endpoint} for site {site}, until {}; digest {}",
                link.not_after,
                link.digest()
            );
            Ok(())
        }
        "enrol" => {
            let f = flags(
                rest,
                &["key", "head", "cell", "scale", "ttl", "controller", "out", "assurance", "head-endpoint", "name", "cells", "operator-pub", "leaf-min-class"],
            )?;
            let head = key_id(need(&f, "head")?)?;
            let cell = Scope::parse(&format!("cell:{}", need(&f, "cell")?.trim_start_matches("cell:")))
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let scale = parse_scale(need(&f, "scale")?)?;
            let until = now + parse_ttl(need(&f, "ttl")?)?;
            let controller = node_addr(&f, "controller")?;
            let key = operator_dir(&f)?;
            sealed_operator_key(&key).map(drop)?;
            let anchor = enrol_once(&f, &key, &head, &cell, scale, until, &controller)?;
            write_anchor(f.get("out").map(String::as_str).unwrap_or("cell-anchor.json"), &anchor)
        }
        "leaf-floor" => {
            // The cell's leaf floor lives in the head's link, so changing it
            // is a re-enrolment: operator-signed to the controller, which
            // signs the head a new link with the new floor and the same end.
            let f = flags(rest, &["key", "anchor", "controller", "class", "out", "cells", "operator-pub"])?;
            let anchor = need(&f, "anchor")?.to_string();
            let mut f2 = f.clone();
            f2.insert("leaf-min-class".into(), need(&f, "class")?.to_string());
            leaf_floor(&f2)?;
            reenrol_head(&f2, &anchor, None, now)
        }
        "leaf" => {
            let f = flags(rest, &["key", "cell", "leaf", "attachment", "head", "ttl"])?;
            let cell = Scope::parse(&format!("cell:{}", need(&f, "cell")?.trim_start_matches("cell:")))
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let leaf = need(&f, "leaf")?;
            let att_path = need(&f, "attachment")?;
            let record: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(att_path).with_context(|| format!("reading {att_path}"))?,
            )
            .with_context(|| format!("{att_path} is not JSON"))?;
            // Read through the code the head runs, so a record the head would
            // refuse is refused here, with the same reason.
            let att = furcate_sense::leaf::Attachment::from_record(&record)
                .map_err(|e| anyhow::anyhow!("{att_path} is not a leaf attachment record: {e}"))?;
            if att.leaf_id != leaf {
                bail!("{att_path} is the attachment of {}, not {leaf}", att.leaf_id);
            }
            eprintln!("leaf {leaf}: key {}, class `{}`: {}", att.public_key, att.assurance(), att.assurance_reason());
            let until = now + parse_ttl(f.get("ttl").map(String::as_str).unwrap_or("30d"))?;
            let head = node_addr(&f, "head")?;
            let key = operator_dir(&f)?;
            sealed_operator_key(&key).map(drop)?;
            let reply = super::signed_post(&key, &head, "/cells/leaf", &serde_json::json!({ "attachment": record, "until": until }))?;
            if let Some(why) = super::refusal(&reply) {
                bail!("{head} refused the leaf: {why}");
            }
            let link: CellDelegation = serde_json::from_value(reply.get("link").cloned().unwrap_or_default())
                .context("the head's answer holds no link")?;
            verify_leaf(&link, &cell, &att)?;
            println!("{}", serde_json::to_string_pretty(&link)?);
            Ok(())
        }
        "renew" => {
            let f = flags(
                rest,
                &["key", "holder", "file", "anchor", "controller", "ttl", "out", "name", "operator-pub", "cells", "leaf-min-class"],
            )?;
            let ttl = parse_ttl(need(&f, "ttl")?)?;
            if let Some(anchor) = f.get("anchor") {
                // A head: the controller signs it a fresh link; the old one
                // runs on to its own end.
                return reenrol_head(&f, anchor, Some(now + ttl), now);
            }
            // A controller: a fresh root link beside the old one, which runs
            // on to its own end so the heads below it keep their chain while
            // they are renewed under the new one.
            let path = f.get("file").map(String::as_str).unwrap_or("cells.json");
            let file = CellFile::load(Path::new(path)).map_err(|e| anyhow::anyhow!("{e}"))?
                .with_context(|| format!("{path} does not exist"))?;
            let old = find_link(&file.links, need(&f, "holder")?)?.clone();
            if old.role != Role::Controller {
                bail!("{} is a {}; renew a head with --anchor and --controller", old.holder, old.role.as_str());
            }
            let mut file = file;
            let key = sealed_operator_key(&operator_dir(&f)?)?;
            check_operator_pub(&f, &ed25519_id(&key.verifying_key()))?;
            let link = controller_link(&mut file, &key, &old.holder, &old.endpoint, &old.name, ttl, now)?;
            drop(key);
            write_file(Path::new(path), &file)?;
            println!("{path}: controller {} renewed until {}; digest {}", link.holder, link.not_after, link.digest());
            Ok(())
        }
        "revoke" => {
            let f = flags(rest, &["key", "link", "reason", "file", "ledger", "operator-pub"])?;
            let path = f.get("file").map(String::as_str).unwrap_or("cells.json");
            let mut file = CellFile::load(Path::new(path)).map_err(|e| anyhow::anyhow!("{e}"))?
                .with_context(|| format!("{path} does not exist"))?;
            let issued = furcate_paths::state("cells-issued.json");
            let mut held = file.links.clone();
            if let Ok(Some(more)) = CellFile::load(&issued) {
                if more.site == file.site {
                    held.extend(more.links);
                }
            }
            let target = find_link(&held, need(&f, "link")?)?.clone();
            let reason = need(&f, "reason")?;
            let key = operator_dir(&f)?;
            let operator = sealed_operator_key(&key)?;
            let issuer = ed25519_id(&operator.verifying_key());
            check_operator_pub(&f, &issuer)?;
            // Against the file with the target in it, so the read-back sees
            // the link and then sees it withdrawn.
            let mut probe = CellFile { links: held, ..file.clone() };
            let r = revoke(&mut probe, &operator, &target, reason, now)?;
            drop(operator);
            // Ledgered before it takes effect: a withdrawal nobody can see
            // afterwards is not one anyone can audit.
            let ledger = f.get("ledger").cloned().unwrap_or_else(|| {
                std::env::var("FURCATE_NODE").unwrap_or_else(|_| "127.0.0.1:7616".into())
            });
            let entry = serde_json::json!({
                "actor": issuer,
                "subject": format!("cell link {} ({} of {})", r.link, target.holder, target.scope.as_string()),
                "result": format!("revoked: {reason}"),
            });
            let reply = super::signed_post(&key, &ledger, "/ledger", &entry)
                .with_context(|| "the revocation is ledgered before it is written, and the ledger did not take it")?;
            if let Some(why) = super::refusal(&reply) {
                bail!("the ledger at {ledger} refused the revocation, so it is not written: {why}");
            }
            file.revoked.push(r.clone());
            write_file(Path::new(path), &file)?;
            println!(
                "{path}: link {} revoked; copy the file to every node holding the cell, which drop it and everything below it",
                r.link
            );
            Ok(())
        }
        "standing" => {
            // Guarded on the head, so it is asked as the operator, with the
            // key opened the way every signed call opens it.
            let f = flags(rest, &["key", "node"])?;
            let node = node_addr(&f, "node")?;
            let key = operator_dir(&f)?;
            let reply = super::signed_get(&key, &node, "/cells/standing")?;
            if let Some(why) = super::refusal(&reply) {
                bail!("{node} refused: {why}");
            }
            println!("{}", serde_json::to_string_pretty(&reply)?);
            Ok(())
        }
        "show" => {
            let f = flags(rest, &["scope", "cells", "operator-pub", "anchor"])?;
            let files = match f.get("cells") {
                Some(p) => vec![std::path::PathBuf::from(p)],
                None => vec![furcate_paths::config("cells.json"), furcate_paths::state("cells-issued.json")],
            };
            let op = f.get("operator-pub").map(std::path::PathBuf::from).unwrap_or_else(|| furcate_paths::config("operator.pub"));
            let anchor = f.get("anchor").map(std::path::PathBuf::from).unwrap_or_else(|| furcate_paths::config("cell-anchor.json"));
            let tree = local_tree(&files, &op, &anchor, now)?;
            let scope = match f.get("scope") {
                Some(s) => Scope::parse(s).map_err(|e| anyhow::anyhow!("{e}"))?,
                None => Scope::Site,
            };
            println!("{}", serde_json::to_string_pretty(&tree.visible_to(&scope))?);
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}

pub(crate) fn verify_leaf(link: &CellDelegation, cell: &Scope, att: &furcate_sense::leaf::Attachment) -> Result<()> {
    link.verify_signature().map_err(|e| anyhow::anyhow!("{e}"))?;
    let leaf = &att.leaf_id;
    if link.role != Role::Leaf || &link.scope != cell || &link.name != leaf {
        bail!(
            "the head signed a {} of {} named {}, not leaf {leaf} of {}",
            link.role.as_str(),
            link.scope.as_string(),
            link.name,
            cell.as_string()
        );
    }
    if link.holder != att.public_key {
        bail!("the link names {}, not the key the leaf attached with ({})", link.holder, att.public_key);
    }
    if link.assurance != Some(att.assurance()) {
        bail!(
            "the link records class {}, not `{}`, the class the leaf's key custody earns",
            link.assurance.map(|a| format!("`{a}`")).unwrap_or_else(|| "none".into()),
            att.assurance()
        );
    }
    Ok(())
}

/// A controller named by key, or by node id resolved through its own
/// `/identity`, which must report that node id.
fn resolve_controller(given: &str, endpoint: &str) -> Result<String> {
    if let Ok(k) = key_id(given) {
        return Ok(k);
    }
    let id = furcate_api::get_json(endpoint, "/identity", 5_000)
        .with_context(|| format!("{given} is not a key, and {endpoint} could not be asked for its own"))?;
    if id.get("node_id").and_then(|v| v.as_str()) != Some(given) {
        bail!(
            "{endpoint} reports node {}, not {given}",
            id.get("node_id").and_then(|v| v.as_str()).unwrap_or("(none)")
        );
    }
    let k = id.get("signing_key").and_then(|v| v.as_str()).with_context(|| format!("{endpoint} reports no signing key"))?;
    let k = key_id(k)?;
    eprintln!("{given} signs as {k}; check it against the machine before installing the link");
    Ok(k)
}

const USAGE: &str = "usage:
  furcatectl cell controller-link --site <site> --controller <key|node id> --endpoint <addr:port> --ttl <dur> [--out cells.json] [--name n] [--key <sealed dir>]
  furcatectl cell enrol --head <ed25519:hex|p256:hex> --cell <path> --scale <home|business|city|other> --ttl <dur> --controller <addr:port> [--head-endpoint a] [--assurance device|tpm] [--leaf-min-class <class>] [--out cell-anchor.json]
  furcatectl cell leaf-floor --anchor <cell-anchor.json> --class <soft|device|se|tee|dice|tpm> --controller <addr:port> [--out file]
  furcatectl cell leaf --cell <path> --leaf <id> --attachment <file> --head <addr:port> [--ttl 30d]
  furcatectl cell renew (--holder <key|digest> [--file cells.json] | --anchor <file> --controller <addr:port> [--leaf-min-class <class>]) --ttl <dur>
  furcatectl cell revoke --link <digest|key> --reason <text> [--file cells.json] [--ledger addr]
  furcatectl cell show [--scope site|cell:<path>] [--cells file] [--anchor file]
  furcatectl cell standing --node <addr:port> [--key <sealed dir>]
  furcatectl cell receipt-keys --endpoint <addr:port>[,<addr:port>...] --ttl <dur> [--out receipt-keys.json] [--key <sealed dir>]
  furcatectl cell receipt-keys-verify --file <receipt-keys.json> --operator <ed25519:hex>
  the operator key is the sealed directory in --key or FURCATE_OPERATOR_KEY";

#[cfg(test)]
mod receipt_keys_tests {
    use super::*;

    #[test]
    fn a_signed_list_verifies_and_a_changed_one_does_not() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let op = ed25519_id(&key.verifying_key());
        let payload = serde_json::json!({ "kind": "furcate-receipt-keys-v1", "issued_at": 10, "not_after": 100,
            "nodes": [{ "node_id": "n1", "endpoint": "a:1", "key_id": "ed25519:00", "held_by": "node key" }] });
        use ed25519_dalek::Signer as _;
        let mut file = serde_json::json!({ "payload": payload, "operator": op,
            "signature": hex::encode(key.sign(&receipt_keys_message(&payload)).to_bytes()) });
        assert_eq!(verify_receipt_keys(&file, &op, 50).unwrap(), 1);
        assert!(verify_receipt_keys(&file, &op, 101).is_err());
        file["payload"]["nodes"][0]["key_id"] = serde_json::json!("ed25519:11");
        assert!(verify_receipt_keys(&file, &op, 50).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_operator_dir, seal_operator_dir, signing_key_from_hex, SealBackend};
    use furcate_identity::custody::{CustodyMode, CustodyRecord};
    use furcate_identity::AssuranceClass;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const NOW: u64 = 1_786_838_400;
    const DAY: u64 = 86_400;

    /// A chip, simulated: what it seals stays in memory.
    #[derive(Default)]
    struct SimulatedSealer {
        held: RefCell<HashMap<PathBuf, Vec<u8>>>,
    }

    impl SealBackend for SimulatedSealer {
        fn seal(&self, secret: &[u8], out_dir: &Path) -> Result<()> {
            std::fs::create_dir_all(out_dir)?;
            std::fs::write(out_dir.join("seal.pub"), b"simulated")?;
            std::fs::write(out_dir.join("seal.priv"), b"simulated")?;
            self.held.borrow_mut().insert(out_dir.to_path_buf(), secret.to_vec());
            Ok(())
        }
        fn unseal(&self, sealed_dir: &Path) -> Result<Vec<u8>> {
            self.held.borrow().get(sealed_dir).cloned().context("not sealed to this chip")
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("furcatectl-cell-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn fresh() -> SigningKey {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("randomness");
        SigningKey::from_bytes(&b)
    }

    /// An operator key sealed to the simulated chip, opened through the same
    /// two-step reader the command uses.
    fn sealed_operator(sealer: &SimulatedSealer, tag: &str) -> SigningKey {
        let dir = scratch(tag);
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("randomness");
        let custody = CustodyRecord { mode: CustodyMode::Elected, class: AssuranceClass::Tpm };
        seal_operator_dir(sealer, hex::encode(b).as_bytes(), &custody, &dir).unwrap();
        let (_, key_hex) = open_operator_dir(sealer, &dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        signing_key_from_hex(&key_hex).unwrap()
    }

    fn site_file() -> CellFile {
        CellFile { site: "s".into(), links: Vec::new(), revoked: Vec::new() }
    }

    fn head_link(ctrl_key: &SigningKey, ctrl: &CellDelegation, head: &SigningKey, cell: &str) -> CellDelegation {
        let e = HeadEnrolment {
            gateway: ed25519_id(&head.verifying_key()),
            assurance: AssuranceClass::Device,
            leaf_min_class: None,
            endpoint: "10.0.0.9:7616".into(),
            name: cell.into(),
            cell: cell.into(),
            scale: Scale::Home,
            until: NOW + 30 * DAY,
        };
        furcate_topology::cell::enrol_head(ctrl, &e, NOW)
            .unwrap()
            .signed_by(|m| Ok(ctrl_key.sign(m).to_bytes().to_vec()))
            .unwrap()
    }

    #[test]
    fn a_controller_link_round_trips_through_the_core_reading() {
        let sealer = SimulatedSealer::default();
        let operator = sealed_operator(&sealer, "ctrl");
        let ctrl = ed25519_id(&fresh().verifying_key());
        let mut file = site_file();
        let link = controller_link(&mut file, &operator, &ctrl, "10.0.0.2:7616", "node-b", 90 * DAY, NOW).unwrap();

        // Written and parsed back, then read as a core node reads it.
        let dir = scratch("ctrl-file");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cells.json");
        write_file(&path, &file).unwrap();
        let back = CellFile::load(&path).unwrap().unwrap();
        let op = ed25519_id(&operator.verifying_key());
        let tree = furcate_topology::cell::derive_revoking(&back, &Root::Operator(op.clone()), Some(&op), NOW + DAY);
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        assert_eq!(tree.controllers.len(), 1);
        assert_eq!(tree.link_of(&ctrl).unwrap().digest(), link.digest());

        // Checked against another operator key, it is refused.
        let other = ed25519_id(&fresh().verifying_key());
        let tree = CellTree::derive("s", &Root::Operator(other), &back.links, NOW + DAY);
        assert!(tree.controllers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_controller_link_with_no_endpoint_is_refused() {
        let operator = fresh();
        let mut file = site_file();
        let ctrl = ed25519_id(&fresh().verifying_key());
        let err = controller_link(&mut file, &operator, &ctrl, "", "", DAY, NOW).unwrap_err();
        assert!(err.to_string().contains("endpoint"), "{err}");
        assert!(file.links.is_empty());
    }

    #[test]
    fn a_plaintext_key_file_is_refused_for_cell_links() {
        let dir = scratch("plain");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("op.key");
        std::fs::write(&p, hex::encode([7u8; 32])).unwrap();
        let err = sealed_operator_key(p.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("sealed"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_enrolment_anchor_verifies_on_a_simulated_head() {
        let operator = fresh();
        let ctrl_key = fresh();
        let mut file = site_file();
        let ctrl = controller_link(
            &mut file,
            &operator,
            &ed25519_id(&ctrl_key.verifying_key()),
            "10.0.0.2:7616",
            "node-b",
            90 * DAY,
            NOW,
        )
        .unwrap();
        let head = fresh();
        let head_id = ed25519_id(&head.verifying_key());
        let anchor = Anchor { own: head_link(&ctrl_key, &ctrl, &head, "home1"), parent_endpoint: ctrl.endpoint.clone() };
        let cell = Scope::cell("home1").unwrap();

        verify_anchor(&anchor, &head_id, &cell, Scale::Home, Some(&ctrl), NOW + 1).unwrap();

        // The head, holding only its anchor, reads its own cell from it.
        let tree = CellTree::derive("s", &Root::Anchor(anchor.own.clone()), &[anchor.own.clone()], NOW + 1);
        assert!(tree.find("home1").is_some(), "{:?}", tree);
        assert_eq!(tree.find("home1").unwrap().head.holder, head_id);

        // Asked for another head, cell or scale, the anchor is refused.
        let stranger = ed25519_id(&fresh().verifying_key());
        assert!(verify_anchor(&anchor, &stranger, &cell, Scale::Home, Some(&ctrl), NOW + 1).is_err());
        assert!(verify_anchor(&anchor, &head_id, &Scope::cell("home2").unwrap(), Scale::Home, Some(&ctrl), NOW + 1).is_err());
        assert!(verify_anchor(&anchor, &head_id, &cell, Scale::City, Some(&ctrl), NOW + 1).is_err());
        // A tampered anchor does not verify.
        let mut forged = anchor.clone();
        forged.own.not_after += DAY;
        assert!(verify_anchor(&forged, &head_id, &cell, Scale::Home, Some(&ctrl), NOW + 1).is_err());
        // Nor one signed by a key other than the controller's.
        let rogue = fresh();
        let mut rogue_ctrl = ctrl.clone();
        rogue_ctrl.holder = ed25519_id(&rogue.verifying_key());
        let wrong = Anchor { own: head_link(&rogue, &rogue_ctrl, &head, "home1"), parent_endpoint: ctrl.endpoint.clone() };
        assert!(verify_anchor(&wrong, &head_id, &cell, Scale::Home, Some(&ctrl), NOW + 1).is_err());
    }

    #[test]
    fn a_revoked_link_and_everything_below_it_is_refused() {
        let operator = fresh();
        let op = ed25519_id(&operator.verifying_key());
        let ctrl_key = fresh();
        let mut file = site_file();
        let ctrl = controller_link(&mut file, &operator, &ed25519_id(&ctrl_key.verifying_key()), "10.0.0.2:7616", "", 90 * DAY, NOW)
            .unwrap();
        let head = fresh();
        let h = head_link(&ctrl_key, &ctrl, &head, "home1");
        file.links.push(h.clone());
        let tree = furcate_topology::cell::derive_revoking(&file, &Root::Operator(op.clone()), Some(&op), NOW + 1);
        assert!(tree.find("home1").is_some());

        let mut revoked = file.clone();
        revoke(&mut revoked, &operator, &h, "gateway stolen", NOW + 2).unwrap();
        let tree = furcate_topology::cell::derive_revoking(&revoked, &Root::Operator(op.clone()), Some(&op), NOW + 3);
        assert!(tree.find("home1").is_none());
        assert!(tree.refused.iter().any(|r| r.holder == h.holder && r.why.contains("gateway stolen")), "{:?}", tree.refused);
        // The head, reading the same file, is told its own link is gone.
        assert_eq!(
            furcate_topology::cell::revoked_reason(&revoked, Some(&op), &h.digest()).as_deref(),
            Some("gateway stolen")
        );

        // Withdrawing the controller takes the cell under it with it.
        let mut root_gone = file.clone();
        revoke(&mut root_gone, &operator, &ctrl, "retired", NOW + 2).unwrap();
        let tree = furcate_topology::cell::derive_revoking(&root_gone, &Root::Operator(op.clone()), Some(&op), NOW + 3);
        assert!(tree.controllers.is_empty() && tree.find("home1").is_none());

        // A revocation not signed by the operator is not applied.
        let mut planted = file.clone();
        let mut r = revoked.revoked[0].clone();
        r.reason = "edited".into();
        planted.revoked.push(r);
        let tree = furcate_topology::cell::derive_revoking(&planted, &Root::Operator(op.clone()), Some(&op), NOW + 3);
        assert!(tree.find("home1").is_some());
        // Nor where the operator's key is not held.
        let tree = furcate_topology::cell::derive_revoking(&revoked, &Root::Operator(op.clone()), None, NOW + 3);
        assert!(tree.find("home1").is_some());
    }

    fn leaf_record(leaf: &SigningKey, name: &str) -> furcate_sense::leaf::Attachment {
        furcate_sense::leaf::Attachment::from_record(&serde_json::json!({
            "leaf_id": name,
            "parent": "pi-home",
            "public_key": hex::encode(leaf.verifying_key().as_bytes()),
            "attached_at": NOW,
            "key_custody": {"kind": "fuse-key"},
        }))
        .unwrap()
    }

    #[test]
    fn a_leaf_link_is_checked_against_what_was_asked() {
        let head = fresh();
        let leaf = fresh();
        let link = CellDelegation {
            site: "s".into(),
            issuer: ed25519_id(&head.verifying_key()),
            holder: ed25519_id(&leaf.verifying_key()),
            role: Role::Leaf,
            scope: Scope::cell("home1").unwrap(),
            scale: None,
            assurance: Some(AssuranceClass::Device),
            leaf_min_class: None,
            endpoint: String::new(),
            name: "t1".into(),
            parent: Some("x".into()),
            not_before: NOW,
            not_after: NOW + DAY,
            signature: String::new(),
        }
        .signed_by(|m| Ok(head.sign(m).to_bytes().to_vec()))
        .unwrap();
        let home1 = Scope::cell("home1").unwrap();
        verify_leaf(&link, &home1, &leaf_record(&leaf, "t1")).unwrap();
        assert!(verify_leaf(&link, &Scope::cell("home2").unwrap(), &leaf_record(&leaf, "t1")).is_err());
        assert!(verify_leaf(&link, &home1, &leaf_record(&leaf, "t2")).is_err());
        assert!(verify_leaf(&link, &home1, &leaf_record(&fresh(), "t1")).is_err());
        let mut soft = leaf_record(&leaf, "t1");
        soft.key_custody = None;
        let e = verify_leaf(&link, &home1, &soft).unwrap_err().to_string();
        assert!(e.contains("`device`") && e.contains("`soft`"), "a link that promotes the leaf is refused: {e}");
    }

    #[test]
    fn the_published_esp32_record_goes_through_the_verifier_end_to_end() {
        let record: serde_json::Value =
            serde_json::from_str(include_str!("../../furcate-sense/fixtures/home-lab-leaf.json")).unwrap();
        let att = furcate_sense::leaf::Attachment::from_record(&record).unwrap();
        assert_eq!(att.assurance(), AssuranceClass::Soft);

        let ctrl_key = fresh();
        let operator = fresh();
        let mut file = site_file();
        let ctrl = controller_link(&mut file, &operator, &ed25519_id(&ctrl_key.verifying_key()), "10.0.0.2:7616", "", 90 * DAY, NOW)
            .unwrap();
        let pi = fresh();
        let e = HeadEnrolment {
            gateway: ed25519_id(&pi.verifying_key()),
            assurance: AssuranceClass::Device,
            endpoint: "pi-lab:7616".into(),
            name: "pi-lab".into(),
            cell: "lab".into(),
            scale: Scale::Home,
            until: NOW + 30 * DAY,
            leaf_min_class: None,
        };
        let head = furcate_topology::cell::enrol_head(&ctrl, &e, NOW)
            .unwrap()
            .signed_by(|m| Ok(ctrl_key.sign(m).to_bytes().to_vec()))
            .unwrap();

        let refused = furcate_topology::cell::enrol_leaf(&head, &att, NOW + DAY, NOW).unwrap_err();
        assert!(refused.contains("cell leaf-floor") && refused.contains("--class soft"), "{refused}");

        // The operator lowers this cell's floor; the controller signs the head
        // a new link carrying it.
        let lowered = HeadEnrolment { leaf_min_class: leaf_floor(&flags(&["--leaf-min-class", "soft"], &["leaf-min-class"]).unwrap()).unwrap(), ..e };
        let head = furcate_topology::cell::enrol_head(&ctrl, &lowered, NOW)
            .unwrap()
            .signed_by(|m| Ok(ctrl_key.sign(m).to_bytes().to_vec()))
            .unwrap();
        assert_eq!(head.leaf_min_class, Some(AssuranceClass::Soft));
        let link = furcate_topology::cell::enrol_leaf(&head, &att, NOW + DAY, NOW)
            .unwrap()
            .signed_by(|m| Ok(pi.sign(m).to_bytes().to_vec()))
            .unwrap();
        let lab = Scope::cell("lab").unwrap();
        verify_leaf(&link, &lab, &att).unwrap();
        assert_eq!(link.assurance, Some(AssuranceClass::Soft));
        assert!(link.holder.starts_with("p256:03749d51"));
    }

    #[test]
    fn a_leaf_floor_flag_is_a_class_or_refused() {
        let f = |v: &str| leaf_floor(&flags(&["--leaf-min-class", v], &["leaf-min-class"]).unwrap());
        assert_eq!(f("soft").unwrap(), Some(AssuranceClass::Soft));
        assert_eq!(f("tpm").unwrap(), Some(AssuranceClass::Tpm));
        assert!(f("lenient").is_err());
        assert_eq!(leaf_floor(&BTreeMap::new()).unwrap(), None);
    }

    #[test]
    fn durations_parse_and_nonsense_is_refused() {
        assert_eq!(parse_ttl("90d").unwrap(), 90 * DAY);
        assert_eq!(parse_ttl("12h").unwrap(), 12 * 3600);
        assert!(parse_ttl("0d").is_err());
        assert!(parse_ttl("1y").is_err());
        assert!(flags(&["--site", "a", "--site", "b"], &["site"]).is_err());
        assert!(flags(&["--nope", "a"], &["site"]).is_err());
    }

    #[test]
    fn a_p256_head_is_named_by_its_compressed_point_and_enrols_like_any_other() {
        // The P-256 base point: a public curve constant, standing in for a
        // key a Pi exported from its firmware.
        const X: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        const Y: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let compressed = format!("p256:03{X}");
        assert_eq!(key_id(&format!("p256:04{X}{Y}")).unwrap(), compressed);
        assert_eq!(key_id(&compressed).unwrap(), compressed);
        let spki = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
        assert_eq!(key_id(&format!("p256:{spki}04{X}{Y}")).unwrap(), compressed);
        assert!(key_id(&format!("p256:02{}", "ff".repeat(32))).is_err());
        assert!(key_id("p256:zz").is_err());

        let operator = fresh();
        let ctrl_key = fresh();
        let mut file = site_file();
        let ctrl = controller_link(&mut file, &operator, &ed25519_id(&ctrl_key.verifying_key()), "10.0.0.2:7616", "", 90 * DAY, NOW)
            .unwrap();
        let e = HeadEnrolment {
            gateway: compressed.clone(),
            assurance: AssuranceClass::Device,
            endpoint: "10.0.0.9:7616".into(),
            name: "home1".into(),
            cell: "home1".into(),
            scale: Scale::Home,
            until: NOW + 30 * DAY,
            leaf_min_class: None,
        };
        let h = furcate_topology::cell::enrol_head(&ctrl, &e, NOW)
            .unwrap()
            .signed_by(|m| Ok(ctrl_key.sign(m).to_bytes().to_vec()))
            .unwrap();
        assert_eq!(h.holder, compressed);
        file.links.push(h);
        let op = ed25519_id(&operator.verifying_key());
        let tree = furcate_topology::cell::derive_revoking(&file, &Root::Operator(op.clone()), Some(&op), NOW + 1);
        assert_eq!(tree.find("home1").map(|c| c.head.holder.as_str()), Some(compressed.as_str()));
    }
}
