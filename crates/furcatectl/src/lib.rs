//! Operator CLI for Furcate.
//!
//! Phase 01 surface: inspect this machine's hardware identity, produce a fresh
//! quote, and emit an enrollment record for a site controller to appraise.

// deploy is open: it builds a site and places it on machines the operator owns.
mod cell;
mod deploy;
pub mod extension;
mod keycustody;
mod gateway;
mod act;
mod chat;
mod login;
mod model;
mod model_front;
mod npu;
mod site;

use anyhow::{bail, Context, Result};
use furcate_attest::policy::classify_coverage;
use furcate_identity::backends::Tpm2Tools;
use furcate_identity::{Enrollment, RootOfTrust};
use site::SiteFile;
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "\
furcatectl — operator CLI for Furcate

IDENTITY
    furcatectl identity show          Show this node's hardware identity
    furcatectl identity quote [HEX]   Produce a quote bound to a nonce
    furcatectl identity enroll        Emit an enrollment record as JSON
    furcatectl identity coverage      What this platform's measurements prove
    furcatectl identity bench         Time repeated quotes (compares backends)
    furcatectl identity recovery      How to recover a faulted root of trust
    furcatectl identity soft-enroll WHY
                                      Admit a machine with no TPM on its hardware
                                      serials. Needs root, and records the reason
    furcatectl identity re-enrol KEY WHY
                                      Change this node's enrolled identity on purpose,
                                      signed with the operator key. Needs root; keeps
                                      the identity it replaces and the reason

SECRETS
    furcatectl seal FILE DIR          Seal a file to this machine's TPM, if the site's
                                      custody settings make this machine a holder
    furcatectl custody stage FILE     Stage a custody change for a set_custody order;
                                      prints the digest the order names
    furcatectl custody sign-self KEY SITE OUT REASON
                                      Sign a self-custody record for SITE with the
                                      operator key; place OUT at state/custody.json
    furcatectl unseal DIR FILE        Recover a sealed file

OPERATOR
    furcatectl operator init DIR      Generate the operator key that arms the kill switch
    furcatectl operator seal KEY DIR  Seal the operator key to this machine's TPM
    furcatectl operator kill KEY SCOPE MODE REASON
    furcatectl operator breakglass KEY HOLDER ACTIONS RESOURCES SECS REASON
                                      Emergency access, verified without a control plane
    furcatectl accelerator reset KEY NODE INDEX
                                      Reset a drained card so its queued repair applies
    furcatectl session open ID ACTOR AUTHORITY
    furcatectl session record ID COMMAND OUTCOME [TARGET]
    furcatectl session close ID
    furcatectl session verify ID [ANCHOR]
                                      Record what was done while holding authority
    furcatectl site administrator
    furcatectl fleet [ADDR]           Every node, what it runs, and how old that is
    furcatectl act KEY PROPOSAL_ID [--yes]
                                      Carry out a proposal a person approved.
                                      Without --yes it says what would happen and
                                      stops. Approval records intent; this is
                                      where the operator signature is spent
    furcatectl chat                   Talk to the cluster. `/big` asks the larger
                                      model, `/facts` shows what the agent is being
                                      told, `/quit` leaves
    furcatectl ask QUESTION...        Ask the cluster, in your own words. Answered
                                      by this machine's agent from what the fleet
                                      reports
    furcatectl ask-big QUESTION...    The same, asked of the larger model on the
                                      accelerated machine
    furcatectl orchestrator list      Models this machine may run as its agent
    furcatectl orchestrator show      Which one it is running, and from where
    furcatectl orchestrator set ID    Fetch it if needed, serve it, and register it
                                      as this node's agent. One per machine
    furcatectl orchestrator import FILE ID
                                      Install weights from a path -- a USB drive,
                                      a mounted share -- with no internet at all
    furcatectl orchestrator export ID FILE
                                      Copy this machine's weights out, to carry to
                                      a machine that cannot reach the internet
    furcatectl orchestrator push ID NODE
                                      Send weights to another machine on the LAN,
                                      so a fleet downloads once
    furcatectl login [SITE]           Sign this machine in to a Praecise account.
                                      Prints a code to approve in a browser; the
                                      screen there names every machine it would
                                      claim
    furcatectl name list              What each machine answers to
    furcatectl name set KEY SITE NODE_ID @NAME
                                      Give a machine a name. Unique in the
                                      cluster; renaming changes nothing about
                                      what the machine may do
    furcatectl name cluster KEY SITE @NAME
                                      What this cluster answers to
    furcatectl owner list [ACCOUNT]   Whose machines these are
    furcatectl owner claim KEY SITE NODE_ID ACCOUNT REASON
                                      Record that a machine belongs to an account
    furcatectl owner release KEY SITE NODE_ID
                                      Give a machine up
    furcatectl fleet people           Who belongs to this fleet, and as what
    furcatectl fleet admit KEY SITE ACCOUNT ROLE
                                      Add an account, or change its role:
                                      member | admin | owner
    furcatectl fleet withdraw KEY SITE ACCOUNT
                                      Remove an account. Refuses the last owner,
                                      and leaves their machines claimed
    furcatectl people list            Who this site admits besides the operator
    furcatectl people admit ID PUBKEY DAYS [ROLE...]
                                      Admit a person under their own key
    furcatectl people withdraw ID     Remove an admission

GATEWAY
    furcatectl gateway add NAME HOST [k=v ...]
                                      Register a public ingress gateway. Pairs:
                                      role=main|backup ip= user= port= key=<priv>
                                      wg_pubkey= wg_endpoint= wg_addr= provider= note=
    furcatectl gateway list           Every registered gateway and how it is reached
    furcatectl gateway show NAME      One gateway, in full
    furcatectl gateway authorize NAME KEYFILE
                                      Install a public key for persistent access,
                                      over the access already recorded — no console
    furcatectl gateway ssh NAME [CMD] Run a command, or open a shell, on a gateway
    furcatectl gateway remove NAME    Forget a gateway (its keys are left in place)

    furcatectl site appoint KEY ADDR NODE_ID HOURS REASON
                                      Name which machine administers a site
    furcatectl network show | links | lan
    furcatectl domain list
    furcatectl domain add KEY NAME
    furcatectl domain records KEY NAME
    furcatectl domain verify KEY NAME
    furcatectl domain map KEY NAME SITE
    furcatectl keys
    furcatectl tunnels
    furcatectl ledger
    furcatectl routing

MACHINE
    furcatectl cooling                Fans, temperatures, and what they cost
    furcatectl thermal                What this machine may draw, and why
    furcatectl thermal set KEY NODE placement=living_space quiet=22-7 envelope=0.6 builds=refuse
                                      Declare how this machine should behave
                                      about noise. Signed, and ruled against
                                      `tune` on the node like any other change.
                                      envelope: full | a fraction | 90W per
                                      package. quiet= on its own clears it.
    furcatectl power                  Supply state and the rung it justifies
    furcatectl hardware               What this machine was recognised as
    furcatectl host                   Filesystems, clock, uptime, reboots
    furcatectl sensors                Everything this node can read
    furcatectl scheduler              What is placed here and what is not
    furcatectl workloads              What is running on this machine
    furcatectl members                Machines this node can see
    furcatectl custody show
    furcatectl advisor show
    furcatectl published
    furcatectl workload restart KEY NODE KIND ID
                                      Ask a node to restart a workload, signed
    furcatectl roster admit KEY SITE NODE_ID PUBKEY HOURS
                                      Admit a machine, so it may report and act
    furcatectl roster withdraw KEY SITE NODE_ID
                                      Take a machine out of the fleet now, rather
                                      than when its admission lapses. Its owner's
                                      claim is left alone
    furcatectl trust list             Who this machine believes, and why
    furcatectl trust withdraw KEY SITE NODE_ID
                                      Stop believing a machine's word. Works on a
                                      machine already out of the roster
    furcatectl trust withdraw-local NODE_ID
                                      The same, edited here. Needs root: the trust
                                      store is the operator's file, which is why a
                                      network-facing service cannot rewrite it
    furcatectl roles list             What each machine is for
    furcatectl roles vocabulary       The words this cluster understands
    furcatectl roles set KEY SITE NODE ROLE... [--note WHY]
                                      Say what a machine is for
    furcatectl roles clear KEY SITE NODE
                                      Say it is for nothing in particular
    furcatectl trust admit-local NODE_ID PUBKEY REASON
                                      Recognise a machine here. The reason is
                                      required and is shown wherever this entry is:
                                      a trust store nobody can read the reasoning
                                      of is one nobody dares remove an entry from
    furcatectl wake forget KEY SITE NODE_ID
                                      Forget how to wake a machine
    furcatectl node decommission KEY SITE NODE_ID
                                      A machine is gone for good: withdraw it from
                                      the roster, stop trusting it, and forget how
                                      to wake it. Its owner's claim is kept
    furcatectl policy grant KEY SITE PRINCIPAL ACTION RESOURCE SECS REASON
    furcatectl policy revoke KEY SITE PRINCIPAL
    furcatectl call KEY ADDR PATH [JSON]
                                      Any guarded route, signed: a POST with
                                      JSON, a GET without. The escape hatch,
                                      so nothing is unreachable
                                      Sign a kill order (SCOPE: cluster|node:ID|domain:ID)

DEPLOY
    furcatectl deploy SRC NAME [DOMAINS]
                                      Build a site and place it here. With no
                                      DOMAINS the cluster's zone supplies the
                                      address: NAME.<zone> for an app and
                                      NAME.<zone-mcp> for an agent application,
                                      so a deploy needs no DNS work. DOMAINS is
                                      comma-separated when given
    furcatectl deploy relink NAME     Rewrite a placed site's unit from what is
                                      already on disk — no rebuild, no source
                                      needed. Gives it the address for the zone
                                      it belongs to now, which a site placed
                                      before the zone existed does not have
    furcatectl deploy rename OLD NEW  Give a placed site a new name and drop the old
                                      one completely: no alias, no redirect. Moves
                                      env, state and releases; NAME.<zone> addresses
                                      follow the name, custom domains stay; the
                                      token rotates (the old one is archived); the
                                      old unit is withdrawn, the new one started,
                                      and the edge rendered once. Refuses if NEW exists
    furcatectl deploy verify NAME HOST
                                      Fetch the site and check the bytes served
                                      are the ones that were approved
    furcatectl deploy env NAME [KEY=VALUE...]
                                      A site's secrets — model and tool credentials.
                                      Kept beside the site, never in the release, so
                                      a redeploy does not disturb them. With no pairs,
                                      lists the names that are set
    furcatectl deploy env NAME --stdin
                                      The same, reading KEY=VALUE lines from stdin
                                      so no value is in argv, `ps` or the journal.
                                      Blank lines and # comments are skipped
    furcatectl deploy remove NAME     Stop the site's unit and confirm it stopped,
                                      remove the unit and its drop-ins (archived
                                      beside the kept releases), then stop serving
                                      it and re-render the edge. A unit that will
                                      not stop fails the removal before anything moves.
    furcatectl edge zone-mcp [ZONE]   The agent zone: an agent application answers
                                      here instead, because software calling it
                                      wants a different name from a browser
    furcatectl edge zone [ZONE]       The platform zone: every placed site also answers
                                      on NAME.<zone> under its wildcard certificate.
    furcatectl deploy rollback NAME RELEASE
                                      Serve a kept release again: move `current`,
                                      restart, and gate on health like a deploy.
                                      Releases are kept, moved aside
    furcatectl edge render            Re-render the edge from the placed sites and
                                      reload it, touching no site. For when an input
                                      to rendering changed without a deploy: a
                                      wildcard certificate placed under
                                      edge/wildcards/<zone>/ is the case

MODELS
    furcatectl model list             Catalog, what is local, what is serving
    furcatectl model pull ID          Fetch weights, verified against the source
    furcatectl model serve ID [OPTS]  Serve it here, OpenAI-compatible.
                                      --cpu | --gpu | --device auto|gpu|cpu
                                      --context N | --gpu-layers N | --reasoning on|off|auto
                                      Defaults may be set in /etc/furcate/model.conf
    furcatectl model gateway [OPTS]   Serve EVERY local model on one endpoint, loaded on
                                      demand. This is what an app's fast/balanced/best
                                      rungs need: one url, several model ids.
                                      --bind ADDR opens it to the cell: requests signed
                                      by an attached leaf or by the operator only
    furcatectl model stop ID
    furcatectl model status           What is answering, asked of the port
    furcatectl model endpoint [ID]    The base URL to point an application at
    furcatectl model credential ID    The loopback token for apps on this machine

SELFTEST
    furcatectl selftest tpm           Exercise the TPM client against a software TPM
    furcatectl selftest pcr           Check predicted PCR 11 against a real TPM
    furcatectl selftest uki PATH      Predict PCR 11 for a real unified kernel image
    furcatectl selftest units         Can every furcate unit start what it names?
                                      A missing binary and one that lost its execute
                                      bit both fail here and in neither `is-active`


SITE
    furcatectl site init PATH         Write a starter site definition
    furcatectl site show PATH         Render the failure-domain tree
    furcatectl site isolation PATH    Which replication levels this site supports

Quotes require a nonce. One is generated if you do not supply it, but a
verifier must supply its own for the result to prove freshness.
";

/// Load the machine's configuration before doing anything with it.
///
/// Everything this tool renders is derived from environment variables —
/// FURCATE_EDGE_TLS decides whether the edge serves HTTPS at all, FURCATE_SITE
/// decides which node is asked whether a name may have a certificate. Those
/// belong to the machine, and they were being read from whatever shell happened
/// to invoke the command.
///
/// The consequence was not theoretical. Running `furcate deploy` from an
/// ordinary root shell rendered the edge with `auto_https off` and `http://`
/// prefixes on every site address, because FURCATE_EDGE_TLS was simply absent —
/// silently turning port 8443 into plaintext for every domain the machine
/// serves. A repair script existed downstream to transform the output back,
/// which is a fix at the wrong end: the render was correct code fed the wrong
/// inputs.
///
/// Values already present in the environment win, so a caller can still
/// override a single setting for one invocation without editing the file.
fn parse_env(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

fn load_machine_env() {
    for path in ["/etc/furcate/env", "/etc/furcate/edge.env"] {
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        for (k, v) in parse_env(&text) {
            if std::env::var_os(&k).is_some() {
                continue;
            }
            // SAFETY: single-threaded startup, before any thread is spawned.
            unsafe { std::env::set_var(&k, &v) };
        }
    }
}


/// The tool's entry point: reads the machine's environment, runs the command
/// and exits non-zero with the error if it fails.
pub fn main() {
    load_machine_env();
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}


fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    match refs.as_slice() {
        [] | ["-h"] | ["--help"] | ["help"] => {
            print!("{USAGE}{}", extension::get().usage());
            Ok(())
        }
        ["identity", "show"] => identity_show(),
        ["identity", "quote"] => identity_quote(None),
        ["identity", "quote", nonce] => identity_quote(Some(nonce)),
        ["identity", "enroll"] => identity_enroll(),
        ["identity", "coverage"] => identity_coverage(),
        ["identity", "bench"] => identity_bench(),
        ["identity", "recovery"] => identity_recovery(),
        ["identity", "soft-enroll", why] => identity_soft_enroll(why),
        ["identity", "re-enrol", key, why] => identity_reenrol(key, why),
        ["selftest", "tpm"] => selftest_tpm(),
        ["selftest", "pcr"] => selftest_pcr(),
        ["selftest", "units"] => selftest_units(),
        ["selftest", "uki", path] => selftest_uki(path),
        ["operator", "init", dir] => operator_init(dir),
        ["seal", input, dir] => seal_file(input, dir),
        ["custody", "stage", file] => {
            let digest = keycustody::stage(&keycustody::Paths::standard(), file)?;
            println!("staged         {digest}");
            println!("next           propose a set_custody order naming this digest");
            Ok(())
        }
        ["custody", "sign-self", key, site, out, reason] => {
            let signing = operator_signing_key(key)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let digest = keycustody::sign_self(&signing, site, std::path::Path::new(out), reason, now)?;
            println!("signed         self-custody for site {site}, epoch 1");
            println!("digest         {digest}");
            println!("written        {out}");
            println!("next           place it at {} on each node before the new binary runs", furcate_paths::state("custody.json").display());
            Ok(())
        }
        ["unseal", dir, output] => unseal_file(dir, output),
        ["operator", "seal", key, dir] => operator_seal(key, dir),
        ["operator", "kill", key, scope, mode, reason] => operator_kill(key, scope, mode, reason),
        ["operator", "breakglass", key, holder, actions, resources, secs, reason] => {
            operator_breakglass(key, holder, actions, resources, secs, reason)
        }
        ["accelerator", "reset", key, node, index] => accelerator_reset(key, node, index),
        ["session", "open", id, actor, authority] => session_open(id, actor, authority),
        ["session", "record", id, command, outcome] => session_record(id, command, outcome, None),
        ["session", "record", id, command, outcome, target] => {
            session_record(id, command, outcome, Some(target))
        }
        ["session", "close", id] => session_close(id),
        ["session", "verify", id] => session_verify(id, None),
        ["session", "verify", id, anchor] => session_verify(id, Some(anchor)),
        ["workload", "restart", key, node, kind, id] => workload_restart(key, node, kind, id),
        ["call", key, addr, path, body] => call_signed(key, addr, path, Some(body)),
        ["call", key, addr, path] => call_signed(key, addr, path, None),
        ["orchestrator", "list"] => model::orchestrator_list(),
        ["orchestrator", "set", id] => model::orchestrator_set(id),
        ["orchestrator", "show"] => model::orchestrator_show(),
        ["orchestrator", "import", path, id] => model::orchestrator_import(path, id),
        ["orchestrator", "export", id, path] => model::orchestrator_export(id, path),
        ["orchestrator", "push", id, node] => model::orchestrator_push(id, node),
        ["ask", rest @ ..] if !rest.is_empty() => {
            chat::ask(&site_addr(), &rest.join(" "), false)
        }
        ["ask-big", rest @ ..] if !rest.is_empty() => {
            chat::ask(&site_addr(), &rest.join(" "), true)
        }
        ["chat"] => chat::converse(&site_addr()),
        ["act", key, id] => act::act(key, &site_addr(), id, false),
        ["act", key, id, "--yes"] => act::act(key, &site_addr(), id, true),
        ["login"] => login::login(&site_addr()),
        ["login", site] => login::login(site),
        ["name", "list"] => handle_list(),
        ["name", "set", key, site, node, handle] => handle_set(key, site, node, handle),
        ["name", "cluster", key, site, handle] => handle_cluster(key, site, handle),
        ["owner", "list"] => owner_list(None),
        ["owner", "list", account] => owner_list(Some(account)),
        ["owner", "claim", key, site, node, account, reason] => {
            owner_claim(key, site, node, account, reason)
        }
        ["owner", "release", key, site, node] => owner_release(key, site, node),
        ["fleet", "people"] => fleet_people(),
        ["fleet", "admit", key, site, account, role] => fleet_admit(key, site, account, role),
        ["fleet", "withdraw", key, site, account] => fleet_withdraw(key, site, account),
        ["roster", "admit", key, site, node, pubkey, hours] => {
            roster_admit(key, site, node, pubkey, hours)
        }
        ["roster", "withdraw", key, site, node] => roster_withdraw(key, site, node),
        ["trust", "withdraw", key, site, id] => trust_withdraw(key, site, id),
        ["trust", "withdraw-local", id] => trust_withdraw_local(id),
        ["trust", "admit-local", id, key, reason] => trust_admit_local(id, key, reason),
        ["roles", "list"] => roles_list(),
        ["roles", "vocabulary"] => roles_vocabulary(),
        ["roles", "set", key, site, node, rest @ ..] => roles_set(key, site, node, rest),
        ["roles", "clear", key, site, node] => roles_clear(key, site, node),
        ["trust", "list"] => trust_list(),
        ["wake", "forget", key, site, node] => wake_forget(key, site, node),
        ["node", "decommission", key, site, node] => node_decommission(key, site, node),
        ["ssh", "cert", key, user, host, pubkey] => ssh_cert(key, user, host, pubkey, "1h"),
        ["ssh", "cert", key, user, host, pubkey, ttl] => ssh_cert(key, user, host, pubkey, ttl),
        ["ledger", "record", key, actor, subject, result] => {
            ledger_record(key, actor, subject, result)
        }
        ["policy", "grant", key, site, principal, action, resource, secs, reason] => {
            policy_grant(key, site, principal, action, resource, secs, reason)
        }
        ["policy", "revoke", key, site, to] => policy_revoke(key, site, to),
        ["overlay", "authorize", key, node, pubkey, tier, hours] => {
            overlay_authorize(key, node, pubkey, tier, hours)
        }
        ["overlay", "anchor", key] => overlay_anchor(key),
        // `verify` first: both arms are four elements, so the general one
        // matches everything and would make this unreachable.
        // deploy and edge are open: placing a build on machines the operator
        // owns is part of running your own cluster.
        ["deploy", "env", name] => deploy::show_env(name),
        // Before the general arm, which would read `--stdin` as a pair and
        // refuse it for having no `=`.
        ["deploy", "env", name, "--stdin"] => deploy::set_env_stdin(name),
        ["deploy", "env", name, pairs @ ..] => deploy::set_env(name, pairs),
        ["deploy", "verify", name, authority] => deploy::verify_cmd(name, authority),
        ["deploy", "remove", name] => deploy::remove(name, "operator"),
        ["deploy", "relink", name] => deploy::relink(name, "operator"),
        // Four elements, so before `deploy SRC NAME DOMAINS` or that arm would
        // try to build a directory called `rename`.
        ["deploy", "rename", old, new] => deploy::rename(old, new, "operator"),
        ["deploy", "rollback", name, release] => deploy::rollback(name, release, "operator"),
        ["edge", "render"] => deploy::render_edge(),
        ["edge", "zone"] => deploy::edge_zone(None),
        ["edge", "zone", zone] => deploy::edge_zone(Some(zone)),
        ["edge", "zone-mcp"] => deploy::edge_zone_mcp(None),
        ["edge", "zone-mcp", zone] => deploy::edge_zone_mcp(Some(zone)),
        // Three elements: no domains given, so the cluster's own zone supplies
        // the address. This is the whole point of having a platform zone —
        // `deploy SRC NAME` is a complete instruction, and asking for a domain
        // as well is asking the operator to repeat what the cluster knows.
        // `deploy()` refuses only if the zone cannot supply one either.
        ["deploy", src, name] => deploy::deploy(src, name, "", "operator"),
        ["deploy", src, name, domains] => deploy::deploy(src, name, domains, "operator"),
        ["cell", rest @ ..] => cell::run(rest),
        ["gateway", "add", name, host, rest @ ..] => gateway::add(name, host, rest),
        ["gateway", "list"] => gateway::list(),
        ["gateway", "show", name] => gateway::show(name),
        ["gateway", "remove", name] => gateway::remove(name),
        ["gateway", "authorize", name, keyfile] => gateway::authorize(name, keyfile),
        ["gateway", "ssh", name, cmd @ ..] => gateway::ssh(name, cmd),
        ["model", "list"] => model::list(),
        ["model", "status"] => model::status(),
        ["model", "endpoint"] => model::endpoint(None),
        ["model", "endpoint", id] => model::endpoint(Some(id)),
        ["model", "credential", id] => model::credential(id),
        ["model", "pull", id] => model::pull(id),
        ["model", "stop", id] => model::stop(id),
        ["model", "gateway", rest @ ..] => model::gateway(rest),
        ["model", "front", rest @ ..] => model_front::run(rest, &model::token_path("gateway")),
        ["model", "serve", id, rest @ ..] => model::serve(id, rest),
        ["site", "administrator"] => site_report("/administrator", "the administrator"),
        ["fleet"] => fleet_show(None),
        ["fleet", addr] => fleet_show(Some(addr)),
        ["people", "list"] => people_list(),
        ["people", "admit", id, pubkey, days, roles @ ..] => people_admit(id, pubkey, days, roles),
        ["people", "withdraw", id] => people_withdraw(id),
        ["site", "appoint", key, addr, node, hours, reason @ ..] => {
            site_appoint(key, addr, node, hours, &reason.join(" "))
        }
        ["network", "show"] => node_report("/network", "network"),
        ["network", "lan"] => node_report("/lan", "the local network"),
        ["keys"] => node_report("/keys", "key material"),
        ["domain", "list"] => node_report("/domains", "domains"),
        ["domain", "add", key, name] => domain_step(key, "/domains/add", name, None),
        ["domain", "records", key, name] => domain_step(key, "/domains/records", name, None),
        ["domain", "verify", key, name] => domain_step(key, "/domains/verify", name, None),
        ["domain", "map", key, name, site] => domain_step(key, "/domains/map", name, Some(site)),
        ["tunnels"] => node_report("/tunnels", "tunnels"),
        ["ledger"] => node_report("/ledger?tail=24", "the record"),
        ["resources"] => node_report("/resources", "resources"),
        ["routing"] => routing_map(),
        ["network", "links"] => node_report("/lldp", "links"),
        // Views this daemon has always served and no verb reached. An operator
        // could see cooling on a console and not in a script, which is the
        // exact gap `node_report` was written for — it had eleven callers and
        // the machine's own thermal state was not one of them.
        ["cooling"] => node_report("/cooling", "cooling"),
        ["thermal", "set", key, node, rest @ ..] if !rest.is_empty() => {
            let f = thermal_fields(rest)?;
            let borrowed: Vec<(&str, &str)> =
                f.iter().map(|(k, v)| (*k, v.as_str())).collect();
            thermal_set(key, node, &borrowed)
        }
        ["thermal"] => node_report("/thermal", "the power envelope"),
        ["power"] => node_report("/power", "power"),
        ["hardware"] => node_report("/hardware", "hardware"),
        ["host"] => node_report("/host", "the host"),
        ["sensors"] => node_report("/sensors", "sensors"),
        ["scheduler"] => node_report("/scheduler", "the scheduler"),
        ["workloads"] => node_report("/workloads", "workloads"),
        ["members"] => node_report("/members", "members"),
        ["custody", "show"] => node_report("/custody", "custody"),
        ["advisor", "show"] => node_report("/models", "advisor"),
        ["published"] => node_report("/published", "published"),
        ["site", "init", path] => site_init(path),
        ["site", "show", path] => site_show(path),
        ["site", "isolation", path] => site_isolation(path),
        // A command the open tool does not have may be the registered
        // edition's.
        other => match extension::get().run(other) {
            Some(result) => result,
            None => bail!(
                "unknown command `{}`\n\n{USAGE}{}",
                other.join(" "),
                extension::get().usage()
            ),
        },
    }
}

/// This node's root of trust, chosen exactly as furcated chooses it: the
/// strongest backend selection opens (TPM, then TEE, then a device key, else
/// the hardware-continuity record), held to the identity recorded in
/// `node-key/enrolled.json`. An emulated TPM is refused there, as it is for
/// the daemon. Nothing is written: recording the identity is furcated's.
fn open_node() -> Result<(furcate_identity::pin::Opened<furcate_identity::pin::Rot>, Vec<String>)> {
    let paths = furcate_identity::pin::NodePaths::new(&furcate_paths::config_dir(), &furcate_paths::state("node-key"));
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (resolved, attempts) = furcate_identity::pin::open_node(&paths, now);
    let resolved = resolved.map_err(anyhow::Error::msg).context("this node's root of trust")?;
    let mut notes: Vec<String> = attempts.iter().map(|a| format!("passed over {}: {}", a.backend, a.outcome)).collect();
    notes.extend(resolved.note);
    if resolved.record.is_some() {
        notes.push(format!("not yet recorded in {}; furcated records it on its next start", paths.record().display()));
    }
    Ok((resolved.opened, notes))
}

/// This node's root of trust, for a command that needs signed quotes over
/// measured platform state. Anything else is refused with what this node has
/// instead, rather than with a failure to open a device it never had.
fn open_quoting(what: &str) -> Result<furcate_identity::pin::Opened<furcate_identity::pin::Rot>> {
    let (node, _) = open_node()?;
    quoting_refusal(what, &node.backend, node.class).map_or(Ok(node), |why| Err(anyhow::anyhow!(why)))
}

fn quoting_refusal(what: &str, backend: &str, class: furcate_identity::AssuranceClass) -> Option<String> {
    (!class.can_quote()).then(|| {
        format!(
            "{what} needs a TPM: a root of trust that signs quotes over measured platform state. \
             This node's root of trust is {backend} (class {class}), which has no measurement \
             registers and signs no quote. `furcatectl identity show` reports what it does attest"
        )
    })
}

fn identity_policy() -> furcate_identity::backends::Policy {
    furcate_identity::backends::Policy::in_config_dir(&furcate_paths::config_dir())
}

fn identity_show() -> Result<()> {
    let (node, notes) = open_node()?;
    let rot = &node.rot;
    let endorsement = furcate_identity::backends::endorsement(rot.as_ref(), &identity_policy());

    println!("node id     {}", node.node_id);
    println!("backend     {}: {}", node.backend, node.reason);
    println!("assurance   {}", node.class);
    match rot.ek_public() {
        Ok(ek) => println!("ek public   {} bytes", ek.len()),
        Err(_) => println!("ek public   none: a {} root has no endorsement key", node.class),
    }
    println!("endorsement {}", endorsement.detail);
    for n in &notes {
        println!("note        {n}");
    }
    if !node.class.can_quote() {
        println!("\npcr bank    none: a {} root has no measurement registers", node.class);
        return Ok(());
    }
    let pcrs = rot.pcrs()?;
    println!("\npcr bank    {}", pcrs.bank);
    for (idx, digest) in pcrs.to_hex() {
        println!("  {idx:>2}  {digest}");
    }
    Ok(())
}

fn identity_quote(nonce_hex: Option<&str>) -> Result<()> {
    let nonce = match nonce_hex {
        Some(h) => hex::decode(h).context("nonce must be hex")?,
        None => generated_nonce(),
    };
    if nonce.is_empty() {
        bail!("nonce must not be empty");
    }

    let node = open_quoting("a quote")?;
    let quote = node.rot.quote(&nonce)?;

    println!("node id     {}", node.node_id);
    println!("nonce       {}", hex::encode(&quote.nonce));
    println!("message     {} bytes", quote.message.len());
    println!("signature   {} bytes", quote.signature.len());
    println!("covers      {} registers in {}", quote.pcrs.values.len(), quote.pcrs.bank);
    if nonce_hex.is_none() {
        println!(
            "\nnote: this nonce was generated locally, so the quote proves the chip \
             signed it\n      but not that it is fresh to anyone else. A verifier must \
             supply the nonce."
        );
    }
    Ok(())
}

/// Admit this machine on hardware continuity, because it has no TPM.
///
/// Reads the board and chassis serials, which are root-only, and writes them
/// with the reason to `soft-identity.json`. `furcated` will start against that
/// record and refuse to start without it.
///
/// This is a smaller claim than attestation and the output says so plainly.
/// A fingerprint proves the machine answering has the characteristics of the
/// one enrolled; it proves nothing about whether those characteristics were
/// copied, because every one of them can be read by anything with access to
/// the device. The node is `Soft`: no sealed custody unless site policy
/// enables both TPM-less custody and `allow_soft`, no signed quote, no
/// attested placement, and it may not hold the controlling role for a cluster.
fn identity_soft_enroll(why: &str) -> Result<()> {
    let policy = furcate_identity::backends::Policy::in_config_dir(&furcate_paths::config_dir());
    if let Ok(chosen) = furcate_identity::backends::select(&policy) {
        anyhow::bail!(
            "this machine has a hardware root of trust ({}, class {}), so it does \
             not need this. Enrolling it on serials instead would throw away the \
             stronger identity it already has.",
            chosen.backend,
            chosen.class
        );
    }

    let path = furcate_paths::config("soft-identity.json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let soft = furcate_identity::backends::SoftIdentity::capture(why, now)?;
    soft.write(&path)?;

    let rot = soft.rot();
    println!("recorded    {}", path.display());
    println!("node id     {}", rot.node_id()?);
    println!("assurance   {} — continuity, not unforgeability", rot.assurance());
    println!("reason      {why}");
    println!();
    println!("Anchored on:");
    for c in soft.observed.anchors() {
        let v = soft.observed.parts.get(&c).map(String::as_str).unwrap_or("");
        println!("  {:<16} {}", c.as_str(), v);
    }
    println!();
    println!("This node holds custody of nothing, produces no signed quote, and");
    println!("cannot lead a cluster. Start it with: systemctl start furcated");
    Ok(())
}

/// Change this node's enrolled identity, deliberately.
///
/// `furcated` refuses to start as a node other than the one recorded in
/// `node-key/enrolled.json`, whatever devices come and go. This is the one
/// way past that: it records what this machine is now (the strongest
/// hardware root, else its hardware-continuity record), keeps the identity it
/// replaces with the reason, and signs the record with the operator key so
/// `furcated` can tell it from an edit.
fn identity_reenrol(key_path: &str, why: &str) -> Result<()> {
    use furcate_identity::pin;
    if why.trim().is_empty() {
        anyhow::bail!("a re-enrolment needs a reason; it is kept with the identity it replaces");
    }
    let record_path = furcate_paths::state("node-key").join(pin::ENROLLED);
    let prior = pin::EnrolledIdentity::load(&record_path).map_err(anyhow::Error::msg)?;
    let (current, attempts) = pin::current(&identity_policy(), &furcate_paths::config("soft-identity.json"));
    for a in &attempts {
        println!("passed over {}: {}", a.backend, a.outcome);
    }
    let opened = current.map_err(|e| anyhow::anyhow!("nothing to enrol as: {e}"))?;
    if let Some(p) = &prior {
        if p.node_id == opened.node_id && p.backend == opened.backend {
            anyhow::bail!(
                "this node is already enrolled as {} on {}; there is nothing to change",
                p.node_id,
                p.backend
            );
        }
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut record = pin::EnrolledIdentity::reenrol(prior.as_ref(), &opened, now, why);
    record.sign(&operator_signing_key(key_path)?);
    // Checked here as furcated will check it, so a wrong key is caught now
    // and not at the next start.
    let operator = std::fs::read_to_string(furcate_paths::config("operator.pub")).ok();
    record.verify(operator.as_deref()).map_err(|e| {
        anyhow::anyhow!("not writing the record: {e}. Sign with the key whose public half is operator.pub")
    })?;
    std::fs::create_dir_all(record_path.parent().expect("node-key has a parent"))?;
    record.write(&record_path).with_context(|| format!("writing {}", record_path.display()))?;

    println!("recorded    {}", record_path.display());
    println!("node id     {}", record.node_id);
    println!("backend     {} ({}): {}", record.backend, record.class, opened.reason);
    match record.previous.last() {
        Some(p) => println!("replaces    {} on {}, enrolled at {}", p.node_id, p.backend, p.recorded_at),
        None => println!("replaces    nothing recorded"),
    }
    println!("reason      {why}");
    println!();
    println!("Restart furcated to start as this node: systemctl restart furcated");
    Ok(())
}

fn identity_enroll() -> Result<()> {
    let rot = open_quoting("enrolment evidence")?.rot;
    let evidence = rot.evidence(&generated_nonce())?;
    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let record = Enrollment::from_evidence(&evidence, hostname)
        .with_endorsement(&furcate_identity::backends::endorsement(rot.as_ref(), &identity_policy()));
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

/// Report what this platform's measurements genuinely establish.
///
/// Registers holding only a separator, or nothing at all, are not evidence.
/// Reporting them as though they were is how attestation turns into false
/// confidence, so this command names the gap rather than printing a tick.
fn identity_coverage() -> Result<()> {
    let node = open_quoting("measurement coverage")?;
    let pcrs = node.rot.pcrs()?;
    let hex = pcrs.to_hex();
    let coverage = classify_coverage(&hex);

    println!("node id     {}", node.node_id);
    println!("coverage    {coverage}");
    println!();

    for (idx, digest) in &hex {
        let note = if digest.chars().all(|c| c == '0') {
            "  never extended"
        } else if digest == furcate_attest::policy::SEPARATOR_ONLY {
            "  separator only — not evidence"
        } else {
            ""
        };
        println!("  {idx:>2}  {}{note}", &digest[..16.min(digest.len())]);
    }

    if coverage != furcate_attest::Coverage::PlatformAndOs {
        println!(
            "\nThe kernel, initrd and command line are not measured on this platform,\n\
             so attestation would detect a firmware change but not a swapped kernel.\n\
             A unified kernel image measured into PCR 11 closes this."
        );
    }
    Ok(())
}

/// Time repeated quotes.
///
/// The reason the native backend exists: the tools backend spawns several
/// processes per quote, which is fine for enrollment and unacceptable for
/// continuous attestation across a site.
fn identity_bench() -> Result<()> {
    const ROUNDS: u32 = 5;
    // Refused before any device is opened when this node does not quote.
    open_quoting("benchmarking quotes")?;

    #[cfg(feature = "tss")]
    {
        use furcate_identity::backends::TssNative;
        match TssNative::open() {
            Ok(native) => {
                let start = std::time::Instant::now();
                for i in 0..ROUNDS {
                    native.quote(&i.to_be_bytes())?;
                }
                let each = start.elapsed() / ROUNDS;
                println!("native (tss-esapi)  {each:?} per quote");
            }
            Err(e) => println!("native (tss-esapi)  unavailable: {e}"),
        }
    }
    #[cfg(not(feature = "tss"))]
    println!("native (tss-esapi)  not compiled in (build with --features tss)");

    let tools = Tpm2Tools::open().context("opening the TPM through tpm2-tools")?;
    let start = std::time::Instant::now();
    for i in 0..ROUNDS {
        tools.quote(&i.to_be_bytes())?;
    }
    let each = start.elapsed() / ROUNDS;
    println!("tpm2-tools          {each:?} per quote");
    Ok(())
}

/// Explain the recovery path for a faulted root of trust.
///
/// No software can restore trust in a machine — only an operator physically
/// at it, holding the firmware password. This command exists so that fact is
/// discoverable at the moment someone needs it, rather than being something
/// they have to already know.
fn identity_recovery() -> Result<()> {
    use furcate_identity::{Fault, RecoveryAction, RecoveryPolicy};

    // A node with no TPM has no chip to recover; say what it runs on instead
    // of reporting the missing device as a fault.
    if furcate_host::board::tpm_kind() == furcate_host::board::TpmKind::Absent {
        let (node, _) = open_node()?;
        println!(
            "root of trust  {} (class {}) — no TPM on this machine, so TPM recovery does not apply",
            node.backend, node.class
        );
        return Ok(());
    }

    // Detect rather than assume: if the chip answers, there is nothing to
    // recover from.
    let fault = match Tpm2Tools::open().and_then(|r| r.pcrs()) {
        Ok(_) => {
            println!("root of trust  responding normally — no recovery needed");
            return Ok(());
        }
        Err(e) => {
            let text = e.to_string();
            if text.contains("0x101") || text.contains("failure") {
                Fault::FailureMode
            } else {
                Fault::Unresponsive
            }
        }
    };

    println!("fault          {}", fault.as_str());
    let action = fault.recommended();
    println!("try first      {action}");
    println!("  identity     {}", if action.preserves_node_identity() { "preserved" } else { "LOST" });
    println!("  sealed data  {}", if action.preserves_sealed_data() { "preserved" } else { "LOST" });
    println!("  afterwards   {}", action.follow_up());

    if let Some(next) = fault.escalation() {
        println!("\nif that fails  {next}");
        println!("  identity     {}", if next.preserves_node_identity() { "preserved" } else { "LOST" });
        println!("  sealed data  {}", if next.preserves_sealed_data() { "preserved" } else { "LOST" });
        println!("  afterwards   {}", next.follow_up());
    }

    println!(
        "\nNone of these can be done from software. Recovery runs through firmware\n\
         setup, so the only party who can restore this machine's root of trust is\n\
         someone physically at it holding the firmware password."
    );

    // Assurance is capped by who can reset the chip, so the policy is worth
    // stating even when it cannot be probed.
    let policy = RecoveryPolicy { firmware_password_set: true, physically_secured: true };
    if let Some(advice) = policy.advice() {
        println!("\nwarning        {advice}");
    }
    let _ = RecoveryAction::PowerCycle.software_invokable();
    Ok(())
}

/// Exercise the TPM client against a software TPM.
///
/// The native backend is the code that faulted a physical chip by leaking
/// transient object handles. Re-running it on real silicon to prove the fix
/// would risk the same outage, so it is exercised here against libtpms
/// instead: a real TPM 2.0 implementation whose object slots and failure modes
/// behave as they do in hardware, but which is discarded rather than needing a
/// power cycle.
fn selftest_tpm() -> Result<()> {
    use furcate_machine::proving::{Sandbox, Swtpm};

    const PORT: u16 = 2321;
    const ROUNDS: u32 = 12;

    let sandbox = Sandbox::new("/tmp/furcate-selftest-tpm")?;
    sandbox.reset()?;
    let _swtpm = Swtpm::start_tcp(&sandbox, PORT)?;
    Swtpm::wait_tcp(PORT, 60)?;
    println!("software TPM   listening on 127.0.0.1:{PORT}");

    let tcti = format!("swtpm:host=127.0.0.1,port={PORT}");

    // Count transient objects left loaded in the chip. A backend that leaks
    // handles shows up here as a number that climbs.
    let loaded = || -> usize {
        std::process::Command::new("tpm2_getcap")
            .arg("handles-transient")
            .env("TPM2TOOLS_TCTI", &tcti)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().filter(|l| l.contains("0x")).count())
            .unwrap_or(0)
    };

    println!("handles before {}", loaded());

    #[cfg(feature = "tss")]
    {
        use furcate_identity::backends::TssNative;
        let mut ok = 0u32;
        for i in 0..ROUNDS {
            match TssNative::with_device(&tcti) {
                Ok(rot) => {
                    rot.quote(&i.to_be_bytes())?;
                    ok += 1;
                }
                Err(e) => println!("  round {i}: {e}"),
            }
        }
        println!("rounds ok      {ok}/{ROUNDS}");
    }
    #[cfg(not(feature = "tss"))]
    println!("rounds ok      skipped — build with --features tss");

    let after = loaded();
    println!("handles after  {after}");
    if after > 2 {
        anyhow::bail!(
            "{after} transient handles left loaded after {ROUNDS} rounds — the backend is \
             leaking object slots, which is what exhausts a TPM and faults it"
        );
    }
    println!("result         no handle leak across {ROUNDS} rounds");
    Ok(())
}

/// Check that a predicted register value matches what a real TPM produces.
///
/// Reference values are only useful if they can be computed before a machine
/// boots. This extends a software TPM with the section digests of a unified
/// kernel image and compares the result against the prediction.
///
/// What this establishes is that the extend arithmetic is right — that
/// `H(PCR ‖ digest)` chained over sections in canonical order lands where the
/// model says. What it does *not* establish is that the section-digest
/// convention matches what systemd-stub actually measures; confirming that
/// needs a real UKI boot, and until then a derived reference value should be
/// treated as a prediction of this model rather than of the boot loader.
/// Check that every Furcate unit can actually start what it names.
///
/// Both production failures of 2026-09-07 were this, in the two forms it takes:
///
///   furcate-exec-guard      ExecStart=/usr/libexec/furcate/exec-guard, and that
///                           file has never existed in any image. A unit was
///                           written for software that was never built, and it
///                           failed 2483 times before systemd gave up on it.
///   furcate-app-*           ExecStart=.../node/bin/npm, present but mode 644
///                           through a symlink, so exec returned 203/EXEC and
///                           no site could be deployed at all.
///
/// One is absent and one is not executable, and neither is visible from
/// `systemctl is-active` — a unit that has been running since before the defect
/// keeps running, and a oneshot that already failed is quietly `disabled`. The
/// question "can this unit start?" is only ever answered by trying, or by this.
///
/// Resolution comes from `systemctl show` rather than from reading unit files,
/// because a drop-in can replace `ExecStart` entirely and reading the fragment
/// would check a command the machine will never run. That is not hypothetical:
/// the workaround deployed for the npm defect was exactly such a drop-in.
fn selftest_units() -> Result<()> {
    use std::process::Command;

    let list = Command::new("systemctl")
        .args([
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--no-pager",
            "furcate-*",
        ])
        .output()
        .context("systemctl list-unit-files failed; is this a systemd host?")?;
    let names: Vec<String> = String::from_utf8_lossy(&list.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| n.ends_with(".service"))
        .map(|n| n.to_string())
        .collect();

    if names.is_empty() {
        println!("no furcate units on this host");
        return Ok(());
    }

    // One call for every unit. `systemctl show` emits a block per unit in the
    // order asked, separated by a blank line.
    let mut cmd = Command::new("systemctl");
    cmd.args(["show", "--property=Id", "--property=ExecStart", "--no-pager"]);
    for n in &names {
        cmd.arg(n);
    }
    let shown = cmd.output().context("systemctl show failed")?;
    let text = String::from_utf8_lossy(&shown.stdout);

    let mut id = String::new();
    let mut checked = 0usize;
    let mut problems: Vec<String> = Vec::new();

    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Id=") {
            id = v.to_string();
            continue;
        }
        let Some(v) = line.strip_prefix("ExecStart=") else {
            continue;
        };
        // `ExecStart={ path=/usr/bin/foo ; argv[]=... }`, and a unit may have
        // several. An empty value is a drop-in clearing the list before
        // setting its own, which is not a command and is skipped.
        // The value is `{ path=/usr/bin/foo ; argv[]=... }`, so the opening
        // brace has to come off before the field name is visible. Leaving it
        // on is not a parse error — every field simply fails to match, the
        // check reports zero paths across ninety-two units and calls the host
        // healthy. It did exactly that the first time it was run.
        let Some(path) = v
            .split(';')
            .find_map(|f| f.trim().trim_start_matches('{').trim().strip_prefix("path="))
            .map(|p| p.trim().to_string())
        else {
            continue;
        };
        checked += 1;

        let meta = std::fs::metadata(&path);
        match meta {
            Err(_) => problems.push(format!(
                "{id}\n    names {path}\n    which does not exist. A unit for software that was \
                 never built, or a package that did not ship it."
            )),
            Ok(m) => {
                // A symlink is followed by `metadata`, which is what execve
                // does too — the npm defect was a correct symlink to a target
                // that had lost its execute bit.
                let mode = {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        m.permissions().mode()
                    }
                    #[cfg(not(unix))]
                    {
                        0o755
                    }
                };
                if m.is_dir() {
                    problems.push(format!("{id}\n    names {path}\n    which is a directory."));
                } else if mode & 0o111 == 0 {
                    problems.push(format!(
                        "{id}\n    names {path}\n    which exists and is not executable (mode \
                         {:o}). exec fails with 203/EXEC and the unit never starts.",
                        mode & 0o7777
                    ));
                }
            }
        }
    }

    println!("checked {checked} ExecStart path(s) across {} unit(s)", names.len());
    if problems.is_empty() {
        println!("every unit can start what it names");
        return Ok(());
    }
    println!();
    for p in &problems {
        println!("  {p}\n");
    }
    bail!(
        "{} unit(s) cannot start what they name.\n\
         Neither form shows up in `systemctl is-active`: a unit already running keeps \n\
         running, and a oneshot that failed sits disabled.",
        problems.len()
    )
}

fn selftest_pcr() -> Result<()> {
    use furcate_machine::proving::{Sandbox, Swtpm};
    use furcate_machine::reference::{expected_pcr11_hex, UkiSections, SECTION_ORDER};
    use sha2::{Digest, Sha256};

    const PORT: u16 = 2323;

    let sections = UkiSections::new()
        .with(".linux", b"kernel-bytes".to_vec())
        .with(".osrel", b"ID=ubuntu".to_vec())
        .with(".cmdline", b"root=/dev/nvme0n1p2 ro quiet".to_vec())
        .with(".initrd", b"initrd-bytes".to_vec());

    let predicted = expected_pcr11_hex(&sections);
    println!("predicted      {predicted}");

    let sandbox = Sandbox::new("/tmp/furcate-selftest-pcr")?;
    sandbox.reset()?;
    let _swtpm = Swtpm::start_tcp(&sandbox, PORT)?;
    Swtpm::wait_tcp(PORT, 60)?;
    let tcti = format!("swtpm:host=127.0.0.1,port={PORT}");

    // Extend the same section digests, in the same canonical order, into a
    // register that starts at zero.
    let contents: Vec<(&str, Vec<u8>)> = vec![
        (".linux", b"kernel-bytes".to_vec()),
        (".osrel", b"ID=ubuntu".to_vec()),
        (".cmdline", b"root=/dev/nvme0n1p2 ro quiet".to_vec()),
        (".initrd", b"initrd-bytes".to_vec()),
    ];
    let mut extended = 0;
    for name in SECTION_ORDER {
        let Some((_, content)) = contents.iter().find(|(n, _)| n == name) else {
            continue;
        };
        let digest = hex::encode(Sha256::digest(content));
        let out = std::process::Command::new("tpm2_pcrextend")
            .arg(format!("11:sha256={digest}"))
            .env("TPM2TOOLS_TCTI", &tcti)
            .output()
            .context("running tpm2_pcrextend")?;
        if !out.status.success() {
            anyhow::bail!(
                "extending PCR 11 with {name} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        extended += 1;
    }
    println!("extended       {extended} sections in canonical order");

    let out = std::process::Command::new("tpm2_pcrread")
        .arg("sha256:11")
        .env("TPM2TOOLS_TCTI", &tcti)
        .output()
        .context("reading PCR 11")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let actual = text
        .lines()
        .find_map(|l| l.split_once(':').and_then(|(i, v)| {
            (i.trim() == "11").then(|| v.trim().trim_start_matches("0x").to_lowercase())
        }))
        .ok_or_else(|| anyhow::anyhow!("could not parse PCR 11 from tpm2_pcrread"))?;
    println!("actual         {actual}");

    if actual == predicted {
        println!("result         prediction matches a real TPM");
        println!(
            "\nnote: this confirms the extend arithmetic, not that the section-digest\n\
             convention matches systemd-stub. That needs a real UKI boot."
        );
        Ok(())
    } else {
        anyhow::bail!("prediction does not match: the reference-value model is wrong")
    }
}

/// Generate the operator key pair that arms the kill switch.
///
/// The private half is the only thing in the system that can stop a machine,
/// so it is written with restrictive permissions and should not stay on a
/// cluster node. The site controller needs only the public half.
fn operator_init(dir: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let dir = std::path::Path::new(dir);
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let priv_path = dir.join("operator.key");
    let pub_path = dir.join("operator.pub");

    if priv_path.exists() {
        bail!(
            "{} already exists; refusing to overwrite an operator key — \
             doing so would orphan every machine it currently governs",
            priv_path.display()
        );
    }

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| anyhow::anyhow!("drawing key material from the system: {e}"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&priv_path)
        .with_context(|| format!("creating {}", priv_path.display()))?;
    f.write_all(hex::encode(signing.to_bytes()).as_bytes())?;
    f.write_all(b"\n")?;

    std::fs::write(&pub_path, format!("{}\n", hex::encode(verifying.to_bytes())))?;

    println!("private key    {}  (mode 0600)", priv_path.display());
    println!("public key     {}", pub_path.display());
    println!("fingerprint    {}", &hex::encode(verifying.to_bytes())[..16]);
    println!(
        "\nInstall the public key on the site controller to arm the kill switch.\n\
         Move the private key off this machine: it is the only thing that can stop\n\
         a node, and a copy sitting on the cluster it governs is not a safeguard."
    );
    Ok(())
}

/// Sign a kill order with the operator key.
///
/// Signing is separate from submitting on purpose. The order is printed rather
/// than sent, so an operator can read exactly what they are authorizing before
/// it reaches a controller — and so the private key never has to live on the
/// machine that serves the API.
/// Seal an arbitrary file to this machine's TPM.
///
/// A TPM seals secrets, not files: a sealed data object is capped at a few
/// hundred bytes. So the payload is encrypted under a freshly generated data
/// key and only that key is sealed to the chip. The ciphertext is inert
/// without the chip, so it can sit anywhere.
///
/// The plaintext is destroyed only after the sealed copy has been read back
/// and compared. Sealing something and deleting the original without checking
/// you can recover it is how data is lost for good.
fn seal_file(input: &str, out_dir: &str) -> Result<()> {
    use furcate_identity::Sealer;
    use furcate_vault::envelope;
    use std::io::Write as _;

    let data = std::fs::read(input).with_context(|| format!("reading {input}"))?;
    if data.is_empty() {
        bail!("{input} is empty; nothing to seal");
    }

    let mut dek = [0u8; envelope::DATA_KEY_LEN];
    let mut nonce = [0u8; envelope::NONCE_LEN];
    getrandom::fill(&mut dek).map_err(|e| anyhow::anyhow!("drawing a data key: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("drawing a nonce: {e}"))?;

    // Sealing makes this machine a holder of the data, so it must be one under
    // the site's custody settings; the envelope records the mode and class of
    // the grant it holds.
    let custody = placement_grant()?.record();

    let sealed_payload = envelope::seal(&data, &dek, &nonce, input, &custody)
        .map_err(|e| anyhow::anyhow!("encrypting the payload: {e}"))?;

    let out = std::path::Path::new(out_dir);
    std::fs::create_dir_all(out)?;
    let sealer = Sealer::open().context("opening the TPM to seal the data key")?;
    sealer.seal(&hex::encode(dek).into_bytes(), out)?;
    std::fs::write(
        out.join("payload.json"),
        serde_json::to_vec_pretty(&sealed_payload)?,
    )?;

    // Verify the whole path before destroying the only other copy.
    let recovered_key = sealer.unseal(out).context("verifying the data key reads back")?;
    let key_bytes: [u8; envelope::DATA_KEY_LEN] = hex::decode(String::from_utf8_lossy(&recovered_key).trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("the sealed data key did not read back as a key"))?;
    let recovered = envelope::open(&sealed_payload, &key_bytes)
        .map_err(|e| anyhow::anyhow!("verifying the payload decrypts: {e}"))?;
    if recovered != data {
        bail!("the sealed copy did not read back identically; plaintext left in place");
    }

    // Overwrite before unlinking: removing a file leaves its blocks readable.
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(input) {
        let _ = f.write_all(&vec![0u8; data.len()]);
        let _ = f.sync_all();
    }
    std::fs::remove_file(input).with_context(|| format!("removing {input}"))?;

    println!("sealed         {} bytes to {}", data.len(), out.display());
    println!("verified       decrypted back identically before removing the plaintext");
    println!("plaintext      overwritten and removed from {input}");
    Ok(())
}

/// The grant to place new material on this machine: the strict election
/// unless the site's custody settings say otherwise.
fn placement_grant() -> Result<furcate_identity::custody::CustodyGrant> {
    let (node_id, class) = keycustody::this_machine()?;
    keycustody::grant_for(&keycustody::Paths::standard(), &furcate_siteview::site_name(), &node_id, class)
}

/// The grant to open material already sealed to this machine, asked before
/// the TPM is. Returns what authorised the settings it was judged under.
fn unseal_grant() -> Result<(furcate_identity::custody::CustodyGrant, &'static str)> {
    let (node_id, class) = keycustody::this_machine()?;
    keycustody::unseal_grant_for(&keycustody::Paths::standard(), &furcate_siteview::site_name(), &node_id, class)
}

/// The custody an opened envelope records beside the grant it was opened
/// under. An envelope sealed before custody was recorded says so.
fn custody_on_read(
    sealed: &furcate_vault::Envelope,
    grant: &furcate_identity::custody::CustodyGrant,
    settings_from: &str,
) -> String {
    let opened = format!(
        "opened under {} custody at class `{}` (settings from {settings_from})",
        grant.mode(),
        grant.class()
    );
    match sealed.custody_stated() {
        Ok(rec) => format!("sealed under {} custody at class `{}`; {opened}", rec.mode, rec.class),
        Err(why) => format!("{why}; {opened}"),
    }
}

/// Recover a sealed file.
fn unseal_file(dir: &str, output: &str) -> Result<()> {
    use furcate_identity::Sealer;
    use furcate_vault::envelope;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    if std::path::Path::new(output).exists() {
        bail!("{output} already exists; refusing to overwrite");
    }
    let dir = std::path::Path::new(dir);
    let (grant, settings_from) = unseal_grant()?;
    let sealer = Sealer::open().context("opening the TPM to unseal")?;
    let key_hex = sealer.unseal(dir)?;
    let key: [u8; envelope::DATA_KEY_LEN] = hex::decode(String::from_utf8_lossy(&key_hex).trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("the sealed data key is malformed"))?;

    let raw = std::fs::read(dir.join("payload.json"))
        .with_context(|| format!("reading {}/payload.json", dir.display()))?;
    let sealed_payload: furcate_vault::Envelope = serde_json::from_slice(&raw)?;
    let data = envelope::open(&sealed_payload, &key)
        .map_err(|e| anyhow::anyhow!("decrypting the payload: {e}"))?;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .with_context(|| format!("creating {output}"))?;
    f.write_all(&data)?;
    println!("recovered      {} bytes to {output} (mode 0600)", data.len());
    println!("custody        {}", custody_on_read(&sealed_payload, &grant, settings_from));
    Ok(())
}

/// Seal the operator key to this machine's TPM and destroy the plaintext.
///
/// After this the key exists only as ciphertext bound to this chip and this
/// boot state. It cannot be copied to another machine, and a stolen disk is
/// inert.
///
/// It must not be sealed on the site controller. The controller is what
/// validates kill orders, so a controller able to unseal the operator key
/// could authorize itself — which is the one thing the design exists to
/// prevent.
fn operator_seal(key_path: &str, out_dir: &str) -> Result<()> {
    use std::io::Write as _;

    let raw = std::fs::read_to_string(key_path)
        .with_context(|| format!("reading {key_path}"))?;
    let hexkey = raw.trim();
    if hex::decode(hexkey).ok().filter(|b| b.len() == 32).is_none() {
        bail!("{key_path} is not a 32-byte hex operator key");
    }

    // Sealing the operator key makes this machine its holder, so it must be
    // one under the site's custody settings; the envelope records the mode and
    // class of the grant it holds.
    let custody = placement_grant()?.record();
    let sealer = furcate_identity::Sealer::open().context("opening the TPM to seal")?;
    let out = std::path::Path::new(out_dir);
    let public = seal_operator_dir(&sealer, hexkey.as_bytes(), &custody, out)?;
    let fingerprint = hex::encode(public.to_bytes());

    // Overwrite before unlinking. Removing a file leaves its blocks readable.
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(key_path) {
        let _ = f.write_all(&vec![0u8; raw.len().max(64)]);
        let _ = f.sync_all();
    }
    std::fs::remove_file(key_path).with_context(|| format!("removing {key_path}"))?;

    println!("sealed to      {}", out.display());
    println!("public key     {}", &fingerprint[..16]);
    println!("custody        sealed under {} custody at class `{}`", custody.mode, custody.class);
    println!("verified       read back through the TPM data key and payload.json before removing the plaintext");
    println!("plaintext      overwritten and removed from {key_path}");
    println!(
        "\nThe key is now bound to this chip and this boot state. It will not\n\
         unseal on another machine, and it will not unseal here if the firmware\n\
         or secure-boot configuration changes — in which case generate a new\n\
         operator key and install its public half on the controller."
    );
    Ok(())
}

/// The context an operator key's envelope is sealed under, naming what it
/// holds. Bound into the authenticated data, so it cannot be edited.
const OPERATOR_KEY_CONTEXT: &str = "furcate:operator-key";

/// The two calls an operator key directory needs from the chip.
///
/// The TPM is the only implementation outside tests; the seam exists so the
/// whole seal and read-back path can be exercised where there is no chip.
trait SealBackend {
    fn seal(&self, secret: &[u8], out_dir: &std::path::Path) -> Result<()>;
    fn unseal(&self, sealed_dir: &std::path::Path) -> Result<Vec<u8>>;
}

impl SealBackend for furcate_identity::Sealer {
    fn seal(&self, secret: &[u8], out_dir: &std::path::Path) -> Result<()> {
        furcate_identity::Sealer::seal(self, secret, out_dir)
    }
    fn unseal(&self, sealed_dir: &std::path::Path) -> Result<Vec<u8>> {
        furcate_identity::Sealer::unseal(self, sealed_dir)
    }
}

/// Write an operator key directory in the layout every reader expects: a data
/// key sealed to the chip (`seal.priv`, `seal.pub`) and the operator key only
/// as ciphertext under that data key (`payload.json`).
///
/// The directory is read back through `open_operator_dir`, the same two steps
/// the signing path takes, before this reports success. If anything fails the
/// files written here are removed, so a half-sealed directory is never left
/// looking like a usable one. Returns the public half of the sealed key.
fn seal_operator_dir(
    sealer: &impl SealBackend,
    key_hex: &[u8],
    custody: &furcate_identity::custody::CustodyRecord,
    out: &std::path::Path,
) -> Result<ed25519_dalek::VerifyingKey> {
    use furcate_vault::envelope;

    let expected = signing_key_from_hex(&String::from_utf8_lossy(key_hex))?.verifying_key();
    for name in ["payload.json", "seal.priv", "seal.pub"] {
        if out.join(name).exists() {
            bail!(
                "{} already holds {name}; refusing to overwrite a sealed key that may be the only copy",
                out.display()
            );
        }
    }

    let mut dek = [0u8; envelope::DATA_KEY_LEN];
    let mut nonce = [0u8; envelope::NONCE_LEN];
    getrandom::fill(&mut dek).map_err(|e| anyhow::anyhow!("drawing a data key: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("drawing a nonce: {e}"))?;
    let sealed = envelope::seal(key_hex, &dek, &nonce, OPERATOR_KEY_CONTEXT, custody)
        .map_err(|e| anyhow::anyhow!("encrypting the operator key: {e}"));

    let created = !out.exists();
    let attempt = sealed.and_then(|sealed| -> Result<()> {
        std::fs::create_dir_all(out)?;
        sealer
            .seal(hex::encode(dek).as_bytes(), out)
            .context("sealing the data key to the TPM")?;
        std::fs::write(out.join("payload.json"), serde_json::to_vec_pretty(&sealed)?)
            .context("writing payload.json")?;

        // Prove it round-trips before the caller destroys the only other
        // copy, through the reader the signing path uses rather than a
        // second opinion about the layout.
        let (_, recovered) = open_operator_dir(sealer, out)
            .context("verifying the sealed key reads back")?;
        if signing_key_from_hex(&recovered)?.verifying_key() != expected {
            bail!("the sealed key did not read back as the same key");
        }
        Ok(())
    });
    dek.fill(0);

    if let Err(e) = attempt {
        for name in ["payload.json", "seal.priv", "seal.pub"] {
            let _ = std::fs::remove_file(out.join(name));
        }
        if created {
            let _ = std::fs::remove_dir(out);
        }
        return Err(e.context(format!(
            "nothing sealed: the partial output in {} was removed and the plaintext left in place",
            out.display()
        )));
    }
    Ok(expected)
}

/// Parse a hex operator key.
fn signing_key_from_hex(raw: &str) -> Result<ed25519_dalek::SigningKey> {
    let bytes: [u8; 32] = hex::decode(raw.trim())
        .context("the operator key is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("an operator key is 32 bytes"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

/// Read the operator's signing key, sealed or plain.
///
/// The same two forms the kill switch accepts, and the same reasoning: a
/// sealed directory is the expected shape, and a plaintext file is allowed so a
/// key can be used before it has been sealed. Written once because two readers
/// of one key file drift, and the one that drifts is the one used less.
/// Commit a service mutation to this node's chain.
///
/// Provisioning a tenant database, a cache or a mail identity is an action on
/// the machine, and it belongs in the same record as power transitions and key
/// use rather than in a private file beside the service that performed it.
///
/// The route is guarded and fixes the kind to `Provision`, so this cannot be
/// used to write an entry that looks like attestation. `key` is any signing key
/// the node recognises — its own machine key is the honest one for a local
/// service; the operator key works too but arms far more than this needs.
/// Ask the site for a short-lived SSH certificate.
///
/// The signing key is sealed to the controller's TPM, so this is the only way
/// to obtain one from anywhere else: the request is signed with a credential
/// this site recognises, the controller checks policy, and the certificate
/// comes back. The private half of the CA never moves.
///
/// `pubkey` is the path to a .pub file — the public half only. Nothing secret
/// leaves the caller.
fn ssh_cert(key: &str, user: &str, host: &str, pubkey: &str, ttl: &str) -> Result<()> {
    let pub_path = if pubkey.ends_with(".pub") {
        pubkey.to_string()
    } else {
        format!("{pubkey}.pub")
    };
    let material = std::fs::read_to_string(&pub_path)
        .with_context(|| format!("reading the public key at {pub_path}"))?;

    let addr = std::env::var("FURCATE_NODE")
        .or_else(|_| std::env::var("FURCATE_LISTEN"))
        .unwrap_or_else(|_| "127.0.0.1:7616".into());
    let body = serde_json::json!({
        "user": user,
        "host": host,
        "ttl": ttl,
        "public_key": material.trim(),
    });
    let out = signed_post(key, &addr, "/ssh/cert", &body)?;
    let cert = out
        .get("certificate")
        .and_then(|v| v.as_str())
        .context("the site returned no certificate")?;

    let dest = pub_path.trim_end_matches(".pub").to_string() + "-cert.pub";
    std::fs::write(&dest, format!("{cert}\n"))
        .with_context(|| format!("writing {dest}"))?;
    println!("certificate written to {dest}");
    if let Some(d) = out.get("detail").and_then(|v| v.as_str()) {
        println!("{d}");
    }
    Ok(())
}

fn ledger_record(key: &str, actor: &str, subject: &str, result: &str) -> Result<()> {
    let addr = std::env::var("FURCATE_NODE")
        .or_else(|_| std::env::var("FURCATE_LISTEN"))
        .unwrap_or_else(|_| "127.0.0.1:7616".into());
    let body = serde_json::json!({
        "actor": actor,
        "subject": subject,
        "result": result,
    });
    let out = signed_post(key, &addr, "/ledger", &body)?;
    println!("{}", serde_json::to_string_pretty(&out).expect("a response serialises"));
    Ok(())
}


/// Recover the operator key from a sealed directory.
///
/// The same two steps `unseal_file` performs, factored out so the signing path
/// and the export path cannot disagree about what "sealed" means — they did,
/// and the disagreement was invisible because both produced a usable key.
fn unseal_operator_dir(dir: &std::path::Path) -> Result<String> {
    // The operator key is custody material: this machine opens it only if
    // the site's custody settings say it holds what is sealed here.
    let (grant, settings_from) = unseal_grant()?;
    let sealer = furcate_identity::Sealer::open().context("opening the TPM to unseal")?;
    let (sealed, key) = open_operator_dir(&sealer, dir)?;
    eprintln!("custody: operator key {}", custody_on_read(&sealed, &grant, settings_from));
    Ok(key)
}

/// Both steps of reading an operator key directory: the chip gives back the
/// data key, and the data key opens payload.json, which holds the key.
fn open_operator_dir(
    sealer: &impl SealBackend,
    dir: &std::path::Path,
) -> Result<(furcate_vault::Envelope, String)> {
    use furcate_vault::envelope;

    // Checked before the chip is asked, so the refusal names what is wrong
    // with the directory rather than surfacing as a decryption failure.
    let payload = dir.join("payload.json");
    if !payload.exists() {
        bail!(
            "{} has no payload.json, so it does not hold an operator key: the chip holds only \
             the data key, and the key itself is the ciphertext in payload.json. A directory \
             written by an `operator seal` that predates payload.json cannot be opened; seal \
             the operator key again",
            dir.display()
        );
    }
    let key_hex = sealer.unseal(dir)?;
    let key: [u8; envelope::DATA_KEY_LEN] = hex::decode(String::from_utf8_lossy(&key_hex).trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("the sealed data key is malformed"))?;

    let raw = std::fs::read(&payload)
        .with_context(|| format!("reading {}", payload.display()))?;
    let sealed: furcate_vault::Envelope = serde_json::from_slice(&raw)?;
    let data = envelope::open(&sealed, &key)
        .map_err(|e| anyhow::anyhow!("decrypting the sealed operator key: {e}"))?;
    let text = String::from_utf8(data).context("the sealed operator key is not valid text")?;
    Ok((sealed, text))
}

/// Load the operator signing key.
///
/// A sealed directory is the expected form; a plaintext file is accepted so a
/// key can be signed with before it has been sealed. Shared by every command
/// that speaks with the operator's own authority, so there is one answer to
/// "where does this key come from" rather than one per command — `operator
/// kill` carried its own copy of this until `operator breakglass` needed the
/// same thing and found it already here.
fn operator_signing_key(key_path: &str) -> Result<ed25519_dalek::SigningKey> {
    let raw = if std::path::Path::new(key_path).is_dir() {
        // A sealed directory is TWO steps, not one.
        //
        // `Sealer::unseal` recovers the DATA KEY the TPM holds; the operator
        // key itself is the ciphertext in payload.json, which that data key
        // opens. Treating the first as the second produced a perfectly valid
        // ed25519 key that simply was not the operator's — so every signed
        // call was refused with "that signature is not from a key this site
        // admits", which reads as a wrong or missing key rather than a key
        // that was never decrypted. The same material passed as a plaintext
        // file worked, which is what made it look like a TPM fault.
        //
        // `unseal_file` has always done both steps. This did one.
        unseal_operator_dir(std::path::Path::new(key_path))?
    } else {
        std::fs::read_to_string(key_path)
            .with_context(|| format!("reading the operator key at {key_path}"))?
    };
    signing_key_from_hex(&raw)
}

/// One step of adding a domain.
///
/// Each step is its own command rather than one that does everything, because
/// the middle of this is a person creating DNS records somewhere else. A
/// command that tried to run the whole sequence would spend most of its life
/// waiting on something outside the machine, and would have to guess when to
/// give up.
fn domain_step(key: &str, path: &str, name: &str, site: Option<&str>) -> Result<()> {
    let addr = std::env::var("FURCATE_NODE")
        .or_else(|_| std::env::var("FURCATE_LISTEN"))
        .unwrap_or_else(|_| "127.0.0.1:7616".into());
    let mut body = serde_json::json!({ "name": name });
    if let Some(s) = site {
        body["site"] = serde_json::json!(s);
    }
    // Signed, like every other change. Adding a domain decides what this
    // machine will request a certificate for, which is a claim about a name
    // somebody else may own.
    let reply = signed_post(key, &addr, path, &body)?;
    println!("{}", serde_json::to_string_pretty(&reply)?);
    Ok(())
}

/// The passthrough map that gets traffic to the machines serving each name.
///
/// A gateway in front of a cluster forwards by the server name the client
/// already sends in the clear, which is what lets it route without holding a
/// key for anything. That map has been maintained by hand; this prints it from
/// what the machines actually serve, so the thing forwarding traffic and the
/// thing serving it cannot drift apart.
///
/// Printed rather than pushed. The gateway is rented and untrusted, and a tool
/// that could reconfigure it from here would make it a thing Furcate depends on
/// being honest.
fn routing_map() -> Result<()> {
    let site = std::env::var("FURCATE_SITE")
        .or_else(|_| std::env::var("FURCATE_SITE_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1:7617".into());
    let nodes = furcate_api::get_json(&site, "/nodes", 5_000)
        .with_context(|| format!("asking {site} which machines are in this site"))?;

    println!("# Generated by `furcatectl routing`. Each line is a name and the");
    println!("# machine that serves it. Anything absent falls to the default.");
    let mut lines = 0usize;
    for n in nodes.get("topology").and_then(|t| t.as_array()).cloned().unwrap_or_default() {
        let Some(id) = n.get("node_id").and_then(|v| v.as_str()) else { continue };
        // Asked of each node rather than assumed from the site's view: what a
        // machine serves is a fact about that machine.
        let addr = n.get("reporting_as").and_then(|v| v.as_str()).unwrap_or_default();
        if addr.is_empty() {
            continue;
        }
        let Ok(published) = furcate_api::get_json(addr, "/published", 4_000) else { continue };
        for site in published.get("placed").and_then(|p| p.as_array()).cloned().unwrap_or_default() {
            for d in site.get("domains").and_then(|d| d.as_array()).cloned().unwrap_or_default() {
                if let Some(name) = d.as_str() {
                    println!("{name} node_{}", id.rsplit(':').next().unwrap_or(id));
                    lines += 1;
                }
            }
        }
    }
    if lines == 0 {
        eprintln!("no machine in this site reports serving a name");
    }
    Ok(())
}

/// Read one thing from the site controller and print it.
///
/// Separate from `node_report` because the two answer different questions: the
/// node knows about this machine, the site knows about the machines in it. A
/// single reader pointed at whichever address happened to be set would answer
/// confidently from the wrong one.
fn site_report(path: &str, what: &str) -> Result<()> {
    let addr = std::env::var("FURCATE_SITE")
        .or_else(|_| std::env::var("FURCATE_SITE_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1:7617".into());
    let v = furcate_api::get_json(&addr, path, 5_000)
        .with_context(|| format!("asking {addr} for {what}"))?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

/// Read one thing from the node agent and print it.
///
/// Four arms of this system had a view and no verb, which meant an operator
/// could see them on a console and not in a script. They are all the same
/// operation — ask the local agent, print what it said — so they are one
/// function rather than four that drift.
///
/// Deliberately unsigned: these are reads of the machine the operator is
/// standing at. A signature would imply an authority decision that is not being
/// made here, and `call` already exists for the ones that are.
fn node_report(path: &str, what: &str) -> Result<()> {
    let addr = std::env::var("FURCATE_NODE")
        .or_else(|_| std::env::var("FURCATE_LISTEN"))
        .unwrap_or_else(|_| "127.0.0.1:7616".into());
    let v = furcate_api::get_json(&addr, path, 5_000)
        .with_context(|| format!("asking {addr} for {what}"))?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}


/// Sign and send an arbitrary request.
///
/// The escape hatch, and deliberately a plain one. Eleven routes were guarded
/// and one had a client, which made every administrative operation unreachable
/// — the guard was correct and the result was a system nobody could run. Rather
/// than eleven half-considered subcommands, this signs whatever an operator
/// hands it, and the operations worth naming get named separately.
///
/// With no body it is a GET: guarded reads, such as `/cells/standing`, need
/// the same signature a write does.
fn call_signed(key_path: &str, addr: &str, path: &str, body: Option<&str>) -> Result<()> {
    let reply = match body {
        Some(body) => {
            let body: serde_json::Value =
                serde_json::from_str(body).context("the body must be JSON")?;
            signed_post(key_path, addr, path, &body)?
        }
        None => signed_get(key_path, addr, path)?,
    };
    println!("{}", serde_json::to_string_pretty(&reply)?);
    Ok(())
}

/// POST as the operator, and hand back whatever came out.
///
/// One place, because every command below is the same three lines and a signer
/// built slightly differently in each would be a signature that fails for
/// reasons nobody can see.
pub fn signed_post(
    key_path: &str,
    addr: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value> {
    let signer = furcate_authn::local::Signer::new(operator_signing_key(key_path)?);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let sign = |m: &str, p: &str, b: &[u8]| signer.credential(m, p, b, now);
    furcate_api::post_signed(addr, path, body, 5_000, Some(&sign))
        .with_context(|| format!("calling {path} on {addr}"))
}

/// GET as the operator: the read half of `signed_post`, with the same key path.
pub(crate) fn signed_get(key_path: &str, addr: &str, path: &str) -> Result<serde_json::Value> {
    let signer = furcate_authn::local::Signer::new(operator_signing_key(key_path)?);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let sign = |m: &str, p: &str, b: &[u8]| signer.credential(m, p, b, now);
    furcate_api::get_signed(addr, path, 5_000, Some(&sign))
        .with_context(|| format!("reading {path} on {addr}"))
}

/// Why a reply was refused, if it was.
///
/// `report` does this for callers that only need "it worked"; this is for the
/// ones that read fields out of a successful reply and would otherwise treat a
/// refusal as a success with everything missing.
fn refusal(reply: &serde_json::Value) -> Option<String> {
    let ok = reply.get("ok").and_then(|v| v.as_bool());
    if ok == Some(false) || reply.get("error").is_some() {
        return Some(
            reply
                .get("because")
                .or_else(|| reply.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("no reason given")
                .to_string(),
        );
    }
    None
}

/// Report a reply in the machine's own words, or fail with them.
fn report(reply: serde_json::Value, done: &str) -> Result<()> {
    let ok = reply.get("ok").and_then(|v| v.as_bool());
    if ok == Some(false) || reply.get("error").is_some() {
        let why = reply
            .get("because")
            .or_else(|| reply.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("no reason given");
        bail!("refused: {why}");
    }
    println!("{done}");
    Ok(())
}

/// Admit a machine to this site.
///
/// The operation that lets a new node take part at all: a report is a guarded
/// route now, and a machine that has not been admitted cannot make one. That is
/// the right posture — a site should not fold a stranger's head into its root
/// because nobody had got round to saying no — but it means this command is the
/// difference between a node that joins and a node that sits there refused.
/// Name which machine administers a site.
///
/// The appointment carries its own signature, separate from the one that
/// authenticates this call: the transport proves who is asking now, the
/// signature travels with the statement so any node can check it later without
/// trusting whoever relayed it.
///
/// `epoch` and `predecessor` are read from the site rather than guessed. An
/// appointment that does not continue the one in force is refused, which is
/// what stops an old one being replayed to move the role backwards — so the
/// current state has to be fetched, not assumed.
fn site_appoint(key_path: &str, addr: &str, node: &str, hours: &str, reason: &str) -> Result<()> {
    use ed25519_dalek::Signer;

    let hours: u64 = hours.parse().context("hours must be a number")?;
    if hours == 0 {
        bail!("an appointment needs a duration; a role that expires on arrival appoints nobody");
    }
    if reason.trim().is_empty() {
        bail!("give a reason — a role change nobody can explain is one nobody dares undo");
    }

    // What the site currently holds, so the new appointment continues it.
    let current = furcate_api::get_json(addr, "/administrator", 5_000)
        .with_context(|| format!("asking {addr} who administers the site"))?;
    let site_name = current
        .get("site")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default();
    let (epoch, predecessor) = match current.get("appointment") {
        Some(a) if !a.is_null() => (
            a.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0) + 1,
            a.get("digest").and_then(|v| v.as_str()).map(String::from),
        ),
        _ => (1, None),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut appointment = furcate_mesh::administration::Appointment {
        site: site_name,
        node_id: node.to_string(),
        epoch,
        // Back-dated slightly: the signer's clock being marginally ahead of a
        // verifier's is ordinary, and an appointment that is not yet valid is
        // refused exactly like a forged one.
        not_before: now.saturating_sub(300),
        not_after: now + hours * 3600,
        predecessor,
        reason: reason.to_string(),
        signature: String::new(),
    };
    let signing = operator_signing_key(key_path)?;
    appointment.signature = hex::encode(signing.sign(&appointment.signed_bytes()).to_bytes());

    let body = serde_json::to_value(&appointment).context("the appointment serialises")?;
    let out = signed_post(key_path, addr, "/administrator/appoint", &body)?;
    report(out, &format!("{node} appointed for {hours}h"))
}

/// Ask a node to reset one accelerator.
///
/// The remedy for a card carrying a queued repair — a recorded row remap, or
/// firmware that stopped answering. The repair is already decided by the card;
/// only a reset applies it.
///
/// The node refuses a card that still has processes on it, and that refusal is
/// the whole safety of this: a reset tears down every context on the device, so
/// draining it first is a scheduling decision belonging to whoever owns the
/// work, not something this command should take on their behalf. Move the work
/// off, then run this.
fn accelerator_reset(key_path: &str, node: &str, index: &str) -> Result<()> {
    let index: u32 = index.parse().context("an accelerator index is a number")?;
    let body = serde_json::json!({ "index": index });
    let reply = signed_post(key_path, node, "/accelerators/reset", &body)?;

    if reply.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        println!("asked to reset accelerator {index} on {node}");
        if let Some(n) = reply.get("nonce").and_then(|v| v.as_str()) {
            println!("  confirm with the result endpoint, nonce {n}");
        }
        return Ok(());
    }
    // In the node's own words. "Refused" with no reason is what sends somebody
    // off to edit files until the machine stops arguing — and here the likely
    // reason is a precondition they can actually satisfy.
    let why = reply
        .get("because")
        .or_else(|| reply.get("error"))
        .and_then(|v| v.as_str())
        .unwrap_or("no reason given");
    bail!("refused: {why}");
}

/// Where a session's record lives.
fn session_path(id: &str) -> Result<std::path::PathBuf> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')) {
        bail!("a session id may only contain letters, digits, dashes and underscores");
    }
    Ok(furcate_paths::state("sessions").join(format!("{id}.json")))
}

fn session_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Open a recorded session under a named authority.
///
/// AUTHORITY is the grant or break-glass nonce this work is being done under —
/// for emergency access it is the `nonce` from `operator breakglass`. It is
/// committed as the first entry, so the record cannot afterwards be attached to
/// a different permission than the one it was taken with.
///
/// Prints the anchor. That number is the only thing that makes truncation
/// detectable later, so it belongs somewhere the person being recorded cannot
/// reach — a ticket, a chat channel, another machine. A recording checked only
/// against itself proves nothing about entries removed from its end.
fn session_open(id: &str, actor: &str, authority: &str) -> Result<()> {
    let path = session_path(id)?;
    if path.exists() {
        bail!("session {id} already exists at {}", path.display());
    }
    let s = furcate_session::Session::open(id, actor, authority, session_now());
    furcate_session::save(&s, &path).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("session {id} opened for {actor} under {authority}");
    if let Some(a) = s.anchor() {
        println!("anchor {}", hex::encode(a));
        println!("  keep this somewhere {actor} cannot edit; it is what proves nothing was cut off");
    }
    Ok(())
}

/// Commit one action to a session.
fn session_record(id: &str, command: &str, outcome: &str, target: Option<&str>) -> Result<()> {
    let path = session_path(id)?;
    let mut s = furcate_session::resume(&path)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("no session {id}; open it first"))?;
    let mut action = furcate_session::Action::new(command, outcome);
    if let Some(t) = target {
        action = action.on(t);
    }
    // Reported rather than swallowed: a session that has stopped recording must
    // stop being used, and the caller needs to know that now rather than at the
    // audit.
    s.record(session_now(), action)
        .map_err(|e| anyhow::anyhow!("session {id} is no longer recording: {e:?}"))?;
    furcate_session::save(&s, &path).map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(a) = s.anchor() {
        println!("recorded; anchor {}", hex::encode(a));
    }
    Ok(())
}

fn session_close(id: &str) -> Result<()> {
    let path = session_path(id)?;
    let s = furcate_session::resume(&path)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("no session {id}"))?;
    // Closing writes the final entry, so the record is saved after it rather
    // than before — a session saved before closing looks abandoned.
    let r = s.close(session_now());
    furcate_session::save_recording(&r, &path).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("session {id} closed after {} action(s)", r.actions());
    if let Some(a) = r.head() {
        println!("final anchor {}", hex::encode(a));
    }
    Ok(())
}

/// Check a session's record.
///
/// Without an anchor this reports only that what is present holds together —
/// which is genuinely weaker, and is said rather than implied. With one, it
/// also establishes that nothing was removed from the end, which is the only
/// part an interested party could have changed without breaking a hash.
fn session_verify(id: &str, anchor: Option<&str>) -> Result<()> {
    let path = session_path(id)?;
    let s = furcate_session::resume(&path)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("no session {id}"))?;
    // Closed only to obtain the reading view; nothing is written back, so
    // verifying a live session does not end it.
    let r = s.close(session_now());

    match anchor {
        Some(hexa) => {
            let bytes: [u8; 32] = hex::decode(hexa.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("an anchor is 32 bytes of hex"))?;
            match r.verify_against(&bytes) {
                Ok(()) => println!("session {id}: intact, and reaches the anchor given"),
                Err(e) => bail!("session {id}: {e:?}"),
            }
        }
        None => {
            match r.verify() {
                Ok(()) => println!("session {id}: internally consistent"),
                Err(e) => bail!("session {id}: {e:?}"),
            }
            println!(
                "  no anchor given, so this does NOT establish that entries were not
                   removed from the end. Re-run with the anchor printed at open."
            );
        }
    }
    println!("  {} action(s)", r.actions());
    Ok(())
}

/// Order the fleet into waves, before anything is changed.
///
/// Printed and not executed. The point of planning a rollout ahead of running
/// one is that the order can be read and argued with while it is still cheap to
/// change; a plan discovered a wave at a time is just a deployment.
///
/// Two things this reads out of the fleet and one it cannot. The administering
/// machine is put in the final wave, because a rollout that updates its own
/// controller early can lose the authority it needs to notice a problem or to
/// undo one. Leaf-tier devices go there too: a microcontroller that flashes
/// firmware with no second slot cannot be rolled back by software, and
/// canarying on it would commit the least recoverable tier first.
///
/// Waves are spread across failure domains, using the WIDEST level the site
/// reports that actually separates these nodes. Widest rather than narrowest on
/// purpose: round-robin across four chassis that all sit in one rack spreads
/// nothing that matters, while round-robin across two feeds guarantees no wave
/// can take out a whole feed. A level with one distinct value groups everything
/// together and is no better than having none, so it is skipped.
///
/// When the tree knows nothing, that is said plainly rather than papered over.
/// A plan that looks domain-aware and is not is worse than one that admits it.
/// The whole site, in the shape somebody reads at 3am.
///
/// Freshness is printed FIRST for each node, before anything it claims to be
/// running, because a workload list from a machine that stopped answering forty
/// minutes ago is history rather than status — and a reader who takes it for
/// status makes exactly the wrong decision.
fn fleet_show(addr: Option<&str>) -> Result<()> {
    let addr = addr
        .map(String::from)
        .or_else(|| std::env::var("FURCATE_SITE").ok())
        .unwrap_or_else(|| "127.0.0.1:7617".to_string());
    let d = furcate_api::get_json(&addr, "/fleet", 8_000)
        .with_context(|| format!("asking {addr} about the fleet"))?;

    let nodes = d.get("nodes").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    println!(
        "site {}  —  {} of {} nodes answering",
        d.get("site").and_then(|v| v.as_str()).unwrap_or("?"),
        d.get("fresh").and_then(|v| v.as_u64()).unwrap_or(0),
        nodes.len()
    );
    if let Some(why) = d.get("refused").and_then(|v| v.as_str()) {
        println!("no administrator: {why}");
    }
    println!();

    for n in &nodes {
        let id = n.get("node_id").and_then(|v| v.as_str()).unwrap_or("?");
        let name = n.get("topology").and_then(|v| v.as_str()).unwrap_or(&id[13..25.min(id.len())]);
        let fresh = n.get("freshness").and_then(|v| v.as_str()).unwrap_or("?");
        let age = n.get("as_of_secs_ago").and_then(|v| v.as_u64());
        // The age is only meaningful when it is not current, so it is shown
        // only then — a number beside every healthy node is noise that trains
        // people to skip the line where it matters.
        let when = match (fresh, age) {
            ("fresh", _) => String::new(),
            (_, Some(a)) if a > 90 => format!("  last seen {:.0}m ago", a as f64 / 60.0),
            (_, Some(a)) => format!("  last seen {a}s ago"),
            (_, None) => "  never answered".into(),
        };
        let role = if n.get("administers").and_then(|v| v.as_bool()) == Some(true) {
            "  [administers]"
        } else {
            ""
        };
        println!("{:<10} {:<7}{}{}", name, fresh, when, role);

        let assurance = n.get("assurance").and_then(|v| v.as_str());
        let attested = n.get("attested").and_then(|v| v.as_bool()).unwrap_or(false);
        let tier = n.get("tier").and_then(|v| v.as_str()).unwrap_or("?");
        let ram = n.get("ram_mb").and_then(|v| v.as_u64()).unwrap_or(0);
        let vram = n.get("vram_mb").and_then(|v| v.as_u64()).unwrap_or(0);
        print!("           {tier}, {} GB ram", ram / 1024);
        if vram > 0 {
            print!(", {} GB vram", vram / 1024);
        }
        match (assurance, attested) {
            (Some(a), true) => print!(", key held as {a}"),
            // A soft node is admitted by an operator and produces no quote. The
            // roster is the appraisal; the quote is what is missing.
            (Some(a), false) => print!(", key held as {a}, not attested"),
            (None, _) => print!(", no attestation on record"),
        }
        if let Some(w) = n.get("power_w").and_then(|v| v.as_f64()) {
            print!(", {w:.0}W");
        }
        println!();

        match n.get("workloads") {
            Some(w) if !w.is_null() => {
                let total = w.get("workloads").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                let degraded = w.get("degraded").and_then(|v| v.as_u64()).unwrap_or(0);
                let critical = w.get("critical_degraded").and_then(|v| v.as_u64()).unwrap_or(0);
                let partial = w.get("partial").and_then(|v| v.as_bool()).unwrap_or(false);
                let qualifier = if fresh == "fresh" { "" } else { " (last known)" };
                print!("           {total} workloads{qualifier}");
                if degraded > 0 {
                    print!(", {degraded} degraded");
                }
                if critical > 0 {
                    print!(", {critical} CRITICAL");
                }
                // "Could not look" is not "nothing is wrong". furcated marks the
                // inventory partial when a source was unavailable, and hiding
                // that would turn an unknown into a clean bill of health.
                if partial {
                    print!(", inventory PARTIAL — a source could not be read");
                }
                println!();

                // Two signals furcated already computes per workload and that
                // nothing surfaced. Both are the kind of thing nobody goes
                // looking for and everybody wants to have been told.
                let items = w.get("workloads").and_then(|v| v.as_array());
                if let Some(items) = items {
                    // A container whose tag now resolves to a different digest
                    // than the one it is running: the deploy did not take, or
                    // took and nothing restarted. Invisible from `docker ps`,
                    // which happily shows the tag it was started with.
                    let stale: Vec<&str> = items
                        .iter()
                        .filter(|i| i.get("image_stale").and_then(|v| v.as_bool()) == Some(true))
                        .filter_map(|i| i.get("id").and_then(|v| v.as_str()))
                        .collect();
                    if !stale.is_empty() {
                        println!(
                            "           {} running a superseded image: {}",
                            stale.len(),
                            stale.join(", ")
                        );
                    }
                    // Restart RATE, not the lifetime counter. A container that
                    // has restarted 400 times since January is fine; one that
                    // restarted 4 times in the last few minutes is crashlooping,
                    // and the lifetime number cannot tell you which is which.
                    let churn: Vec<String> = items
                        .iter()
                        .filter_map(|i| {
                            let n = i.get("recent_restarts").and_then(|v| v.as_u64())?;
                            let id = i.get("id").and_then(|v| v.as_str())?;
                            (n > 0).then(|| format!("{id} ({n})"))
                        })
                        .collect();
                    if !churn.is_empty() {
                        println!("           restarting: {}", churn.join(", "));
                    }
                }
            }
            _ => println!("           workloads unknown"),
        }
        println!();
    }
    if let Some(note) = d.get("note").and_then(|v| v.as_str()) {
        println!("{note}");
    }
    Ok(())
}

/// Seconds since the epoch. The other modules each have their own private
/// copy; this is main.rs asking the same question rather than making one of
/// them public for a caller they do not otherwise know about.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Where the people roster lives. Configuration, not state: it is a set of
/// decisions an operator made, the same kind of thing as trust.json.
fn people_path() -> std::path::PathBuf {
    furcate_paths::config("people.json")
}

fn people_load() -> Result<furcate_authn::local::People> {
    let p = people_path();
    match std::fs::read_to_string(&p) {
        Ok(t) => serde_json::from_str(&t)
            .with_context(|| format!("{} is not a readable roster", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(furcate_authn::local::People::default())
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}

fn people_save(r: &furcate_authn::local::People) -> Result<()> {
    let p = people_path();
    let bytes = serde_json::to_vec_pretty(r).context("the roster serialises")?;
    // Temp-then-rename: a half-written roster reads as absent on the next start,
    // which silently withdraws everybody.
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &p).with_context(|| format!("installing {}", p.display()))?;
    Ok(())
}

fn people_list() -> Result<()> {
    let r = people_load()?;
    if r.people.is_empty() {
        println!("this site admits nobody but the operator");
        return Ok(());
    }
    let now = now();
    for p in &r.people {
        let days = (p.valid_until as i64 - now as i64) as f64 / 86400.0;
        let state = if days < 0.0 { "LAPSED".to_string() } else { format!("{days:.1}d left") };
        println!("{:<24} {:<10} roles=[{}]", p.id, state, p.roles.join(","));
        if !p.reason.is_empty() {
            println!("{:>24}   {}", "", p.reason);
        }
    }
    Ok(())
}

/// Admit somebody under their own key.
///
/// Deliberately NOT a way to hand out the operator key. They sign as
/// themselves, decisions are recorded under their name, and withdrawing them is
/// deleting one line rather than rotating the key the whole site depends on.
fn people_admit(id: &str, pubkey: &str, days: &str, roles: &[&str]) -> Result<()> {
    if !id.starts_with("person:") {
        bail!("an id is `person:<name>`, so it can never be confused with `operator` or a node id");
    }
    if hex::decode(pubkey).map(|b| b.len()) != Ok(32) {
        bail!("a public key is 32 bytes of hex");
    }
    let days: u64 = days.parse().context("days must be a number")?;
    if days == 0 {
        bail!("an admission needs a duration; one that lapses on arrival admits nobody");
    }
    if roles.is_empty() {
        bail!("give at least one role — an admission with no roles can do nothing, \
               and a rule naming a person directly is the thing roles exist to avoid");
    }
    let mut r = people_load()?;
    r.people.retain(|p| p.id != id);
    r.people.push(furcate_authn::local::Person {
        id: id.to_string(),
        key: pubkey.to_string(),
        roles: roles.iter().map(|s| s.to_string()).collect(),
        valid_until: now() + days * 86400,
        reason: String::new(),
    });
    r.people.sort_by(|a, b| a.id.cmp(&b.id));
    people_save(&r)?;
    println!("admitted {id} for {days}d with roles [{}]", roles.join(","));
    println!("the daemons read this at start — restart them to apply");
    Ok(())
}

fn people_withdraw(id: &str) -> Result<()> {
    let mut r = people_load()?;
    let before = r.people.len();
    r.people.retain(|p| p.id != id);
    if r.people.len() == before {
        bail!("this site does not admit {id}");
    }
    people_save(&r)?;
    println!("withdrew {id}");
    println!("restart the daemons to apply");
    Ok(())
}

fn roster_admit(
    key_path: &str,
    site: &str,
    node: &str,
    pubkey: &str,
    hours: &str,
) -> Result<()> {
    let hours: u64 = hours.parse().context("hours must be a number")?;
    if hex::decode(pubkey).map(|b| b.len()) != Ok(32) {
        bail!("a public key is 32 bytes of hex; read it from the node's /identity");
    }
    // The controller reads `ttl_s`, a duration, and ignores anything else:
    //
    //     let ttl = req.body.get("ttl_s").and_then(|v| v.as_u64()).unwrap_or(3600);
    //
    // This sent `valid_until`, an absolute timestamp, under a name the
    // controller never looks up — so the `hours` argument was silently
    // discarded and every admission lasted exactly one hour. A roster that
    // lapses an hour after it is set looks like neglect and is a field-name
    // mismatch. `policy grant` next door already sends `ttl_s` correctly.
    let body = serde_json::json!({
        "node_id": node,
        "public_key": pubkey,
        "ttl_s": hours * 3600,
    });
    report(signed_post(key_path, site, "/roster/admit", &body)?, &format!("admitted {node}"))
}


/// Where the fleet controller answers.
///
/// The same variable the daemons use, so a machine that knows its controller
/// does not have to be told again for the CLI.
fn site_addr() -> String {
    std::env::var("FURCATE_SITE").unwrap_or_else(|_| "127.0.0.1:7617".to_string())
}

fn get_site(path: &str) -> Result<serde_json::Value> {
    furcate_api::get_json(&site_addr(), path, 5_000)
        .with_context(|| format!("reading {path} from {}", site_addr()))
}


/// Take a machine out of the fleet now.
///
/// An admission is granted for a term and a year is ordinary, so a machine
/// that has been decommissioned otherwise keeps a key this site believes for
/// however long is left on it.
fn roster_withdraw(key_path: &str, site: &str, node: &str) -> Result<()> {
    let body = serde_json::json!({ "node_id": node });
    let reply = signed_post(key_path, site, "/roster/withdraw", &body)?;
    // Ownership survives this, deliberately. Said out loud so nobody assumes
    // removing a machine from the fleet also gave it up.
    if let Some(who) = reply.get("still_owned_by").and_then(|v| v.as_str()) {
        println!("still claimed by {who} — release it separately if that is wrong:");
        println!("  furcatectl owner release KEY {site} {node}");
    }
    let left = reply.get("admitted").and_then(|v| v.as_u64());
    report(
        reply,
        &format!(
            "withdrew {node}{}",
            left.map(|n| format!("; {n} machine(s) still admitted")).unwrap_or_default()
        ),
    )
}



/// Where this machine keeps who it believes.
fn trust_path() -> std::path::PathBuf {
    furcate_paths::config("trust.json")
}

fn trust_load() -> Result<furcate_authn::TrustStore> {
    let path = trust_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    };
    furcate_authn::TrustStore::load(text.as_deref())
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
}

/// Who this machine believes, and why.
fn trust_list() -> Result<()> {
    let t = trust_load()?;
    if t.issuers.is_empty() {
        println!("this machine recognises nobody");
        return Ok(());
    }
    for i in &t.issuers {
        println!("{}  {:?}  {:?}", i.id, i.kind, i.level);
        if !i.reason.is_empty() {
            println!("    {}", i.reason);
        }
    }
    Ok(())
}


/// Recognise a machine on this host.
///
/// The counterpart to `trust withdraw-local`, and the thing whose absence
/// meant the trust store could only ever be edited by hand: entries could be
/// removed by a command and added only with a text editor, so in practice both
/// were done with an editor and the file drifted between machines.
///
/// Local by construction, like the withdrawal. The store belongs to root and
/// the controller runs unprivileged on purpose — who a machine believes is not
/// something a network-facing service should be able to add to.
fn trust_admit_local(id: &str, key: &str, reason: &str) -> Result<()> {
    if furcate_identity::NodeId::parse(id).is_err() {
        bail!("`{id}` is not a node identifier");
    }
    if hex::decode(key).map(|b| b.len()) != Ok(32) {
        bail!("a public key is 32 bytes of hex; read it from the node's /identity");
    }
    if reason.trim().is_empty() {
        bail!("a reason is required — an entry nobody can read the reasoning of \
               is one nobody dares remove");
    }

    let mut t = trust_load()?;
    // Replace rather than duplicate: a machine appearing twice is two answers
    // to one question, and the second is the one nobody looks at.
    let was = t.issuers.iter().position(|i| i.id == id).map(|at| t.issuers.remove(at));
    t.issuers.push(furcate_authn::trust::Issuer {
        id: id.to_string(),
        level: furcate_authn::trust::Level::Local,
        key: key.to_string(),
        reason: reason.to_string(),
        kind: furcate_authn::trust::Kind::Machine,
        boot_measured: false,
    });
    t.save(&trust_path())
        .with_context(|| format!("writing {} (run as root)", trust_path().display()))?;

    match was {
        Some(prev) => println!("{id} re-recognised (was: {})", prev.reason),
        None => println!("{id} is now recognised here"),
    }
    println!("  {} issuer(s)", t.issuers.len());
    println!();
    println!("the daemons read this at start — restart them to apply");
    Ok(())
}

/// Stop believing a machine, editing the store here.
///
/// The trust store lives in the configuration directory and belongs to root,
/// while the controller runs unprivileged — on purpose: who a site believes is
/// an operator's decision, and a network-facing service that could rewrite it
/// would be one an attacker could use to admit themselves. So the guarded
/// route refuses honestly and this does the edit with the operator's own
/// rights, on the machine, which is where that authority already is.
fn trust_withdraw_local(id: &str) -> Result<()> {
    let mut t = trust_load()?;
    let Some(gone) = t.withdraw(id) else {
        bail!("this machine does not recognise {id}");
    };
    t.save(&trust_path())
        .with_context(|| format!("writing {} (run as root)", trust_path().display()))?;
    println!("no longer trusting {id}");
    if !gone.reason.is_empty() {
        println!("  was: {}", gone.reason);
    }
    println!("  {} issuer(s) remain", t.issuers.len());
    // The daemons read this at start, the same caveat `people admit` carries.
    println!();
    println!("the daemons read this at start — restart them to apply");
    Ok(())
}

/// Stop believing a machine's word.
fn trust_withdraw(key_path: &str, site: &str, id: &str) -> Result<()> {
    let body = serde_json::json!({ "id": id });
    report(
        signed_post(key_path, site, "/trust/withdraw", &body)?,
        &format!("no longer trusting {id}"),
    )
}

/// Forget how to wake a machine.
fn wake_forget(key_path: &str, site: &str, node: &str) -> Result<()> {
    let body = serde_json::json!({ "node_id": node });
    report(
        signed_post(key_path, site, "/wake/forget", &body)?,
        &format!("forgot how to wake {node}"),
    )
}

/// A machine is gone for good.
///
/// One command, because a machine is recorded in several places and removing
/// it from one of them is the state that causes trouble: a node withdrawn from
/// the roster but still trusted is still an issuer this site believes and
/// still announced to anything reading /trust. That is exactly what happened
/// to the machine this was written for.
///
/// Each step is reported and none is fatal to the next. A machine already out
/// of the roster still has its trust withdrawn — that combination is the whole
/// reason the separate primitives exist, and refusing at the first 404 would
/// leave the job half done for the case most likely to need it.
///
/// Ownership is deliberately NOT released. A decommissioned machine is still
/// somebody's machine, and giving it up is a decision rather than a
/// consequence.
fn node_decommission(key_path: &str, site: &str, node: &str) -> Result<()> {
    let mut did = Vec::new();
    let mut left = Vec::new();

    // Each step reports what the controller actually said. An earlier version
    // printed its own guess ("it was not an issuer here") for every non-ok
    // reply, which turned "this controller may not write the trust store" into
    // a sentence claiming the machine was already untrusted — the opposite of
    // the truth, about the one list that still had it.
    let mut step = |path: &str, body: serde_json::Value, done: &'static str| {
        match signed_post(key_path, site, path, &body) {
            Ok(v) => match v.get("error").and_then(|e| e.as_str()) {
                None => did.push(done),
                Some(why) => {
                    println!("  {path}: {why}");
                    left.push(done);
                }
            },
            Err(e) => {
                println!("  {path}: {e}");
                left.push(done);
            }
        }
    };

    step("/roster/withdraw", serde_json::json!({ "node_id": node }), "withdrawn from the roster");
    step("/trust/withdraw", serde_json::json!({ "id": node }), "no longer trusted");
    step("/wake/forget", serde_json::json!({ "node_id": node }), "wake record forgotten");

    if did.is_empty() && left.is_empty() {
        bail!("{node} was not recorded anywhere on this site");
    }
    if !did.is_empty() {
        println!("{node}: {}", did.join(", "));
    }
    // What did NOT happen, named, because a decommission that half worked is
    // the state this command exists to avoid leaving somebody in.
    if !left.is_empty() {
        println!();
        println!("NOT done: {}", left.join(", "));
        println!("Read the lines above — each says which step refused and why.");
    }
    // Said afterwards, because it is the part somebody would otherwise assume
    // went the other way.
    println!();
    println!("Its owner's claim is kept. To give the machine up as well:");
    println!("  furcatectl owner release KEY {site} {node}");
    Ok(())
}


/// What each machine answers to.
fn handle_list() -> Result<()> {
    let reply = get_site("/handles")?;
    match reply.get("cluster").and_then(|v| v.as_str()) {
        Some(c) => println!("cluster @{c}"),
        None => println!("this cluster has no name — `furcatectl name cluster KEY SITE @NAME`"),
    }
    let machines = reply.get("machines").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if machines.is_empty() {
        println!("no machines have names yet");
        return Ok(());
    }
    println!();
    for m in machines {
        let h = m.get("handle").and_then(|v| v.as_str()).unwrap_or("?");
        let id = m.get("node_id").and_then(|v| v.as_str()).unwrap_or("?");
        // Said, because the two are treated differently on a clash and an
        // operator renaming a machine should know which they are looking at.
        let how = if m.get("chosen").and_then(|v| v.as_bool()).unwrap_or(false) {
            "chosen"
        } else {
            "from the machine"
        };
        println!("@{h:<12} {id}  ({how})");
    }
    Ok(())
}

/// What every machine is for, and what this cluster has nobody for.
fn roles_list() -> Result<()> {
    let reply = get_site("/roles")?;
    let nodes = reply.get("nodes").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if nodes.is_empty() {
        println!("no machine has been assigned a role here");
    }
    for n in &nodes {
        let id = n.get("node_id").and_then(|v| v.as_str()).unwrap_or("?");
        let roles: Vec<&str> =
            n.get("roles").and_then(|v| v.as_array()).map(|a| {
                a.iter().filter_map(|x| x.as_str()).collect()
            }).unwrap_or_default();
        println!("{id}");
        println!("  {}", roles.join(", "));
        if let Some(note) = n.get("note").and_then(|v| v.as_str()) {
            println!("  {note}");
        }
    }
    // What nothing is assigned to. An operator who believes they have storage
    // should be told when they do not.
    let missing: Vec<&str> = reply
        .get("unassigned")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    if !missing.is_empty() {
        println!();
        println!("nothing here is: {}", missing.join(", "));
    }
    Ok(())
}

/// The words this cluster understands, and what each one means.
fn roles_vocabulary() -> Result<()> {
    let reply = get_site("/roles")?;
    for v in reply.get("vocabulary").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        println!(
            "  {:<14} {}",
            v.get("role").and_then(|x| x.as_str()).unwrap_or("?"),
            v.get("means").and_then(|x| x.as_str()).unwrap_or("")
        );
    }
    println!();
    println!("any other word is kept as you typed it");
    Ok(())
}

/// Say what a machine is for.
fn roles_set(key_path: &str, site: &str, node: &str, words: &[&str]) -> Result<()> {
    let note_at = words.iter().position(|w| *w == "--note");
    let (roles, note) = match note_at {
        Some(i) => (&words[..i], words.get(i + 1).map(|s| s.to_string())),
        None => (words, None),
    };
    if roles.is_empty() {
        bail!("give at least one role; `furcatectl roles vocabulary` lists them");
    }
    let mut body = serde_json::json!({ "node_id": node, "roles": roles });
    if let Some(n) = note {
        body["note"] = serde_json::Value::String(n);
    }
    let reply = signed_post(key_path, site, "/roles/set", &body)?;
    // A refusal carries no `roles`, so reading the reply as a success printed
    // an empty list and exited 0 — a refused action that looked like a quiet
    // one. Check first, in the site's own words.
    if let Some(why) = refusal(&reply) {
        bail!("refused: {why}");
    }
    let now: Vec<String> = reply
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(str::to_string).collect())
        .unwrap_or_default();
    // Say what changed, not only what is now true.
    if let Some(was) = reply.get("was").and_then(|v| v.as_array()) {
        let was: Vec<&str> = was.iter().filter_map(|x| x.as_str()).collect();
        if !was.is_empty() {
            println!("was  {}", was.join(", "));
        }
    }
    println!("now  {}", now.join(", "));
    Ok(())
}

/// Say a machine is for nothing in particular.
fn roles_clear(key_path: &str, site: &str, node: &str) -> Result<()> {
    let body = serde_json::json!({ "node_id": node });
    let reply = signed_post(key_path, site, "/roles/clear", &body)?;
    if let Some(why) = refusal(&reply) {
        bail!("refused: {why}");
    }
    println!("{node} has no roles assigned here");
    Ok(())
}

/// Give a machine a name.
fn handle_set(key_path: &str, site: &str, node: &str, handle: &str) -> Result<()> {
    let body = serde_json::json!({ "node_id": node, "handle": handle });
    let reply = signed_post(key_path, site, "/handles/set", &body)?;
    if let Some(was) = reply.get("was").and_then(|v| v.as_str()) {
        println!("was @{was}");
    }
    // Copied before the move: `report` takes the reply by value, and holding
    // a borrow into it across that is what the compiler is objecting to.
    let now = reply
        .get("handle")
        .and_then(|v| v.as_str())
        .unwrap_or(handle)
        .to_string();
    report(reply, &format!("@{now}"))
}

/// Name the cluster.
fn handle_cluster(key_path: &str, site: &str, handle: &str) -> Result<()> {
    let body = serde_json::json!({ "handle": handle });
    let reply = signed_post(key_path, site, "/handles/cluster", &body)?;
    if let Some(was) = reply.get("was").and_then(|v| v.as_str()) {
        println!("was @{was}");
    }
    let now = reply
        .get("cluster")
        .and_then(|v| v.as_str())
        .unwrap_or(handle)
        .to_string();
    report(reply, &format!("this cluster is @{now}"))
}

/// Whose machines these are.
fn owner_list(account: Option<&str>) -> Result<()> {
    let path = match account {
        // The account goes in the query, percent-encoded, because an email
        // contains characters a bare query string would split on.
        Some(a) => format!("/owners?account={}", urlencode(a)),
        None => "/owners".to_string(),
    };
    let reply = get_site(&path)?;
    let claims = reply.get("claims").and_then(|v| v.as_array()).cloned().unwrap_or_default();

    if claims.is_empty() && account.is_some() {
        println!("no machines are claimed by {}", account.unwrap_or(""));
    } else if claims.is_empty() {
        println!("no machines are claimed here yet");
    }
    for c in &claims {
        let node = c.get("node_id").and_then(|v| v.as_str()).unwrap_or("?");
        let acct = c.get("account").and_then(|v| v.as_str()).unwrap_or("?");
        let why = c.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        println!("{node}  {acct}{}", if why.is_empty() { String::new() } else { format!("  — {why}") });
    }

    // Machines nobody has claimed are the actionable part of this list, so
    // they are printed rather than left for somebody to work out by
    // subtraction.
    if account.is_none() {
        let unclaimed = reply.get("unclaimed").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        if !unclaimed.is_empty() {
            println!();
            println!("{} machine(s) with no owner recorded:", unclaimed.len());
            for n in unclaimed {
                println!("  {}", n.as_str().unwrap_or("?"));
            }
            println!();
            println!("claim one with `furcatectl owner claim KEY SITE NODE_ID ACCOUNT REASON`");
        }
    }
    Ok(())
}

fn owner_claim(key_path: &str, site: &str, node: &str, account: &str, reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        bail!("a reason is required — an unexplained claim is one nobody can review");
    }
    let body = serde_json::json!({ "node_id": node, "account": account, "reason": reason });
    let reply = signed_post(key_path, site, "/owners/claim", &body)?;
    // A transfer is reported rather than passed over: somebody else just
    // stopped seeing this machine.
    if let Some(prev) = reply.get("displaced").and_then(|v| v.as_object()) {
        if let Some(who) = prev.get("account").and_then(|v| v.as_str()) {
            println!("taken from {who}");
        }
    }
    report(reply, &format!("{node} belongs to {account}"))
}

fn owner_release(key_path: &str, site: &str, node: &str) -> Result<()> {
    let body = serde_json::json!({ "node_id": node });
    report(signed_post(key_path, site, "/owners/release", &body)?, &format!("released {node}"))
}

/// Who belongs to this fleet.
fn fleet_people() -> Result<()> {
    let reply = get_site("/people")?;
    let people = reply.get("people").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if people.is_empty() {
        println!("nobody has been added to this fleet yet");
        println!("add the first owner with `furcatectl fleet admit KEY SITE ACCOUNT owner`");
        return Ok(());
    }
    for m in people {
        let acct = m.get("account").and_then(|v| v.as_str()).unwrap_or("?");
        let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("?");
        let by = m.get("added_by").and_then(|v| v.as_str()).unwrap_or("");
        println!("{role:<7} {acct}{}", if by.is_empty() { String::new() } else { format!("  (added by {by})") });
    }
    Ok(())
}

fn fleet_admit(key_path: &str, site: &str, account: &str, role: &str) -> Result<()> {
    // Checked here as well as at the controller, so a typo costs a round trip
    // and not an authenticated request that is then refused.
    let Some(parsed) = furcate_mesh::ownership::Role::parse(role) else {
        bail!("a role is one of: member, admin, owner");
    };
    let body = serde_json::json!({ "account": account, "role": role });
    let reply = signed_post(key_path, site, "/people/admit", &body)?;
    if let Some(was) = reply.get("was").and_then(|v| v.as_str()) {
        println!("was {was}");
    }
    report(reply, &format!("{account} is {role} of this fleet"))?;

    // Membership is what somebody is ENTITLED to; `people.json` is which key
    // this site will believe and what roles the principal behind it carries.
    // Two lists of humans that are edited separately drift, and the drift is
    // silent in the worst direction: somebody added on one and not the other
    // either cannot work, or can still work after being removed.
    //
    // So this says which admission the membership implies. It does not write
    // it, because an admission needs the person's own public key -- which
    // `furcatectl login` produces on their machine and which must never travel
    // to somebody else's terminal to be typed in for them.
    let id = furcate_mesh::ownership::Role::person_id(account);
    let roles = parsed.policy_roles().join(" ");
    println!();
    println!("{account} is now a {role} of this fleet. To let them actually use it,");
    println!("admit their key — they produce it with `furcatectl login` and send you");
    println!("the public half:");
    println!();
    println!("  furcatectl people admit {id} <PUBKEY> 30 {roles}");
    println!();
    println!("Until then they are a member on paper and every signed call they make");
    println!("is refused, which is the safe direction but not an obvious one.");
    Ok(())
}

fn fleet_withdraw(key_path: &str, site: &str, account: &str) -> Result<()> {
    let body = serde_json::json!({ "account": account });
    let reply = signed_post(key_path, site, "/people/withdraw", &body)?;
    // Said out loud, because it is the part people assume goes the other way.
    if let Some(n) = reply.get("machines_still_claimed").and_then(|v| v.as_u64()) {
        if n > 0 {
            println!("{n} machine(s) are still claimed by {account}; release them separately if that is wrong");
        }
    }
    report(reply, &format!("{account} no longer belongs to this fleet"))?;

    // The membership is gone; the admission that lets their key sign is not.
    // Said plainly, because the gap between the two is exactly where somebody
    // keeps working after being removed.
    let id = furcate_mesh::ownership::Role::person_id(account);
    println!();
    println!("their key can still sign for this site until its admission lapses. To end");
    println!("that now:");
    println!();
    println!("  furcatectl people withdraw {id}");
    Ok(())
}

/// Percent-encode a query value.
///
/// An account is usually an email, and `@` and `+` both mean something else in
/// a query string — `+` becomes a space, which silently turns
/// `a+b@example.com` into a different account that owns nothing.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Grant authority, narrowly and with an end.
fn policy_grant(
    key_path: &str,
    site: &str,
    principal: &str,
    action: &str,
    resource: &str,
    secs: &str,
    reason: &str,
) -> Result<()> {
    let secs: u64 = secs.parse().context("seconds must be a number")?;
    // The field names the endpoint actually reads. The first version of this
    // invented its own and was refused by the handler *after* authenticating
    // cleanly — which at least proved the signature path, and is exactly the
    // kind of mismatch a client written from memory produces.
    let body = serde_json::json!({
        "to": principal,
        "actions": [action],
        "resources": [resource],
        "ttl_s": secs,
        "reason": reason,
    });
    let reply = signed_post(key_path, site, "/policy/grant", &body)?;
    // The controller caps a grant at a day. Echoing the number that was ASKED
    // for told an operator they had something they did not.
    if let Some(c) = reply.get("capped") {
        if let (Some(asked), Some(got)) = (
            c.get("asked_s").and_then(|v| v.as_u64()),
            c.get("granted_s").and_then(|v| v.as_u64()),
        ) {
            println!("asked for {asked}s; a grant may last {got}s at most");
        }
    }
    let secs = reply
        .get("expires_in_s")
        .and_then(|v| v.as_u64())
        .unwrap_or(secs);
    report(
        reply,
        &format!("granted {principal} {action} on {resource} for {secs}s"),
    )
}

/// Revoke every grant held by a principal.
fn policy_revoke(key_path: &str, site: &str, to: &str) -> Result<()> {
    let body = serde_json::json!({ "to": to });
    report(signed_post(key_path, site, "/policy/revoke", &body)?, &format!("revoked grants held by {to}"))
}

/// Ask a node to restart one workload, proving who is asking.
///
/// This is the operator's half of the guarded route. The node reads nothing
/// about who this is from the request — the signature is the claim, and it
/// covers the method, the path and the body, so a credential for this restart
/// authorises no other.
///
/// Being permitted here is only the first half. The node still rules the
/// request against the site's written policy, which by default permits nothing:
/// authenticated and authorised are two answers, and an operator should be able
/// to tell which one they are being refused on.
/// Declare how this machine should behave about noise.
///
/// Signed, and ruled node-side against `tune` on `node:<id>` by the same policy
/// engine that rules a restart. A site that has written nothing refuses it,
/// which is the difference between an operator who can act and one who acts
/// because nobody stopped them.
///
/// One verb with named fields rather than three verbs, because placement,
/// quiet hours and the envelope are one declaration: setting them separately
/// would let a machine sit in a state nobody meant, between two calls.
fn thermal_set(key_path: &str, node: &str, fields: &[(&str, &str)]) -> Result<()> {
    let mut body = serde_json::Map::new();
    for (k, v) in fields {
        body.insert((*k).to_string(), serde_json::Value::String((*v).to_string()));
    }
    if body.is_empty() {
        bail!(
            "nothing to set. Pass one or more of: placement=machine_room|shared_space|\
             living_space, quiet=22-7 (or quiet= to clear it), envelope=full|0.6|90W, \
             builds=narrow|refuse"
        );
    }
    let reply = signed_post(key_path, node, "/thermal", &serde_json::Value::Object(body))?;

    if let Some(d) = reply.get("declared") {
        println!("{}", serde_json::to_string_pretty(d)?);
        if let Some(n) = reply.get("note").and_then(|v| v.as_str()) {
            println!("\n{n}");
        }
        return Ok(());
    }
    // In the node's own words. "Refused" with no reason is what sends somebody
    // off to edit files until the machine stops arguing.
    let why = reply
        .get("because")
        .or_else(|| reply.get("error"))
        .and_then(|v| v.as_str())
        .unwrap_or("no reason given");
    bail!("refused: {why}");
}

/// Parse `key=value` arguments into the fields the route accepts.
///
/// Unknown keys are refused rather than ignored: a typo that silently sets
/// nothing is how an operator believes a machine is quiet when it is not.
fn thermal_fields(args: &[&str]) -> Result<Vec<(&'static str, String)>> {
    let mut out = Vec::new();
    for a in args {
        let Some((k, v)) = a.split_once('=') else {
            bail!("`{a}` should look like placement=living_space");
        };
        let key = match k {
            "placement" => "placement",
            "quiet" | "quiet_hours" => "quiet_hours",
            "envelope" => "envelope",
            "builds" => "builds",
            other => bail!(
                "`{other}` is not a thermal setting; expected placement, quiet, envelope or builds"
            ),
        };
        out.push((key, v.to_string()));
    }
    Ok(out)
}

fn workload_restart(key_path: &str, node: &str, kind: &str, id: &str) -> Result<()> {
    let body = serde_json::json!({ "id": id, "kind": kind });
    let reply = signed_post(key_path, node, "/workloads/restart", &body)?;

    if reply.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        println!("asked: {id}");
        if let Some(n) = reply.get("nonce").and_then(|v| v.as_str()) {
            println!("  confirm with the result endpoint, nonce {n}");
        }
        return Ok(());
    }
    // Reported in the node's own words. "Refused" with no reason is what sends
    // somebody off to edit files until the machine stops arguing.
    let why = reply
        .get("because")
        .or_else(|| reply.get("error"))
        .and_then(|v| v.as_str())
        .unwrap_or("no reason given");
    bail!("refused: {why}");
}

/// A fresh nonce and the current time, for an order that must not be replayable.
fn nonce_and_now() -> Result<(String, u64)> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("drawing a nonce: {e}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok((hex::encode(nonce), now))
}

/// Sign emergency access that a node can verify with nothing else running.
///
/// Printed rather than sent, and that is the entire point. `policy grant` next
/// door posts to a site controller, which is precisely the thing that is
/// unavailable when somebody needs this: the identity provider is down, the
/// site is partitioned, or the control plane is what has failed. The signed
/// order is carried to the node by whoever holds it and checked there against
/// operator keys distributed in advance.
///
/// ACTIONS and RESOURCES are comma-separated. `*` is refused as an action —
/// name what is actually needed — and no action forbidden to every principal
/// can appear at all, so this is not a route to a halt or a crypto-erase.
/// Those stay with an operator physically holding the key.
fn operator_breakglass(
    key_path: &str,
    holder: &str,
    actions: &str,
    resources: &str,
    secs: &str,
    reason: &str,
) -> Result<()> {
    use furcate_breakglass::BreakGlass;

    let secs: u64 = secs.parse().context("seconds must be a number")?;
    let split = |s: &str| -> Vec<String> {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    };
    let signing = operator_signing_key(key_path)?;
    let (nonce, now) = nonce_and_now()?;

    let order = BreakGlass::new(
        holder,
        split(actions),
        split(resources),
        reason,
        now,
        now + secs,
        nonce,
    );
    // Refuse locally, before signing, so the operator is told what is wrong
    // rather than handed an order a node will reject when it matters.
    order.validate(now)?;
    let order = order.sign(&signing);

    eprintln!(
        "warning: emergency access for {holder} until {} — this must be announced and reviewed;          an unreviewed use makes the next one need two signatures",
        now + secs
    );
    println!("{}", serde_json::to_string(&order)?);
    Ok(())
}

fn operator_kill(key_path: &str, scope: &str, mode: &str, reason: &str) -> Result<()> {
    use furcate_killswitch::{KillMode, KillOrder, KillScope};

    let signing = operator_signing_key(key_path)?;

    let scope = match scope {
        "cluster" => KillScope::Cluster,
        s if s.starts_with("node:") => KillScope::Node(s.trim_start_matches("node:").to_string()),
        s if s.starts_with("domain:") => {
            KillScope::Domain(s.trim_start_matches("domain:").to_string())
        }
        other => bail!("scope `{other}` must be cluster, node:ID or domain:ID"),
    };

    let mode = match mode {
        "drain" => KillMode::Drain,
        "halt" => KillMode::Halt,
        "power_off" => KillMode::PowerOff,
        "isolate" => KillMode::Isolate,
        "crypto_erase" => KillMode::CryptoErase,
        other => bail!("mode `{other}` must be drain, halt, power_off, isolate or crypto_erase"),
    };

    // A nonce drawn fresh each time, so an order cannot be replayed. A short
    // window follows from the same reasoning: an order that stays valid for
    // hours is an order someone can use later.
    let (nonce, now) = nonce_and_now()?;

    let order = KillOrder::new(scope, mode, nonce, now, now + 300, reason).sign(&signing);

    if !mode.is_reversible() {
        eprintln!(
            "warning: `{}` is irreversible — {}",
            mode.as_str(),
            if mode == KillMode::CryptoErase {
                "sealed data will be unrecoverable"
            } else {
                "the machine will need physical or out-of-band intervention to return"
            }
        );
    }
    println!("{}", serde_json::to_string(&order)?);
    Ok(())
}

/// Predict PCR 11 for a real unified kernel image, and check it against a TPM.
///
/// Sections are extracted from the image itself rather than supplied, so this
/// exercises the model against an artifact a machine could actually boot.
///
/// The remaining caveat is unchanged and worth repeating: this confirms the
/// extend arithmetic over the sections in canonical order. Whether the
/// per-section digest convention matches what systemd-stub measures at boot
/// can only be settled by booting one and reading the register.
fn selftest_uki(path: &str) -> Result<()> {
    use furcate_machine::proving::{Sandbox, Swtpm};
    use furcate_machine::reference::{expected_pcr11_hex, UkiSections, SECTION_ORDER};
    use sha2::{Digest, Sha256};

    const PORT: u16 = 2325;

    if !std::path::Path::new(path).exists() {
        bail!("{path} does not exist");
    }

    // Pull each measurable section out of the image with objcopy.
    let tmp = std::env::temp_dir().join(format!("furcate-uki-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;
    let mut sections = UkiSections::new();
    let mut extracted: Vec<(String, Vec<u8>)> = Vec::new();

    for name in SECTION_ORDER {
        let out = tmp.join(format!("{}.bin", name.trim_start_matches('.')));
        // objcopy needs somewhere to write its (unused) output copy, and it
        // reports failure when that target is /dev/null even though the
        // section was dumped. So the dump is judged by whether the section
        // file appeared, not by the exit status.
        let scratch = tmp.join("copy.efi");
        let _ = std::process::Command::new("objcopy")
            .args([
                "--dump-section",
                &format!("{name}={}", out.display()),
                path,
                &scratch.display().to_string(),
            ])
            .output();
        let _ = std::fs::remove_file(&scratch);
        if !out.exists() {
            continue;
        }
        let Ok(bytes) = std::fs::read(&out) else { continue };
        if bytes.is_empty() {
            continue;
        }
        println!("  {name:<10} {} bytes", bytes.len());
        sections = sections.with(name, bytes.clone());
        extracted.push((name.to_string(), bytes));
    }

    if extracted.is_empty() {
        let _ = std::fs::remove_dir_all(&tmp);
        bail!("{path} carries no measurable sections; is it a unified kernel image?");
    }

    let predicted = expected_pcr11_hex(&sections);
    println!("\npredicted      {predicted}");

    let sandbox = Sandbox::new("/tmp/furcate-selftest-uki")?;
    sandbox.reset()?;
    let _swtpm = Swtpm::start_tcp(&sandbox, PORT)?;
    Swtpm::wait_tcp(PORT, 60)?;
    let tcti = format!("swtpm:host=127.0.0.1,port={PORT}");

    for (name, content) in &extracted {
        let digest = hex::encode(Sha256::digest(content));
        let out = std::process::Command::new("tpm2_pcrextend")
            .arg(format!("11:sha256={digest}"))
            .env("TPM2TOOLS_TCTI", &tcti)
            .output()
            .context("running tpm2_pcrextend")?;
        if !out.status.success() {
            let _ = std::fs::remove_dir_all(&tmp);
            bail!("extending PCR 11 with {name} failed");
        }
    }

    let out = std::process::Command::new("tpm2_pcrread")
        .arg("sha256:11")
        .env("TPM2TOOLS_TCTI", &tcti)
        .output()
        .context("reading PCR 11")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let actual = text
        .lines()
        .find_map(|l| {
            l.split_once(':').and_then(|(i, v)| {
                (i.trim() == "11").then(|| v.trim().trim_start_matches("0x").to_lowercase())
            })
        })
        .ok_or_else(|| anyhow::anyhow!("could not parse PCR 11"))?;
    println!("actual         {actual}");
    let _ = std::fs::remove_dir_all(&tmp);

    if actual == predicted {
        println!("result         prediction matches for a real unified kernel image");
        println!(
            "\nThis is a reference value computed before the machine boots. It confirms\n\
             the extend arithmetic over real sections in canonical order; whether the\n\
             per-section digest convention matches systemd-stub is settled only by\n\
             booting one and reading the register."
        );
        Ok(())
    } else {
        bail!("prediction does not match for this image")
    }
}

fn site_init(path: &str) -> Result<()> {
    if std::path::Path::new(path).exists() {
        bail!("{path} already exists; refusing to overwrite a site definition");
    }
    let starter = SiteFile::starter();
    std::fs::write(path, serde_json::to_string_pretty(&starter)?)
        .with_context(|| format!("writing {path}"))?;
    println!("wrote {path}");
    println!("Edit it to match your hardware, then run `furcatectl site isolation {path}`.");
    Ok(())
}

fn site_show(path: &str) -> Result<()> {
    let tree = SiteFile::load(path)?.tree()?;
    print!("{}", tree.render());
    if tree.has_declared_facts() {
        println!(
            "\nEntries marked declared were supplied by an operator and cannot be\n\
             verified by Furcate. Placement decisions rest on them being true."
        );
    }
    Ok(())
}

fn site_isolation(path: &str) -> Result<()> {
    let tree = SiteFile::load(path)?.tree()?;
    let nodes = tree.compute_nodes().len();
    println!("{nodes} compute nodes\n");

    for (kind, replicas, result) in site::report_isolation(&tree) {
        match result {
            Ok(domains) => println!(
                "  ok    {replicas} replicas across {:<8} → {domains} distinct domains",
                kind.as_str()
            ),
            Err(why) => println!("  FAIL  {replicas} replicas across {:<8} → {why}", kind.as_str()),
        }
    }
    Ok(())
}

/// A locally generated nonce, for inspection commands only.
///
/// This is deliberately not presented as a freshness guarantee: a nonce the
/// attester chose itself proves nothing to a verifier, which is why the
/// commands that use it say so.
fn generated_nonce() -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut nonce = now.to_be_bytes().to_vec();
    nonce.extend_from_slice(&std::process::id().to_be_bytes());
    nonce
}

/// Sign a statement that a machine may join this overlay, and on what terms.
///
/// Run wherever the operator key lives, which is deliberately not the
/// coordinator: the coordinator relays this and cannot produce it. The output
/// goes into what the node publishes about itself, so a machine carries its
/// own authorization and every other node checks it.
fn overlay_authorize(
    key_path: &str,
    node: &str,
    pubkey: &str,
    tier: &str,
    hours: &str,
) -> Result<()> {
    let hours: u64 = hours.parse().map_err(|_| anyhow::anyhow!("hours must be a number"))?;
    // Refused here rather than at the far end, where it would already be a
    // signature somebody could keep.
    //
    // Either the node's WireGuard key, for a node that keeps one, or its
    // hardware key (`p256:<hex>`, `ed25519:<hex>`), for a node whose
    // WireGuard key lives for one lease: the hardware then binds each lease's
    // key itself, and this approval is what makes peers believe it.
    let hardware;
    let pubkey = if furcate_net::wg::is_key(pubkey) {
        pubkey
    } else if pubkey.starts_with("p256:") || pubkey.starts_with("ed25519:") {
        hardware = furcate_policy::delegation::CellKey::normalise(pubkey)
            .map_err(|e| anyhow::anyhow!("that hardware key cannot be read: {e}"))?;
        hardware.as_str()
    } else {
        anyhow::bail!(
            "that is neither a wireguard public key nor a hardware key (`p256:<hex>` or `ed25519:<hex>`)"
        );
    };
    // The same check every node applies before it carries the lease, so a
    // tier that is spelled wrong, or one a Device-class key cannot hold, is
    // refused here rather than signed into an approval that verifies nowhere.
    furcate_net::lock::admissible_tier(pubkey, tier, None)
        .map_err(|why| anyhow::anyhow!("not authorized: {why}"))?;
    let signing = operator_signing_key(key_path)?;
    let key_id = anchor_id(&signing);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let not_after = now + hours * 3600;
    let auth = furcate_net::lock::authorize(
        &key_id,
        &signing,
        &furcate_net::lock::Claim { node_id: node, public_key: pubkey, tier, not_after },
    );
    println!("{}", serde_json::to_string_pretty(&auth).expect("an authorization serialises"));
    eprintln!(
        "authorized {node} on tier {tier} until {not_after}. It stops being a peer after that \
         unless it is authorized again."
    );
    Ok(())
}

/// Print the anchor a node should be told to trust.
///
/// Public half only. This is what goes into `overlay-anchors.json` on every
/// machine, carried there by anything that is not the coordinator.
fn overlay_anchor(key_path: &str) -> Result<()> {
    let signing = operator_signing_key(key_path)?;
    let anchor = furcate_net::lock::Anchor {
        key_id: anchor_id(&signing),
        public_key: hex::encode(signing.verifying_key().to_bytes()),
    };
    println!("{}", serde_json::to_string_pretty(&[anchor]).expect("an anchor serialises"));
    Ok(())
}

/// A stable name for a key, derived from the key itself.
///
/// Derived rather than chosen so the name on an authorization and the name in
/// the trust file cannot disagree — two people naming the same key differently
/// is how a valid signature comes to be refused.
fn anchor_id(signing: &ed25519_dalek::SigningKey) -> String {
    let full = hex::encode(signing.verifying_key().to_bytes());
    format!("op-{}", &full[..16])
}

#[cfg(test)]
mod machine_env_tests {
    use super::parse_env;

    #[test]
    fn it_reads_the_shape_the_machine_actually_writes() {
        // Exactly the file on node-a, comments and all.
        let got = parse_env(
            "# Delivery target\n\nFURCATE_LISTEN=192.0.2.28:7616\n\
             FURCATE_NODE_NAME=node-a\n  FURCATE_EDGE_TLS=1  \n\
             QUOTED=\"http://x/y\"\n",
        );
        assert_eq!(got.len(), 4, "got {got:?}");
        assert_eq!(got[2], ("FURCATE_EDGE_TLS".into(), "1".into()));
        assert_eq!(got[3].1, "http://x/y", "quotes belong to the shell, not the value");
    }

    #[test]
    fn a_line_without_an_equals_is_skipped_rather_than_panicking() {
        // A stray word in a config file must not stop a deploy.
        assert_eq!(parse_env("nonsense\nA=1\n").len(), 1);
    }

    #[test]
    fn values_containing_equals_survive_intact() {
        // Base64 and query strings both contain '='; splitting on the last one
        // would silently truncate them.
        let got = parse_env("TOKEN=abc=def==\n");
        assert_eq!(got[0].1, "abc=def==");
    }
}

#[cfg(test)]
mod sealed_key_tests {
    /// A sealed directory and a plaintext file must yield the SAME key.
    ///
    /// They did not. `unseal_file` recovered the TPM-held data key and then
    /// decrypted payload.json with it; the signing path stopped after the
    /// first step and signed with the data key. That is a perfectly valid
    /// ed25519 key which is simply not the operator's, so every signed call
    /// was refused with "that signature is not from a key this site admits" —
    /// a message about the wrong key, for a key that had never been decrypted.
    /// The same material passed as a plaintext file worked, which made it look
    /// like a TPM fault for as long as nobody compared the two.
    ///
    /// Asserted on the source rather than by sealing something, because
    /// sealing needs a TPM and this has to fail on a laptop too. What it
    /// pins is that one function does both steps and the other calls it.
    #[test]
    fn the_sealed_path_decrypts_the_payload_not_just_the_data_key() {
        let src = include_str!("lib.rs");
        let from = src
            .find("fn operator_signing_key")
            .expect("the signing path is still here");
        // Bounded by the end of the function, not a byte count: a comment
        // growing must not fail this, and a call moving out of the function
        // must.
        let end = src[from..].find("\n}\n").map(|i| from + i).unwrap_or(src.len());
        let body = &src[from..end];
        assert!(
            body.contains("unseal_operator_dir"),
            "operator_signing_key must go through the two-step unseal, not Sealer::unseal alone"
        );
        assert!(
            !body.contains("sealer.unseal("),
            "operator_signing_key is calling Sealer::unseal directly again — that recovers the \
             data key, not the operator key"
        );
        // And the shared helper must actually open the envelope.
        let helper = src
            .find("fn unseal_operator_dir")
            .expect("the shared helper is still here");
        let helper_end = src[helper..].find("\n}\n").map(|i| helper + i).unwrap_or(src.len());
        let helper_body = &src[helper..helper_end];
        assert!(
            helper_body.contains("open_operator_dir("),
            "unseal_operator_dir must go through the shared two-step reader"
        );
        let reader = src
            .find("fn open_operator_dir")
            .expect("the two-step reader is still here");
        let reader_end = src[reader..].find("\n}\n").map(|i| reader + i).unwrap_or(src.len());
        assert!(
            src[reader..reader_end].contains("envelope::open"),
            "open_operator_dir must decrypt payload.json"
        );
    }

    use super::{open_operator_dir, seal_operator_dir, SealBackend};
    use anyhow::{bail, Result};
    use furcate_identity::custody::{CustodyMode, CustodyRecord};
    use furcate_identity::AssuranceClass;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    /// A chip, simulated: what it seals stays in memory, and the directory
    /// gets only an opaque handle, as with the real one.
    #[derive(Default)]
    struct SimulatedSealer {
        held: RefCell<HashMap<PathBuf, Vec<u8>>>,
        fail_seal: bool,
    }

    impl SealBackend for SimulatedSealer {
        fn seal(&self, secret: &[u8], out_dir: &Path) -> Result<()> {
            std::fs::create_dir_all(out_dir)?;
            std::fs::write(out_dir.join("seal.pub"), b"simulated")?;
            if self.fail_seal {
                bail!("the simulated chip refused");
            }
            std::fs::write(out_dir.join("seal.priv"), b"simulated")?;
            self.held.borrow_mut().insert(out_dir.to_path_buf(), secret.to_vec());
            Ok(())
        }
        fn unseal(&self, sealed_dir: &Path) -> Result<Vec<u8>> {
            for name in ["seal.pub", "seal.priv"] {
                if !sealed_dir.join(name).exists() {
                    bail!("{name} is missing from {}", sealed_dir.display());
                }
            }
            match self.held.borrow().get(sealed_dir) {
                Some(s) => Ok(s.clone()),
                None => bail!("not sealed to this chip"),
            }
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("furcatectl-opseal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn custody() -> CustodyRecord {
        CustodyRecord { mode: CustodyMode::Elected, class: AssuranceClass::Tpm }
    }

    /// A key drawn for the test, never a fixed value.
    fn fresh_key_hex() -> String {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("randomness");
        hex::encode(b)
    }

    #[test]
    fn an_operator_seal_opens_through_the_two_step_reader() {
        let sealer = SimulatedSealer::default();
        let dir = scratch("roundtrip");
        let key_hex = fresh_key_hex();
        let expected = super::signing_key_from_hex(&key_hex).unwrap().verifying_key();

        let public = seal_operator_dir(&sealer, key_hex.as_bytes(), &custody(), &dir).unwrap();
        assert_eq!(public, expected);
        for name in ["seal.priv", "seal.pub", "payload.json"] {
            assert!(dir.join(name).exists(), "{name} was not written");
        }
        // The key is on disk only as ciphertext.
        let payload = std::fs::read_to_string(dir.join("payload.json")).unwrap();
        assert!(!payload.contains(&key_hex), "payload.json holds the key in the clear");

        let (sealed, recovered) = open_operator_dir(&sealer, &dir).unwrap();
        let opened = super::signing_key_from_hex(&recovered).unwrap();
        assert_eq!(opened.verifying_key(), expected);
        assert_eq!(sealed.custody_stated().unwrap(), custody());

        // Sealing over it again would destroy the only copy.
        let again = seal_operator_dir(&sealer, fresh_key_hex().as_bytes(), &custody(), &dir).unwrap_err();
        assert!(format!("{again:#}").contains("refusing to overwrite"), "{again:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_without_payload_json_is_refused_with_the_reason() {
        let sealer = SimulatedSealer::default();
        let dir = scratch("nopayload");
        // What `operator seal` used to leave: the chip's files and nothing else.
        sealer.seal(fresh_key_hex().as_bytes(), &dir).unwrap();
        let err = open_operator_dir(&sealer, &dir).unwrap_err();
        let why = format!("{err:#}");
        assert!(why.contains("no payload.json"), "{why}");
        assert!(why.contains("seal the operator key again"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_seal_leaves_no_partial_directory() {
        let sealer = SimulatedSealer { fail_seal: true, ..Default::default() };
        let dir = scratch("partial");
        let err = seal_operator_dir(&sealer, fresh_key_hex().as_bytes(), &custody(), &dir).unwrap_err();
        assert!(format!("{err:#}").contains("plaintext left in place"), "{err:#}");
        assert!(!dir.exists(), "a half-sealed directory was left behind");
    }
}

#[cfg(test)]
mod overlay_authorize_tests {
    use super::overlay_authorize;

    /// The P-256 generator, compressed: a valid point, as a Pi prints its key.
    const PI: &str = "p256:036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

    fn operator_key_file(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("furcatectl-authorize-{tag}-{}", std::process::id()));
        std::fs::write(&p, hex::encode([5u8; 32])).expect("written");
        p
    }

    #[test]
    fn a_device_class_key_is_authorized_on_the_device_tier() {
        let key = operator_key_file("device");
        let r = overlay_authorize(key.to_str().unwrap(), "pi-gw", PI, "device", "24");
        let _ = std::fs::remove_file(&key);
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn an_approval_naming_platform_for_a_device_class_key_is_refused_with_the_reason() {
        let key = operator_key_file("platform");
        for over in ["platform", "attested"] {
            let err = overlay_authorize(key.to_str().unwrap(), "pi-gw", PI, over, "24").unwrap_err();
            let why = format!("{err:#}");
            assert!(why.contains("Device-class") && why.contains("`device` at most"), "{why}");
        }
        let _ = std::fs::remove_file(&key);
    }
}

#[cfg(test)]
mod identity_root_tests {
    use super::quoting_refusal;
    use furcate_identity::AssuranceClass;

    #[test]
    fn a_device_class_node_is_refused_a_quote_with_the_reason() {
        let why = quoting_refusal("a quote", "rpi-fw-crypto", AssuranceClass::Device).unwrap();
        assert!(why.starts_with("a quote needs a TPM"), "{why}");
        assert!(why.contains("rpi-fw-crypto (class device)") && why.contains("signs no quote"), "{why}");
        assert!(!why.contains("tss") && !why.contains("/dev/tpmrm0"), "{why}");
    }

    #[test]
    fn soft_and_tee_nodes_are_refused_too() {
        for class in [AssuranceClass::Soft, AssuranceClass::Tee, AssuranceClass::SecureElement] {
            assert!(quoting_refusal("measurement coverage", "x", class).is_some(), "{class}");
        }
    }

    #[test]
    fn a_tpm_node_quotes() {
        assert!(quoting_refusal("a quote", "tpm", AssuranceClass::Tpm).is_none());
        assert!(quoting_refusal("a quote", "dice", AssuranceClass::Dice).is_none());
    }
}
