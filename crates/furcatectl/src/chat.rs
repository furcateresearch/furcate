//! Talking to the cluster.
//!
//! An operator asks a question in their own words and the machines answer. The
//! controller's own orchestrator does the reasoning, given what the fleet
//! actually reports, and hands a harder question to the larger model on the
//! accelerated node.
//!
//! WHAT THIS IS NOT, YET: it reads. Every fact in an answer comes from an
//! endpoint the controller already serves, and nothing here writes to a
//! machine. Control through an agent is a separate step and wants the
//! approval model that goes with it -- a conversational surface that can
//! change a fleet is exactly where a confused deputy does its damage, and
//! shipping the reading half first is how the writing half gets built against
//! something real.
//!
//! The model never sees a raw endpoint. It is given a short, named summary
//! assembled here, because a model handed several hundred kilobytes of JSON
//! answers questions about JSON.

use anyhow::{bail, Context, Result};

/// What the fleet looks like right now, in the fewest words that are still true.
///
/// Assembled rather than dumped. `/fleet` alone is 88 KB; a 0.8B model given
/// that will spend its context on field names. What an operator asks about is
/// which machines are answering, what is degraded, and what the cluster is
/// drawing -- so that is what goes in.
fn fleet_summary(site: &str) -> Result<String> {
    let fleet = furcate_api::get_json(site, "/fleet", 8_000)
        .with_context(|| format!("asking {site} about the fleet"))?;

    let mut out = String::new();
    let name = fleet.get("site").and_then(|v| v.as_str()).unwrap_or("this fleet");
    let fresh = fleet.get("fresh").and_then(|v| v.as_u64()).unwrap_or(0);
    let of = fleet.get("of").and_then(|v| v.as_u64()).unwrap_or(0);
    out.push_str(&format!("Fleet {name}: {fresh} of {of} machines answering.\n"));

    if let Some(nodes) = fleet.get("nodes").and_then(|v| v.as_array()) {
        for n in nodes {
            // The handle an operator types, falling back to what the
            // machine calls itself. Asking about @node-e and being answered
            // about something else is a conversation nobody can follow.
            let who = n
                .get("handle")
                .and_then(|v| v.as_str())
                .or_else(|| n.get("topology").and_then(|v| v.as_str()))
                .unwrap_or("?");
            let state = n.get("freshness").and_then(|v| v.as_str()).unwrap_or("?");
            let tier = n.get("tier").and_then(|v| v.as_str()).unwrap_or("?");
            let power = n.get("power_w").and_then(|v| v.as_f64());
            // `workloads` is an inventory object, not a list: the list is
            // nested inside it beside the counts. Reading it as an array
            // yielded 0 for every machine, so the agent was told a fleet
            // running 113 workloads was running none — and answered
            // confidently about an idle cluster.
            let inv = n.get("workloads");
            let workloads = inv
                .and_then(|w| w.get("workloads"))
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let degraded = inv
                .and_then(|w| w.get("degraded"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let partial = inv
                .and_then(|w| w.get("partial"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let roles = match (
                n.get("controller").and_then(|v| v.as_bool()).unwrap_or(false),
                n.get("administers").and_then(|v| v.as_bool()).unwrap_or(false),
            ) {
                (true, true) => " [controller, administers]",
                (true, false) => " [controller]",
                (false, true) => " [administers]",
                _ => "",
            };
            // Degradation is named rather than left for the model to infer
            // from a count, and a partial inventory is said rather than
            // reported as a smaller number — "7 workloads" and "7 that this
            // machine could enumerate" are different claims.
            out.push_str(&format!(
                "- {who}: {state}, {tier}, {workloads} workloads{}{}{}{roles}\n",
                if partial { " (inventory incomplete)" } else { "" },
                if degraded > 0 { format!(", {degraded} degraded") } else { String::new() },
                power.map(|w| format!(", {w:.0}W")).unwrap_or_default()
            ));
        }
    }
    Ok(out)
}

/// Where the accelerated node answers, if there is one.
///
/// Escalation is a fact about the fleet rather than a setting: the machine
/// with the accelerator is the one that can hold a larger model, and asking
/// the fleet which that is keeps one answer instead of two.
fn accelerated_node(site: &str) -> Option<(String, String)> {
    let fleet = furcate_api::get_json(site, "/fleet", 8_000).ok()?;
    let nodes = fleet.get("nodes")?.as_array()?;
    for n in nodes {
        if n.get("tier").and_then(|v| v.as_str()) != Some("accelerated") {
            continue;
        }
        if n.get("freshness").and_then(|v| v.as_str()) != Some("fresh") {
            continue;
        }
        let ep = n.get("endpoint")?.as_str()?.to_string();
        let who = n.get("topology").and_then(|v| v.as_str()).unwrap_or("the accelerated node");
        return Some((ep, who.to_string()));
    }
    None
}


/// Where the controller's own agent answers.
///
/// The fleet knows: it records the endpoint each node reports, and marks which
/// one is running the controller. Falling back to any fresh node rather than
/// to loopback, because a fleet with an agent somewhere can still answer and a
/// guess at an address cannot.
fn controller_agent(site: &str) -> Option<String> {
    let fleet = furcate_api::get_json(site, "/fleet", 8_000).ok()?;
    let nodes = fleet.get("nodes")?.as_array()?;
    let fresh = |n: &serde_json::Value| n.get("freshness").and_then(|v| v.as_str()) == Some("fresh");
    nodes
        .iter()
        .find(|n| n.get("controller").and_then(|v| v.as_bool()).unwrap_or(false) && fresh(n))
        .or_else(|| nodes.iter().find(|n| fresh(n)))
        .and_then(|n| n.get("endpoint")?.as_str())
        .map(String::from)
}

/// Ask a node's agent to reason.
fn ask_node(endpoint: &str, model: &str, prompt: &str, max_tokens: u32) -> Result<String> {
    let body = serde_json::json!({
        "model": model,
        "input": prompt,
        "max_tokens": max_tokens,
    });
    let reply = furcate_api::post_json(endpoint, "/infer", &body, 120_000)
        .with_context(|| format!("asking {endpoint} to reason"))?;
    if let Some(e) = reply.get("error").and_then(|v| v.as_str()) {
        bail!("{endpoint}: {e}");
    }
    reply
        .get("output")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow::anyhow!("{endpoint} answered with no output"))
}

/// The instruction the model is given, ahead of the question.
///
/// Short and specific. A small model told to "be a helpful assistant" writes
/// an essay; told what it is looking at and how long the answer should be, it
/// answers.
///
/// No improvised continuation marker at the end. The node applies the model's
/// own chat template, which ends the prompt at the point the model was trained
/// to continue from; a hand-written "ANSWER:" after that is a second, wrong
/// one, and it produced empty replies from a model that was working.
fn system_prompt() -> &'static str {
    "You are the agent for a Furcate cluster. Answer the operator's question \
     using only the facts given. If the facts do not contain the answer, say \
     which machine or command would have it. Be brief: one or two sentences, \
     no preamble."
}


/// A conversation, rather than one question at a time.
///
/// The operator's seat. Reading only, like `ask`: every fact comes from an
/// endpoint the controller already serves, and nothing here writes to a
/// machine.
///
/// Each turn says which machine and model answered it, before the answer
/// rather than after. Somebody deciding whether to act on what they are told
/// should not have to read to the end to learn where it came from — and when
/// a question is escalated to the bigger model, that is the most important
/// thing on the line.
pub fn converse(site: &str) -> Result<()> {
    use std::io::{BufRead as _, Write as _};

    let facts = fleet_summary(site).unwrap_or_else(|e| format!("(the fleet could not be read: {e})"));
    let cluster = cluster_name(site);

    println!("{}", facts.trim_end());
    println!();
    println!("Ask about {}. `/big` sends the next question to the larger model,", cluster);
    println!("`/facts` shows what the agent is being told, `/quit` leaves.");
    println!();

    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let mut escalate_next = false;

    loop {
        print!("{cluster} ");
        let _ = std::io::stdout().flush();
        let Some(line) = lines.next() else { break };
        let line = line.unwrap_or_default();
        let q = line.trim();

        match q {
            "" => continue,
            "/quit" | "/exit" | "quit" | "exit" => break,
            "/facts" => {
                // What the model is actually given. An operator who doubts an
                // answer should be able to see the input rather than guess at
                // it, and a small model's mistakes are usually visible here.
                match fleet_summary(site) {
                    Ok(f) => println!("{}", f.trim_end()),
                    Err(e) => println!("the fleet could not be read: {e}"),
                }
                continue;
            }
            "/big" => {
                escalate_next = true;
                println!("the next question goes to the larger model");
                continue;
            }
            "/help" => {
                println!("/big    ask the larger model on the accelerated machine");
                println!("/facts  show what the agent is being told");
                println!("/quit   leave");
                continue;
            }
            _ => {}
        }

        // Read the fleet again for every question: a conversation outlives the
        // state it started in, and answering from a snapshot taken minutes ago
        // is how somebody is told a machine is fine after it stopped
        // answering.
        let facts = match fleet_summary(site) {
            Ok(f) => f,
            Err(e) => {
                println!("the fleet could not be read: {e}");
                continue;
            }
        };

        match answer(site, &facts, q, escalate_next) {
            Ok((text, model, who)) => {
                println!("[{model} on {who}]");
                println!("{text}");
            }
            Err(e) => println!("no answer: {e}"),
        }
        escalate_next = false;
        println!();
    }
    Ok(())
}

/// What this cluster is called, for the prompt.
fn cluster_name(site: &str) -> String {
    furcate_api::get_json(site, "/handles", 5_000)
        .ok()
        .and_then(|v| v.get("cluster")?.as_str().map(|c| format!("@{c}")))
        .unwrap_or_else(|| "this cluster".to_string())
}

/// One question, one answer.
pub fn ask(site: &str, question: &str, escalate: bool) -> Result<()> {
    let facts = fleet_summary(site)?;
    let (text, model, who) = answer(site, &facts, question, escalate)?;
    println!("{text}");
    // Quietly, after the answer: an operator acting on it should be able to
    // see where it came from without reading a header first.
    eprintln!("\n[{model} on {who}]");
    Ok(())
}

/// Ask whichever machine should answer, and say which one did.
fn answer(site: &str, facts: &str, question: &str, escalate: bool) -> Result<(String, String, String)> {
    let prompt = format!("{}\n\nFACTS\n{facts}\nQUESTION: {question}", system_prompt());

    // The controller's own orchestrator first. It is on the machine that holds
    // the state, so the question does not leave the box for the ordinary case.
    //
    // Its address is asked of the fleet rather than assumed to be loopback: a
    // node binds the address it reports on, which on a tailnet is not
    // 127.0.0.1.
    let here = std::env::var("FURCATE_ORCHESTRATOR_ADDR")
        .ok()
        .filter(|a| !a.is_empty())
        .or_else(|| controller_agent(site))
        .unwrap_or_else(|| "127.0.0.1:7616".to_string());
    let model = orchestrator_of(&here).unwrap_or_else(|| "qwen3.5-0.8b".to_string());

    let (endpoint, model, who) = if escalate {
        match accelerated_node(site) {
            Some((ep, who)) => {
                let m = orchestrator_of(&ep).unwrap_or_else(|| "qwen3.5-4b".to_string());
                (ep, m, who)
            }
            None => {
                eprintln!("no accelerated machine is answering; asking this one instead");
                (here, model, "this machine".to_string())
            }
        }
    } else {
        (here, model, "this machine".to_string())
    };

    let text = ask_node(&endpoint, &model, &prompt, 320)?;
    Ok((text, model, who))
}

/// Which model a node runs as its agent.
fn orchestrator_of(endpoint: &str) -> Option<String> {
    let v = furcate_api::get_json(endpoint, "/models", 4_000).ok()?;
    let models = v.get("models")?.as_array()?;
    models.first()?.get("id").and_then(|v| v.as_str()).map(String::from)
}
