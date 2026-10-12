//! Serving models locally.
//!
//! The runtime is deliberately thin: it verifies and measures a model artifact
//! before loading, then forwards inference to a llama.cpp server over HTTP.
//! llama.cpp is the pragmatic backbone because its backend is abstracted
//! behind a protocol, which is what makes a heterogeneous cluster work at all.
//!
//! Nothing here fabricates an answer. If no runtime is reachable the call
//! fails, because a receipt over an output no model produced would bind a
//! model to something it never computed.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;

/// A model this node can serve.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoadedModel {
    pub id: String,
    /// Digest of the artifact, measured before load.
    pub digest: String,
    /// Where the serving process is listening.
    pub endpoint: String,
    /// Artifact path, kept so the digest can be re-checked after a restart.
    #[serde(default)]
    pub path: Option<String>,
}

/// Hash a model artifact.
///
/// Streamed rather than read whole: model files run to gigabytes, and a node
/// that loads one into memory to hash it will fail on exactly the models worth
/// serving.
pub fn measure(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Whether a serving endpoint is answering.
pub fn reachable(endpoint: &str) -> bool {
    let Some(addr) = endpoint.strip_prefix("http://") else {
        return false;
    };
    let addr = addr.split('/').next().unwrap_or(addr);
    std::net::TcpStream::connect_timeout(
        &match addr.parse() {
            Ok(a) => a,
            Err(_) => return false,
        },
        std::time::Duration::from_millis(500),
    )
    .is_ok()
}



/// Separate a model's thinking from its answer.
///
/// Four shapes, all observed: a well-formed block; a close whose open was
/// eaten by the chat template, where the close is authoritative because it is
/// what would otherwise leak; an open with no close, which is what a model
/// returns when it starts thinking and goes straight to an answer; and
/// ordinary text.
///
/// The same split the site controller applies to its advisor. Kept as two
/// small copies rather than a shared crate: this one is the node's own runtime
/// and depends on nothing, and a crate between them would couple the daemon to
/// the controller for twenty lines.
fn split_reasoning(raw: &str) -> (String, Option<String>) {
    const OPEN: &str = "<think>";
    const CLOSE: &str = "</think>";
    let non_empty = |s: String| if s.trim().is_empty() { None } else { Some(s) };

    match (raw.find(OPEN), raw.find(CLOSE)) {
        (Some(o), Some(c)) if o < c => {
            let reasoning = raw[o + OPEN.len()..c].trim().to_string();
            // Join the two halves with a single space rather than butting them
            // together: removing a block from the middle of a reply otherwise
            // leaves the blank lines that surrounded it, and a caller asking
            // for one word gets ",\n\n\n\nok". Trimmed, so a block at either
            // end leaves nothing behind.
            let before = raw[..o].trim();
            let after = raw[c + CLOSE.len()..].trim();
            let visible = match (before.is_empty(), after.is_empty()) {
                (true, _) => after.to_string(),
                (_, true) => before.to_string(),
                _ => format!("{before} {after}"),
            };
            (visible, non_empty(reasoning))
        }
        (_, Some(c)) => {
            let reasoning = raw[..c].trim().to_string();
            (raw[c + CLOSE.len()..].trim().to_string(), non_empty(reasoning))
        }
        (Some(o), None) => {
            let reasoning = raw[o + OPEN.len()..].trim().to_string();
            (raw[..o].trim().to_string(), non_empty(reasoning))
        }
        (None, None) => (raw.trim().to_string(), None),
    }
}

/// The key this node's model runtime expects, if it wants one.
///
/// Read from the same file the runtime was started with
/// (`--api-key-file`), rather than an environment variable: a token in a
/// unit is readable by anything that can read /proc, and this one opens every
/// model on the node.
fn gateway_token() -> Option<String> {
    let path = std::env::var("FURCATE_MODEL_TOKEN_FILE")
        .unwrap_or_else(|_| "/var/lib/furcate/models/gateway.token".to_string());
    std::fs::read_to_string(path)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Run a completion against a llama.cpp server.
///
/// Returns the generated text, or an error describing why nothing was
/// produced. The caller turns that into a receipt only on success.
pub fn complete(endpoint: &str, prompt: &str, max_tokens: u32) -> anyhow::Result<String> {
    complete_as(endpoint, None, prompt, max_tokens)
}

/// The same, naming which model to run.
///
/// A single-model server infers it; a gateway serving several refuses without
/// it ("model name is missing from the request"), because it has no way to
/// guess which set of weights was meant. Every node now runs a gateway, so the
/// name is the ordinary case and its absence is the exception.
pub fn complete_as(
    endpoint: &str,
    model: Option<&str>,
    prompt: &str,
    max_tokens: u32,
) -> anyhow::Result<String> {
    let addr = endpoint
        .strip_prefix("http://")
        .and_then(|a| a.split('/').next())
        .ok_or_else(|| anyhow::anyhow!("endpoint must be http://host:port"))?;

    // The chat endpoint, not the legacy completion one.
    //
    // These are chat-tuned models, and /completion applies NO chat template:
    // no ChatML turn markers, no reliable end-of-turn token. A model handed a
    // plain-text transcript continues the transcript -- it answered, then
    // invented the next question and answered that too, until the budget ran
    // out. Adding stop strings made it worse: one of them matched a heading in
    // the caller's own prompt and generation stopped after a single token, so
    // a working model returned an empty answer.
    //
    // /v1/chat/completions applies the template the GGUF carries, which knows
    // where a turn ends. All of that goes away.
    let mut body = json!({
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "max_tokens": max_tokens,
        // Thinking off. These models render a closed, empty <think> block into
        // the PROMPT when it is disabled -- that is the template doing its job,
        // not a leak -- and the model then answers after it. Measured on
        // qwen3.5-0.8b: `enable_thinking: false` alone gives a clean answer.
        //
        // `reasoning_format: "none"` is deliberately NOT sent. It tells the
        // server to stop separating reasoning out, which puts the block back
        // into the content -- the opposite of what is wanted here.
        "chat_template_kwargs": {"enable_thinking": false},
        // Qwen's published settings for non-thinking text. Greedy decoding is
        // not among them, and llama.cpp's own repeat_penalty default of 1.1
        // has to be overridden to the 1.0 the model was tuned for.
        // presence_penalty is the documented lever against endless repetition.
        "temperature": 1.0,
        "top_p": 1.0,
        "top_k": 20,
        "min_p": 0.0,
        "presence_penalty": 2.0,
        "repeat_penalty": 1.0,
    });

    if let Some(m) = model {
        if let Some(o) = body.as_object_mut() {
            o.insert("model".to_string(), json!(m));
        }
    }

    // The runtime is key-gated, so the key goes with the request.
    //
    // Without it this reached the server, was refused 401, and reported
    // "runtime returned no content" with the refusal buried in the payload —
    // which reads as a model that produced nothing rather than a request that
    // was never allowed to run. A node asking another node to reason got that
    // message and nothing else.
    //
    // Read from the file the runtime itself was started with, so there is one
    // token and not a copy of it in a unit's environment, where anything that
    // can read /proc can see it.
    let token = gateway_token();
    let auth = token.clone().unwrap_or_default();
    let credential = |_: &str, _: &str, _: &[u8]| auth.clone();
    let reply = if token.is_some() {
        furcate_api::post_bearer(addr, "/v1/chat/completions", &body, 120_000, Some(&credential))
    } else {
        furcate_api::post_json(addr, "/v1/chat/completions", &body, 120_000)
    }
    .map_err(|e| anyhow::anyhow!("reaching the model runtime at {addr}: {e}"))?;

    // An explicit refusal is worth repeating as itself. Folding it into "no
    // content" sends somebody looking at the model for a problem with the key.
    if let Some(m) = reply.pointer("/error/message").and_then(|v| v.as_str()) {
        anyhow::bail!("the model runtime refused: {m}");
    }

    let raw = reply
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow::anyhow!("runtime returned no content: {reply}"))?;

    // A reasoning model puts its thinking in the answer when the server does
    // not classify it, and can open a `<think>` block and never close it.
    // Returning that verbatim hands the caller a tag as if it were a decision;
    // measured here, qwen3.5-0.8b answered ",\n\n<think>\n\n</think>\n\nok"
    // to a question whose whole answer was "ok".
    // A stray comma before a thinking block is an artefact of the template and
    // not an answer. Only a comma, and only if something follows it: `.` and
    // `-` lead perfectly good sentences and lists, and trimming those ate real
    // answers. Whitespace is handled by the trim either way.
    let answer = split_reasoning(raw).0;
    let answer = answer.trim();
    let answer = match answer.strip_prefix(',') {
        Some(rest) if !rest.trim().is_empty() => rest.trim(),
        _ => answer,
    };
    Ok(answer.to_string())
}


/// Model registrations that survive a restart.
///
/// A registration is a statement that this node measured an artifact and can
/// serve it. Losing that on restart would mean a node silently stops serving
/// models an operator registered, which looks like the model disappearing
/// rather than the agent forgetting.
pub fn save(path: &Path, models: &[LoadedModel]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(models).unwrap_or_default())
}

/// Reload registrations, dropping any whose artifact no longer matches.
///
/// Re-measuring on load is the point: a registration is only meaningful if the
/// bytes on disk are still the bytes that were measured. A swapped model file
/// drops the registration rather than being served under the old digest.
pub fn load(path: &Path) -> Vec<LoadedModel> {
    let Ok(raw) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(saved): Result<Vec<LoadedModel>, _> = serde_json::from_slice(&raw) else {
        return Vec::new();
    };
    saved
        .into_iter()
        .filter(|m| match &m.path {
            Some(p) => measure(Path::new(p)).map(|d| d == m.digest).unwrap_or(false),
            None => false,
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn measuring_is_stable_and_content_dependent() {
        let dir = std::env::temp_dir().join("furcate-runtime-test");
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.gguf");
        let b = dir.join("b.gguf");
        std::fs::File::create(&a).unwrap().write_all(b"weights").unwrap();
        std::fs::File::create(&b).unwrap().write_all(b"other").unwrap();

        assert_eq!(measure(&a).unwrap(), measure(&a).unwrap());
        assert_ne!(measure(&a).unwrap(), measure(&b).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn measuring_a_missing_artifact_is_an_error_not_a_default_digest() {
        // A default digest would let an absent model pass a signature check.
        assert!(measure(Path::new("/nonexistent/model.gguf")).is_err());
    }

    #[test]
    fn an_unreachable_endpoint_is_reported_rather_than_assumed_up() {
        assert!(!reachable("http://127.0.0.1:1"));
        assert!(!reachable("not-a-url"));
    }

    #[test]
    fn completion_against_nothing_fails_rather_than_inventing_text() {
        let e = complete("http://127.0.0.1:1", "hello", 8).unwrap_err();
        assert!(e.to_string().contains("reaching the model runtime"));
    }
}

#[cfg(test)]
mod reasoning_tests {
    use super::split_reasoning;

    /// Exactly what qwen3.5-0.8b returned on this cluster when asked for a
    /// one-word answer: a leading comma, an empty thinking block, then the
    /// answer. Returned verbatim, the caller gets the tags.
    #[test]
    fn an_empty_think_block_is_stripped_from_a_real_answer() {
        let (text, thinking) = split_reasoning(",\n\n<think>\n\n</think>\n\nok");
        // The block goes; what surrounded it stays, trimmed. The stray comma
        // is the model's and not ours to remove: this separates reasoning from
        // an answer, it does not edit the answer.
        assert!(!text.contains("<think>"), "the tag must not survive: {text:?}");
        assert!(text.ends_with("ok"), "the answer must survive: {text:?}");
        assert_eq!(thinking, None, "an empty block is not a thought");
    }

    #[test]
    fn an_unclosed_block_is_not_an_answer() {
        let (text, thinking) = split_reasoning("<think>\n\n\n");
        assert_eq!(text, "");
        assert_eq!(thinking, None);
    }

    /// A stray leading comma goes; a full stop or a dash does not.
    ///
    /// The first version trimmed every leading `,.:;- ` and turned a list into
    /// nothing when the model answered with one.
    #[test]
    fn only_a_stray_comma_is_dropped() {
        use super::split_reasoning;
        // The split joins the halves with a space, so a reply whose only
        // content before the block was a comma comes back as ", ok" -- which
        // is what the comma trim in `complete_as` then removes.
        assert_eq!(split_reasoning(",\n\n<think>\n\n</think>\n\nok").0, ", ok");
        // And what the trim must not touch: an answer that legitimately
        // starts with punctuation.
        assert_eq!(split_reasoning("- node-a\n- node-b").0, "- node-a\n- node-b");
    }

    #[test]
    fn ordinary_text_is_left_alone() {
        let (text, thinking) = split_reasoning("ok");
        assert_eq!(text, "ok");
        assert_eq!(thinking, None);
    }
}
