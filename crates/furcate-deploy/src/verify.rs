//! Confirming that what is being served is what was approved.
//!
//! **Placing is not serving.** The same distinction the validator gate draws
//! between a process existing and a node being back in the chain: a symlink
//! moved and a server reloaded prove that two operations returned success,
//! not that a request now returns the site. The gap between them is where a
//! deploy that "worked" and a site that is down live together.
//!
//! What makes this checkable at all is that a release is named by the hash of
//! its own bytes. So verification is not "did I get a 200" — it is "is the
//! byte sequence I am being handed one of the ones in the release I
//! approved". A 200 serving the *previous* release is the failure that a
//! status-code check reports as success.

use sha2::{Digest, Sha256};

/// What came back from asking the edge for a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The verdict on a deploy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The bytes served match the release that was approved.
    Serving,
    /// It answered, with something else.
    Mismatch { expected: String, got: String },
    /// It did not answer usefully.
    Unreachable { status: u16 },
}

impl Verdict {
    pub fn ok(&self) -> bool {
        matches!(self, Verdict::Serving)
    }

    pub fn describe(&self) -> String {
        match self {
            Verdict::Serving => "serving the release that was approved".into(),
            Verdict::Mismatch { expected, got } => format!(
                "answering, but with different bytes: expected content {}, got {}. \
                 Most often the edge is still holding the previous release",
                crate::release::short(expected),
                crate::release::short(got)
            ),
            Verdict::Unreachable { status } => {
                format!("the edge answered {status}; nothing is being served here")
            }
        }
    }
}

/// Hash one served body the same way a file in a release is hashed.
///
/// Path is not mixed in: this compares a single response against a single
/// file, and including the request path would make an identical file served
/// at two paths look like two different things.
pub fn body_digest(body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"furcate-release-file-v1");
    h.update((body.len() as u64).to_be_bytes());
    h.update(body);
    hex::encode(h.finalize())
}

/// Compare what the edge served against what was placed.
pub fn check(fetched: &Fetched, expected_body: &[u8]) -> Verdict {
    if fetched.status != 200 {
        return Verdict::Unreachable {
            status: fetched.status,
        };
    }
    let got = body_digest(&fetched.body);
    let expected = body_digest(expected_body);
    if got == expected {
        Verdict::Serving
    } else {
        Verdict::Mismatch { expected, got }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_approved_bytes_coming_back_is_the_only_success() {
        let v = check(
            &Fetched {
                status: 200,
                body: b"<html>site</html>".to_vec(),
            },
            b"<html>site</html>",
        );
        assert_eq!(v, Verdict::Serving);
        assert!(v.ok());
    }

    #[test]
    fn a_200_serving_the_previous_release_is_a_failure_not_a_success() {
        // The whole reason this module exists. A status check passes here.
        let v = check(
            &Fetched {
                status: 200,
                body: b"the old site".to_vec(),
            },
            b"the new site",
        );
        assert!(!v.ok());
        assert!(matches!(v, Verdict::Mismatch { .. }));
        assert!(v.describe().contains("still holding the previous release"));
    }

    #[test]
    fn anything_that_is_not_a_200_is_reported_with_its_status() {
        for s in [404u16, 502, 503] {
            let v = check(
                &Fetched {
                    status: s,
                    body: vec![],
                },
                b"x",
            );
            assert_eq!(v, Verdict::Unreachable { status: s });
            assert!(v.describe().contains(&s.to_string()));
        }
    }

    #[test]
    fn an_empty_body_does_not_pass_for_an_empty_expectation_by_accident() {
        // Both empty genuinely is a match; the point is that it is a match
        // because the bytes agree, not because the comparison was skipped.
        assert_eq!(check(&Fetched { status: 200, body: vec![] }, b""), Verdict::Serving);
        assert!(!check(&Fetched { status: 200, body: vec![] }, b"x").ok());
    }

    #[test]
    fn length_is_mixed_in_so_a_truncated_page_is_not_a_prefix_match() {
        assert_ne!(body_digest(b"abc"), body_digest(b"abcd"));
        assert_ne!(body_digest(b""), body_digest(b"\0"));
    }
}
