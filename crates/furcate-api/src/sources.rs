//! Who this machine answers at all.
//!
//! A signed request proves who made it. It does not stop a stranger from reading what an open route says, or from
//! sending a thousand unsigned requests to see what happens. A machine that reports to its controller has no reason to
//! answer anyone else, so the site can name the addresses it answers: the overlay's, the machines of the site, the
//! controller. A connection from any other address is closed before a byte is read or written, and the refusal is
//! logged. Loopback is always answered, because the machine's own services use it.
//!
//! This is the second line. The credential on every guarded route and the firewall are the other two, and none of the
//! three depends on the others being right.

use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Net {
    addr: IpAddr,
    bits: u8,
}

impl Net {
    fn parse(s: &str) -> Result<Net, String> {
        let (a, n) = match s.split_once('/') {
            Some((a, n)) => (a, Some(n)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().map_err(|_| format!("`{s}` is not an address"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match n {
            None => max,
            Some(n) => n.trim().parse::<u8>().map_err(|_| format!("`{s}`: the prefix is not a number"))?,
        };
        if bits > max {
            return Err(format!("`{s}`: the prefix is longer than the address"));
        }
        Ok(Net { addr, bits })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        fn prefix_equal(a: &[u8], b: &[u8], bits: u8) -> bool {
            let full = (bits / 8) as usize;
            if a[..full] != b[..full] {
                return false;
            }
            let rem = bits % 8;
            rem == 0 || (a[full] ^ b[full]) >> (8 - rem) == 0
        }
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => prefix_equal(&n.octets(), &i.octets(), self.bits),
            (IpAddr::V6(n), IpAddr::V6(i)) => prefix_equal(&n.octets(), &i.octets(), self.bits),
            // An IPv4 peer that arrives on a dual-stack socket is mapped into IPv6.
            (IpAddr::V4(_), IpAddr::V6(i)) => i.to_ipv4_mapped().is_some_and(|m| self.contains(IpAddr::V4(m))),
            _ => false,
        }
    }
}

/// The addresses a machine answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sources {
    allow: Vec<Net>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    allow: Vec<String>,
}

impl Sources {
    pub fn parse(text: &str) -> Result<Sources, String> {
        let f: File = serde_json::from_str(text).map_err(|e| format!("not a source list: {e}"))?;
        if f.allow.is_empty() {
            return Err("`allow` is empty: a machine that answers no address could not be reached to fix that".into());
        }
        Ok(Sources { allow: f.allow.iter().map(|s| Net::parse(s)).collect::<Result<_, _>>()? })
    }

    /// Read the list from `path`. `Ok(None)` when there is no file, which leaves the machine answering as before.
    /// A file that is there and cannot be read or understood is an error: guessing what it meant would be a silent
    /// fallback in one direction or the other.
    pub fn load(path: &Path) -> Result<Option<Sources>, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => Sources::parse(&t).map(Some).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn answers(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        ip.is_loopback() || self.allow.iter().any(|n| n.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_the_named_addresses_and_loopback_are_answered() {
        let s = Sources::parse(r#"{"allow": ["10.90.0.0/24", "10.91.0.61"]}"#).unwrap();
        assert!(s.answers(ip("10.90.0.9")));
        assert!(s.answers(ip("10.91.0.61")));
        assert!(s.answers(ip("127.0.0.1")));
        assert!(s.answers(ip("::1")));
        assert!(!s.answers(ip("10.90.1.9")), "outside the /24");
        assert!(!s.answers(ip("10.91.0.62")), "next door to the controller is not the controller");
        assert!(!s.answers(ip("10.92.0.43")), "another machine on the same tailnet");
        assert!(!s.answers(ip("192.168.1.66")));
        assert!(!s.answers(ip("fd7a:115c:a1e0::1")));
    }

    #[test]
    fn a_mapped_peer_is_judged_as_the_address_it_is() {
        let s = Sources::parse(r#"{"allow": ["10.91.0.61"]}"#).unwrap();
        assert!(s.answers(ip("::ffff:10.91.0.61")));
        assert!(!s.answers(ip("::ffff:10.91.0.62")));
    }

    #[test]
    fn odd_prefix_lengths_cut_where_they_say() {
        let s = Sources::parse(r#"{"allow": ["172.16.0.0/12"]}"#).unwrap();
        assert!(s.answers(ip("172.31.255.255")));
        assert!(!s.answers(ip("100.128.0.0")));
    }

    #[test]
    fn a_list_that_is_wrong_is_refused_not_guessed_at() {
        assert!(Sources::parse("{}").is_err());
        assert!(Sources::parse(r#"{"allow": []}"#).is_err());
        assert!(Sources::parse(r#"{"allow": ["10.90.0.0/33"]}"#).is_err());
        assert!(Sources::parse(r#"{"allow": ["not-an-address"]}"#).is_err());
        assert!(Sources::parse(r#"{"allow": ["10.0.0.1"], "extra": 1}"#).is_err());
        let dir = std::env::temp_dir().join(format!("sources-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(Sources::load(&dir.join("missing.json")), Ok(None));
        std::fs::write(dir.join("bad.json"), "oops").unwrap();
        assert!(Sources::load(&dir.join("bad.json")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
