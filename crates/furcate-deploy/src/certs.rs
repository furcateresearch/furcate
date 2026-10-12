//! When the certificates this machine holds stop working.
//!
//! An expiring certificate is the failure that takes a site off the internet
//! while every service reports healthy. Renewal is automatic and usually works;
//! the case worth showing an operator is the one where it has not, and that is
//! invisible until a browser refuses the connection.
//!
//! ## Why this reads the certificate rather than the metadata beside it
//!
//! The issuer writes a JSON file next to each certificate with its own idea of
//! when renewal should happen. That is a statement about intent. The date a
//! browser enforces is inside the certificate, and those two can disagree —
//! after a failed renewal the metadata is the more optimistic of the two, which
//! is exactly the wrong way round for something meant to raise an alarm.
//!
//! ## Why the parse is a scan and not an X.509 library
//!
//! One field is needed. A certificate's first two time values are `notBefore`
//! and `notAfter`, in that order, and finding them costs a walk over the DER
//! rather than a dependency that can parse everything. The trade is stated
//! rather than hidden: this cannot validate a certificate and does not claim
//! to — it answers "when does this stop" and nothing else.

/// Seconds since the Unix epoch at which a certificate stops being valid.
pub fn not_after(pem: &str) -> Option<i64> {
    let der = der_from_pem(pem)?;
    let (_not_before, not_after) = two_times(&der)?;
    parse_time(&not_after)
}

fn der_from_pem(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE"))
        .collect();
    base64_decode(&body)
}

/// The first two ASN.1 time values, which in a certificate are the validity
/// pair. Tag `0x17` is UTCTime, `0x18` GeneralizedTime.
fn two_times(der: &[u8]) -> Option<(String, String)> {
    let mut found: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + 2 < der.len() && found.len() < 2 {
        let tag = der[i];
        if tag == 0x17 || tag == 0x18 {
            let len = der[i + 1] as usize;
            // A time is short and fixed-width. A long-form length here means
            // this is not a time field and the byte pattern coincided.
            if (11..=32).contains(&len) && i + 2 + len <= der.len() {
                if let Ok(text) = std::str::from_utf8(&der[i + 2..i + 2 + len]) {
                    if text.ends_with('Z') && text[..text.len() - 1].bytes().all(|b| b.is_ascii_digit()) {
                        found.push(text.to_string());
                        i += 2 + len;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    match found.len() {
        2 => Some((found[0].clone(), found[1].clone())),
        _ => None,
    }
}

/// `YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ` to seconds since the epoch.
fn parse_time(t: &str) -> Option<i64> {
    let d = t.strip_suffix('Z')?;
    // Lengths after the trailing Z has been removed: `YYMMDDHHMMSS` is twelve
    // and `YYYYMMDDHHMMSS` fourteen. Matching the lengths *with* the Z still
    // attached is what the first version did, and it rejected every real
    // certificate while the unit tests for the date arithmetic passed.
    let (year, rest) = match d.len() {
        12 => {
            let yy: i64 = d[0..2].parse().ok()?;
            // RFC 5280: a two-digit year of 50 or more is 19xx.
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &d[2..])
        }
        14 => (d[0..4].parse().ok()?, &d[4..]),
        _ => return None,
    };
    let n = |a: usize, b: usize| -> Option<i64> { rest[a..b].parse().ok() };
    let (mon, day, hh, mm, ss) = (n(0, 2)?, n(2, 4)?, n(4, 6)?, n(6, 8)?, n(8, 10)?);
    Some(days_from_civil(year, mon, day) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Days since 1970-01-01 for a civil date, by Howard Hinnant's algorithm.
///
/// Written out rather than pulled in: the whole point of this module is to
/// answer one question without acquiring a dependency to do it.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_two_digit_year_splits_at_fifty() {
        // RFC 5280's rule. Getting it backwards would report a certificate
        // issued this century as having expired in the last one, which reads
        // as an emergency rather than a parsing error.
        assert_eq!(parse_time("491231235959Z"), parse_time("20491231235959Z"));
        assert_eq!(parse_time("501231235959Z"), parse_time("19501231235959Z"));
    }

    #[test]
    fn the_epoch_is_where_it_should_be() {
        assert_eq!(parse_time("19700101000000Z"), Some(0));
        assert_eq!(parse_time("700101000000Z"), Some(0));
    }

    #[test]
    fn a_leap_day_is_a_real_day() {
        let feb29 = parse_time("20240229000000Z").expect("a date");
        let mar01 = parse_time("20240301000000Z").expect("a date");
        assert_eq!(mar01 - feb29, 86_400);
    }

    #[test]
    fn nonsense_is_refused_rather_than_guessed() {
        assert_eq!(parse_time("not-a-time"), None);
        assert_eq!(parse_time(""), None);
        assert_eq!(not_after("not a certificate"), None);
    }

    /// A whole certificate made by openssl (self-signed, test only), so the
    /// parse is checked against real DER and not only against typed dates:
    /// the timestamp's length must be read without its trailing `Z`.
    #[test]
    fn a_certificate_parses_to_the_date_openssl_reports() {
        let pem = include_str!("testdata/test.crt");
        // openssl x509 -noout -enddate: Nov 15 08:21:55 2030 GMT
        assert_eq!(not_after(pem), Some(1_920_961_315));
    }

    #[test]
    fn a_certificate_with_no_times_reports_nothing() {
        // Better than a plausible number: a caller can say "unknown" but cannot
        // recover from being told the wrong date confidently.
        assert_eq!(two_times(&[0x30, 0x03, 0x02, 0x01, 0x00]), None);
    }
}
