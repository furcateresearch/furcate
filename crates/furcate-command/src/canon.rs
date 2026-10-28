//! Canonical JSON (RFC 8785) and the strict reader the gate uses.
//!
//! The gate accepts a command only if the bytes it received ARE the canonical form of what they parse to. That one
//! rule removes every canonicalisation attack at once: duplicate keys, reordered keys, escapes where a literal would
//! do, `1.0` for `1`, whitespace, a byte order mark, trailing data. What is signed is then unambiguous.

use serde_json::Value;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CanonError {
    /// Not JSON, or JSON the profile does not allow (depth, trailing data, lone surrogate).
    Malformed,
    /// An integer-valued number at or beyond 2^53, which two implementations could read differently.
    NumberTooLarge,
    /// Valid JSON whose bytes are not its canonical form.
    NotCanonical,
}

const MAX_SAFE: f64 = 9_007_199_254_740_992.0; // 2^53

/// ECMAScript `Number::toString` for a finite double that is not an integer-valued number of magnitude 2^53 or more.
fn es6_number(v: f64) -> String {
    if v == 0.0 {
        return "0".into();
    }
    let neg = v < 0.0;
    // Rust's `{:e}` gives the shortest digits that round-trip, but where two candidates of that length are equally near
    // (an exact tie) it may pick the odd one. ECMAScript takes the nearest, and the even one on a tie: so take the correctly
    // rounded decimal of the same length, which is also inside the rounding interval and therefore also round-trips.
    let shortest = format!("{:e}", v.abs());
    let k = shortest.split_once('e').unwrap().0.chars().filter(|c| *c != '.').count();
    let exact = format!("{:.*e}", k - 1, v.abs());
    let s = if exact.parse::<f64>().ok() == Some(v.abs()) { exact } else { shortest };
    let (mant, exp) = s.split_once('e').unwrap();
    let e: i32 = exp.parse().unwrap();
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = e + 1;
    let body = if k <= n && n <= 21 {
        format!("{}{}", digits, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let sign = if n - 1 < 0 { '-' } else { '+' };
        let ex = (n - 1).abs();
        if k == 1 {
            format!("{digits}e{sign}{ex}")
        } else {
            format!("{}.{}e{sign}{ex}", &digits[..1], &digits[1..])
        }
    };
    if neg {
        format!("-{body}")
    } else {
        body
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(out: &mut String, v: &Value) -> Result<(), CanonError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if (i as f64).abs() >= MAX_SAFE {
                    return Err(CanonError::NumberTooLarge);
                }
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                if (u as f64) >= MAX_SAFE {
                    return Err(CanonError::NumberTooLarge);
                }
                out.push_str(&u.to_string());
            } else {
                let f = n.as_f64().ok_or(CanonError::Malformed)?;
                if !f.is_finite() {
                    return Err(CanonError::Malformed);
                }
                if f.fract() == 0.0 {
                    if f.abs() >= MAX_SAFE {
                        return Err(CanonError::NumberTooLarge);
                    }
                    // An integer-valued double written with a point or exponent: render as an integer.
                    out.push_str(&es6_number(f));
                } else {
                    out.push_str(&es6_number(f));
                }
            }
        }
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(out, x)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            // UTF-16 code unit order, as the canonical form specifies.
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write(out, &m[*k])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The canonical JSON text of a value.
pub fn canonical(v: &Value) -> Result<String, CanonError> {
    let mut s = String::new();
    write(&mut s, v)?;
    Ok(s)
}

/// Parse bytes that must already be canonical. Anything else is refused with the reason.
pub fn parse_canonical(bytes: &[u8]) -> Result<Value, CanonError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| CanonError::Malformed)?;
    let c = canonical(&v)?;
    if c.as_bytes() != bytes {
        return Err(CanonError::NotCanonical);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_follow_ecmascript() {
        let cases = [
            (0.5, "0.5"),
            (-2.25, "-2.25"),
            (1e-7, "1e-7"),
            (1.5e-7, "1.5e-7"),
            (0.000001, "0.000001"),
            (123456789.125, "123456789.125"),
            (4.35, "4.35"),
            (0.1 + 0.2, "0.30000000000000004"),
        ];
        for (f, s) in cases {
            assert_eq!(es6_number(f), s);
        }
    }

    #[test]
    fn keys_sort_by_utf16_units_not_bytes() {
        // U+FF5E sorts after U+1F600 in UTF-8 bytes but before it in UTF-16 code units (0xFF5E vs 0xD83D).
        let v: Value = serde_json::from_str("{\"\u{ff5e}\":1,\"\u{1f600}\":2}").unwrap();
        let c = canonical(&v).unwrap();
        assert!(c.find('\u{1f600}').unwrap() < c.find('\u{ff5e}').unwrap());
    }

    #[test]
    fn non_canonical_bytes_are_refused() {
        for bad in [
            &b"{\"a\":1,\"a\":1}"[..],
            b"{\"b\":1,\"a\":2}",
            b"{\"a\": 1}",
            b"{\"a\":1.0}",
            b"{\"a\":\"\\u0061\"}",
            b"\xef\xbb\xbf{\"a\":1}",
            b"{\"a\":1} ",
        ] {
            assert!(parse_canonical(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        assert!(parse_canonical(b"{\"a\":1,\"b\":[true,null,\"x\"]}").is_ok());
        assert_eq!(parse_canonical(b"{\"a\":9007199254740993}").unwrap_err(), CanonError::NumberTooLarge);
    }
}
