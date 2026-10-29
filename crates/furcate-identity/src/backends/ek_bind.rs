//! Binding an EK certificate to the TPM that presented it.
//!
//! A certificate that chains to a trusted CA proves a manufacturer signed
//! *some* endorsement key. It says nothing about the key in this TPM unless the
//! certificate's subject public key is that key. Without the comparison, the
//! public EK certificate of any genuine device, copied onto an impostor, passes
//! the chain check. This module builds the SubjectPublicKeyInfo a TPM's EK
//! corresponds to and compares it, byte for byte, with the one in the
//! certificate.
//!
//! Supported keys are the two the TCG EK profile mandates: RSA 2048 (template
//! H-1) and ECC NIST P-256 (H-2), plus P-384 (H-5). Anything else is refused.

use std::path::Path;
use std::process::Command;

const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ECC_NIST_P256: u16 = 0x0003;
const TPM_ECC_NIST_P384: u16 = 0x0004;

struct R<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.b.len()).ok_or("TPM public area truncated")?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn sized(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut o = vec![tag];
    der_len(body.len(), &mut o);
    o.extend_from_slice(body);
    o
}

fn der_uint(bytes: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    tlv(0x02, &v)
}

/// The SubjectPublicKeyInfo DER for a marshalled TPM public area.
///
/// Accepts the `TPM2B_PUBLIC` form (a 2-byte size then the area) that
/// `tpm2_createek -u` writes, and a bare `TPMT_PUBLIC`. If both readings are
/// possible the input is ambiguous and is refused.
pub fn spki_from_tpm_public(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let sized = (bytes.len() >= 2 && u16::from_be_bytes([bytes[0], bytes[1]]) as usize == bytes.len() - 2)
        .then(|| parse_area(&bytes[2..]))
        .and_then(Result::ok);
    let bare = parse_area(bytes).ok();
    match (sized, bare) {
        (Some(a), None) | (None, Some(a)) => Ok(a),
        (Some(a), Some(b)) if a == b => Ok(a),
        (Some(_), Some(_)) => Err("TPM public area is ambiguous".into()),
        (None, None) => Err("not a recognised RSA or ECC TPM public area".into()),
    }
}

fn parse_area(b: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = R { b, at: 0 };
    let kind = r.u16()?;
    let _name_alg = r.u16()?;
    let _attrs = r.u32()?;
    let _policy = r.sized()?;
    let sym = r.u16()?;
    if sym != TPM_ALG_NULL {
        r.u16()?; // key bits
        r.u16()?; // mode
    }
    let scheme = r.u16()?;
    if scheme != TPM_ALG_NULL {
        r.u16()?; // hash
    }
    let spki = match kind {
        TPM_ALG_RSA => {
            let bits = r.u16()?;
            let exp = r.u32()?;
            let n = r.sized()?;
            if bits != 2048 || n.len() != 256 {
                return Err(format!("RSA EK of {bits} bits is not an accepted EK template"));
            }
            let e = if exp == 0 { 65537 } else { exp };
            let mut seq = der_uint(n);
            seq.extend(der_uint(&e.to_be_bytes()));
            let rsa = tlv(0x30, &seq);
            let mut bit = vec![0u8];
            bit.extend(rsa);
            let alg = tlv(0x30, &[&[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01][..], &[0x05, 0x00]].concat());
            tlv(0x30, &[alg, tlv(0x03, &bit)].concat())
        }
        TPM_ALG_ECC => {
            let curve = r.u16()?;
            let kdf = r.u16()?;
            if kdf != TPM_ALG_NULL {
                r.u16()?;
            }
            let x = r.sized()?;
            let y = r.sized()?;
            let (oid, size): (&[u8], usize) = match curve {
                TPM_ECC_NIST_P256 => (&[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], 32),
                TPM_ECC_NIST_P384 => (&[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22], 48),
                other => return Err(format!("ECC curve {other:#06x} is not an accepted EK template")),
            };
            if x.len() != size || y.len() != size {
                return Err("ECC coordinate length does not match its curve".into());
            }
            let mut point = vec![0u8, 0x04];
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            let alg = tlv(0x30, &[&[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01][..], oid].concat());
            tlv(0x30, &[alg, tlv(0x03, &point)].concat())
        }
        other => return Err(format!("TPM key type {other:#06x} is not RSA or ECC")),
    };
    if r.at != b.len() {
        return Err("bytes after the TPM public area".into());
    }
    Ok(spki)
}

/// The SubjectPublicKeyInfo DER of a DER X.509 certificate, read with `openssl`.
pub fn spki_from_certificate(cert_der: &[u8], work: &Path) -> Result<Vec<u8>, String> {
    let p = work.join("ek-bind.der");
    std::fs::write(&p, cert_der).map_err(|e| format!("writing the certificate: {e}"))?;
    let out = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-noout", "-pubkey", "-in"])
        .arg(&p)
        .output()
        .map_err(|e| format!("openssl is not available: {e}"))?;
    if !out.status.success() {
        return Err("not an X.509 certificate".into());
    }
    let pem = String::from_utf8_lossy(&out.stdout);
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    data_encoding::BASE64.decode(b64.trim().as_bytes()).map_err(|e| format!("certificate public key: {e}"))
}

/// `Ok` only when the certificate's subject key is exactly the TPM's EK.
pub fn certificate_matches_ek(cert_der: &[u8], ek_public: &[u8], work: &Path) -> Result<(), String> {
    let from_tpm = spki_from_tpm_public(ek_public)?;
    let from_cert = spki_from_certificate(cert_der, work)?;
    if from_tpm == from_cert {
        Ok(())
    } else {
        Err("the certificate's public key is not this TPM's endorsement key".into())
    }
}
