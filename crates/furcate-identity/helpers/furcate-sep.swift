// The Secure Enclave, on behalf of the agent.
//
// furcated is Rust and does not link the Security framework. Binding it would
// mean CoreFoundation lifetimes on every path, and a mistake there is a leak or
// a crash inside the daemon. This helper is small enough to read in full and
// does three things: make a key, show its public half, sign a message.
//
// ## Why this uses CryptoKit rather than the keychain
//
// The obvious implementation stores a persistent SecKey with
// kSecAttrTokenIDSecureEnclave. It does not work here, and the reason is worth
// recording because it looks like a bug: adding a persistent Secure Enclave key
// to the keychain returns **-34018, errSecMissingEntitlement**, and a
// code-signed binary attempting it is killed outright rather than given the
// error. The entitlement it wants must be backed by an Apple provisioning
// profile -- an Apple licence sitting under the node's identity, which is
// exactly what Furcate's trust root may not depend on.
//
// CryptoKit's SecureEnclave.P256 avoids the keychain entirely. The enclave
// returns a *wrapped* representation of the key -- measured at 284 bytes --
// which only this machine's Secure Enclave can unwrap. It is stored in an
// ordinary file, needs no entitlement, and the private key still never exists
// outside the enclave. A copy of that file on another Mac is inert.
//
// What the blob is NOT is a secret the file must protect: it cannot be
// unwrapped anywhere else. It is stored 0600 regardless, because a machine's
// identity should not be world-readable even when it is useless elsewhere.
//
//   furcate-sep create PATH      -> writes the wrapped key, prints its public key
//   furcate-sep public PATH      -> prints the public key, hex
//   furcate-sep sign PATH HEX    -> prints an ECDSA signature over HEX, hex
//   furcate-sep seal DIR         -> seals a new Ed25519 seed, prints its public key
//   furcate-sep unseal DIR       -> recovers the seed, prints it as hex
//
// ## Why seal/unseal exist as well as create/sign
//
// `create` makes a P-256 key the enclave signs with. That proves possession,
// but the roster speaks Ed25519 and a node's receipts are Ed25519 — so the
// node needs an Ed25519 seed that survives a restart without ever being
// written in the clear.
//
// This mirrors Furcate's TPM `Sealer` exactly (`furcate-identity/src/seal.rs`):
// tpm2_create under a PCR policy writes `<state>/node-key/{seal.pub,
// seal.priv}`. The macOS analogue writes the same two files — `seal.pub` is an
// SE key-agreement blob, `seal.priv` is the seed encrypted to it — so the Rust
// side sees one shape whichever hardware it is on.
//
// The seed is decrypted only by an ECDH against a private key that never
// leaves the enclave. Both files on another Mac are inert.
//
// Build: swiftc -O furcate-sep.swift -o furcate-sep

import Foundation
import CryptoKit

func die(_ msg: String) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(1)
}

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func unhex(_ s: String) -> Data? {
    let c = Array(s)
    guard c.count % 2 == 0 else { return nil }
    var out = Data(capacity: c.count / 2)
    var i = 0
    while i < c.count {
        guard let b = UInt8(String(c[i...i+1]), radix: 16) else { return nil }
        out.append(b)
        i += 2
    }
    return out
}

func load(_ path: String) -> SecureEnclave.P256.Signing.PrivateKey {
    guard SecureEnclave.isAvailable else {
        die("this machine has no Secure Enclave")
    }
    guard let blob = FileManager.default.contents(atPath: path) else {
        die("no key at \(path) — run `furcate-sep create` first")
    }
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
    } catch {
        // The common cause is a key wrapped by a DIFFERENT machine's enclave,
        // which is the mechanism working: the file copied, the identity did not.
        die("the Secure Enclave will not unwrap that key — it was made on another machine: \(error)")
    }
}

func create(_ path: String) {
    guard SecureEnclave.isAvailable else { die("this machine has no Secure Enclave") }
    if FileManager.default.fileExists(atPath: path) {
        // Never silently replace an identity. A node that quietly re-keys looks
        // to its site like a different machine answering on the same address.
        die("a key already exists at \(path); remove it deliberately to re-key")
    }
    do {
        let k = try SecureEnclave.P256.Signing.PrivateKey()
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try k.dataRepresentation.write(to: URL(fileURLWithPath: path), options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
        print(hex(k.publicKey.rawRepresentation))
    } catch {
        die("creating the key: \(error)")
    }
}

func publicKey(_ path: String) {
    print(hex(load(path).publicKey.rawRepresentation))
}

func sign(_ path: String, _ messageHex: String) {
    guard let msg = unhex(messageHex) else { die("the message is not hex") }
    do {
        // The enclave hashes with SHA-256 itself, so there is no separate hash
        // step for the two sides to disagree about.
        print(hex(try load(path).signature(for: msg).rawRepresentation))
    } catch {
        die("the Secure Enclave refused to sign: \(error)")
    }
}

let a = CommandLine.arguments
// The HKDF salt. Fixed and domain-specific so a key agreement here cannot
// produce the same symmetric key as one derived for any other purpose.
let sealSalt = Data("furcate-node-seal".utf8)

func sealKey(_ ka: SecureEnclave.P256.KeyAgreement.PrivateKey,
             _ ephPub: P256.KeyAgreement.PublicKey) throws -> SymmetricKey {
    try ka.sharedSecretFromKeyAgreement(with: ephPub)
        .hkdfDerivedSymmetricKey(using: SHA256.self, salt: sealSalt,
                                 sharedInfo: Data(), outputByteCount: 32)
}

/// Draw a fresh Ed25519 seed and seal it to this machine's enclave.
///
/// Refuses to overwrite: re-sealing would silently replace the node's
/// identity, and a node that changes identity on restart is a node the roster
/// stops recognising.
func seal(_ dir: String) {
    let pubPath = URL(fileURLWithPath: dir).appendingPathComponent("seal.pub")
    let privPath = URL(fileURLWithPath: dir).appendingPathComponent("seal.priv")
    if FileManager.default.fileExists(atPath: privPath.path) {
        die("\(privPath.path) already exists; refusing to replace this node's identity")
    }
    do {
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let ed = Curve25519.Signing.PrivateKey()
        let seed = ed.rawRepresentation

        let ka = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        let eph = P256.KeyAgreement.PrivateKey()
        let box = try AES.GCM.seal(seed, using: sealKey(ka, eph.publicKey))
        var blob = eph.publicKey.rawRepresentation
        blob.append(box.combined!)

        try ka.dataRepresentation.write(to: pubPath, options: .completeFileProtection)
        try blob.write(to: privPath, options: .completeFileProtection)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pubPath.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: privPath.path)

        // Prove it reads back before the caller relies on it. The TPM path does
        // the same check for the same reason: a seal that cannot be opened is
        // discovered at the next restart, when the node is already enrolled.
        let check = try unsealSeed(dir)
        guard check == seed else { die("the sealed seed did not read back") }

        print(hex(ed.publicKey.rawRepresentation))
    } catch {
        die("sealing a node key in the Secure Enclave: \(error)")
    }
}

func unsealSeed(_ dir: String) throws -> Data {
    let pubPath = URL(fileURLWithPath: dir).appendingPathComponent("seal.pub")
    let privPath = URL(fileURLWithPath: dir).appendingPathComponent("seal.priv")
    let ka = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: try Data(contentsOf: pubPath))
    let raw = try Data(contentsOf: privPath)
    guard raw.count > 64 else { throw CocoaError(.fileReadCorruptFile) }
    let eph = try P256.KeyAgreement.PublicKey(rawRepresentation: raw.prefix(64))
    return try AES.GCM.open(AES.GCM.SealedBox(combined: raw.dropFirst(64)),
                            using: sealKey(ka, eph))
}

/// Print the sealed seed as hex, for the agent to load as an Ed25519 key.
///
/// The seed reaches the agent over a pipe and is never written back to disk.
/// That is the same trade the TPM path makes: the chip hands back the secret,
/// and what protects it is that nothing else can ask.
func unseal(_ dir: String) {
    do {
        print(hex(try unsealSeed(dir)))
    } catch {
        die("unsealing the node key: \(error)")
    }
}

switch a.count > 1 ? a[1] : "" {
case "create": guard a.count == 3 else { die("usage: furcate-sep create PATH") }; create(a[2])
case "public": guard a.count == 3 else { die("usage: furcate-sep public PATH") }; publicKey(a[2])
case "sign":   guard a.count == 4 else { die("usage: furcate-sep sign PATH HEX") }; sign(a[2], a[3])
case "seal":   guard a.count == 3 else { die("usage: furcate-sep seal DIR") }; seal(a[2])
case "unseal": guard a.count == 3 else { die("usage: furcate-sep unseal DIR") }; unseal(a[2])
default:       die("usage: furcate-sep create PATH | public PATH | sign PATH HEX | seal DIR | unseal DIR")
}
