//! Sealed custody survives an image update and a revert.
//!
//! An update replaces `/usr` and never writes the state directory, and a
//! silicon-fingerprint machine re-derives its custody key from the silicon on
//! every boot. Together those mean the sealed keys a machine held before an
//! update come back byte-identical after it, and again after a revert. This
//! runs that sequence against a scratch root with simulated silicon.

use anyhow::Result;
use furcate_identity::backends::{Characteristic, Fingerprint, FingerprintRot};
use furcate_identity::custody::{custody_key, elect, Candidate, CustodySettings, SiliconKey};
use furcate_identity::{AssuranceClass, CustodyGrant};
use furcate_vault::{Sealed, Vault};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A fuse key, simulated: only keyed digests come out.
struct SimulatedFuse([u8; 32]);

impl SiliconKey for SimulatedFuse {
    fn class(&self) -> AssuranceClass {
        AssuranceClass::Device
    }
    fn keyed_digest(&self, message: &[u8]) -> Result<[u8; 32]> {
        Ok(Sha256::new().chain_update(self.0).chain_update(message).finalize().into())
    }
}

fn grant(class: AssuranceClass, settings: &CustodySettings) -> CustodyGrant {
    let me = Candidate { id: "node-1".into(), class: Some(class), reachable: true };
    elect(settings, &[me]).unwrap().grant("node-1").unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("furcate-custody-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("usr/lib/furcate")).unwrap();
    std::fs::create_dir_all(root.join("var/lib/furcate/custody")).unwrap();
    root
}

/// Boot: re-derive the custody key from the silicon and open the vault.
fn boot(silicon: &dyn SiliconKey, grant: &CustodyGrant) -> Vault {
    let key = custody_key(silicon, grant, "vault").unwrap();
    Vault::open(key, grant).unwrap()
}

/// An image update or revert: `/usr` is replaced wholesale, nothing else.
fn install_image(root: &Path, version: &str) {
    let usr = root.join("usr");
    std::fs::remove_dir_all(&usr).unwrap();
    std::fs::create_dir_all(usr.join("lib/furcate")).unwrap();
    std::fs::write(usr.join("lib/furcate/version"), version).unwrap();
}

fn read_sealed(root: &Path) -> Vec<(Vec<u8>, Sealed)> {
    let dir = root.join("var/lib/furcate/custody");
    let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    names.sort();
    names
        .into_iter()
        .map(|p| {
            let raw = std::fs::read(&p).unwrap();
            let sealed = serde_json::from_slice(&raw).unwrap();
            (raw, sealed)
        })
        .collect()
}

fn round_trip(name: &str, silicon: &dyn SiliconKey, grant: &CustodyGrant) {
    let root = scratch(name);
    install_image(&root, "v1");

    let held: Vec<(&str, Vec<u8>)> = vec![
        ("site-ca", (0u8..32).collect()),
        ("operator", (32u8..96).collect()),
    ];
    let mut vault = boot(silicon, grant);
    for (i, (id, secret)) in held.iter().enumerate() {
        let sealed = vault.seal(id, secret, &[i as u8 + 1; 12], "node-1").unwrap();
        assert_eq!(sealed.custody, grant.record());
        std::fs::write(
            root.join(format!("var/lib/furcate/custody/{id}.json")),
            serde_json::to_vec(&sealed).unwrap(),
        )
        .unwrap();
    }
    drop(vault);
    let before = read_sealed(&root);

    for version in ["v2", "v1"] {
        install_image(&root, version);
        let after = read_sealed(&root);
        let vault = boot(silicon, grant);
        assert_eq!(after.len(), held.len());
        for ((raw_before, _), (raw_after, sealed)) in before.iter().zip(&after) {
            assert_eq!(raw_before, raw_after, "{version} rewrote a sealed object");
            let (_, secret) = held.iter().find(|(id, _)| *id == sealed.id).unwrap();
            assert_eq!(&vault.unseal(sealed).unwrap(), secret, "{version}: {}", sealed.id);
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn device_custody_survives_update_and_revert_byte_identical() {
    let settings = CustodySettings { tpm_less: true, ..Default::default() };
    round_trip("device", &SimulatedFuse([0x3cu8; 32]), &grant(AssuranceClass::Device, &settings));
}

#[test]
fn soft_custody_survives_update_and_revert_byte_identical() {
    let settings = CustodySettings { tpm_less: true, allow_soft: true, ..Default::default() };
    let rot = FingerprintRot::new(
        Fingerprint::default()
            .with(Characteristic::SocSerial, "10000000abcdef01")
            .with(Characteristic::BoardSerial, "board-7"),
    );
    round_trip("soft", &rot, &grant(AssuranceClass::Soft, &settings));
}

#[test]
fn different_silicon_cannot_open_what_was_sealed() {
    let settings = CustodySettings { tpm_less: true, ..Default::default() };
    let g = grant(AssuranceClass::Device, &settings);
    let mut mine = boot(&SimulatedFuse([1u8; 32]), &g);
    let sealed = mine.seal("site-ca", b"root", &[1u8; 12], "node-1").unwrap();
    let theirs = boot(&SimulatedFuse([2u8; 32]), &g);
    assert!(theirs.unseal(&sealed).is_err());
}
