# NVIDIA Jetson (Orin and Thor): medium processing node

**Status, exactly: built from NVIDIA documentation and checked against fixtures only. Not run on a real device; the owner owns none.** Nothing on this page was observed on a Jetson. Every "confirmed" below means confirmed against NVIDIA's published text, not against hardware.

Open code: `crates/open/furcate-host/src/tegra_fuse.rs` (fuse reader) and `board.rs`; `crates/open/furcate-identity/src/backends/{firmware_tpm,ek_bind,optee,select}.rs`. The event-log, quote, evidence, deploy, safety and bring-up code is in the enterprise tree.

## What NVIDIA documents (read 2026-10-29)

Sources are the Jetson Linux Developer Guide pages at `docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/SD/Security/` (SecureBoot, SecureBoot/FuseConfiguration, SecureBoot/FuseOperations, SecureBoot/QuickStartOrin, QuickStartThor, UefiSecureBoot, DiskEncryption, OpTee, OpTee/Ekb, FirmwareTPM, FirmwareTPM/Provisioning, FirmwareTPM/BootFlow), the r39.2 and r39.2.1 release notes, the SPE guide (r36.4.3), the power guides (r36.4.3 for Orin, r38.4 for Thor), the NVIDIA embedded FAQ, and NVIDIA's security bulletins. Statements marked (forum) are NVIDIA staff replies on `forums.developer.nvidia.com`, not Developer Guide text.

| Topic | Fact | Version |
|---|---|---|
| Releases | Orin: Jetson Linux 36.5.2 / JetPack 6.2.3 (2026-08-12; kernel 5.15, Ubuntu 22.04). Orin and Thor: 39.2.1 / JetPack 7.2.1 (2026-08-11; kernel 6.8, Ubuntu 24.04), 39.2.0 / 7.2 before it, which is the first JetPack 7 release to cover Orin. Thor only: 38.2 / 7.0, 38.4 / 7.1. | as listed |
| OP-TEE | v4.6.0 in Jetson Linux 39.2. Version in 36.x not verified. | r39.2 |
| Exception levels | Hafnium (S-EL2) on Thor only; Orin reaches OP-TEE directly from ATF. | r39.2 |
| Root of trust | BootROM checks the BCT and bootloader against `PublicKeyHash`. The chain ends at the bootloader; UEFI then uses PK, KEK, db. | r39.2 |
| Fuse lock | `SecurityMode` (1 bit, `odm_production_mode`): once 1, further fuse writes are blocked ("some ODM fuses remain writable"). Burning is irreversible. The ODM blob (carries `SecurityMode`) is burned after the OEM blob. | r39.2 |
| Orin fuses | `PublicKeyHash` 64 bytes (SHA-512 of the PKC key), `PkcPubkeyHash1/2`, `SecureBootKey` 32, `Kdk0` 32 (fTPM root), `OemK1` 32 (EKB), `OemK2` 32, `OdmId` 8, `OdmInfo` 4, `ReservedOdm0-7`, `ArmJtagDisable`, `PscOdmStatic`, `OptInEnable`, `BootSecurityInfo` 4, `SecurityMode`. `BootSecurityInfo` bits [2:0] = scheme (`001` RSA-3K), [3] SBK encrypt, [9] OEM key valid, [11] OEM key KDF, [13] silicon-ID KDF. Samples `0x2be1`, `0x2be9`. | r39.2 |
| Thor fuses | `PublicKeyHash` over 16 PKC key hashes (15 revocable), `PscOemKdk0/1`, `OespOemKdk0/1`, `SbOemKdk0/1`, `PscSecureBootKey`, `OespSecureBootKey`, `SbSecureBootKey` (all three equal), `OdmId`, `OdmInfo`, `ReservedOdm0-7`, `OptInEnable`, `BootSecurityInfo` ([3] SBK encrypt, [5] revocation policy, [9] OEM key valid, [13] fTPM enable; samples `0x2220`, `0x2228`), `SecurityMode`. Scheme is chosen at signing. | r39.2 |
| PKC algorithms | RSA-3K, ECDSA P-256, ECDSA P-521, XMSS listed on the Key List page; the Thor key list example has 4 of each of RSA-3K, P-256, P-521, XMSS. ED25519 and LMS not found. | r39.2 |
| Burn tools | Orin `odmfuse.sh -X ... -i <chip_id>` or `fskp_fuseburn.py -c 0x23`; Thor `fskp_fuseburn.py -c 0x26`. `--test` is a dry run. | r39.2 |
| Reading fuses | `sudo nv_fuse_read.sh -l` lists names; `sudo nv_fuse_read.sh <name>` reads one (`boot_security_info`, `ecid`, ...). Output format undocumented. Sysfs nodes `/sys/devices/platform/efuse-burn/` seen on JetPack 5 / L4T 35.6 (forum); whether JetPack 6 and 7 publish them is unverified. | r39.2; forum |
| Disk encryption | LUKS, passphrase from the OP-TEE `luks-srv` TA; key lives in the EKB (`eks_t234.img` v2.0 Orin, `eks_t264.img` v2.1 Thor), updatable by OTA only. EKB Orin: AES-128 keys from `OEM_K1`; Thor: AES-256 from `PSC_OEM_KDK1`. | r39.2 |
| OP-TEE client | `libteec.so`, `libckteec.so` (PKCS#11 2.40), `tee-supplicant`. Default TA signing key `default_ta.pem` must be replaced for production. | r39.2 |
| fTPM | AGX Thor, AGX Orin, Orin NX, Orin Nano. Exists only when the TOS was built with the fTPM option, the fTPM is enabled by fuse (Thor `BootSecurityInfo` bit 13), the EKB is paired (`--ekb-pair`), and the device is provisioned. Seed from `KDK0` (`Kdk0` Orin, `PscOemKdk0` Thor) and `Device_SN`. Provisioning is offline: the OEM/ODM's CA signs the RSA and EC EK certificates, which travel in the per-device EKB. NVIDIA publishes no EK CA chain; `SimulatorCA` is development only. EK cert NV indexes `0x1C00002` (RSA), `0x1C0000A` (EC); persistent EK handles `0x81010001`, `0x81010002`; empty `tpm2_getcap handles-persistent` means not provisioned. | r39.2, r39.2.1 |
| fTPM generations | From 38.4 the fTPM uses a newer reference implementation (TPM library spec rev 1.84; 1.59 on 36.4.4). The RSA EK is not compatible across the boundary. | r39.2 |
| Measured boot | Pre-fTPM measurements are kept as an event log and replayed into PCRs at fTPM start. PCR0 is the Jetson boot chain (Orin: MB2, TOS, UEFI; Thor adds BL31, BL32, SP images). PCR1 to 8 come from the UEFI log at `/sys/kernel/security/tpm0/binary_bios_measurements`. `ftpm_gen_measurement_list.py` computes golden PCR0 offline (SHA-256, 384, 512). | r39.2 |
| Attestation | No NVIDIA attestation service found. Documented story: EK certificates, PCR0 golden values, an external verifier such as Keylime. | r39.2 |
| Chip identity | `ecid` fuse via `nv_fuse_read.sh ecid`: 64 bits, "a unique chip ID, not a serial number" (forum); recovery-mode `BR_CID` 128 bits (forum). Widths are inconsistent across statements. | forum |
| Real time | Orin SPE: Cortex-R5, always-on cluster, FreeRTOS V10.4.3, IVC (echo channel only in the shipped distribution). Thor: SPE not documented in what was read. AGX Thor has no Functional Safety Island; IGX Thor has one (forum). IGX Thor materials say the platform supports accelerating IEC 61508 and ISO 26262 certification; that is not a certificate. | SPE guide r36.4.3 |
| Power (nvpmodel) | AGX Orin 64GB: MAXN, 15, 30, 50 W (default 30). AGX Orin 32GB: MAXN, 15, 30, 40 W. Orin NX 16GB: MAXN, 10, 15, 25 W (Super: to 40 W). Orin Nano 8GB: 15, 7 W (Super: 25 W). Thor T5000: MAXN, 120 W (default), 90, 70 W; T4000: MAXN, 70 W. 40 W and 25 W Super budgets apply to the Super flash configurations only. | r36.4.3, r38.4 |
| Temperature | AGX Orin -25 to 80 C at the thermal transfer plate, 5-year life; AGX Orin Industrial -40 to 85 C, 10-year life (NVIDIA embedded FAQ). Orin NX, Orin Nano and Thor ranges not verified. | FAQ |
| Isaac ROS, Holoscan | Isaac ROS 4.6.0 (2026-08-18) adds Orin and JetPack 7.2; 5.0.0 (2026-09-21) moves to ROS 2 Lyrical Luth. Holoscan Sensor Bridge 2.7-GA (July 2026) on JetPack 7.2 for AGX Thor and AGX Orin. | release pages |
| Containers | NVIDIA Container Toolkit 1.19 is in the JetPack 7.2.1 image; the toolkit documentation recommends CDI for Podman. Rootless Podman on Jetson specifically: not stated by NVIDIA. | r39.2.1 |
| Security bulletins | March 2026: CVE-2026-24148 (8.3, Orin and Xavier, fixed in 36.5), CVE-2026-24154 (initrd command line), CVE-2026-24153 (nvluks TA). From search summaries; read the bulletin before relying on the numbers. | a_id 5797 |

## Furcate's Jetson claims, reconciled

| # | Claim in the repository | Verdict | Action |
|---|---|---|---|
| 1 | Orin and Thor run a TPM 2.0 as an OP-TEE trusted application | Confirmed, with a condition the old text left out: only when the TOS is built for it, enabled by fuse, EKB-paired and provisioned. A stock module has none. | `platform.md` reworded; provisioning check added (enterprise tree) |
| 2 | "Fuse state is not readable from userspace on current Orin releases" | Wrong. The Developer Guide documents `nv_fuse_read.sh` (root). Which sysfs nodes exist on JetPack 6 and 7 is unverified. | Reader rewritten to use sysfs nodes then `nv_fuse_read.sh` |
| 3 | Any non-zero `security_mode` read from `/sys/devices/platform/tegra-fuse/security_mode` is secure boot | Wrong. `SecurityMode` is only the lock; enforcement also needs a burned `PublicKeyHash`, and on Orin the scheme bits. That node name is not in NVIDIA's pages. | `tegra_fuse::secure_boot` requires lock and key hash (Orin also `BootSecurityInfo[2:0] = 001`); anything else is not enforced |
| 4 | The EK certificate is issued by the ODM, not NVIDIA, and needs the KDK0 fuse | Confirmed. The OEM/ODM CA signs; NVIDIA publishes no chain. Thor's fuse is `PscOemKdk0`. | `firmware_tpm.rs` header updated |
| 5 | The EK chain check proves the EK is vouched for | Wrong in effect: the check never compared the certificate's key with the TPM's own endorsement key, so any genuine certificate copied onto another device passed. Not an NVIDIA fact; a defect found during this review. | `ek_bind.rs`; used on the class and the endorsement paths; tested with a borrowed certificate |
| 6 | MB2 and the trusted OS are extended into PCR0 | Confirmed (Orin: MB2, TOS, UEFI; Thor adds BL31, BL32, SP). PCR1 to 8 are the UEFI log. | Event log replay and quote check added (enterprise tree) |
| 7 | Unknown fuse state is treated as unfused | Confirmed as the right default; kept and extended (every missing or odd reading is not enforced). | |
| 8 | Module part numbers `p3701`, `p3767` (-0000/-0001 NX, -0003/-0004/-0005 Nano), `p3834` Thor | Unverifiable here; not on the pages read. | Left; the bring-up script records `/proc/device-tree/compatible` |
| 9 | fTPM TA UUID `bc50d971-d4c9-42c4-82cb-343fb7f37896` | Unverifiable: it is the Linux `tpm_ftpm_tee` driver's id, not shown in NVIDIA's pages. | Bring-up checks the TEE bus |
| 10 | Driver names `ftpm-tee` and `optee-ftpm`; `/dev/tee0`, `/dev/teepriv0`, `/dev/tpmrm0` | Unverifiable from NVIDIA's pages (Linux kernel names; NVIDIA forum mentions the `tpm_ftpm_tee` module). | Bring-up records them |
| 11 | AGX Orin Industrial -40 to 85 C at the plate; standard AGX Orin -25 C | Confirmed (NVIDIA FAQ: -25 to 80 C and -40 to 85 C at the thermal transfer plate). | Research note cites the FAQ |
| 12 | "SPE and Cortex-R5 UNVERIFIED" | Now confirmed for Orin (Cortex-R5, AON, FreeRTOS, IVC). Thor still unverified. | enterprise tree |
| 13 | AGX Thor has no safety island; IGX Thor has | Confirmed as NVIDIA staff statement (forum), not from a data sheet. | |
| 14 | "Jetson joins when NVIDIA supports 26.04" (`architecture.md`) | Unverifiable. The current JetPack 7.2.1 image is Ubuntu 24.04, kernel 6.8; no Ubuntu 26.04 BSP was found. | Reworded |
| 15 | Class is `tpm` when fused and the chain verifies | Insufficient alone: a quote, its nonce and a replayed boot log were not checked. | `tpm` now needs the quote, log and operator-pinned PCR0 as well (enterprise tree) |

## Hardware bring-up checklist

Read-only first. Steps 1 to 6 write nothing to the device.

1. Run the read-only observation commands (device tree, `/etc/nv_tegra_release`, `nv_fuse_read.sh -l` and the non-secret fuses, `mokutil --sb-state`, `/dev/tee*` and `/dev/tpm*` listings, `tpm2_getcap handles-persistent` and `handles-nv-index`, `tpm2_readpublic` on the persistent EK handles, `tpm2_nvread` of the EK certificate indexes, `tpm2_pcrread`, a copy of `binary_bios_measurements`, `nvpmodel -q`). Key fuses (SBK, KDK, OEM_K, FEK, KEK) are never asked for.
2. Compare each observation with the claims table above; every mismatch is a correction to make before anything else.
3. Keep the captures as the fixture set, with serial numbers and the ECID removed.
4. Confirm which fuse read path works on this release (sysfs or `nv_fuse_read.sh`) and its output format.
5. If `tpm2_getcap handles-persistent` is empty the fTPM is not provisioned: stop. Provisioning needs an operator CA and a per-device key blob and is not a read-only step.
6. Create an attestation key and take a quote with a verifier-issued nonce (transient TPM objects only), then check the quote, the event log replay, the EK certificate chain and its binding to the EK public area. This is the first time the `tpm` class can be computed.
7. Burning fuses is not in this checklist. It is irreversible and needs the owner's written approval for the specific device.

What Furcate needs from a Jetson to verify each claim: the file for each observation in step 1; for claims 4 and 5 an EK certificate, the operator's CA bundle and, to test the borrowed-certificate refusal, a certificate from a second device; for claim 15 a quote with the attestation key's public area; for the container path `podman info`, the CDI spec directory and `/dev/kvm`.

## Unverified, kept visible

OP-TEE version on 36.x; whether JetPack 6 and 7 publish the `efuse-burn` sysfs nodes; the `nv_fuse_read.sh` output format; ED25519 and LMS support; Thor SPE and ArmJtagDisable; the exact ECID width; the Thor data sheet figures (module maximum 130 W for T5000 and 90 W for T4000, junction -25 to 115 C: search summaries only); Orin NX and Nano temperature ranges; whether the Jetson kernels carry KVM; rootless Podman on Jetson; IGX Thor fTPM; the FSI IPC interface and SDK. The Developer Guide pages were read through a search and fetch tool, and the data sheets were not opened as PDFs.
