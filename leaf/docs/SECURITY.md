# Security

## 1. Goal

> Getting into a Furcate leaf node needs physical access to the hardware and a reflash. The Furcate firmware on it is one-way: only the Furcate nodes the operator has authorised can connect to it, fetch data from it or communicate with it in any way. Commands, model loads, configuration, OTA and telemetry are all covered. The leaf itself connects only to authorised nodes.

How the design meets this:

- **Over the network, there is nothing to attack without an operator grant.**
  - The leaf does not listen. It speaks only after it has sent HELLO and received an AUTH carrying a grant that a pinned operator key signed, for the key of the node it is talking to.
  - Every later message is authenticated and encrypted, and checked against the grant's roles.
  - Firmware, models and revocations are signed artifacts. The leaf checks their own signatures as well as the channel's.
- **With physical access**, what an attacker can do depends on the stage (section 4) and the chip (section 3).
- **On production hardware** (ESP32-C5 / ESP32-P4) the device key never leaves the chip.
- **On the classic ESP32 development board** there is no key engine, and lab attacks on secure boot and flash encryption are published and unfixed.

## 2. Hardware dossier (development board)

Read-only identification, 2026-10-11 (esptool 5.5.0, espefuse summary, boot log):

| Item | Value | Source |
|---|---|---|
| SoC | ESP32-D0WD-V3, silicon revision v3.1 (wafer major 3, minor 1), package 1, dual-core Xtensa LX6, 240 MHz | esptool chip-id, espefuse |
| v3.1 vs v3.0 | v3.1 is a backward-compatible minor revision (marking "G"; v3.0 is "E"). Every v3.0 erratum applies to v3.1; none concern eFuse, secure boot or flash encryption. | ESP32 Series SoC Errata, chip identification and errata summary (docs.espressif.com/projects/esp-chip-errata, accessed 2026-10-11) |
| Flash | JEDEC 0x5E 0x4016: 32 Mbit (4 MB) quad SPI NOR, most likely Zbit ZB25VQ32 (Linux spi-nor identifies the 128 Mbit Zbit part as 0x5E4018; suffix unverified). Not XMC, so ESP-IDF's XMC-specific workarounds do not apply. The flash is external to the SoC. | esptool flash-id; LKML ZB25VQ128 patch (2021-09) |
| PSRAM | None (the D0WD has none in the package; the boot log shows only internal RAM, about 330 KB) | boot log |
| USB bridge | Silicon Labs CP2102 (VID 0x10C4, PID 0xEA60), serial "0001" (a generic value, not unique). This, plus 4 MB of non-Espressif flash and no PSRAM, points to a third-party DevKitC-style board (likely WROOM-32E-class); unverified. | USB descriptors |
| eFuse coding scheme | NONE (BLOCK1-3 are 256 bits each). This is required for the anti-rollback secure version. | espefuse |
| eFuse state | All security eFuses unburned: ABS_DONE_0/1 = 0, FLASH_CRYPT_CNT = 0, JTAG enabled, UART_DOWNLOAD_DIS = 0, BLOCK1/2/3 empty, RD_DIS = WR_DIS = 0. CONSOLE_DEBUG_DISABLE = 1 (factory default). | espefuse summary |
| Key engines | **None.** No HMAC, Digital Signature, ECDSA or Key Manager peripheral exists on classic ESP32. A read-protected BLOCK3 cannot be read by software either. | ESP-IDF eFuse docs (esp32) |
| Hardware PUF | None. Only a software SRAM start-up fingerprint (used here, section 5). | Espressif docs; ESP32 PUF literature |
| Secure Boot v2 | Supported from silicon v3.0. RSA-3072 only, **one** key digest, no revocation slots. | ESP-IDF Secure Boot v2 (v5.5 docs) |
| ESP-IDF | Built with v6.0.1. ESP-IDF's compatibility table lists v3.0 as supported from the first release and v3.1 as "to be added"; v3.1 needs no software change per the errata. | ESP-IDF COMPATIBILITY.md |
| PSA Certified | Classic ESP32 is not certified. (C6 holds Level 2, 2025-02-20; S3, C3 and H2 hold Level 1.) | Espressif product security certifications page |

### Published attacks on this chip and revision

| Attack | Affects | Result | Fix | Source |
|---|---|---|---|---|
| Voltage glitch reads read-protected eFuses (CVE-2019-17391, LimitedResults "Fatal Fury") | rev 1 | flash-encryption and secure-boot keys read out | V3 ROM adds checks; rev 1 unfixable | NVD CVE-2019-17391; Espressif advisory 2019 |
| Power side-channel (CPA) on the AES engine during boot decryption (Ledger "Unlimited Results", AR2022-003) | **v3.0 / v3.1** | full flash-encryption key recovered in a few hours, 100% success; about 300k to 2M traces | none on this silicon | IACR ePrint 2023/090; AR2022-003 (2022-11-18) |
| Single EM glitch loads an attacker-chosen PC and jumps into ROM download mode with secure boot and flash encryption on (Raelize/TII, CVE-2023-35818, AR2023-005) | **v3.0 / v3.1** | secure boot and flash encryption bypassed, flash readable | "no immediate mitigation"; needs new silicon | USENIX WOOT 2024 (Delvaux et al.); AR2023-005 (2023-07-11) |
| SRAM fingerprint under faults | ESP32 | fingerprint reliability drops sharply under voltage faults | design-level (ours is not secret against a lab attacker anyway) | Komanduri and Nelson, "Power PUFs", IEEE 2025 |
| Undocumented Bluetooth HCI commands (AR2025-004) | ESP32 | host-side BT controller commands | not relevant: Bluetooth is off in this firmware | Espressif advisories (2025-05-22) |

No other ESP32 security advisory was published in 2024-2026 (Espressif advisory list, accessed 2026-10-11). The fault-injection countermeasures in S2/S3/C3/C6/P4 ROMs do not carry over to the classic ESP32.

**Conclusion that drives the design.** Treat everything stored on this chip as recoverable by a lab attacker. Hence:

- every leaf has its own key, and no fleet-wide secret is ever stored on a leaf;
- trust anchors on the leaf are public keys only;
- production uses the C5 or P4.

## 3. Production hardware (decided)

| Need | Chip | Why |
|---|---|---|
| Sensors and control | **ESP32-C5** (rev 1.2 or later) | Key Manager whose hardware unique key comes from an **SRAM PUF in hardware**, never exposed to software; ECDSA P-256 peripheral; ESP-TEE with attestation; hardware glitch detector; AES side-channel countermeasures (dummy rounds); Wi-Fi 6 dual-band |
| Vision | **ESP32-P4** (rev 3.0 or later) + C5/C6 radio | Key Manager/PUF, ECDSA, glitch detector, AI vector instructions, PSRAM; YOLO11n-320 at about 0.32 s |

On these chips the leaf key is generated inside the chip and used only by the ECDSA peripheral. It is never readable by software, never stored in flash in usable form, and never sent anywhere. The identity backend `fl_identity_hwkey.c` implements this (pending; see PENDING.md). The rest of the firmware is unchanged.

## 4. What an attacker can do, by stage

| Attacker | Development (no eFuses burned: this board now) | Development, hardened (section 7 applied to this board) | Production (C5 / P4, locked down) |
|---|---|---|---|
| Network, no grant | Nothing answers (no radio in this build; on a network, no listener) | Same | Same |
| Network, stolen grant | Nothing: a grant works only with that node's hardware-held key | Same | Same |
| Network, stolen node (key in its TPM) | Acts within that grant's roles until the operator revokes the grant's generation | Same | Same |
| USB cable / flash reader | Reads the flash (helper data, configuration) and can reflash anything. A reflashed leaf cannot be the old leaf unless the attacker also reads the SRAM fingerprint, which a running attacker firmware can do. **So on this stage the device can be taken over.** | Flash dumps are ciphertext; download mode, JTAG and ROM console are off; unsigned firmware does not boot | Same, and the device key is in the key engine: never readable |
| Lab (EM glitch, power side-channel) | n/a | **Breaks this chip** (AR2022-003, AR2023-005): flash key recovered, secure boot bypassed, own firmware run, fingerprint read, device impersonated. The blast radius is that one device: no fleet or operator secret is on it. | Glitch detector and side-channel countermeasures raise the cost sharply. The device key stays inside the key engine. |
| Replace or reflash the device and pose as it | **Detected** if the attacker lacks the old fingerprint. The leaf ID is a hash of the derived public key, and the parent's roster pins it. | Same | Detected: the key cannot be extracted; attestation shows a different secure-boot digest or key |

## 5. Identity (owner decision 2026-10-11: silicon fingerprint is the primary path where there is no TPM)

**Classic ESP32 (this board):**

- **Source.** The SRAM start-up pattern of a 2 KB region that neither ROM nor bootloader writes, read before any other code. Deep sleep is used to power the SRAM down when a reset kept it powered.
- **Enrollment.**
  - The leaf takes 8 power-ups and keeps only cells that never changed.
  - It chooses 256 × 7 of them, spread across the region.
  - The helper data is the cell positions plus parity: each cell XOR the first cell of its group. It is stored in NVS.
- **Reconstruction.** On each boot, a majority vote over 7 cells per bit gives the 256-bit secret.
- **Key.** `HKDF(fingerprint secret ‖ factory MAC)` → P-256 private key, held in RAM only while running. The public key's SHA-256 is the leaf ID.
- **What it guarantees.**
  - The key is never stored, so a flash dump alone does not reveal it.
  - The identity is tied to this die and changes if the die changes.
  - Firmware running on the chip can read the fingerprint, so on an unlocked board an attacker who reflashes can recompute the key. Secure boot (section 7) closes that path, except against the lab attacks above.
- **Helper data leakage.**
  - The repetition-code helper reveals the XOR relations within each group. Each secret bit's entropy rests on the first cell of its group, plus the cells' bias, which the leaf reports.
  - A stronger fuzzy extractor (BCH with debiasing) is listed in PENDING.md.
- **Assurance class reported:** `silicon-fingerprint/development` until secure boot and flash encryption are on.

**C5 / P4:** the Key Manager's hardware PUF does the same thing in silicon, and the private key never reaches software.

**Pi / Jetson nodes:** keys in TPM / fTPM where present. Per the owner's decision, a node without a TPM uses its silicon fingerprint path and reports that class.

## 6. Keys and who holds them

| Key | Holder | Never |
|---|---|---|
| Leaf key | Leaf silicon (fingerprint-derived here; key engine in production) | stored, exported, sent |
| Node key (parent) | Node's TPM / fTPM / Secure Enclave, or silicon-fingerprint path on a TPM-less node | in a file in usable form |
| Operator key(s) | Operator passkey (WebAuthn, also via a hosted console in the browser), Secure Enclave, or TPM on an operator machine | on a server; a hosted console only relays and records signed authorisations |
| Release keys (firmware, models) | TPMs on at least two different machines; threshold 2 | single signer able to ship alone |

In the development setup on this repository's test bench, the operator, both release signers and the node are separate Secure Enclave keys on one Mac. In a deployment they are on separate devices, as in the table.

## 7. Development-board lock-down (classic ESP32 only)

**This hardens development units. It does not make them production units** (section 2). Every step below is irreversible and needs the owner's explicit approval, per device. Nothing here has been executed. Rehearse the whole sequence on a spare board first. This is the only board right now, so it stays unlocked.

The order follows Espressif's bootloader-driven flow, where the device generates its own keys. The flash-encryption key is generated by the chip's RNG and burned read- and write-protected, so no copy of it ever exists outside the chip. The host-generated-key flow (`espsecure generate-flash-encryption-key` + `espefuse burn-key`) puts a raw key in a file. That breaks our rule, so it is not used.

| # | Step | Command / setting | Locks permanently | Verify | Risks |
|---|---|---|---|---|---|
| 0 | Pre-flight | `espefuse -p PORT summary` and `espefuse -p PORT dump` saved; minimum chip revision v3.0 in menuconfig; partition table without `factory`/`test`; add an `nvs_keys` partition flagged `encrypted`; check the larger bootloader still fits below the partition table, and if not move `CONFIG_PARTITION_TABLE_OFFSET` | nothing | saved output | bootloader overlapping the partition table |
| 1 | Secure-boot signing key in hardware | RSA-3072 key generated inside a PKCS#11 HSM (`pip install 'esptool[hsm]'`); sign with `espsecure sign-data --version 2 --hsm --hsm-config hsm.cfg`; or detached: `idf.py secure-sign-data --pub-key pub.pem --signature sig.bin`; build with `CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=n` | nothing yet | `espsecure verify-signature --version 2 --hsm ...` | **only one digest and no revocation on ESP32**: losing the HSM key ends all updates |
| 2 | Build configuration | `CONFIG_SECURE_BOOT=y` (V2), `CONFIG_SECURE_FLASH_ENC_ENABLED=y` mode **Release**, `CONFIG_SECURE_FLASH_CHECK_ENC_EN_IN_APP=y`, `CONFIG_NVS_ENCRYPTION=y`, `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y` + `CONFIG_BOOTLOADER_APP_SECURE_VERSION=N`; leave all `*_ALLOW_JTAG`, `*_ALLOW_ROM_BASIC`, `*_ALLOW_EFUSE_RD_DIS`, `SECURE_FLASH_UART_BOOTLOADER_ALLOW_*` off; ROM download mode left enabled for this first boot (closed in step 5) | nothing yet | menuconfig review | none until first boot |
| 3 | First boot (the bootloader burns these) | flash the signed plaintext bootloader, partition table and app; reset with uninterrupted power | BLOCK2 = secure-boot key digest, `ABS_DONE_1`; `JTAG_DISABLE`; `CONSOLE_DEBUG_DISABLE`; write-protect on `RD_DIS`; BLOCK1 = RNG flash-encryption key, read- and write-protected; `FLASH_CRYPT_CONFIG = 0xF`; `DISABLE_DL_ENCRYPT`, `DISABLE_DL_DECRYPT`, `DISABLE_DL_CACHE`; `FLASH_CRYPT_CNT` bit 0 (write-protected in Release) | espefuse summary: `ABS_DONE_1 = True`, BLOCK1 shows `??` (read-protected), `FLASH_CRYPT_CNT = 1` write-protected, `FLASH_CRYPT_CONFIG = 15`, `DISABLE_DL_* = True`, `JTAG_DISABLE = True`; the boot log reports secure boot and Release-mode flash encryption (capture the exact lines on the rehearsal unit) | **power loss during the first encryption pass corrupts the flash**; an unsigned or wrongly signed bootloader bricks; plaintext reflash afterwards soft-bricks |
| 4 | Anti-rollback | set in step 2; burned when the app confirms an update (`esp_ota_mark_app_valid_cancel_rollback`) | `SECURE_VERSION` bits in BLOCK3 (32 increments at most) | espefuse `SECURE_VERSION` | never write-protect BLOCK3, or the version can never be raised again |
| 5 | Close ROM download mode (last) | `espefuse -p PORT burn-efuse UART_DOWNLOAD_DIS` (v3 only), or `esp_efuse_disable_rom_download_mode()` from the app | serial flashing and espefuse access, permanently | GPIO0 held low at reset no longer enters download mode | **from here only signed OTA can update the device**; firmware with no working OTA path is a permanent brick |

**What the hardened development board then guarantees:**

- **Remote attacker:** only signed firmware runs and no downgrade is possible, so a remote compromise would need a bug in the firmware itself.
- **USB attacker:** no download mode, no JTAG, no ROM console, and flash dumps are ciphertext.
- **Lab attacker:** still wins, through AR2022-003 and AR2023-005.

Sources (accessed 2026-10-11): ESP-IDF Security Features Enablement Workflows (latest); ESP-IDF v5.5 Secure Boot v2, Flash Encryption and OTA/anti-rollback guides; esptool espsecure HSM docs; ESP-IDF v5.5 source `bootloader_support/src/esp32/secure_boot_secure_features.c` and `flash_encryption_secure_features.c`; Espressif advisories AR2022-003, AR2023-005, AR2025-004; NVD CVE-2019-17391.

Not verified: the exact boot-log strings; whether the ESP32 menuconfig offers a "secure download mode" choice (it is an S2/C3+ feature; we use step 5 instead); the exact flash part suffix.

## 8. Production lock-down (C5 / P4)

This will be written and verified against those chips' own documentation and advisories when the boards arrive (PENDING.md). It differs from section 7 in several ways:

- the key is generated by the Key Manager;
- the signing key digest has revocable slots (three on newer chips);
- the hardware glitch detector is enabled;
- secure download mode is available;
- the ESP-TEE attestation service is used.
