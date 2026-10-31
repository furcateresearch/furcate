"""Chip profiles: what is known about a chip and revision, as data.

A profile states the identity source, the lock-down rules that apply, and the advisories and errata this repository
has read, each with a source. It says only what was read: `advisories_checked` is the date the advisory list was last
compared with the vendor's own pages, or None when it has not been. A chip with no profile, or a profile that has
not been checked, is reported as unchecked, never as clean.

The operator names the profile of each leaf in the head config ({"profiles": {"<leaf id hex>": "<profile name>"}}),
because a leaf does not report its chip model. A new chip is a new entry here, or an entry in a JSON file loaded
with `load_extra`; nothing else changes. See docs/CHIP-ADVISORIES-2026-10-31.md for the sources.
"""

from __future__ import annotations

import json

SCHEMA = "furcate-chip-profile/1"

PROFILES: dict[str, dict] = {
    "esp32-classic-v3": {
        "chip": "ESP32-D0WD-V3", "identity": "silicon fingerprint (no fuse-held key)",
        "lockdown": {"secure_boot": {"allowed": ["rsa-v2"], "forbidden": []},
                     "notes": ["UART download disable and DISABLE_DL_ENCRYPT burned only when the board is final"]},
        "advisories_checked": "2026-10-31",
        "advisories": [{"id": "AR2023-005", "cve": "CVE-2023-35818",
                        "summary": "one EM glitch reaches ROM Download Mode and bypasses Secure Boot and Flash Encryption",
                        "status": "hardware flaw, no fix on this revision",
                        "source": "https://www.usenix.org/system/files/woot24-delvaux.pdf"}]},
    "esp32-s3": {
        "chip": "ESP32-S3", "identity": "eFuse HMAC key (HMAC_UP), unreadable",
        "lockdown": {"secure_boot": {"allowed": ["rsa-v2"], "forbidden": []},
                     "notes": ["secure boot and flash encryption burns are separate steps and not done on the lab board"]},
        "advisories_checked": "2026-10-31",
        "advisories": [
            {"id": "AR2022-004", "summary": "USB-OTG download stays open unless a download-disable eFuse is set; USB-Serial-JTAG download has its own bit",
             "status": "burn EFUSE_DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE separately; burn EFUSE_DIS_USB_OTG_DOWNLOAD_MODE (chips from date code 2219) unless ENABLE_SECURITY_DOWNLOAD, DIS_USB_OTG or DIS_DOWNLOAD_MODE is programmed",
             "source": "https://documentation.espressif.com/AR2022-004%20Security%20Advisory%20for%20USB_OTG%20&%20USB_Serial_JTAG%20Download%20Functions%20of%20ESP32-S3%20Series%20Products%20EN.pdf"},
            {"id": "USBOTG-4289", "summary": "USB-OTG download unavailable on chips before date code 2219 (eFuse bit set by default)",
             "status": "download over USB-Serial-JTAG works; fixed in some batches of v0.2",
             "source": "https://docs.espressif.com/projects/esp-chip-errata/en/latest/esp32s3/03-errata-description/index.html"},
            {"id": "ANALOG-160", "summary": "chip permanently damaged if BIAS_SLEEP = 0 and PD_CUR = 1 (ULP or touch sensor in sleep)",
             "status": "bypassed in ESP-IDF v4.4.2+ and v5.0+; no hardware fix scheduled",
             "source": "https://docs.espressif.com/projects/esp-chip-errata/en/latest/esp32s3/03-errata-description/index.html"}],
        "other_errata_titles_read": ["CACHE-126", "RTC-126", "LCD-239", "RMT-176", "TOUCH-100", "ADC-183"]},
    "esp32-p4-v3.2": {
        "chip": "ESP32-P4 revision v3.2", "identity": "eFuse HMAC key block (Key Manager is not available)",
        "lockdown": {"secure_boot": {"allowed": ["rsa-v2"], "forbidden": ["ecdsa-v2"]},
                     "notes": ["flash encryption: set pseudo-round strength and clock randomization to the highest options",
                               "flash encryption resists remote attackers, not a lab with a power probe"]},
        "advisories_checked": "2026-10-31",
        "advisories": [
            {"id": "AR2026-006", "summary": "ROM may accept invalid ECDSA Secure Boot signatures; ECDSA Secure Boot disabled",
             "status": "use RSA Secure Boot v2; fix promised in a future hardware ECO",
             "source": "https://docs.espressif.com/projects/esp-idf/en/stable/esp32p4/security/secure-boot-v2.html"},
            {"id": "ECDSA_DS-836", "summary": "ECDSA peripheral accepts signatures with r or s equal to 0 or n",
             "status": "no fix scheduled; workaround RSA_DS",
             "source": "https://docs.espressif.com/projects/esp-chip-errata/en/latest/esp32p4/_tags/v3-2.html"},
            {"id": "ROM-816", "summary": "device hang when the flash power-on sequence runs twice with rom_download_xpd_on set",
             "status": "see the erratum", "source": "same errata page"},
            {"id": "AR2026-001", "summary": "CPA side channel on XTS-AES pseudo-round (named for C5, may apply to P4)",
             "status": "mitigations only", "source": "https://documentation.espressif.com/AR2026-001_Security_Advisory_Concerning_Bypassing_Pseudo-round_Mechanism_of_XTS-AES_Using_CPA_Attack_on_ESP32-C5_EN.html"}]},
    "esp32-c5": {
        "chip": "ESP32-C5", "identity": "eFuse HMAC key block (Key Manager is not available)",
        "lockdown": {"secure_boot": {"allowed": ["rsa-v2"], "forbidden": ["ecdsa-v2"]},
                     "notes": ["flash encryption: highest pseudo-round strength and clock randomization"]},
        "advisories_checked": "2026-10-31",
        "advisories": [
            {"id": "AR2026-006", "summary": "ROM may accept invalid ECDSA Secure Boot signatures; ECDSA Secure Boot disabled",
             "status": "use RSA Secure Boot v2", "source": "https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/security/secure-boot-v2.html"},
            {"id": "FLASH-938", "summary": "flash manual encryption may fail when the CPU runs at 240 MHz (v1.0, v1.2)",
             "status": "workaround: CPU at 160 MHz or lower while encrypting; no fix scheduled",
             "source": "https://docs.espressif.com/projects/esp-chip-errata/en/latest/esp32c5/03-errata-description/index.html"},
            {"id": "ECC-833", "summary": "forcing ECC memory power-down makes ECDSA_DS report any signature valid (v1.0, v1.2)",
             "status": "workaround: use RSA_DS; to be fixed in the next chip revision",
             "source": "https://docs.espressif.com/projects/esp-chip-errata/en/latest/esp32c5/03-errata-description/index.html"},
            {"id": "HUK-576", "summary": "inrush at power-on can make the first HUK recovery fail, so the ROM may not derive flash encryption keys (v0.0 to v1.0)",
             "status": "no workaround; fixed in v1.2 (ROM retries)",
             "source": "https://docs.espressif.com/projects/esp-chip-errata/en/latest/esp32c5/03-errata-description/index.html"},
            {"id": "SRAM-436", "summary": "internal SRAM may be corrupted after digital peripheral power-down (v1.0)",
             "status": "ESP-IDF 5.5+ disables the power-down on v1.0; fixed in hardware from v1.2",
             "source": "https://docs.espressif.com/projects/esp-chip-errata/en/latest/esp32c5/03-errata-description/index.html"},
            {"id": "AR2026-001", "summary": "CPA side channel recovers XTS-AES flash encryption keys",
             "status": "mitigations only, no complete fix",
             "source": "https://documentation.espressif.com/AR2026-001_Security_Advisory_Concerning_Bypassing_Pseudo-round_Mechanism_of_XTS-AES_Using_CPA_Attack_on_ESP32-C5_EN.html"}]},
    "raspberry-pi-5": {
        "chip": "Raspberry Pi 5", "identity": "firmware-held OTP device key through the signing broker (device class); a discrete TPM would make it tpm",
        "lockdown": {"notes": ["no TPM on the lab board"]}, "advisories_checked": None, "advisories": []},
}


def profile(name):
    """-> the profile for describe, or a marker that says the name is unknown. Never None for a named profile."""
    if name is None:
        return None
    p = PROFILES.get(name)
    if p is None:
        return {"schema": SCHEMA, "name": name, "known": False}
    return dict(p, schema=SCHEMA, name=name, known=True, checked=p["advisories_checked"] is not None)


def load_extra(path: str) -> int:
    """Adds or replaces profiles from a JSON file {name: profile}. A malformed entry raises ValueError, changes nothing."""
    with open(path) as fh:
        extra = json.load(fh)
    staged = {}
    for name, e in extra.items():
        if not isinstance(e, dict) or "chip" not in e or "advisories" not in e or "advisories_checked" not in e:
            raise ValueError("profile %r needs chip, advisories and advisories_checked" % name)
        staged[name] = e
    PROFILES.update(staged)
    return len(staged)
