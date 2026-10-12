# Gateway board interfaces (Raspberry Pi class)

Agreed 2026-10-12 between the Furcate core and the board OS. The board OS provides them; furcated consumes them.

## Firmware signing broker

- Socket: `/run/furcate-os/fwcrypto.sock`, unix SOCK_STREAM, mode 0660, group `furcate-fwcrypto`. furcated runs with `SupplementaryGroups=furcate-fwcrypto`. The broker also checks `SO_PEERCRED`.
- One JSON object per line: a request, then a response.
- `{"op":"sign","key_id":1,"alg":"ecdsa-p256-sha256","msg_b64":"..."}` → `{"ok":true,"key_id":1,"sig_der_b64":"...","sig_raw_b64":"..."}`. The broker hashes the message with SHA-256 and signs with OTP key 1. `sig_raw` is r||s, 64 bytes. The message is at most 1 MiB.
- `{"op":"pubkey","key_id":1}` → `{"ok":true,"key_id":1,"spki_der_b64":"..."}`.
- Errors: `{"ok":false,"error":"..."}`.
- Only `sign` and `pubkey` exist, and only for key 1. There is no private-key export and no key generation.

## Power status

`/run/furcate-os/power.status`, JSON, rewritten atomically every 5 s:

```
{"ts":unix_s,"supply_max_current_ma":1500,"usb_high_current":false,
 "undervoltage_now":bool,"undervoltage_since_boot":bool,"freq_capped_now":bool,
 "throttled_now":bool,"soft_temp_limit_now":bool,"throttled_raw":"0x...",
 "ext5v_v":5.08,"soc_temp_c":52.1,"load_shed":bool,"shed_since":unix_s|null,
 "cpu_max_khz":2400000}
```

`/run/furcate-os/shed-load` exists while load is being shed. A missing or stale file (older than 15 s) means "not measured", never "healthy".

## Journal upload

`systemd-journal-upload` to `http://10.90.0.20:19532/upload` (journal-remote's default port), over the overlay only. It is off until the node is on `fur0`. The URL comes from `/etc/furcate/node.conf`, key `JOURNAL_REMOTE_URL`. The controller runs `systemd-journal-remote` bound to its overlay address, with the firewall open on `fur0` only, a per-host directory and a retention cap.
