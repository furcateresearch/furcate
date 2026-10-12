# Leaf attachment record

Agreed 2026-10-12 between the Furcate core and the leaf firmware. The leaf firmware writes the record; `furcatectl cell leaf` reads it and the cell's head checks it with the same code (`furcate_sense::leaf::Attachment::from_record`) before naming the leaf in a signed link.

## Canonical form

One JSON object:

```json
{
  "leaf_id": "1d3d319e958177e5a4f2d8fb58c11cfe",
  "parent": "pi-lab",
  "public_key": "p256:03749d5173ee808e288b9aca1d31293c6af71d9cf83e819e562c296213e40cdc54",
  "attached_at": 1791783303,
  "key_custody": {
    "kind": "sram-fingerprint",
    "lockdown": {
      "secure_boot": false,
      "flash_encryption": false,
      "download_disabled": false,
      "jtag_disabled": false
    }
  }
}
```

- `leaf_id`: the leaf's name. For a P-256 leaf it is derived from the key: the hex of the first 16 bytes of the SHA-256 of the 65-byte uncompressed point. A record that names a P-256 leaf any other way is refused.
- `parent`: the head the leaf attached to, by name or by key.
- `public_key`: `ed25519:<hex>` (32 bytes) or `p256:<hex>`, a SEC1 point compressed or uncompressed or a DER SubjectPublicKeyInfo. Links always carry the compressed point. A bare hex key is Ed25519.
- `attached_at`: seconds since the epoch.
- `key_custody`: how the signing key is held. `kind` is one of:
  - `stored`: kept in flash.
  - `readable-identifiers`: derived only from values any code on the part can read (factory MAC, chip ID, flash ID).
  - `sram-fingerprint`: rebuilt on every boot from the SRAM start-up pattern and helper data.
  - `fuse-key`: held in read-protected eFuse or a key peripheral (Key Manager, ECDSA peripheral) and never read back.

  `lockdown` states the four fuses; an absent fuse is read as open, and a misspelt one is refused.

Any other field (trust anchors, firmware, capabilities, link) is the leaf's own description. The head leaves it alone.

## The class is derived, never stated

The record does not carry a class. The head derives it from `key_custody` in one place (`furcate_identity::LeafKeyCustody::class`):

| key custody | class |
| --- | --- |
| `stored`, `readable-identifiers` | `soft` |
| `sram-fingerprint`, any of the four fuses open | `soft` |
| `sram-fingerprint`, secure boot, flash encryption, download disabled and JTAG disabled | `device` |
| `fuse-key` | `device` |
| no `key_custody` | `soft` |

A record that also states `assurance` is accepted only when it equals the derived class.

## Which leaves a cell takes

Each cell has a leaf floor, `leaf_min_class`: the lowest class a leaf may hold to attach there. It is `device` unless the operator sets it otherwise, and it lives in the head's link, signed by the controller on an operator-signed request, so neither the head nor anyone with its files can lower it. A leaf below the floor is refused, and the refusal names the cell and the command that changes it:

```
furcatectl cell leaf-floor --anchor cell-anchor.json --class soft --controller <addr:port>
```

This re-enrols the head with the new floor and the same end date, using the operator's sealed key; install the new anchor on the head. `cell enrol` and `cell renew --anchor` take `--leaf-min-class` too, and a renewal keeps the floor it had.

The leaf floor has nothing to do with node key custody: `custody.allow_soft` and `custody.tpm_less` decide only which machines hold the site's keys, and a cell admitting `soft` leaves changes neither.

The class is recorded in the leaf's link, the cell tree, the roll-up (`leaf_classes`), `/cells`, `/cells/view` and `furcatectl cell show`, as derived. The floor is shown in `cell show`, `/cells` and `/cells/view`.

## Firmware form read today

`docs/attach/home-lab-leaf.json` in the leaf firmware (df1e831) is read as published:

- a bare hex `public_key` with `leaf.public_key_type` `ecdsa-p256-uncompressed`;
- no `key_custody`, but `leaf.assurance_reported`: `silicon-fingerprint/development` reads as `sram-fingerprint` with every fuse open, and `silicon-fingerprint+secure-boot` as `sram-fingerprint` with secure boot and flash encryption on and download mode and JTAG open, since the string says nothing of those two. Any other string is refused.
- `assurance` `soft`, which matches the derived class.

That record grades `soft`.

## What the leaf firmware should change

1. Write `key_custody` with all four `lockdown` fuses. The firmware already reads them for its HELLO evidence (secure boot, flash encryption, JTAG, UART download). Without them a fully locked part still grades `soft`.
2. Write `public_key` as `p256:<hex>`, so the type travels with the key.
3. Stop writing `assurance`, or keep it equal to the derived class.
4. The hardware key backend (ESP32-C5/P4) should report `fuse-key` once it holds its key in the Key Manager or ECDSA peripheral.
