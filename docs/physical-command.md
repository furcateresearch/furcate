# Physical command and receipt: the shadow-mode wire format

The down path. A simulation platform (Living Worlds core) proposes a setpoint; a site gate (Furcate) decides and answers with a signed receipt. Only shadow mode exists: the site records what it would do and actuates nothing. A request to actuate is refused with the typed code `actuation_not_approved`; there is no actuator driver, and the only executor is a shadow one. Version lives in the payload (`v`), never in a URL: the route is `/physical/commands`.

Both records are JSON in RFC 8785 canonical form. A gate accepts a document only if the bytes it received ARE the canonical form of what they parse to (no whitespace, keys in UTF-16 code unit order, integers as integers, other numbers in ECMAScript shortest form, strings escaped only where required). That one rule rules out duplicate keys, reordered keys, escapes where a literal would do, `1.0` for `1`, a byte order mark and trailing data. Integer-valued numbers of magnitude 2^53 or more are refused. Unknown members are refused.

## Signatures

Every signature is Ed25519 over `SHA-256( len(domain) || domain || len(msg) || msg )`, lengths as 8 bytes big-endian, `msg` the canonical bytes of the record without its `signature` member. Keys are written `ed25519:<64 lowercase hex>`, signatures as 128 lowercase hex. Verification is strict (small-order keys and non-reduced signatures refused).

| Record | Signer | Domain |
|---|---|---|
| physical-command | enrolled simulation-platform key | `lw-physical/command/v1` |
| twin-band-certificate | enrolled simulation-platform key | `lw-physical/twin-cert/v1` |
| physical-receipt | the site key | `furcate/physical-receipt/v1` |

The platform signer is a hardware-backed key held by the platform's operators and enrolled at the site by the site owner. No private key is ever stored in a repository; golden vectors use public test seeds (32 bytes of `0x4c` for the platform, `0x53` for the site).

## physical-command (v1)

```
{ "format": "physical-command", "v": 1,
  "command_id": id, "tenant": id, "site_id": id,
  "target": { "actuator_id": id, "scope": id },
  "kind": "setpoint",
  "body": { "quantity": name, "unit": name, "value": number },
  "issued_at_ms": int, "not_before_ms": int, "expires_at_ms": int,
  "nonce": 32 hex, "command_seq": int >= 1,
  "mode": "shadow" | "actuate",
  "policy_sha256": 64 hex, "model_sha256": 64 hex, "birth_record_sha256": 64 hex (optional),
  "envelope": { "min": number, "max": number, "max_rate_per_s": number >= 0 },
  "twin_cert": { twin-band-certificate },
  "signer": key, "signature": 128 hex }
```
`id` is 1 to 64 characters of `[A-Za-z0-9._:-]`; `name` is 1 to 32 characters of `[a-z_]`. Only `kind: setpoint` is accepted in v1; other kinds (`trajectory`, `model_update`, `calibration_update`, `mode`) are reserved and refused as `unsupported_kind`. Times are milliseconds since the Unix epoch. `command_seq` is strictly increasing per site over accepted commands. `policy_sha256` is the hash of the signed operator policy the sender believes is in force; `model_sha256` is the model that produced the setpoint; `birth_record_sha256`, when present, binds the model to its signed birth record (world, twin, run, solved-band certificate at release). `envelope` is the sender's clipped envelope; the site enforces its own, independent and stricter-wins.

## twin-band-certificate (v1)

The twin's solved-band certificate, issued by the platform from the twin state and signed by it.
```
{ "format": "twin-band-certificate", "v": 1, "tenant": id, "twin_id": id, "version": int,
  "ranges": [ { "quantity": name, "unit": name, "min": number, "max": number } ],
  "valid_from_ms": int, "valid_until_ms": int, "fidelity_score": number in [0,1],
  "signer": key, "signature": 128 hex }
```

## Gate order (first failure is the answer)

1. canonical and well formed (`malformed`, `not_canonical`, `unsupported_format`, `unsupported_kind`)
2. `wrong_site`, `wrong_tenant`
3. kill switch for the site or actuator in force: `kill_switch_active` (decision `killed`)
4. signer enrolled (`signer_not_enrolled`) and signature valid (`bad_signature`)
5. mode: `actuate` is `actuation_not_approved`
6. freshness: `issued_at_ms` not beyond now plus the site skew and now at or after `not_before_ms` (`not_yet_valid`); now before `expires_at_ms` and no older than the site's maximum age (`expired`, decision `expired`); lifetime within the site maximum (`ttl_too_long`)
7. `command_seq` greater than the last accepted (`replayed_sequence`)
8. `policy_sha256` equals the site policy (`policy_hash_mismatch`); `model_sha256` in the approved set (`model_not_approved`); where the site requires a birth record, present (`birth_record_required`) and approved (`birth_record_not_approved`)
9. certificate: signer enrolled (`twin_cert_signer_not_enrolled`), signature (`twin_cert_bad_signature`), same tenant (`twin_cert_wrong_tenant`), `valid_from_ms` reached (`twin_cert_not_yet_valid`), unexpired and valid through the command's expiry (`twin_cert_expired`), fidelity at or above the site minimum (`twin_fidelity_low`), value inside a certified range for its quantity and unit (`outside_certified_range`)
10. envelopes: inside the sender's envelope (`outside_lw_envelope`); the site has a limit for the actuator and quantity (`no_site_limit`, default deny); inside the site limit (`outside_site_envelope`); change per second since the last accepted setpoint within both rates (`rate_exceeded`)

Only an accepted command advances the sequence. Decision values: `executed` (reserved, never produced), `shadowed`, `denied`, `expired`, `killed`.

## physical-receipt (v1)

One per decision, refusals included, appended to the site ledger chain before it is returned.
```
{ "format": "physical-receipt", "v": 1, "command_id": id | "unparsed", "tenant", "site_id",
  "decision": "executed|shadowed|denied|expired|killed", "error_code": code | null,
  "mode": string | null, "command_sha256": sha256 of the bytes received,
  "policy_sha256": the site's, "model_sha256": string | null, "birth_record_sha256": string | null,
  "envelope_applied": { "min", "max" } | null  (intersection of both envelopes, accepted only),
  "decided_at_ms": int, "receipt_seq": int, "site_key": key,
  "ledger": { "seq": int, "entry_hash": 64 hex }, "signature": 128 hex }
```
The ledger entry (kind `command`) has the actor `gate:<site_id>`, the subject the command id, and the result `decision:code:digest`, where digest is SHA-256 of the canonical receipt without its `ledger` and `signature` members. The receipt carries the entry's sequence and hash, and the site signs the whole.

## Error codes

`malformed not_canonical unsupported_format unsupported_kind wrong_site wrong_tenant kill_switch_active signer_not_enrolled bad_signature actuation_not_approved expired not_yet_valid ttl_too_long replayed_sequence policy_hash_mismatch model_not_approved birth_record_required birth_record_not_approved twin_cert_signer_not_enrolled twin_cert_bad_signature twin_cert_wrong_tenant twin_cert_expired twin_cert_not_yet_valid twin_fidelity_low outside_certified_range outside_lw_envelope no_site_limit outside_site_envelope rate_exceeded`

## Golden vector

`tests/fixtures/physical-command.golden.json` (crates/open/furcate-command in Furcate, tests/fixtures in core): the unsigned inputs, the canonical signed command, the receipt for it and the receipt for its replay. Both sides rebuild the command from the inputs with the public test seed and require the same bytes; the Furcate side also regenerates the receipts. The file is identical in both repositories; a test on each side fails on drift.

## Numbers

Non-integer numbers are written in the ECMAScript shortest form, the nearest digits of the shortest length and the even one on a tie. A reader must parse exactly (round to nearest) and write that form back; `tests/fixtures/canonical-numbers.json` holds 4,000 numbers generated by Node that both sides must render to exactly the text given. (Parsing that is off by one unit in the last place changes the canonical bytes and so the signature; the Furcate gate enables the exact parser for that reason.)

## Offline verification of the action history

`furcate-history-verify <chain.json> <checkpoint.json> [--site-key <key> <receipt.json>...]` checks a site's ledger chain against a quoted checkpoint `{size, head, merkle_root}` (the Merkle root is over the entry hashes). It finds a deleted, reordered or altered entry (the chain no longer verifies), a history shorter than the quote, a different history behind the same quote (head or root differ), and two histories that fork. For a receipt it checks the site's signature, that its `ledger.seq` and `entry_hash` are the entry in the chain, and that the entry's result carries the digest of that receipt. With an inclusion proof instead of the chain it checks the receipt's entry hash is the leaf at its position under the quoted root. It cannot check that the physical effect matched the command.
