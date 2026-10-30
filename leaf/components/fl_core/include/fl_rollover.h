#pragma once
// S3 identity rollover record, version 1 ("FLI1").
//
// A leaf whose identity key changes (ESP32-S3: the identifier-derived key
// becomes the read-protected HMAC-derived key after an owner burn) would be
// orphaned, because the parent roster pins the leaf id. The rollover record
// is how the old identity authorises the new one so the roster can accept the
// new id and retire the old one. Design and the parent-side rule:
// docs/IDENTITY-ROLLOVER.md. Pure code: no device calls, host-tested.
//
// Body (157 bytes, big-endian):
//   "FLI1" | old public key (65) | successor public key (65) | sequence (u32)
//   | not_before (u64, unix s) | not_after (u64) | old level (u8)
//   | successor level (u8) | reserved (u8, must be 0)
// Record: body | old signature (64, raw r||s) | successor signature (64)
//   | operator signature length (u8, 0 or 8..72) | operator signature (DER)
// Signatures are ECDSA P-256 over SHA-256(domain || body), one domain per
// signer, so a signature made for one role cannot be replayed as another.
//   old:       "furcate-leaf rollover v1 old\n"
//   successor: "furcate-leaf rollover v1 new\n"   (proof of possession)
//   operator:  "furcate-leaf rollover v1 operator\n"  (DER, same operator keys as grants)
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fl_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FL_ROLLOVER_BODY_LEN (4 + FL_PUB_LEN + FL_PUB_LEN + 4 + 8 + 8 + 3)
#define FL_ROLLOVER_OPSIG_MAX 72
#define FL_ROLLOVER_MAX_LEN (FL_ROLLOVER_BODY_LEN + 2 * FL_SIG_LEN + 1 + FL_ROLLOVER_OPSIG_MAX)
#define FL_ROLLOVER_MAX_WINDOW_S (7u * 24u * 3600u)

// Assurance levels, ordered. The order is part of version 1 of the record.
enum {
    FL_LEVEL_NONE = 0,
    FL_LEVEL_SILICON_ID_DEV = 1,       // "silicon-id/development"
    FL_LEVEL_FINGERPRINT_DEV = 2,      // "silicon-fingerprint/development"
    FL_LEVEL_HMAC_DEV = 3,             // "efuse-hmac/development"
    FL_LEVEL_FINGERPRINT_SB = 4,       // "silicon-fingerprint+secure-boot"
    FL_LEVEL_HMAC_SB = 5,              // "efuse-hmac+secure-boot"
    FL_LEVEL_MAX = 5,
};
// The assurance string a leaf reports in its evidence, to its level (0 when unknown).
uint8_t fl_rollover_level(const char *assurance);

typedef struct {
    uint8_t old_pub[FL_PUB_LEN];
    uint8_t new_pub[FL_PUB_LEN];
    uint32_t seq;
    uint64_t not_before, not_after;
    uint8_t old_level, new_level;
} fl_rollover_t;

typedef bool (*fl_rollover_signer_t)(const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]);

// Leaf side. Builds the body and both signatures; the old and successor
// signers are the two identities of the same leaf. Returns the record length
// (no operator signature yet), or 0 on any refusal or signing failure.
size_t fl_rollover_build(const fl_rollover_t *r, fl_rollover_signer_t old_sign, fl_rollover_signer_t new_sign,
                         uint8_t *out, size_t cap);
// Appends an operator countersignature (DER over fl_rollover_operator_hash)
// to a record built without one. Returns the new length or 0.
size_t fl_rollover_attach_operator(uint8_t *rec, size_t len, size_t cap, const uint8_t *der, size_t der_len);
// The digest each role signs.
void fl_rollover_hash(const char *role /* "old", "new", "operator" */, const uint8_t *body, uint8_t out[32]);

// The parent's view when it checks a record. All inputs come from the parent,
// none from the record.
typedef struct {
    uint64_t now;
    uint8_t old_id[32];          // the roster leaf the record claims to retire
    uint8_t roster_old_level;    // level the roster holds for it
    uint8_t proven_new_level;    // level the successor proved in live, verified evidence
    uint32_t last_seq;           // highest sequence accepted for this old id (0 = none)
    bool old_retired;            // this old id was already rolled over
    uint8_t retired_successor_id[32];
    const uint8_t (*known_ids)[32];  // every other roster leaf id (successor may not be one)
    size_t n_known;
    const uint8_t (*operator_pubs)[FL_PUB_LEN];
    size_t n_operators;
    bool require_operator;
} fl_rollover_policy_t;

// Returns NULL when the record is acceptable, else the refusal reason (the
// strings in docs/IDENTITY-ROLLOVER.md section 5; the Python reference returns the
// same ones). On success *out is filled. The caller then records the new
// last_seq, retires the old id and enrols the successor id
// (SHA-256 of the successor public key).
const char *fl_rollover_verify(const uint8_t *rec, size_t len, const fl_rollover_policy_t *p, fl_rollover_t *out);

#ifdef __cplusplus
}
#endif
