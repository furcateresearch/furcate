#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "fl_crypto.h"
#include "fl_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

// Derives the leaf's P-256 identity from its silicon fingerprint and eFuse
// MAC. Fails closed: with no fingerprint there is no identity this boot.
esp_err_t fl_identity_init(void);
bool fl_identity_ready(void);
const uint8_t *fl_identity_pub(void);    // 65 bytes
const uint8_t *fl_identity_id(void);     // 32 bytes, SHA-256 of the public key
const char *fl_identity_id_hex(void);    // first 16 bytes as hex
bool fl_identity_sign(const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]);
// Writes the attestation evidence (TLV) for HELLO.
void fl_identity_evidence(fl_wbuf_t *w);
const char *fl_identity_assurance(void);

// Builds the S3 identity rollover record (fl_rollover.h) for this leaf: the
// identifier-derived key (old) and the eFuse-HMAC key (successor) both sign.
// The operator countersignature is added by the parent. `seq` must be higher
// than every sequence this leaf has built before (kept in NVS). Returns the
// record length, or 0 with *why set. Only the S3 backend with a burned HMAC
// key builds a record; every other backend refuses.
size_t fl_identity_rollover_record(uint32_t seq, uint64_t not_before, uint64_t not_after, uint8_t *out, size_t cap,
                                   const char **why);

#ifdef __cplusplus
}
#endif
