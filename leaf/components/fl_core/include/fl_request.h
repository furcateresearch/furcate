#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fl_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// A leaf-signed request to the model gateway on the cell's head
// (furcate docs/interfaces/leaf-gateway-request.md).
//
// The leaf signs SHA-256 of the canonical request
//
//   furcate-request/1\n<METHOD>\n<target>\n<sha256(body) hex>\n<nonce>\n<expires_at>\n
//
// with its identity key, and sends the header
//
//   X-Furcate-Credential: leaf:p256:<02|03 + x, hex>:<nonce>.<expires_at>.<r || s, hex>
//
// This module is pure: it builds the strings and calls the signer it is
// given. It holds no key.

#define FL_REQ_GATEWAY_PORT 8750
#define FL_REQ_VALIDITY_S 60
#define FL_REQ_NONCE_MIN 8
#define FL_REQ_NONCE_MAX 64
#define FL_REQ_TARGET_MAX 256
#define FL_REQ_HOLDER_LEN (5 + 66)  // "p256:" + 33-byte compressed point in hex
// "leaf:" holder ":" nonce "." expires "." signature
#define FL_REQ_CRED_MAX (5 + FL_REQ_HOLDER_LEN + 1 + FL_REQ_NONCE_MAX + 1 + 20 + 1 + 128 + 1)
#define FL_REQ_CANON_MAX (18 + 5 + FL_REQ_TARGET_MAX + 1 + 65 + FL_REQ_NONCE_MAX + 1 + 21 + 1)

typedef bool (*fl_req_signer_t)(const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]);

// 8-64 characters of A-Z a-z 0-9 - _.
bool fl_req_nonce_ok(const char *nonce);
// GET or POST (upper case), to /health or /v1/..., printable ASCII with no
// space, so nothing can be smuggled onto the request line.
bool fl_req_method_ok(const char *method);
bool fl_req_target_ok(const char *target);

// The canonical request. Returns its length, or 0 when an argument is
// refused or it does not fit.
size_t fl_req_canonical(const char *method, const char *target, const uint8_t *body, size_t body_len,
                        const char *nonce, uint64_t expires_at, char *out, size_t cap);

// "p256:" and the compressed SEC1 point, from the 65-byte uncompressed one.
bool fl_req_holder(const uint8_t pub[FL_PUB_LEN], char out[FL_REQ_HOLDER_LEN + 1]);

// Rewrites s as n - s when s is in the upper half (the low-S form the
// reference client writes; the gateway accepts either).
void fl_req_low_s(uint8_t sig[FL_SIG_LEN]);

// The X-Furcate-Credential value: canonical request, SHA-256, sign, low-S,
// spell. Returns its length, or 0 on any refusal or signing failure.
size_t fl_req_credential(const uint8_t pub[FL_PUB_LEN], fl_req_signer_t sign, const char *method,
                         const char *target, const uint8_t *body, size_t body_len, const char *nonce,
                         uint64_t expires_at, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
