#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fl_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Grant roles (bitmap).
enum {
    FL_ROLE_READ = 1,
    FL_ROLE_COMMAND = 2,
    FL_ROLE_MODEL = 4,
    FL_ROLE_CONFIG = 8,
    FL_ROLE_OTA = 16,
};

// A grant: "FLG1" | node public key (65) | roles (1) | generation (u32 BE) |
// leaf scope (32; all zero = any leaf). Signed (DER ECDSA over SHA-256) by a
// pinned operator key.
#define FL_GRANT_LEN (4 + FL_PUB_LEN + 1 + 4 + 32)

typedef struct {
    uint8_t node_pub[FL_PUB_LEN];
    uint8_t roles;
    uint32_t generation;
} fl_grant_t;

void fl_trust_init(void);
// Returns NULL on success or a reason string.
const char *fl_trust_check_grant(const uint8_t *grant, size_t gl, const uint8_t *sig, size_t sl,
                                 const uint8_t leaf_id[32], fl_grant_t *out);
// A signed envelope: TLV with T_BODY and one or more T_SIG (signer index u8 + DER).
// Requires the release threshold of distinct pinned release keys.
const char *fl_trust_check_release(const uint8_t *env, size_t n, const uint8_t **body, size_t *bl,
                                   int *signers);
// Revocation: operator-signed body "FLR1" | minimum grant generation (u32 BE).
const char *fl_trust_apply_revocation(const uint8_t *env, size_t n);
// True when one pinned operator key signed SHA-256(body) (DER ECDSA).
bool fl_trust_operator_signed(const uint8_t *body, size_t n, const uint8_t *sig, size_t sl);
uint32_t fl_trust_min_generation(void);
int fl_trust_release_threshold(void);
uint32_t fl_trust_last_verify_us(void);

#ifdef __cplusplus
}
#endif
