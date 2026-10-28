// Leaf key derivation from ESP32-S3 silicon values. See fl_derive.h.

#include "fl_derive.h"

#include <stdio.h>
#include <string.h>

static bool all_same(const uint8_t *p, size_t n, uint8_t v) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return false;
    return true;
}

static bool expand(fl_derive_hkdf_t kdf, fl_derive_scalar_ok_t ok, const char *salt, const uint8_t *ikm, size_t il,
                   uint8_t priv[32]) {
    char info[32];
    for (int ctr = 0; ctr < 16; ctr++) {
        snprintf(info, sizeof info, "furcate-leaf p256 %d", ctr);
        kdf((const uint8_t *)salt, strlen(salt), ikm, il, info, priv, 32);
        if (ok(priv)) return true;
    }
    return false;
}

bool fl_derive_from_identifiers(fl_derive_hkdf_t kdf, fl_derive_scalar_ok_t ok, const uint8_t mac[6],
                                const uint8_t uid[FL_DERIVE_UID_LEN], uint8_t priv[32]) {
    if (all_same(uid, FL_DERIVE_UID_LEN, 0x00) || all_same(uid, FL_DERIVE_UID_LEN, 0xff)) return false;
    uint8_t ikm[FL_DERIVE_UID_LEN + 6];
    memcpy(ikm, uid, FL_DERIVE_UID_LEN);
    memcpy(ikm + FL_DERIVE_UID_LEN, mac, 6);
    return expand(kdf, ok, "furcate-leaf identity s3 identifiers v1", ikm, sizeof ikm, priv);
}

bool fl_derive_from_hmac(fl_derive_hkdf_t kdf, fl_derive_scalar_ok_t ok, const uint8_t hmac_out[32],
                         const uint8_t mac[6], uint8_t priv[32]) {
    if (all_same(hmac_out, 32, 0x00)) return false;
    uint8_t ikm[32 + 6];
    memcpy(ikm, hmac_out, 32);
    memcpy(ikm + 32, mac, 6);
    return expand(kdf, ok, "furcate-leaf identity s3 hmac v1", ikm, sizeof ikm, priv);
}
