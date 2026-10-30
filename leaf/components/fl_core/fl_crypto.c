// Primitives: SHA-256 and AES-GCM through the PSA Crypto API (mbedTLS 4,
// hardware SHA and AES on ESP32), HMAC/HKDF on top of SHA-256, and P-256
// from micro-ecc.

#include "fl_crypto.h"

#include <string.h>
#include "bootloader_random.h"
#include "esp_random.h"
#include "psa/crypto.h"
#include "uECC.h"

_Static_assert(sizeof(psa_hash_operation_t) <= sizeof(((fl_sha256_t *)0)->state), "hash op");

void fl_wipe(void *p, size_t n) {
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

void fl_sha256_init(fl_sha256_t *c) {
    psa_hash_operation_t *op = (psa_hash_operation_t *)c->state;
    *op = psa_hash_operation_init();
    psa_hash_setup(op, PSA_ALG_SHA_256);
}
void fl_sha256_update(fl_sha256_t *c, const void *p, size_t n) {
    psa_hash_update((psa_hash_operation_t *)c->state, p, n);
}
void fl_sha256_final(fl_sha256_t *c, uint8_t out[32]) {
    size_t len;
    psa_hash_finish((psa_hash_operation_t *)c->state, out, 32, &len);
}
void fl_sha256(const void *p, size_t n, uint8_t out[32]) {
    size_t len;
    psa_hash_compute(PSA_ALG_SHA_256, p, n, out, 32, &len);
}

static void hmac(const uint8_t *key, size_t kl, const uint8_t *m1, size_t l1, const uint8_t *m2, size_t l2,
                 uint8_t out[32]) {
    uint8_t k[64] = {0}, pad[64];
    if (kl > 64) fl_sha256(key, kl, k);
    else memcpy(k, key, kl);
    fl_sha256_t c;
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    fl_sha256_init(&c);
    fl_sha256_update(&c, pad, 64);
    fl_sha256_update(&c, m1, l1);
    if (l2) fl_sha256_update(&c, m2, l2);
    fl_sha256_final(&c, out);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    fl_sha256_init(&c);
    fl_sha256_update(&c, pad, 64);
    fl_sha256_update(&c, out, 32);
    fl_sha256_final(&c, out);
    fl_wipe(k, sizeof k);
    fl_wipe(pad, sizeof pad);
}

// RFC 5869
void fl_hkdf(const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il, const char *info, uint8_t *out,
             size_t ol) {
    uint8_t prk[32], t[32 + 64 + 1];
    hmac(salt, sl, ikm, il, NULL, 0, prk);
    size_t il2 = strlen(info), tl = 0, done = 0;
    if (il2 > 64) il2 = 64;
    for (uint8_t i = 1; done < ol; i++) {
        uint8_t blk[32 + 64 + 1];
        size_t bl = 0;
        memcpy(blk, t, tl);
        bl = tl;
        memcpy(blk + bl, info, il2);
        bl += il2;
        blk[bl++] = i;
        hmac(prk, 32, blk, bl, NULL, 0, t);
        tl = 32;
        size_t n = ol - done < 32 ? ol - done : 32;
        memcpy(out + done, t, n);
        done += n;
    }
    fl_wipe(prk, sizeof prk);
    fl_wipe(t, sizeof t);
}

static psa_key_id_t gcm_key(const uint8_t key[32]) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&a, PSA_ALG_GCM);
    psa_key_id_t id = 0;
    if (psa_import_key(&a, key, 32, &id) != PSA_SUCCESS) return 0;
    return id;
}

bool fl_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in, size_t n, uint8_t *out) {
    psa_key_id_t id = gcm_key(key);
    if (!id) return false;
    size_t ol;
    bool ok = psa_aead_encrypt(id, PSA_ALG_GCM, nonce, 12, NULL, 0, in, n, out, n + 16, &ol) == PSA_SUCCESS;
    psa_destroy_key(id);
    return ok && ol == n + 16;
}

bool fl_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in, size_t n, uint8_t *out) {
    if (n < 16) return false;
    psa_key_id_t id = gcm_key(key);
    if (!id) return false;
    size_t ol;
    bool ok = psa_aead_decrypt(id, PSA_ALG_GCM, nonce, 12, NULL, 0, in, n, out, n - 16, &ol) == PSA_SUCCESS;
    psa_destroy_key(id);
    return ok;
}

static int rng(uint8_t *dest, unsigned size) {
    esp_fill_random(dest, size);
    return 1;
}

void fl_crypto_init(void) {
    // Without the radio running, the RNG needs an entropy source enabled.
    bootloader_random_enable();
    psa_crypto_init();
    uECC_set_rng(rng);
}

static const uint8_t P256_N[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
                                   0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

bool fl_p256_scalar_ok(const uint8_t priv[32]) {
    bool zero = true;
    for (int i = 0; i < 32; i++) zero &= priv[i] == 0;
    if (zero) return false;
    return memcmp(priv, P256_N, 32) < 0;
}

bool fl_p256_pub(const uint8_t priv[32], uint8_t pub[FL_PUB_LEN]) {
    pub[0] = 0x04;
    return uECC_compute_public_key(priv, pub + 1, uECC_secp256r1()) == 1;
}

bool fl_p256_keygen(uint8_t priv[32], uint8_t pub[FL_PUB_LEN]) {
    pub[0] = 0x04;
    return uECC_make_key(pub + 1, priv, uECC_secp256r1()) == 1;
}

bool fl_p256_sign(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]) {
    return uECC_sign(priv, hash, 32, sig, uECC_secp256r1()) == 1;
}

bool fl_p256_pub_valid(const uint8_t pub[FL_PUB_LEN]) {
    return pub[0] == 0x04 && uECC_valid_public_key(pub + 1, uECC_secp256r1());
}

bool fl_p256_verify(const uint8_t pub[FL_PUB_LEN], const uint8_t hash[32], const uint8_t sig[FL_SIG_LEN]) {
    if (pub[0] != 0x04) return false;
    return uECC_verify(pub + 1, hash, 32, sig, uECC_secp256r1()) == 1;
}

// DER: 30 len 02 rlen r 02 slen s
static bool der_int(const uint8_t **p, const uint8_t *end, uint8_t out[32]) {
    if (*p + 2 > end || (*p)[0] != 0x02) return false;
    size_t n = (*p)[1];
    const uint8_t *v = *p + 2;
    if (v + n > end || n == 0 || n > 33) return false;
    while (n > 32) {
        if (*v != 0) return false;
        v++;
        n--;
    }
    memset(out, 0, 32);
    memcpy(out + 32 - n, v, n);
    *p = v + n;
    return true;
}

bool fl_p256_verify_der(const uint8_t pub[FL_PUB_LEN], const uint8_t hash[32], const uint8_t *der, size_t n) {
    if (n < 8 || der[0] != 0x30 || der[1] != n - 2) return false;
    const uint8_t *p = der + 2, *end = der + n;
    uint8_t sig[64];
    if (!der_int(&p, end, sig) || !der_int(&p, end, sig + 32) || p != end) return false;
    return fl_p256_verify(pub, hash, sig);
}

bool fl_p256_ecdh(const uint8_t priv[32], const uint8_t peer[FL_PUB_LEN], uint8_t shared[32]) {
    if (peer[0] != 0x04 || !uECC_valid_public_key(peer + 1, uECC_secp256r1())) return false;
    return uECC_shared_secret(peer + 1, priv, shared, uECC_secp256r1()) == 1;
}
