#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// P-256 public keys are SEC1 uncompressed (65 bytes, 0x04 || X || Y).
#define FL_PUB_LEN 65
#define FL_SIG_LEN 64  // raw r || s

typedef struct {
    uint64_t state[64];  // holds a psa_hash_operation_t
} fl_sha256_t;

void fl_sha256_init(fl_sha256_t *c);
void fl_sha256_update(fl_sha256_t *c, const void *p, size_t n);
void fl_sha256_final(fl_sha256_t *c, uint8_t out[32]);
void fl_sha256(const void *p, size_t n, uint8_t out[32]);
void fl_hkdf(const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il, const char *info, uint8_t *out,
             size_t ol);

// AES-256-GCM, 12-byte nonce, 16-byte tag appended to the ciphertext.
bool fl_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in, size_t n, uint8_t *out);
bool fl_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in, size_t n, uint8_t *out);

void fl_crypto_init(void);
bool fl_p256_pub(const uint8_t priv[32], uint8_t pub[FL_PUB_LEN]);
bool fl_p256_keygen(uint8_t priv[32], uint8_t pub[FL_PUB_LEN]);
bool fl_p256_sign(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]);
bool fl_p256_verify(const uint8_t pub[FL_PUB_LEN], const uint8_t hash[32], const uint8_t sig[FL_SIG_LEN]);
// Accepts a DER ECDSA signature (as produced by the Secure Enclave or a TPM).
bool fl_p256_verify_der(const uint8_t pub[FL_PUB_LEN], const uint8_t hash[32], const uint8_t *der, size_t n);
bool fl_p256_ecdh(const uint8_t priv[32], const uint8_t peer[FL_PUB_LEN], uint8_t shared[32]);
// Reduces 32 bytes of key material to a valid P-256 scalar; false if it must be retried.
bool fl_p256_scalar_ok(const uint8_t priv[32]);

void fl_wipe(void *p, size_t n);

#ifdef __cplusplus
}
#endif
