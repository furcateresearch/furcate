#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Leaf key derivation for parts that identify themselves through eFuse
// values rather than a start-up pattern (ESP32-S3). Pure functions over their
// inputs, so the same derivation runs in the host tests.
//
// Two sources, never mixed, each under its own domain string:
//   identifiers: the factory MAC and the 128-bit unique ID. Anything that can
//                run on the part, or read it over USB, can compute this key.
//   hmac:        the output of the eFuse HMAC peripheral over a fixed label.
//                The key behind it cannot be read, so this one needs the part.
#define FL_DERIVE_UID_LEN 16

// The caller supplies the key-derivation function so the host tests can run
// this file without the device crypto library.
typedef void (*fl_derive_hkdf_t)(const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il, const char *info,
                                 uint8_t *out, size_t ol);
typedef bool (*fl_derive_scalar_ok_t)(const uint8_t priv[32]);

// Fails (false) when the unique ID is all zero or all ones: an unprogrammed
// field identifies nothing.
bool fl_derive_from_identifiers(fl_derive_hkdf_t kdf, fl_derive_scalar_ok_t ok, const uint8_t mac[6],
                                const uint8_t uid[FL_DERIVE_UID_LEN], uint8_t priv[32]);
bool fl_derive_from_hmac(fl_derive_hkdf_t kdf, fl_derive_scalar_ok_t ok, const uint8_t hmac_out[32],
                         const uint8_t mac[6], uint8_t priv[32]);

// The message the HMAC peripheral is asked to authenticate.
#define FL_DERIVE_HMAC_LABEL "furcate-leaf identity hmac v1"

#ifdef __cplusplus
}
#endif
