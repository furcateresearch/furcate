#pragma once
// The arithmetic of the SRAM fingerprint, with no device calls, so the host
// tests run the same code the leaf runs: choosing cells at enrollment,
// rebuilding the secret from a later reading, and the key check that tells a
// wrong reconstruction from a right one.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FL_PUF_BITS 256          // secret bits reconstructed from the fingerprint
#define FL_PUF_REP 7             // cells per secret bit (majority vote)
#define FL_PUF_REGION_BYTES 2048

// Helper data: which cells carry each secret bit and their parities. Public
// by design; the secret is the cell values.
typedef struct {
    uint16_t pos[FL_PUF_BITS][FL_PUF_REP];
    uint8_t parity[FL_PUF_BITS];
} fl_puf_helper_t;

#define FL_PUF_CHECK_LEN 16
// Version 3 helper data: the version-2 layout, the region address it was
// enrolled at, and a check value over the secret. Sent to the parent after
// enrollment so it can be put back after the flash is erased.
typedef struct {
    uint32_t magic;                       // FL_PUF_BLOB_MAGIC
    uint32_t addr;                        // physical address of the region
    fl_puf_helper_t h;
    uint8_t check[FL_PUF_CHECK_LEN];      // first bytes of SHA-256(domain || secret)
} fl_puf_blob_t;
#define FL_PUF_BLOB_MAGIC 0x33424846u     // "FHB3"

// Picks FL_PUF_BITS groups of FL_PUF_REP cells out of the cells that never
// changed (bit set in stable), spread across the region, and records the
// parities against the enrollment reading ref. False if too few cells.
bool fl_puf_core_enroll(const uint8_t *ref, const uint8_t *stable, fl_puf_helper_t *h);

// Majority vote per group against a later reading. cells_flipped counts the
// cells that disagreed with the vote, bits_corrected the groups with any.
void fl_puf_core_reconstruct(const fl_puf_helper_t *h, const uint8_t *reading, uint8_t out[FL_PUF_BITS / 8],
                             uint16_t *cells_flipped, uint16_t *bits_corrected);

void fl_puf_core_check(const uint8_t secret[FL_PUF_BITS / 8], uint8_t check[FL_PUF_CHECK_LEN]);
bool fl_puf_core_check_ok(const uint8_t secret[FL_PUF_BITS / 8], const uint8_t check[FL_PUF_CHECK_LEN]);

// Structural check of a blob received from outside (positions inside the
// region, magic, address). It does not prove the blob matches this chip; the
// check value does that at the next reconstruction.
bool fl_puf_blob_valid(const fl_puf_blob_t *b, uint32_t region_addr);

// Builds a version 3 blob from existing version 2 helper data and the secret
// rebuilt from a good reading: the adopt step for leaves enrolled before the
// check value existed. Same helper data bit for bit, plus the address and the
// check. False if the helper data is structurally invalid.
bool fl_puf_core_adopt(const fl_puf_helper_t *h, const uint8_t secret[FL_PUF_BITS / 8], uint32_t region_addr,
                       fl_puf_blob_t *out);

#ifdef __cplusplus
}
#endif
