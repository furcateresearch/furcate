#pragma once
// Transport and refusal rules for the classic ESP32 helper data escrow
// (version 1 of the messages). Pure code: no device calls, host-tested.
// Message formats, flows and the parent-side rules: docs/PUF-ESCROW.md.
//
//   export   leaf -> parent   "FHX1" | leaf id (32) | eFuse MAC (6) | blob digest (32)
//                              | leaf signature (64, raw, over SHA-256(body)) | blob (3864)
//   restore  parent -> leaf   "FHR1" | MAC (6) | replace id (32) | leaf id (32) | blob digest (32)
//                              | sequence (u32) | operator signature length (u8)
//                              | operator signature (DER over SHA-256(body)) | blob (3864)
//   adopt    parent -> leaf   "FHA1" | MAC (6) | leaf id (32) | sequence (u32)
//                              | operator signature length (u8) | operator signature (DER)
//
// Blob wire form (3864 bytes, big-endian, independent of struct layout):
//   magic u32 | region address u32 | cell positions u16 [256][7] | parities u8 [256] | check (16)
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fl_crypto.h"
#include "fl_puf_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FL_PUF_BLOB_WIRE_LEN (4 + 4 + FL_PUF_BITS * FL_PUF_REP * 2 + FL_PUF_BITS + FL_PUF_CHECK_LEN)
#define FL_ESC_EXPORT_BODY_LEN (4 + 32 + 6 + 32)
#define FL_ESC_RESTORE_BODY_LEN (4 + 6 + 32 + 32 + 32 + 4)
#define FL_ESC_ADOPT_BODY_LEN (4 + 6 + 32 + 4)
#define FL_ESC_OPSIG_MAX 72
// Most cells that may disagree with the enrollment before an adopt is refused
// (a healthy boot flips about 1%; 5% leaves room without adopting a bad boot).
#define FL_ESC_ADOPT_MAX_FLIPPED (FL_PUF_BITS * FL_PUF_REP * 5 / 100)
// The reading-mismatch limit fl_puf.c applies at every boot (15%); a restore
// trial against a retained reading uses the same limit.
#define FL_ESC_MAX_FLIPPED (FL_PUF_BITS * FL_PUF_REP * 15 / 100)

void fl_puf_blob_pack(const fl_puf_blob_t *b, uint8_t out[FL_PUF_BLOB_WIRE_LEN]);
// False unless the bytes decode to a structurally valid blob for this region address.
bool fl_puf_blob_unpack(const uint8_t in[FL_PUF_BLOB_WIRE_LEN], uint32_t region_addr, fl_puf_blob_t *out);
// SHA-256("furcate-leaf puf blob v1\n" || wire bytes)
void fl_puf_blob_digest(const uint8_t wire[FL_PUF_BLOB_WIRE_LEN], uint8_t out[32]);

typedef bool (*fl_esc_signer_t)(const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]);

// Leaf side: the export message for a version 3 blob. Returns its length or 0.
size_t fl_puf_escrow_export_build(const fl_puf_blob_t *b, const uint8_t leaf_id[32], const uint8_t mac[6],
                                  fl_esc_signer_t sign, uint8_t *out, size_t cap);
// Parent reference check of an export message against the leaf's public key
// (from the roster). NULL = acceptable; *blob and digest are filled.
const char *fl_puf_escrow_export_verify(const uint8_t *msg, size_t len, const uint8_t leaf_pub[FL_PUB_LEN],
                                        uint32_t region_addr, fl_puf_blob_t *blob, uint8_t digest[32],
                                        uint8_t leaf_id[32], uint8_t mac[6]);

// What the leaf knows when an operator command arrives.
typedef struct {
    uint8_t mac[6];
    uint32_t region_addr;
    bool enrolled;               // helper2 or helper3 in flash
    bool has_v3;                 // helper3 in flash
    bool id_valid;               // the identity was derived this boot
    uint8_t id[32];              // its id (SHA-256 of the public key)
    uint16_t cells_flipped;      // this boot's reading against the enrollment
    uint32_t last_seq;           // highest operator sequence stored (0 = none)
    const uint8_t *trial_reading;  // the retained start-up reading (2048 bytes) or NULL
    const uint8_t (*operator_pubs)[FL_PUB_LEN];
    size_t n_operators;
} fl_escrow_dev_t;

// Each returns NULL when the command may be executed, else the refusal reason.
// The caller stores *seq_out after a successful execution.
const char *fl_puf_escrow_check_restore(const uint8_t *msg, size_t len, const fl_escrow_dev_t *d,
                                        fl_puf_blob_t *blob_out, uint32_t *seq_out);
const char *fl_puf_escrow_check_adopt(const uint8_t *msg, size_t len, const fl_escrow_dev_t *d, uint32_t *seq_out);

// Operator side (also the reference for the parent): build the commands.
// The signer returns a DER ECDSA signature over the 32-byte hash.
typedef bool (*fl_esc_der_signer_t)(const uint8_t hash[32], uint8_t *der, size_t *der_len);
size_t fl_puf_escrow_restore_build(const uint8_t mac[6], const uint8_t replace_id[32], const uint8_t leaf_id[32],
                                   const uint8_t wire[FL_PUF_BLOB_WIRE_LEN], uint32_t seq, fl_esc_der_signer_t sign,
                                   uint8_t *out, size_t cap);
size_t fl_puf_escrow_adopt_build(const uint8_t mac[6], const uint8_t leaf_id[32], uint32_t seq,
                                 fl_esc_der_signer_t sign, uint8_t *out, size_t cap);

#ifdef __cplusplus
}
#endif
