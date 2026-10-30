// Helper data escrow messages and refusal rules. See fl_puf_escrow.h.

#include "fl_puf_escrow.h"

#include <string.h>

static void put32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (24 - 8 * i));
}
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

void fl_puf_blob_pack(const fl_puf_blob_t *b, uint8_t o[FL_PUF_BLOB_WIRE_LEN]) {
    put32(o, b->magic);
    put32(o + 4, b->addr);
    o += 8;
    for (int i = 0; i < FL_PUF_BITS; i++)
        for (int j = 0; j < FL_PUF_REP; j++) {
            *o++ = (uint8_t)(b->h.pos[i][j] >> 8);
            *o++ = (uint8_t)b->h.pos[i][j];
        }
    memcpy(o, b->h.parity, FL_PUF_BITS);
    o += FL_PUF_BITS;
    memcpy(o, b->check, FL_PUF_CHECK_LEN);
}

bool fl_puf_blob_unpack(const uint8_t in[FL_PUF_BLOB_WIRE_LEN], uint32_t region_addr, fl_puf_blob_t *out) {
    memset(out, 0, sizeof *out);
    out->magic = get32(in);
    out->addr = get32(in + 4);
    const uint8_t *p = in + 8;
    for (int i = 0; i < FL_PUF_BITS; i++)
        for (int j = 0; j < FL_PUF_REP; j++, p += 2) out->h.pos[i][j] = (uint16_t)(p[0] << 8 | p[1]);
    memcpy(out->h.parity, p, FL_PUF_BITS);
    p += FL_PUF_BITS;
    memcpy(out->check, p, FL_PUF_CHECK_LEN);
    return fl_puf_blob_valid(out, region_addr);
}

void fl_puf_blob_digest(const uint8_t wire[FL_PUF_BLOB_WIRE_LEN], uint8_t out[32]) {
    uint8_t buf[25 + FL_PUF_BLOB_WIRE_LEN];
    memcpy(buf, "furcate-leaf puf blob v1\n", 25);
    memcpy(buf + 25, wire, FL_PUF_BLOB_WIRE_LEN);
    fl_sha256(buf, sizeof buf, out);
}

static bool all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i]) return false;
    return true;
}

// ---- export -----------------------------------------------------------

size_t fl_puf_escrow_export_build(const fl_puf_blob_t *b, const uint8_t leaf_id[32], const uint8_t mac[6],
                                  fl_esc_signer_t sign, uint8_t *out, size_t cap) {
    const size_t total = FL_ESC_EXPORT_BODY_LEN + FL_SIG_LEN + FL_PUF_BLOB_WIRE_LEN;
    if (!b || !sign || cap < total || !fl_puf_blob_valid(b, b->addr)) return 0;
    uint8_t *wire = out + FL_ESC_EXPORT_BODY_LEN + FL_SIG_LEN;
    fl_puf_blob_pack(b, wire);
    memcpy(out, "FHX1", 4);
    memcpy(out + 4, leaf_id, 32);
    memcpy(out + 36, mac, 6);
    fl_puf_blob_digest(wire, out + 42);
    uint8_t h[32];
    fl_sha256(out, FL_ESC_EXPORT_BODY_LEN, h);
    if (!sign(h, out + FL_ESC_EXPORT_BODY_LEN)) return 0;
    return total;
}

const char *fl_puf_escrow_export_verify(const uint8_t *msg, size_t len, const uint8_t leaf_pub[FL_PUB_LEN],
                                        uint32_t region_addr, fl_puf_blob_t *blob, uint8_t digest[32],
                                        uint8_t leaf_id[32], uint8_t mac[6]) {
    if (!msg || len != FL_ESC_EXPORT_BODY_LEN + FL_SIG_LEN + FL_PUF_BLOB_WIRE_LEN || memcmp(msg, "FHX1", 4) != 0)
        return "malformed message";
    uint8_t id[32], h[32];
    fl_sha256(leaf_pub, FL_PUB_LEN, id);
    if (memcmp(id, msg + 4, 32) != 0) return "leaf id does not match the roster key";
    fl_sha256(msg, FL_ESC_EXPORT_BODY_LEN, h);
    if (!fl_p256_verify(leaf_pub, h, msg + FL_ESC_EXPORT_BODY_LEN)) return "leaf signature invalid";
    const uint8_t *wire = msg + FL_ESC_EXPORT_BODY_LEN + FL_SIG_LEN;
    if (!fl_puf_blob_unpack(wire, region_addr, blob)) return "blob invalid";
    fl_puf_blob_digest(wire, digest);
    if (memcmp(digest, msg + 42, 32) != 0) return "blob does not match its digest";
    memcpy(leaf_id, msg + 4, 32);
    memcpy(mac, msg + 36, 6);
    return NULL;
}

// ---- operator commands ---------------------------------------------------

static bool operator_ok(const fl_escrow_dev_t *d, const uint8_t *body, size_t bl, const uint8_t *sig, size_t sl) {
    uint8_t h[32];
    fl_sha256(body, bl, h);
    for (size_t i = 0; i < d->n_operators; i++)
        if (fl_p256_verify_der(d->operator_pubs[i], h, sig, sl)) return true;
    return false;
}

const char *fl_puf_escrow_check_restore(const uint8_t *msg, size_t len, const fl_escrow_dev_t *d,
                                        fl_puf_blob_t *blob_out, uint32_t *seq_out) {
    const size_t base = FL_ESC_RESTORE_BODY_LEN + 1;
    if (!msg || len < base || memcmp(msg, "FHR1", 4) != 0) return "malformed command";
    size_t ol = msg[FL_ESC_RESTORE_BODY_LEN];
    if (ol < 8 || ol > FL_ESC_OPSIG_MAX || len != base + ol + FL_PUF_BLOB_WIRE_LEN) return "malformed command";
    if (!operator_ok(d, msg, FL_ESC_RESTORE_BODY_LEN, msg + base, ol)) return "operator signature invalid";
    const uint8_t *mac = msg + 4, *replace_id = msg + 10, *leaf_id = msg + 42, *digest = msg + 74;
    uint32_t seq = get32(msg + 106);
    if (memcmp(mac, d->mac, 6) != 0) return "command is for a different chip";
    if (d->last_seq && seq <= d->last_seq) return "replay: sequence not newer";
    // An existing enrollment is replaced only when the command names its id.
    if (d->enrolled && !(d->id_valid && !all_zero(replace_id, 32) && memcmp(replace_id, d->id, 32) == 0))
        return "already enrolled";
    if (all_zero(leaf_id, 32)) return "malformed command";
    const uint8_t *wire = msg + base + ol;
    fl_puf_blob_t b;
    if (!fl_puf_blob_unpack(wire, d->region_addr, &b)) return "blob invalid";
    uint8_t dg[32];
    fl_puf_blob_digest(wire, dg);
    if (memcmp(dg, digest, 32) != 0) return "blob does not match the command";
    if (d->trial_reading) {
        uint8_t secret[FL_PUF_BITS / 8];
        uint16_t flipped = 0;
        fl_puf_core_reconstruct(&b.h, d->trial_reading, secret, &flipped, NULL);
        bool ok = fl_puf_core_check_ok(secret, b.check);
        fl_wipe(secret, sizeof secret);
        if (flipped > FL_ESC_MAX_FLIPPED) return "reading does not match the helper data";
        if (!ok) return "check value mismatch";
    }
    *blob_out = b;
    if (seq_out) *seq_out = seq;
    return NULL;
}

const char *fl_puf_escrow_check_adopt(const uint8_t *msg, size_t len, const fl_escrow_dev_t *d, uint32_t *seq_out) {
    const size_t base = FL_ESC_ADOPT_BODY_LEN + 1;
    if (!msg || len < base || memcmp(msg, "FHA1", 4) != 0) return "malformed command";
    size_t ol = msg[FL_ESC_ADOPT_BODY_LEN];
    if (ol < 8 || ol > FL_ESC_OPSIG_MAX || len != base + ol) return "malformed command";
    if (!operator_ok(d, msg, FL_ESC_ADOPT_BODY_LEN, msg + base, ol)) return "operator signature invalid";
    uint32_t seq = get32(msg + 42);
    if (memcmp(msg + 4, d->mac, 6) != 0) return "command is for a different chip";
    if (d->last_seq && seq <= d->last_seq) return "replay: sequence not newer";
    if (!d->enrolled) return "not enrolled";
    if (d->has_v3) return "already adopted";
    if (!d->id_valid) return "identity not derived this boot";
    if (all_zero(msg + 10, 32) || memcmp(msg + 10, d->id, 32) != 0) return "identity differs from the command";
    if (d->cells_flipped > FL_ESC_ADOPT_MAX_FLIPPED) return "too many cells flipped";
    if (seq_out) *seq_out = seq;
    return NULL;
}

static size_t finish(uint8_t *out, size_t body_len, size_t cap, fl_esc_der_signer_t sign) {
    uint8_t h[32], der[FL_ESC_OPSIG_MAX];
    size_t dl = sizeof der;
    fl_sha256(out, body_len, h);
    if (!sign(h, der, &dl) || dl < 8 || dl > FL_ESC_OPSIG_MAX || cap < body_len + 1 + dl) return 0;
    out[body_len] = (uint8_t)dl;
    memcpy(out + body_len + 1, der, dl);
    return body_len + 1 + dl;
}

size_t fl_puf_escrow_restore_build(const uint8_t mac[6], const uint8_t replace_id[32], const uint8_t leaf_id[32],
                                   const uint8_t wire[FL_PUF_BLOB_WIRE_LEN], uint32_t seq, fl_esc_der_signer_t sign,
                                   uint8_t *out, size_t cap) {
    if (cap < FL_ESC_RESTORE_BODY_LEN + 1 + FL_ESC_OPSIG_MAX + FL_PUF_BLOB_WIRE_LEN) return 0;
    memcpy(out, "FHR1", 4);
    memcpy(out + 4, mac, 6);
    memcpy(out + 10, replace_id, 32);
    memcpy(out + 42, leaf_id, 32);
    fl_puf_blob_digest(wire, out + 74);
    put32(out + 106, seq);
    size_t n = finish(out, FL_ESC_RESTORE_BODY_LEN, cap - FL_PUF_BLOB_WIRE_LEN, sign);
    if (!n) return 0;
    memcpy(out + n, wire, FL_PUF_BLOB_WIRE_LEN);
    return n + FL_PUF_BLOB_WIRE_LEN;
}

size_t fl_puf_escrow_adopt_build(const uint8_t mac[6], const uint8_t leaf_id[32], uint32_t seq,
                                 fl_esc_der_signer_t sign, uint8_t *out, size_t cap) {
    if (cap < FL_ESC_ADOPT_BODY_LEN + 1 + FL_ESC_OPSIG_MAX) return 0;
    memcpy(out, "FHA1", 4);
    memcpy(out + 4, mac, 6);
    memcpy(out + 10, leaf_id, 32);
    put32(out + 42, seq);
    return finish(out, FL_ESC_ADOPT_BODY_LEN, cap, sign);
}
