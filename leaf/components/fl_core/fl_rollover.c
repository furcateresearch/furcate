// S3 identity rollover record: build and verify. See fl_rollover.h.

#include "fl_rollover.h"

#include <string.h>

static void put32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (24 - 8 * i));
}
static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) << 32 | get32(p + 4); }

uint8_t fl_rollover_level(const char *a) {
    static const struct {
        const char *s;
        uint8_t l;
    } T[] = {{"silicon-id/development", FL_LEVEL_SILICON_ID_DEV},
             {"silicon-fingerprint/development", FL_LEVEL_FINGERPRINT_DEV},
             {"efuse-hmac/development", FL_LEVEL_HMAC_DEV},
             {"silicon-fingerprint+secure-boot", FL_LEVEL_FINGERPRINT_SB},
             {"efuse-hmac+secure-boot", FL_LEVEL_HMAC_SB}};
    if (!a) return 0;
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++)
        if (strcmp(a, T[i].s) == 0) return T[i].l;
    return 0;
}

void fl_rollover_hash(const char *role, const uint8_t *body, uint8_t out[32]) {
    uint8_t buf[25 + 16 + 1 + FL_ROLLOVER_BODY_LEN];
    size_t rl = strlen(role), n = 0;
    if (rl > 16) rl = 16;
    memcpy(buf, "furcate-leaf rollover v1 ", 25);
    n = 25;
    memcpy(buf + n, role, rl);
    n += rl;
    buf[n++] = '\n';
    memcpy(buf + n, body, FL_ROLLOVER_BODY_LEN);
    fl_sha256(buf, n + FL_ROLLOVER_BODY_LEN, out);
}

static void body_write(const fl_rollover_t *r, uint8_t *b) {
    memcpy(b, "FLI1", 4);
    memcpy(b + 4, r->old_pub, FL_PUB_LEN);
    memcpy(b + 4 + FL_PUB_LEN, r->new_pub, FL_PUB_LEN);
    uint8_t *p = b + 4 + 2 * FL_PUB_LEN;
    put32(p, r->seq);
    put64(p + 4, r->not_before);
    put64(p + 12, r->not_after);
    p[20] = r->old_level;
    p[21] = r->new_level;
    p[22] = 0;
}

size_t fl_rollover_build(const fl_rollover_t *r, fl_rollover_signer_t old_sign, fl_rollover_signer_t new_sign,
                         uint8_t *out, size_t cap) {
    if (!r || !old_sign || !new_sign || cap < FL_ROLLOVER_BODY_LEN + 2 * FL_SIG_LEN + 1) return 0;
    if (r->old_pub[0] != 0x04 || r->new_pub[0] != 0x04) return 0;
    if (memcmp(r->old_pub, r->new_pub, FL_PUB_LEN) == 0) return 0;
    if (r->seq == 0 || r->not_after <= r->not_before) return 0;
    if (r->old_level == 0 || r->old_level > FL_LEVEL_MAX || r->new_level == 0 || r->new_level > FL_LEVEL_MAX)
        return 0;
    body_write(r, out);
    uint8_t h[32];
    fl_rollover_hash("old", out, h);
    if (!old_sign(h, out + FL_ROLLOVER_BODY_LEN)) return 0;
    fl_rollover_hash("new", out, h);
    if (!new_sign(h, out + FL_ROLLOVER_BODY_LEN + FL_SIG_LEN)) return 0;
    out[FL_ROLLOVER_BODY_LEN + 2 * FL_SIG_LEN] = 0;
    return FL_ROLLOVER_BODY_LEN + 2 * FL_SIG_LEN + 1;
}

size_t fl_rollover_attach_operator(uint8_t *rec, size_t len, size_t cap, const uint8_t *der, size_t der_len) {
    const size_t base = FL_ROLLOVER_BODY_LEN + 2 * FL_SIG_LEN + 1;
    if (len != base || rec[base - 1] != 0 || der_len < 8 || der_len > FL_ROLLOVER_OPSIG_MAX || cap < base + der_len)
        return 0;
    rec[base - 1] = (uint8_t)der_len;
    memcpy(rec + base, der, der_len);
    return base + der_len;
}

static bool is_id(const uint8_t pub[FL_PUB_LEN], const uint8_t id[32]) {
    uint8_t d[32];
    fl_sha256(pub, FL_PUB_LEN, d);
    return memcmp(d, id, 32) == 0;
}

const char *fl_rollover_verify(const uint8_t *rec, size_t len, const fl_rollover_policy_t *p, fl_rollover_t *out) {
    const size_t base = FL_ROLLOVER_BODY_LEN + 2 * FL_SIG_LEN + 1;
    if (!rec || !p || len < base || memcmp(rec, "FLI1", 4) != 0) return "malformed record";
    size_t ol = rec[base - 1];
    if (len != base + ol || (ol != 0 && (ol < 8 || ol > FL_ROLLOVER_OPSIG_MAX))) return "malformed record";
    fl_rollover_t r;
    memcpy(r.old_pub, rec + 4, FL_PUB_LEN);
    memcpy(r.new_pub, rec + 4 + FL_PUB_LEN, FL_PUB_LEN);
    const uint8_t *q = rec + 4 + 2 * FL_PUB_LEN;
    r.seq = get32(q);
    r.not_before = get64(q + 4);
    r.not_after = get64(q + 12);
    r.old_level = q[20];
    r.new_level = q[21];
    if (q[22] != 0) return "malformed record";
    if (!fl_p256_pub_valid(r.old_pub) || !fl_p256_pub_valid(r.new_pub)) return "malformed record";

    // Who is being retired, and into what.
    if (!is_id(r.old_pub, p->old_id)) return "old key is not the roster leaf";
    if (memcmp(r.old_pub, r.new_pub, FL_PUB_LEN) == 0) return "successor equals the old key";
    uint8_t nid[32];
    fl_sha256(r.new_pub, FL_PUB_LEN, nid);
    for (size_t i = 0; i < p->n_known; i++)
        if (memcmp(p->known_ids[i], nid, 32) == 0) return "successor is another leaf";
    if (p->old_retired && memcmp(p->retired_successor_id, nid, 32) != 0)
        return "already rolled to a different successor";

    // Signatures: authority of the old key, possession of the new one.
    uint8_t h[32];
    fl_rollover_hash("old", rec, h);
    if (!fl_p256_verify(r.old_pub, h, rec + FL_ROLLOVER_BODY_LEN)) return "old signature invalid";
    fl_rollover_hash("new", rec, h);
    if (!fl_p256_verify(r.new_pub, h, rec + FL_ROLLOVER_BODY_LEN + FL_SIG_LEN)) return "successor signature invalid";

    // Operator approval. Required by policy because the identifier-derived old
    // key can be computed by anyone holding the part.
    if (ol) {
        fl_rollover_hash("operator", rec, h);
        bool ok = false;
        for (size_t i = 0; i < p->n_operators && !ok; i++)
            ok = fl_p256_verify_der(p->operator_pubs[i], h, rec + base, ol);
        if (!ok) return "operator approval invalid";
    } else if (p->require_operator) {
        return "operator approval missing";
    }

    // Freshness and replay.
    if (r.seq == 0 || r.seq <= p->last_seq) return "replay: sequence not newer";
    if (r.not_after <= r.not_before || r.not_after - r.not_before > FL_ROLLOVER_MAX_WINDOW_S)
        return "validity window too long";
    if (p->now < r.not_before || p->now > r.not_after) return "outside validity window";

    // Assurance: nothing claimed beyond what is proven, nothing lost.
    if (r.old_level == 0 || r.old_level > FL_LEVEL_MAX || r.new_level == 0 || r.new_level > FL_LEVEL_MAX)
        return "unknown level";
    if (r.old_level != p->roster_old_level) return "old level mismatch";
    if (r.new_level > p->proven_new_level) return "successor level exceeds proven";
    if (r.new_level < r.old_level) return "assurance downgrade";

    if (out) *out = r;
    return NULL;
}
