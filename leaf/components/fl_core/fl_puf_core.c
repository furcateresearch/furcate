// See fl_puf_core.h.
#include "fl_puf_core.h"

#include <string.h>
#include "fl_crypto.h"

static int bit_at(const uint8_t *buf, int pos) { return (buf[pos >> 3] >> (pos & 7)) & 1; }

bool fl_puf_core_enroll(const uint8_t *ref, const uint8_t *stable, fl_puf_helper_t *h) {
    int stable_bits = 0;
    for (int i = 0; i < FL_PUF_REGION_BYTES; i++) stable_bits += __builtin_popcount(stable[i]);
    if (stable_bits < FL_PUF_BITS * FL_PUF_REP) return false;
    int stride = stable_bits / (FL_PUF_BITS * FL_PUF_REP);
    int seen = 0, k = 0;
    for (int p = 0; p < FL_PUF_REGION_BYTES * 8 && k < FL_PUF_BITS * FL_PUF_REP; p++) {
        if (!bit_at(stable, p)) continue;
        if (seen++ % stride) continue;
        h->pos[k / FL_PUF_REP][k % FL_PUF_REP] = (uint16_t)p;
        k++;
    }
    if (k < FL_PUF_BITS * FL_PUF_REP) return false;
    for (int b = 0; b < FL_PUF_BITS; b++) {
        uint8_t par = 0;
        int first = bit_at(ref, h->pos[b][0]);
        for (int j = 1; j < FL_PUF_REP; j++) par |= (uint8_t)((bit_at(ref, h->pos[b][j]) ^ first) << (j - 1));
        h->parity[b] = par;
    }
    return true;
}

void fl_puf_core_reconstruct(const fl_puf_helper_t *h, const uint8_t *reading, uint8_t out[FL_PUF_BITS / 8],
                             uint16_t *cells_flipped, uint16_t *bits_corrected) {
    memset(out, 0, FL_PUF_BITS / 8);
    int flipped = 0, corrected = 0;
    for (int b = 0; b < FL_PUF_BITS; b++) {
        int votes1 = 0;
        // Each cell votes for the value of the first cell at enrollment.
        for (int j = 0; j < FL_PUF_REP; j++) {
            int v = bit_at(reading, h->pos[b][j]);
            if (j > 0) v ^= (h->parity[b] >> (j - 1)) & 1;
            votes1 += v;
        }
        int bit = votes1 * 2 > FL_PUF_REP;
        int minority = bit ? FL_PUF_REP - votes1 : votes1;
        flipped += minority;
        if (minority) corrected++;
        out[b >> 3] |= (uint8_t)(bit << (b & 7));
    }
    if (cells_flipped) *cells_flipped = (uint16_t)flipped;
    if (bits_corrected) *bits_corrected = (uint16_t)corrected;
}

void fl_puf_core_check(const uint8_t secret[FL_PUF_BITS / 8], uint8_t check[FL_PUF_CHECK_LEN]) {
    static const char dom[] = "furcate-leaf puf check v1";
    uint8_t buf[sizeof dom + FL_PUF_BITS / 8], d[32];
    memcpy(buf, dom, sizeof dom);
    memcpy(buf + sizeof dom, secret, FL_PUF_BITS / 8);
    fl_sha256(buf, sizeof buf, d);
    memcpy(check, d, FL_PUF_CHECK_LEN);
    fl_wipe(buf, sizeof buf);
    fl_wipe(d, sizeof d);
}

bool fl_puf_core_check_ok(const uint8_t secret[FL_PUF_BITS / 8], const uint8_t check[FL_PUF_CHECK_LEN]) {
    uint8_t c[FL_PUF_CHECK_LEN];
    fl_puf_core_check(secret, c);
    uint8_t diff = 0;
    for (int i = 0; i < FL_PUF_CHECK_LEN; i++) diff |= (uint8_t)(c[i] ^ check[i]);
    return diff == 0;
}

bool fl_puf_blob_valid(const fl_puf_blob_t *b, uint32_t region_addr) {
    if (b->magic != FL_PUF_BLOB_MAGIC || b->addr != region_addr) return false;
    for (int i = 0; i < FL_PUF_BITS; i++) {
        if (b->h.parity[i] >> (FL_PUF_REP - 1)) return false;
        for (int j = 0; j < FL_PUF_REP; j++) {
            if (b->h.pos[i][j] >= FL_PUF_REGION_BYTES * 8) return false;
            for (int k = 0; k < j; k++)
                if (b->h.pos[i][k] == b->h.pos[i][j]) return false;
        }
    }
    return true;
}
