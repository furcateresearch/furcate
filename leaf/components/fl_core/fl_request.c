// Leaf-signed gateway request: canonical form and credential spelling
// (fl_request.h). No ESP-IDF dependency, so the host test builds it as is.

#include "fl_request.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char HEX[] = "0123456789abcdef";

static void hex(const uint8_t *p, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = HEX[p[i] >> 4];
        out[2 * i + 1] = HEX[p[i] & 15];
    }
    out[2 * n] = 0;
}

bool fl_req_nonce_ok(const char *nonce) {
    if (!nonce) return false;
    size_t n = strlen(nonce);
    if (n < FL_REQ_NONCE_MIN || n > FL_REQ_NONCE_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        char c = nonce[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
            return false;
    }
    return true;
}

bool fl_req_method_ok(const char *method) {
    return method && (strcmp(method, "GET") == 0 || strcmp(method, "POST") == 0);
}

bool fl_req_target_ok(const char *target) {
    if (!target) return false;
    size_t n = strlen(target);
    if (n == 0 || n > FL_REQ_TARGET_MAX) return false;
    if (strcmp(target, "/health") != 0 && strncmp(target, "/v1/", 4) != 0) return false;
    for (size_t i = 0; i < n; i++)
        if (target[i] <= 0x20 || target[i] >= 0x7F) return false;
    return true;
}

size_t fl_req_canonical(const char *method, const char *target, const uint8_t *body, size_t body_len,
                        const char *nonce, uint64_t expires_at, char *out, size_t cap) {
    if (!fl_req_method_ok(method) || !fl_req_target_ok(target) || !fl_req_nonce_ok(nonce)) return 0;
    if (body_len && !body) return 0;
    uint8_t d[32];
    char dh[65];
    fl_sha256(body_len ? body : (const uint8_t *)"", body_len, d);
    hex(d, 32, dh);
    int n = snprintf(out, cap, "furcate-request/1\n%s\n%s\n%s\n%s\n%" PRIu64 "\n", method, target, dh, nonce,
                     expires_at);
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

bool fl_req_holder(const uint8_t pub[FL_PUB_LEN], char out[FL_REQ_HOLDER_LEN + 1]) {
    if (!pub || pub[0] != 0x04) return false;
    uint8_t c[33];
    c[0] = 0x02 | (pub[64] & 1);
    memcpy(c + 1, pub + 1, 32);
    memcpy(out, "p256:", 5);
    hex(c, 33, out + 5);
    return true;
}

// The order of the P-256 group and half of it, big-endian.
static const uint8_t N[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
                              0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
static const uint8_t HALF_N[32] = {0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B,
                                   0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8};

void fl_req_low_s(uint8_t sig[FL_SIG_LEN]) {
    uint8_t *s = sig + 32;
    if (memcmp(s, HALF_N, 32) <= 0) return;
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int v = (int)N[i] - (int)s[i] - borrow;
        borrow = v < 0;
        s[i] = (uint8_t)(v + (borrow ? 256 : 0));
    }
}

size_t fl_req_credential(const uint8_t pub[FL_PUB_LEN], fl_req_signer_t sign, const char *method,
                         const char *target, const uint8_t *body, size_t body_len, const char *nonce,
                         uint64_t expires_at, char *out, size_t cap) {
    char canon[FL_REQ_CANON_MAX];
    size_t cl = fl_req_canonical(method, target, body, body_len, nonce, expires_at, canon, sizeof canon);
    char holder[FL_REQ_HOLDER_LEN + 1];
    if (!cl || !sign || !fl_req_holder(pub, holder)) return 0;
    uint8_t h[32], sig[FL_SIG_LEN];
    fl_sha256(canon, cl, h);
    if (!sign(h, sig)) return 0;
    fl_req_low_s(sig);
    char sh[2 * FL_SIG_LEN + 1];
    hex(sig, FL_SIG_LEN, sh);
    int n = snprintf(out, cap, "leaf:%s:%s.%" PRIu64 ".%s", holder, nonce, expires_at, sh);
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}
