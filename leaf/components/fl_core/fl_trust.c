// Pinned public keys and the checks that use them.
//
// The leaf holds only public keys: the operator set (who may authorise a
// node) and the release set (who may sign firmware and models). The matching
// private keys live in the operators' passkeys or TPMs and the release
// hosts' TPMs. Nothing secret is shared with the leaf.

#include "fl_trust.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "fl_pinned_keys.h"
#include "fl_wire.h"
#include "nvs.h"

static const char *TAG = "fl-trust";
static uint32_t s_min_gen;
static uint32_t s_verify_us;

void fl_trust_init(void) {
    s_min_gen = FL_PINNED_MIN_GENERATION;
    nvs_handle_t h;
    if (nvs_open("fl-trust", NVS_READONLY, &h) == ESP_OK) {
        uint32_t g;
        if (nvs_get_u32(h, "min_gen", &g) == ESP_OK && g > s_min_gen) s_min_gen = g;
        nvs_close(h);
    }
    ESP_LOGI(TAG, "%d operator keys, %d release keys (threshold %d), minimum grant generation %u",
             FL_PINNED_OPERATOR_COUNT, FL_PINNED_RELEASE_COUNT, FL_PINNED_RELEASE_THRESHOLD, (unsigned)s_min_gen);
}

uint32_t fl_trust_min_generation(void) { return s_min_gen; }
int fl_trust_release_threshold(void) { return FL_PINNED_RELEASE_THRESHOLD; }
uint32_t fl_trust_last_verify_us(void) { return s_verify_us; }

static bool by_operator(const uint8_t hash[32], const uint8_t *sig, size_t sl) {
    int64_t t0 = esp_timer_get_time();
    bool ok = false;
    for (int i = 0; i < FL_PINNED_OPERATOR_COUNT && !ok; i++)
        ok = fl_p256_verify_der(FL_PINNED_OPERATOR[i], hash, sig, sl);
    s_verify_us = (uint32_t)(esp_timer_get_time() - t0);
    return ok;
}

bool fl_trust_operator_signed(const uint8_t *body, size_t n, const uint8_t *sig, size_t sl) {
    uint8_t h[32];
    fl_sha256(body, n, h);
    return by_operator(h, sig, sl);
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

const char *fl_trust_check_grant(const uint8_t *grant, size_t gl, const uint8_t *sig, size_t sl,
                                 const uint8_t leaf_id[32], fl_grant_t *out) {
    if (gl != FL_GRANT_LEN || memcmp(grant, "FLG1", 4) != 0) return "malformed grant";
    uint8_t h[32];
    fl_sha256(grant, gl, h);
    if (!by_operator(h, sig, sl)) return "grant not signed by a pinned operator key";
    memcpy(out->node_pub, grant + 4, FL_PUB_LEN);
    out->roles = grant[4 + FL_PUB_LEN];
    out->generation = be32(grant + 4 + FL_PUB_LEN + 1);
    const uint8_t *scope = grant + 4 + FL_PUB_LEN + 5;
    bool any = true;
    for (int i = 0; i < 32; i++) any &= scope[i] == 0;
    if (!any && memcmp(scope, leaf_id, 32) != 0) return "grant is for a different leaf";
    if (out->generation < s_min_gen) return "grant revoked (generation below minimum)";
    return NULL;
}

const char *fl_trust_check_release(const uint8_t *env, size_t n, const uint8_t **body, size_t *bl,
                                   int *signers) {
    fl_field_t b;
    if (!fl_r_valid(env, n) || !fl_r_find(env, n, T_BODY, 0, &b)) return "malformed signed envelope";
    uint8_t h[32];
    fl_sha256(b.p, b.n, h);
    uint32_t seen = 0;
    int good = 0;
    int64_t t0 = esp_timer_get_time();
    fl_field_t s;
    for (int i = 0; fl_r_find(env, n, T_SIG, i, &s); i++) {
        if (s.n < 9) continue;
        int idx = s.p[0];
        if (idx >= FL_PINNED_RELEASE_COUNT || (seen & (1u << idx))) continue;
        if (fl_p256_verify_der(FL_PINNED_RELEASE[idx], h, s.p + 1, s.n - 1)) {
            seen |= 1u << idx;
            good++;
        }
    }
    s_verify_us = (uint32_t)(esp_timer_get_time() - t0);
    *signers = good;
    if (good < FL_PINNED_RELEASE_THRESHOLD) return "not enough valid release signatures";
    *body = b.p;
    *bl = b.n;
    return NULL;
}

const char *fl_trust_apply_revocation(const uint8_t *env, size_t n) {
    fl_field_t b, s;
    if (!fl_r_valid(env, n) || !fl_r_find(env, n, T_BODY, 0, &b) || !fl_r_find(env, n, T_SIG, 0, &s))
        return "malformed revocation";
    if (b.n != 8 || memcmp(b.p, "FLR1", 4) != 0) return "malformed revocation";
    uint8_t h[32];
    fl_sha256(b.p, b.n, h);
    if (!by_operator(h, s.p, s.n)) return "revocation not signed by a pinned operator key";
    uint32_t g = be32(b.p + 4);
    if (g <= s_min_gen) return "revocation does not raise the minimum generation";
    nvs_handle_t nv;
    if (nvs_open("fl-trust", NVS_READWRITE, &nv) != ESP_OK) return "storage unavailable";
    nvs_set_u32(nv, "min_gen", g);
    nvs_commit(nv);
    nvs_close(nv);
    s_min_gen = g;
    return NULL;
}
