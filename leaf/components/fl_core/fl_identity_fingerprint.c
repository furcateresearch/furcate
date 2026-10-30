// Leaf identity: a P-256 key derived on every boot from the SRAM start-up
// fingerprint and the factory MAC in eFuse. It is never stored. Only the
// fingerprint's helper data (which positions to read, and their parities)
// is kept in NVS.

#include "fl_identity.h"

#include <stdio.h>
#include <string.h>
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "fl_puf.h"

static const char *TAG = "fl-identity";

static uint8_t s_priv[32];
static uint8_t s_pub[FL_PUB_LEN];
static uint8_t s_id[32];
static char s_id_hex[33];
static bool s_ready;
static fl_puf_stats_t s_puf;
static uint32_t s_derive_us;

esp_err_t fl_identity_init(void) {
    uint8_t secret[FL_PUF_BITS / 8];
    esp_err_t e = fl_puf_secret(secret, &s_puf);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "no silicon fingerprint this boot (%s); identity unavailable", esp_err_to_name(e));
        return e;
    }
    int64_t t0 = esp_timer_get_time();
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    uint8_t ikm[sizeof secret + 6];
    memcpy(ikm, secret, sizeof secret);
    memcpy(ikm + sizeof secret, mac, 6);
    fl_wipe(secret, sizeof secret);

    char info[32];
    for (int ctr = 0; ctr < 16; ctr++) {
        snprintf(info, sizeof info, "furcate-leaf p256 %d", ctr);
        fl_hkdf((const uint8_t *)"furcate-leaf identity v1", 24, ikm, sizeof ikm, info, s_priv, 32);
        if (fl_p256_scalar_ok(s_priv)) break;
    }
    fl_wipe(ikm, sizeof ikm);
    if (!fl_p256_pub(s_priv, s_pub)) return ESP_FAIL;
    fl_sha256(s_pub, FL_PUB_LEN, s_id);
    for (int i = 0; i < 16; i++) sprintf(s_id_hex + 2 * i, "%02x", s_id[i]);
    s_derive_us = (uint32_t)(esp_timer_get_time() - t0);
    s_ready = true;
    ESP_LOGI(TAG, "leaf id %s (fingerprint: %u cells flipped, %u bits corrected, bias %u/1000)", s_id_hex,
             s_puf.cells_flipped, s_puf.bits_corrected, s_puf.ones_permille);
    return ESP_OK;
}

bool fl_identity_ready(void) { return s_ready; }
const uint8_t *fl_identity_pub(void) { return s_pub; }
const uint8_t *fl_identity_id(void) { return s_id; }
const char *fl_identity_id_hex(void) { return s_id_hex; }

bool fl_identity_sign(const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]) {
    return s_ready && fl_p256_sign(s_priv, hash, sig);
}

const char *fl_identity_assurance(void) {
    // Fingerprint-derived key on a part with no secure boot or flash
    // encryption burned: real silicon binding, but software-held while it
    // runs and replaceable firmware. Reported as such, never more.
    bool sb = esp_efuse_read_field_bit(ESP_EFUSE_ABS_DONE_1);
    uint32_t fe = 0;
    esp_efuse_read_field_blob(ESP_EFUSE_FLASH_CRYPT_CNT, &fe, 7);
    if (sb && (__builtin_popcount(fe) & 1)) return "silicon-fingerprint+secure-boot";
    return "silicon-fingerprint/development";
}

void fl_identity_evidence(fl_wbuf_t *w) {
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    esp_chip_info_t ci;
    esp_chip_info(&ci);
    uint32_t fe = 0;
    esp_efuse_read_field_blob(ESP_EFUSE_FLASH_CRYPT_CNT, &fe, 7);
    uint32_t flags = 0;
    flags |= esp_efuse_read_field_bit(ESP_EFUSE_ABS_DONE_1) ? 1u : 0;
    flags |= (__builtin_popcount(fe) & 1) ? 2u : 0;
    flags |= esp_efuse_read_field_bit(ESP_EFUSE_DISABLE_JTAG) ? 4u : 0;
    flags |= esp_efuse_read_field_bit(ESP_EFUSE_UART_DOWNLOAD_DIS) ? 8u : 0;
    const esp_app_desc_t *app = esp_app_get_description();

    fl_w_bytes(w, 1, mac, 6);
    fl_w_u16(w, 2, ci.revision);
    fl_w_u32(w, 3, flags);
    fl_w_str(w, 4, fl_identity_assurance());
    fl_w_str(w, 5, app->version);
    fl_w_bytes(w, 6, app->app_elf_sha256, 32);
    fl_w_u16(w, 7, s_puf.ones_permille);
    fl_w_u16(w, 8, s_puf.enroll_stable_permille);
    fl_w_u16(w, 9, s_puf.cells_flipped);
    fl_w_u16(w, 10, s_puf.bits_corrected);
    fl_w_u32(w, 11, s_puf.sleep_cycles);
    fl_w_u8(w, 12, s_puf.enrolled_now);
    fl_w_u32(w, 13, s_derive_us);
    fl_w_u32(w, 14, FL_FW_SEQ);
}

size_t fl_identity_rollover_record(uint32_t seq, uint64_t not_before, uint64_t not_after, uint8_t *out, size_t cap,
                                   const char **why) {
    (void)seq; (void)not_before; (void)not_after; (void)out; (void)cap;
    if (why) *why = "this identity backend has no rollover";
    return 0;
}
