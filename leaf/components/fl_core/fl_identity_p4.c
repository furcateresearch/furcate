// Leaf identity on ESP32-P4 (Waveshare ESP32-P4-WIFI6), assurance class "soft".
//
// The P4 has hardware key engines (Key Manager, HMAC, ECDSA), but every path
// that binds a key to this die writes an eFuse: a key block and its purpose
// for the HMAC and ECDSA peripherals, and the one-time Key Manager state
// (KM_HUK_GEN_STATE, the deploy-once and lock bits) for a Key Manager key.
// This board is not a sacrificial one, so nothing here writes an eFuse. The
// identity is therefore a P-256 key held in the firmware's own flash (NVS):
//
//   * generated on the chip on first boot from the hardware RNG mixed with
//     the MAC, the unique ID and a timing sample, then kept; an NVS erase
//     makes a new leaf (the old id is gone, it was never derivable);
//   * readable by anyone who can read the flash (flash encryption is off,
//     download mode is open): that is exactly what "soft" says;
//   * signing uses software P-256 (micro-ecc), as on the other targets.
//
// What a burned unit would add is in docs/ESP32-P4-WAVESHARE.md section 9:
// "device" class (key bound to the die, not extractable by software).
// No source, no identity: a failure to store or reload the key fails closed.

#include "fl_identity.h"

#include <stdio.h>
#include <string.h>
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_secure_boot.h"
#include "esp_timer.h"
#include "nvs.h"

static const char *TAG = "fl-identity";

#define NS "fl-id"
#define KEY "k1"

static uint8_t s_priv[32];
static uint8_t s_pub[FL_PUB_LEN];
static uint8_t s_id[32];
static char s_id_hex[33];
static bool s_ready;
static bool s_fresh;

static void mix_seed(uint8_t out[32]) {
    static const uint8_t zero_salt[32] = {0};
    uint8_t ikm[32 + 6 + 16 + 8], uid[16] = {0};
    esp_fill_random(ikm, 32);
    esp_efuse_mac_get_default(ikm + 32);
    esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, uid, sizeof uid * 8);
    memcpy(ikm + 38, uid, 16);
    int64_t t = esp_timer_get_time();
    memcpy(ikm + 54, &t, 8);
    fl_hkdf(zero_salt, 32, ikm, sizeof ikm, "furcate/leaf/p4-soft-key/v1", out, 32);
    fl_wipe(ikm, sizeof ikm);
}

esp_err_t fl_identity_init(void) {
    nvs_handle_t h;
    size_t n = 32;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "cannot open the key store; identity unavailable");
        return ESP_FAIL;
    }
    esp_err_t e = nvs_get_blob(h, KEY, s_priv, &n);
    if (e != ESP_OK || n != 32 || !fl_p256_scalar_ok(s_priv)) {
        bool ok = false;
        for (int i = 0; i < 8 && !ok; i++) {
            mix_seed(s_priv);
            ok = fl_p256_scalar_ok(s_priv);
        }
        if (!ok || nvs_set_blob(h, KEY, s_priv, 32) != ESP_OK || nvs_commit(h) != ESP_OK) {
            nvs_close(h);
            fl_wipe(s_priv, sizeof s_priv);
            ESP_LOGE(TAG, "cannot create or store a key; identity unavailable");
            return ESP_FAIL;
        }
        s_fresh = true;
    }
    nvs_close(h);
    if (!fl_p256_pub(s_priv, s_pub)) return ESP_FAIL;
    fl_sha256(s_pub, FL_PUB_LEN, s_id);
    for (int i = 0; i < 16; i++) sprintf(s_id_hex + 2 * i, "%02x", s_id[i]);
    s_ready = true;
    ESP_LOGI(TAG, "leaf id %s (source: key held in flash, %s)", s_id_hex, s_fresh ? "created this boot" : "loaded");
    return ESP_OK;
}

bool fl_identity_ready(void) { return s_ready; }
const uint8_t *fl_identity_pub(void) { return s_pub; }
const uint8_t *fl_identity_id(void) { return s_id; }
const char *fl_identity_id_hex(void) { return s_id_hex; }

bool fl_identity_sign(const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]) {
    return s_ready && fl_p256_sign(s_priv, hash, sig);
}

// "soft": the key is in unprotected flash. With secure boot or flash
// encryption the class would still be soft (the key is not bound to the die).
const char *fl_identity_assurance(void) { return "soft"; }

void fl_identity_evidence(fl_wbuf_t *w) {
    uint8_t mac[6], uid[16] = {0};
    esp_efuse_mac_get_default(mac);
    esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, uid, sizeof uid * 8);
    esp_chip_info_t ci;
    esp_chip_info(&ci);
    uint32_t fe = 0;
    esp_efuse_read_field_blob(ESP_EFUSE_SPI_BOOT_CRYPT_CNT, &fe, 3);
    uint32_t flags = 0;
    flags |= esp_secure_boot_enabled() ? 1u : 0;
    flags |= (__builtin_popcount(fe) & 1) ? 2u : 0;
    flags |= esp_efuse_read_field_bit(ESP_EFUSE_SOFT_DIS_JTAG) ? 4u : 0;
    flags |= esp_efuse_read_field_bit(ESP_EFUSE_DIS_DOWNLOAD_MODE) ? 8u : 0;
    const esp_app_desc_t *app = esp_app_get_description();

    fl_w_bytes(w, 1, mac, 6);
    fl_w_u16(w, 2, ci.revision);
    fl_w_u32(w, 3, flags);
    fl_w_str(w, 4, fl_identity_assurance());
    fl_w_str(w, 5, app->version);
    fl_w_bytes(w, 6, app->app_elf_sha256, 32);
    fl_w_u32(w, 13, 0);
    fl_w_u32(w, 14, FL_FW_SEQ);
    fl_w_bytes(w, 20, uid, sizeof uid);
    fl_w_str(w, 21, "esp32p4");
    fl_w_u8(w, 22, 0);
}

size_t fl_identity_rollover_record(uint32_t seq, uint64_t not_before, uint64_t not_after, uint8_t *out, size_t cap,
                                   const char **why) {
    (void)seq; (void)not_before; (void)not_after; (void)out; (void)cap;
    if (why) *why = "a soft identity has no successor key; a burned unit would add one";
    return 0;
}
