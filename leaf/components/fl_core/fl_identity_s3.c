// Leaf identity on ESP32-S3.
//
// The S3 has no start-up pattern worth reading and no key the firmware may
// create without burning an eFuse, so there are two honest sources:
//
//   identifiers  The factory MAC and the 128-bit unique ID in eFuse. Present
//                on every part, burns nothing, and readable by anyone with
//                the part (esptool reads both over USB). The key is bound to
//                the silicon and not secret from it. Reported as
//                "silicon-id/development".
//   hmac         An eFuse key block whose purpose is HMAC_UP, used through the
//                HMAC peripheral. The key behind it is not readable, so
//                the identity needs the part and the firmware to reproduce.
//                Reported as "efuse-hmac" (with "+secure-boot" when secure
//                boot is on). This path only reads: it uses a key block when
//                the owner has burned one and never writes any.
//
// No source, no identity: it fails closed like the other backends.

#include "fl_identity.h"

#include <stdio.h>
#include <string.h>
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_hmac.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_secure_boot.h"
#include "esp_timer.h"
#include "fl_derive.h"
#include "fl_hmac_select.h"
#include "fl_rollover.h"
#include "nvs.h"

static const char *TAG = "fl-identity";

static uint8_t s_priv[32];
static uint8_t s_pub[FL_PUB_LEN];
static uint8_t s_id[32];
static char s_id_hex[33];
static bool s_ready;
static bool s_hmac;
static uint32_t s_derive_us;

// ESP_OK: one block found. ESP_ERR_NOT_FOUND: none. ESP_ERR_INVALID_STATE:
// more than one HMAC_UP block, which would make the identity depend on burn
// order; refused rather than guessed.
static esp_err_t find_hmac_key(hmac_key_id_t *id) {
    uint8_t purpose[FL_KEY_BLOCKS];
    for (int b = 0; b < FL_KEY_BLOCKS; b++) purpose[b] = (uint8_t)esp_efuse_get_key_purpose((esp_efuse_block_t)(EFUSE_BLK_KEY0 + b));
    int n = 0;
    int b = fl_hmac_select_block(purpose, (uint8_t)ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &n);
    if (n > 1) return ESP_ERR_INVALID_STATE;
    if (b < 0) return ESP_ERR_NOT_FOUND;
    *id = (hmac_key_id_t)(HMAC_KEY0 + b);
    return ESP_OK;
}

esp_err_t fl_identity_init(void) {
    int64_t t0 = esp_timer_get_time();
    uint8_t mac[6], uid[FL_DERIVE_UID_LEN];
    esp_efuse_mac_get_default(mac);
    bool ok = false;
    hmac_key_id_t key;
    esp_err_t fk = find_hmac_key(&key);
    if (fk == ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "more than one HMAC_UP key block; identity unavailable");
        return ESP_FAIL;
    }
    if (fk == ESP_OK) {
        uint8_t out[32];
        if (esp_hmac_calculate(key, FL_DERIVE_HMAC_LABEL, strlen(FL_DERIVE_HMAC_LABEL), out) == ESP_OK) {
            ok = fl_derive_from_hmac(fl_hkdf, fl_p256_scalar_ok, out, mac, s_priv);
            s_hmac = ok;
        }
        fl_wipe(out, sizeof out);
    }
    if (!ok) {
        if (esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, uid, 8 * FL_DERIVE_UID_LEN) != ESP_OK) {
            ESP_LOGE(TAG, "cannot read the unique ID; identity unavailable");
            return ESP_FAIL;
        }
        ok = fl_derive_from_identifiers(fl_hkdf, fl_p256_scalar_ok, mac, uid, s_priv);
    }
    if (!ok) {
        ESP_LOGE(TAG, "no silicon identifier on this part; identity unavailable");
        return ESP_FAIL;
    }
    if (!fl_p256_pub(s_priv, s_pub)) return ESP_FAIL;
    fl_sha256(s_pub, FL_PUB_LEN, s_id);
    for (int i = 0; i < 16; i++) sprintf(s_id_hex + 2 * i, "%02x", s_id[i]);
    s_derive_us = (uint32_t)(esp_timer_get_time() - t0);
    s_ready = true;
    ESP_LOGI(TAG, "leaf id %s (source: %s)", s_id_hex, s_hmac ? "efuse hmac key" : "silicon identifiers");
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
    bool sb = esp_secure_boot_enabled();
    if (s_hmac) return sb ? "efuse-hmac+secure-boot" : "efuse-hmac/development";
    return "silicon-id/development";
}

void fl_identity_evidence(fl_wbuf_t *w) {
    uint8_t mac[6], uid[FL_DERIVE_UID_LEN];
    esp_efuse_mac_get_default(mac);
    esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, uid, 8 * FL_DERIVE_UID_LEN);
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
    fl_w_u32(w, 13, s_derive_us);
    fl_w_u32(w, 14, FL_FW_SEQ);
    // Silicon values the parent enrols (tags 20-22): the unique ID, the chip
    // model, and the chip revision. Public by nature.
    fl_w_bytes(w, 20, uid, sizeof uid);
    fl_w_str(w, 21, "esp32s3");
    fl_w_u8(w, 22, s_hmac ? 1 : 0);
}

// ---- identity rollover (see fl_rollover.h and docs/IDENTITY-ROLLOVER.md) ----

#define ROLL_NS "fl-roll"
#define ROLL_KEY "seq"

static uint8_t s_old_priv[32];
static bool old_sign(const uint8_t h[32], uint8_t sig[FL_SIG_LEN]) { return fl_p256_sign(s_old_priv, h, sig); }
static bool new_sign(const uint8_t h[32], uint8_t sig[FL_SIG_LEN]) { return fl_identity_sign(h, sig); }

size_t fl_identity_rollover_record(uint32_t seq, uint64_t not_before, uint64_t not_after, uint8_t *out, size_t cap,
                                   const char **why) {
    const char *w = NULL;
    size_t n = 0;
    nvs_handle_t h;
    bool have_h = false;
    uint32_t last = 0;
    if (!s_ready) {
        w = "no identity";
        goto done;
    }
    if (!s_hmac) {
        w = "no HMAC key is burned: there is no successor identity";
        goto done;
    }
    if (nvs_open(ROLL_NS, NVS_READWRITE, &h) != ESP_OK) {
        w = "cannot open the rollover counter";
        goto done;
    }
    have_h = true;
    if (nvs_get_u32(h, ROLL_KEY, &last) != ESP_OK) last = 0;
    if (seq == 0 || seq <= last) {
        w = "replay: sequence not newer";
        goto done;
    }
    uint8_t mac[6], uid[FL_DERIVE_UID_LEN];
    esp_efuse_mac_get_default(mac);
    if (esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, uid, 8 * FL_DERIVE_UID_LEN) != ESP_OK ||
        !fl_derive_from_identifiers(fl_hkdf, fl_p256_scalar_ok, mac, uid, s_old_priv)) {
        w = "cannot derive the old identity";
        goto done;
    }
    fl_rollover_t r = {.seq = seq, .not_before = not_before, .not_after = not_after,
                       .old_level = FL_LEVEL_SILICON_ID_DEV, .new_level = fl_rollover_level(fl_identity_assurance())};
    if (!fl_p256_pub(s_old_priv, r.old_pub)) {
        w = "cannot derive the old public key";
        goto done;
    }
    memcpy(r.new_pub, s_pub, FL_PUB_LEN);
    n = fl_rollover_build(&r, old_sign, new_sign, out, cap);
    if (n == 0) {
        w = "record refused (window, levels or keys)";
        goto done;
    }
    if (nvs_set_u32(h, ROLL_KEY, seq) != ESP_OK || nvs_commit(h) != ESP_OK) {
        w = "cannot store the rollover counter";
        n = 0;
    }
done:
    fl_wipe(s_old_priv, sizeof s_old_priv);
    if (have_h) nvs_close(h);
    if (why) *why = w;
    return n;
}
