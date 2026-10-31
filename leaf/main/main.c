// Furcate leaf node firmware.
//
// Boot order:
//   1. read the SRAM start-up fingerprint before anything else uses memory
//      (classic ESP32 only; the ESP32-S3 derives from eFuse values instead)
//   2. derive the leaf identity from it (no identity = no communication)
//   3. load pinned trust anchors, the model server and its active model
//   4. confirm or roll back a freshly installed firmware image
//   5. start Wi-Fi when the operator has configured it (station, dial-out only)
//   6. set the clock by SNTP once the station has an address (gateway requests
//      need it)
//   7. run the channel: the leaf initiates, and only operator-granted nodes
//      get a session

#include <string.h>
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "fl_crypto.h"
#include "fl_gateway.h"
#include "fl_identity.h"
#include "fl_link.h"
#include "fl_models.h"
#include "fl_net.h"
#if CONFIG_IDF_TARGET_ESP32S3
#include "fl_nicla.h"
#endif
#include "fl_ota.h"
#include "fl_puf.h"
#include "fl_rollover.h"
#if CONFIG_IDF_TARGET_ESP32
#include "esp_mac.h"
#include "fl_pinned_keys.h"
#include "fl_puf_escrow.h"
#include "nvs.h"
#endif
#include "fl_sensors.h"
#include "sdkconfig.h"
#include "fl_trust.h"
#include "nvs_flash.h"
#if CONFIG_IDF_TARGET_ESP32P4
#include "fl_spool.h"
#endif

static const char *TAG = "furcate-leaf";

#if defined(FL_ONESHOT_S5B) && CONFIG_IDF_TARGET_ESP32
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_flash_encrypt.h"
#include "esp_secure_boot.h"
// Stage S5b of the classic ESP32 lock-down, done from the running signed app because
// UART_DOWNLOAD_DIS (S6) already closed the ROM loader: the two burns ESP-IDF's own
// release-mode bootloader makes after the cell count is at its maximum.
//   DISABLE_DL_ENCRYPT       the UART download mode may not encrypt flash (the last of the
//                            three DISABLE_DL_* bits that esp_get_flash_encryption_mode()
//                            reads to report RELEASE)
//   WR_DIS bit 3 (DIS_CACHE) write-protects MAC, MAC_CRC, DISABLE_APP_CPU, DISABLE_BT,
//                            DIS_CACHE and VOL_LEVEL_HP_INV so none can be set later by accident
// It touches nothing else (not the SECURE_VERSION group, not FLASH_CRYPT_CNT) and
// does nothing unless every precondition holds. Idempotent.
static void oneshot_s5b(void) {
    uint8_t cnt = 0;
    esp_efuse_read_field_blob(ESP_EFUSE_FLASH_CRYPT_CNT, &cnt, 7);
    bool dl_dec = esp_efuse_read_field_bit(ESP_EFUSE_DISABLE_DL_DECRYPT);
    bool dl_cache = esp_efuse_read_field_bit(ESP_EFUSE_DISABLE_DL_CACHE);
    bool dl_enc = esp_efuse_read_field_bit(ESP_EFUSE_DISABLE_DL_ENCRYPT);
    bool wr3 = esp_efuse_read_field_bit(ESP_EFUSE_WR_DIS_DIS_CACHE);
    ESP_LOGW(TAG, "S5b before: FLASH_CRYPT_CNT 0x%02x, DL_DECRYPT %d, DL_CACHE %d, DL_ENCRYPT %d, WR_DIS bit3 %d, mode %d",
             cnt, dl_dec, dl_cache, dl_enc, wr3, (int)esp_get_flash_encryption_mode());
    if (cnt != 0x7f || !dl_dec || !dl_cache || !esp_secure_boot_enabled() || !esp_efuse_is_flash_encryption_enabled()) {
        ESP_LOGE(TAG, "S5b: preconditions not met; nothing burned");
        return;
    }
    if (!dl_enc) esp_efuse_write_field_bit(ESP_EFUSE_DISABLE_DL_ENCRYPT);
    if (!wr3) esp_efuse_write_field_bit(ESP_EFUSE_WR_DIS_DIS_CACHE);
    ESP_LOGW(TAG, "S5b after: DL_ENCRYPT %d, WR_DIS bit3 %d, mode %d (2 = RELEASE, 1 = DEVELOPMENT)",
             esp_efuse_read_field_bit(ESP_EFUSE_DISABLE_DL_ENCRYPT), esp_efuse_read_field_bit(ESP_EFUSE_WR_DIS_DIS_CACHE),
             (int)esp_get_flash_encryption_mode());
}
#endif

#if CONFIG_IDF_TARGET_ESP32
// Helper data escrow (classic ESP32): export, adopt, restore. Rules and message
// formats: docs/PUF-ESCROW.md. The three commands need the config role.
static uint32_t escrow_seq_get(void) {
    nvs_handle_t h;
    uint32_t v = 0;
    if (nvs_open("fl-escrow", NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_u32(h, "seq", &v) != ESP_OK) v = 0;
        nvs_close(h);
    }
    return v;
}

static bool escrow_seq_set(uint32_t v) {
    nvs_handle_t h;
    if (nvs_open("fl-escrow", NVS_READWRITE, &h) != ESP_OK) return false;
    bool ok = nvs_set_u32(h, "seq", v) == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

static bool leaf_sign_cb(const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]) { return fl_identity_sign(hash, sig); }

static uint8_t escrow_result(fl_wbuf_t *r, const char *why, const char *ok_note) {
    fl_w_u8(r, T_OK, why == NULL);
    if (why) fl_w_str(r, T_REASON, why);
    else if (ok_note) fl_w_str(r, T_DETAIL, ok_note);
    return FL_MSG_ESCROW;
}

static uint8_t escrow_op(uint8_t type, const uint8_t *tlv, size_t n, fl_wbuf_t *r) {
    if (!fl_identity_ready()) return escrow_result(r, "no identity this boot", NULL);
    if (type == FL_MSG_ESCROW_EXPORT_REQ) {
        fl_puf_blob_t b;
        if (fl_puf_helper_export(&b) != ESP_OK)
            return escrow_result(r, "no version 3 helper data: adopt first", NULL);
        static uint8_t msg[FL_ESC_EXPORT_BODY_LEN + FL_SIG_LEN + FL_PUF_BLOB_WIRE_LEN];
        uint8_t mac[6];
        esp_efuse_mac_get_default(mac);
        size_t len = fl_puf_escrow_export_build(&b, fl_identity_id(), mac, leaf_sign_cb, msg, sizeof msg);
        if (len == 0) return escrow_result(r, "cannot build the export", NULL);
        fl_w_u8(r, T_OK, 1);
        fl_w_bytes(r, T_RECORD, msg, len);
        return FL_MSG_ESCROW;
    }
    fl_field_t rec;
    if (!fl_r_find(tlv, n, T_RECORD, 0, &rec)) return escrow_result(r, "malformed command", NULL);
    fl_escrow_dev_t d = {0};
    esp_efuse_mac_get_default(d.mac);
    d.region_addr = fl_puf_region_addr();
    d.enrolled = fl_puf_enrolled();
    d.has_v3 = fl_puf_has_v3();
    d.id_valid = fl_identity_ready();
    memcpy(d.id, fl_identity_id(), 32);
    d.cells_flipped = fl_puf_stats()->cells_flipped;
    d.last_seq = escrow_seq_get();
    d.trial_reading = fl_puf_trial_reading();
    d.operator_pubs = FL_PINNED_OPERATOR;
    d.n_operators = FL_PINNED_OPERATOR_COUNT;
    uint32_t seq = 0;
    if (type == FL_MSG_ESCROW_ADOPT) {
        const char *why = fl_puf_escrow_check_adopt(rec.p, rec.n, &d, &seq);
        if (why) return escrow_result(r, why, NULL);
        if (fl_puf_adopt() != ESP_OK) return escrow_result(r, "adopt failed", NULL);
        if (!escrow_seq_set(seq)) return escrow_result(r, "adopted, but the sequence was not stored", NULL);
        fl_puf_clear_trial();
        return escrow_result(r, NULL, "version 3 helper data written; helper2 kept");
    }
    static fl_puf_blob_t blob;
    const char *why = fl_puf_escrow_check_restore(rec.p, rec.n, &d, &blob, &seq);
    if (why) return escrow_result(r, why, NULL);
    if (fl_puf_forget() != ESP_OK || fl_puf_helper_import(&blob) != ESP_OK)
        return escrow_result(r, "restore failed: reset and check the identity", NULL);
    escrow_seq_set(seq);
    fl_puf_clear_trial();
    return escrow_result(r, NULL, "helper data restored; reset the leaf to use it");
}
#endif

static uint8_t handle(uint8_t type, const uint8_t *tlv, size_t n, const fl_grant_t *g, fl_wbuf_t *r) {
    switch (type) {
    case FL_MSG_INFO_REQ:
        fl_w_str(r, T_DETAIL, fl_identity_id_hex());
        fl_w_str(r, 60, fl_identity_assurance());
        fl_w_u32(r, 61, fl_trust_min_generation());
        fl_w_u8(r, 62, (uint8_t)fl_trust_release_threshold());
        fl_models_info(r);
        fl_ota_info(r);
        fl_w_str(r, 70, fl_link_transport());
        fl_net_info(r);
        fl_gateway_info(r);
        fl_sensors_info(r);
        return FL_MSG_INFO;
    case FL_MSG_CONFIG:
        return fl_net_config(tlv, n, r);
    case FL_MSG_ROLLOVER_REQ: {
        // Operator-granted (config role). The host names the sequence and the
        // validity window; the leaf has no trusted clock of its own.
        uint32_t seq = 0;
        fl_field_t nb, na;
        static uint8_t rec[FL_ROLLOVER_MAX_LEN];
        const char *why = "malformed request";
        size_t len = 0;
        if (fl_r_u32(tlv, n, T_ROLL_SEQ, &seq) && fl_r_find(tlv, n, T_NOT_BEFORE, 0, &nb) && nb.n == 8 &&
            fl_r_find(tlv, n, T_NOT_AFTER, 0, &na) && na.n == 8) {
            uint64_t b = 0, a = 0;
            for (int i = 0; i < 8; i++) {
                b = b << 8 | nb.p[i];
                a = a << 8 | na.p[i];
            }
            len = fl_identity_rollover_record(seq, b, a, rec, sizeof rec, &why);
        }
        fl_w_u8(r, T_OK, len != 0);
        if (len) fl_w_bytes(r, T_RECORD, rec, len);
        else fl_w_str(r, T_REASON, why);
        return FL_MSG_ROLLOVER;
    }
#if CONFIG_IDF_TARGET_ESP32
    case FL_MSG_ESCROW_EXPORT_REQ:
    case FL_MSG_ESCROW_ADOPT:
    case FL_MSG_ESCROW_RESTORE:
        return escrow_op(type, tlv, n, r);
#endif
    case FL_MSG_SINK: {
        fl_field_t d;
        fl_w_u32(r, T_OFFSET, fl_r_find(tlv, n, T_DATA, 0, &d) ? (uint32_t)d.n : 0);
        return FL_MSG_RESULT;
    }
    case FL_MSG_MODEL_OFFER:
        return fl_models_offer(tlv, n, r);
    case FL_MSG_MODEL_CHUNK:
        return fl_models_chunk(tlv, n, r);
    case FL_MSG_MODEL_COMMIT:
        return fl_models_commit(r);
    case FL_MSG_MODEL_ROLLBACK:
        return fl_models_rollback(r);
    case FL_MSG_INFER:
        return fl_models_infer(tlv, n, r);
    case FL_MSG_SENSE_REQ:
        return fl_sensors_read(r);
#if CONFIG_IDF_TARGET_ESP32P4
    case FL_MSG_SPOOL_REQ:
        return fl_spool_request(tlv, n, g, r);
#endif
    case FL_MSG_GATEWAY_ASK:
        return fl_gateway_ask(tlv, n, r);
    case FL_MSG_OTA_OFFER:
        return fl_ota_offer(tlv, n, r);
    case FL_MSG_OTA_CHUNK:
        return fl_ota_chunk(tlv, n, r);
    case FL_MSG_OTA_COMMIT:
        return fl_ota_commit(r);
    case FL_MSG_REVOKE: {
        fl_field_t env;
        const char *why = fl_r_find(tlv, n, T_SIGNED, 0, &env) ? fl_trust_apply_revocation(env.p, env.n)
                                                                : "no revocation";
        fl_w_u8(r, T_OK, why == NULL);
        if (why) fl_w_str(r, T_REASON, why);
        return FL_MSG_RESULT;
    }
    default:
        return 0;
    }
}

void app_main(void) {
#if CONFIG_IDF_TARGET_ESP32
    fl_puf_capture();  // must run first; may deep-sleep to power SRAM down
#endif

    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    fl_link_console_init();
#if defined(FL_ONESHOT_S5B) && CONFIG_IDF_TARGET_ESP32
    oneshot_s5b();
#endif
    fl_crypto_init();
    ESP_LOGI(TAG, "Furcate leaf node, firmware %s (seq %d)", FL_FW_VERSION, FL_FW_SEQ);

    // Enrollment takes several deep-sleep power cycles. A trial boot cannot
    // sleep (the bootloader would count the wake as a second unconfirmed
    // boot and roll back), so an image that must enroll is judged on its
    // other checks and enrolls after confirmation. An enrolled leaf whose
    // fingerprint does not reconstruct fails the health check.
#if CONFIG_IDF_TARGET_ESP32
    bool enrolled = fl_puf_enrolled();
#else
    bool enrolled = true;  // nothing to enrol: the identity comes from eFuse values
#endif
    bool id_ok = enrolled && fl_identity_init() == ESP_OK;
    fl_trust_init();
    fl_net_init();  // before the model arena takes the largest free block
#if CONFIG_IDF_TARGET_ESP32S3 && !CONFIG_FL_NICLA_I2C_ENABLE
    fl_nicla_ble_start();  // BLE central for the sensing module; the model arena takes what is left
#endif  // with the I2C transport enabled the module is read over the bus and the BLE host is not started
    bool models_ok = fl_models_init() == ESP_OK;

    bool healthy = (enrolled ? id_ok : true) && models_ok;
#ifdef FL_SELFTEST_FAIL
    ESP_LOGW(TAG, "this build is made to fail its health check (rollback test)");
    healthy = false;
#endif
    fl_ota_boot_check(healthy);
    if (!enrolled) {
        ESP_LOGW(TAG, "no fingerprint enrollment for the fixed region; enrolling now");
        id_ok = fl_identity_init() == ESP_OK;
    }
    fl_sensors_init();
#if CONFIG_IDF_TARGET_ESP32P4
    if (id_ok) fl_spool_start();  // the signed readings go to the SD card; needs the identity key for its seals
#endif
    if (id_ok) {
        ESP_LOGI(TAG, "identity %s, assurance %s, transport serial, models %s", fl_identity_id_hex(),
                 fl_identity_assurance(), models_ok ? "ready" : "unavailable");
    }
    ESP_LOGI(TAG, "free internal heap %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));

    fl_link_run(handle);
}
