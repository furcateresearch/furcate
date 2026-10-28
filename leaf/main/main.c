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
#include "fl_sensors.h"
#include "sdkconfig.h"
#include "fl_trust.h"
#include "nvs_flash.h"

static const char *TAG = "furcate-leaf";

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
    if (id_ok) {
        ESP_LOGI(TAG, "identity %s, assurance %s, transport serial, models %s", fl_identity_id_hex(),
                 fl_identity_assurance(), models_ok ? "ready" : "unavailable");
    }
    ESP_LOGI(TAG, "free internal heap %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));

    fl_link_run(handle);
}
