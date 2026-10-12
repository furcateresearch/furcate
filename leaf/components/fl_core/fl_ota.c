// Firmware update over the authenticated channel.
//
// The image is accepted only with a manifest signed by the release threshold,
// written to the inactive app slot, checked against the manifest digest, and
// booted once on trial. The new image must pass its health check on first
// boot or the bootloader returns to the previous slot.
//
// Downgrade protection in this development build is a sequence number kept
// in NVS. In production it is the eFuse secure version, enforced by the
// bootloader (see docs/SECURITY.md).

#include "fl_ota.h"

#include <string.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "fl_crypto.h"
#include "fl_manifest.h"
#include "fl_puf.h"
#include "fl_trust.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"

static const char *TAG = "fl-ota";

static struct {
    bool open;
    esp_ota_handle_t h;
    const esp_partition_t *part;
    uint32_t size, written, version;
    uint8_t sha[32];
    fl_sha256_t ctx;
} s_up;

static char s_boot_event[96] = "normal boot";

static uint32_t min_seq(void) {
    nvs_handle_t h;
    uint32_t v = 0;
    if (nvs_open("fl-ota", NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u32(h, "min_seq", &v);
        nvs_close(h);
    }
    return v;
}

static void set_min_seq(uint32_t v) {
    nvs_handle_t h;
    if (nvs_open("fl-ota", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u32(h, "min_seq", v);
        nvs_commit(h);
        nvs_close(h);
    }
}

void fl_ota_boot_check(bool healthy) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    if (esp_ota_get_state_partition(run, &st) != ESP_OK) return;
    if (st == ESP_OTA_IMG_PENDING_VERIFY) {
        if (healthy) {
            esp_ota_mark_app_valid_cancel_rollback();
            if (FL_FW_SEQ > min_seq()) set_min_seq(FL_FW_SEQ);
            snprintf(s_boot_event, sizeof s_boot_event, "new firmware seq %d passed its health check", FL_FW_SEQ);
            ESP_LOGI(TAG, "%s", s_boot_event);
        } else {
            ESP_LOGE(TAG, "new firmware failed its health check; rolling back");
            esp_ota_mark_app_invalid_rollback_and_reboot();
        }
    } else {
        const esp_partition_t *last_invalid = esp_ota_get_last_invalid_partition();
        if (last_invalid)
            snprintf(s_boot_event, sizeof s_boot_event, "running %s; %s was rolled back", run->label,
                     last_invalid->label);
        if (FL_FW_SEQ > min_seq()) set_min_seq(FL_FW_SEQ);
    }
}

static uint8_t result(fl_wbuf_t *r, bool ok, const char *why) {
    fl_w_u8(r, T_OK, ok);
    if (why) fl_w_str(r, T_REASON, why);
    return FL_MSG_RESULT;
}

uint8_t fl_ota_offer(const uint8_t *tlv, size_t n, fl_wbuf_t *r) {
    fl_field_t env, sha, tgt;
    if (!fl_r_find(tlv, n, T_SIGNED, 0, &env)) return result(r, false, "no manifest");
    const uint8_t *b;
    size_t bl;
    int signers;
    const char *why = fl_trust_check_release(env.p, env.n, &b, &bl, &signers);
    fl_w_u32(r, T_LATENCY_US, fl_trust_last_verify_us());
    if (why) return result(r, false, why);
    uint8_t kind = 0;
    uint32_t version = 0, size = 0;
    if (!fl_r_u8(b, bl, M_KIND, &kind) || kind != FL_FIRMWARE_KIND || !fl_r_u32(b, bl, M_VERSION, &version) ||
        !fl_r_u32(b, bl, M_SIZE, &size) || !fl_r_find(b, bl, M_SHA256, 0, &sha) || sha.n != 32)
        return result(r, false, "not a firmware manifest");
    bool target = false;
    for (int i = 0; fl_r_find(b, bl, M_TARGET, i, &tgt); i++) target |= tgt.n == strlen(CONFIG_IDF_TARGET) && !memcmp(tgt.p, CONFIG_IDF_TARGET, tgt.n);
    if (!target) return result(r, false, "firmware is not built for this chip");
    if (version <= min_seq()) return result(r, false, "downgrade refused (sequence not newer)");
    if (s_up.open) esp_ota_abort(s_up.h);
    memset(&s_up, 0, sizeof s_up);
    s_up.part = esp_ota_get_next_update_partition(NULL);
    if (!s_up.part || size > s_up.part->size) return result(r, false, "image does not fit the app slot");
    if (esp_ota_begin(s_up.part, size, &s_up.h) != ESP_OK) return result(r, false, "cannot start update");
    s_up.size = size;
    s_up.version = version;
    memcpy(s_up.sha, sha.p, 32);
    fl_sha256_init(&s_up.ctx);
    s_up.open = true;
    ESP_LOGI(TAG, "accepted firmware seq %u (%u bytes, %d signatures) for %s", (unsigned)version,
             (unsigned)size, signers, s_up.part->label);
    return result(r, true, NULL);
}

uint8_t fl_ota_chunk(const uint8_t *tlv, size_t n, fl_wbuf_t *r) {
    uint32_t off;
    fl_field_t d;
    if (!s_up.open) return result(r, false, "no update in progress");
    if (!fl_r_u32(tlv, n, T_OFFSET, &off) || !fl_r_find(tlv, n, T_DATA, 0, &d)) return result(r, false, "bad chunk");
    if (off != s_up.written || off + d.n > s_up.size) return result(r, false, "chunk out of order");
    if (esp_ota_write(s_up.h, d.p, d.n) != ESP_OK) return result(r, false, "flash write failed");
    fl_sha256_update(&s_up.ctx, d.p, d.n);
    s_up.written += d.n;
    return result(r, true, NULL);
}

// The new image is started through deep sleep, not a plain restart. A plain
// restart keeps SRAM powered, so the fingerprint read on the trial boot would
// find the wipe marker and deep-sleep to power SRAM down; the bootloader then
// sees a second boot of an unconfirmed image and rolls it back before its
// health check can run. Deep sleep powers SRAM down first, so the trial boot
// reads a fresh fingerprint and reaches its health check.
static void reboot_task(void *arg) {
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_sleep_enable_timer_wakeup(FL_PUF_SLEEP_US);
    esp_deep_sleep_start();
}

uint8_t fl_ota_commit(fl_wbuf_t *r) {
    if (!s_up.open || s_up.written != s_up.size) return result(r, false, "image incomplete");
    s_up.open = false;
    uint8_t h[32];
    fl_sha256_final(&s_up.ctx, h);
    if (memcmp(h, s_up.sha, 32) != 0) {
        esp_ota_abort(s_up.h);
        return result(r, false, "digest does not match the manifest");
    }
    if (esp_ota_end(s_up.h) != ESP_OK) return result(r, false, "image failed validation");
    if (esp_ota_set_boot_partition(s_up.part) != ESP_OK) return result(r, false, "cannot select new slot");
    ESP_LOGI(TAG, "firmware seq %u staged in %s; rebooting on trial", (unsigned)s_up.version, s_up.part->label);
    xTaskCreate(reboot_task, "reboot", 2048, NULL, 5, NULL);
    return result(r, true, NULL);
}

void fl_ota_info(fl_wbuf_t *w) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    fl_w_str(w, 50, run->label);
    fl_w_u32(w, 51, FL_FW_SEQ);
    fl_w_u32(w, 52, min_seq());
    fl_w_str(w, 53, s_boot_event);
}
