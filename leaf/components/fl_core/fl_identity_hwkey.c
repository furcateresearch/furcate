// Identity backend for parts with a hardware key engine (ESP32-C5, ESP32-P4:
// Key Manager with a PUF-derived hardware unique key and the ECDSA
// peripheral). The private key is generated inside the chip and is never
// readable by software; signing happens in the peripheral.
//
// Not implemented yet (docs/PENDING.md). It fails closed: no identity, no
// communication.

#include "fl_identity.h"
#include "esp_log.h"

static const char *TAG = "fl-identity";
static uint8_t s_zero[FL_PUB_LEN];

esp_err_t fl_identity_init(void) {
    ESP_LOGE(TAG, "hardware key backend not implemented for this target; identity unavailable");
    return ESP_ERR_NOT_SUPPORTED;
}
bool fl_identity_ready(void) { return false; }
const uint8_t *fl_identity_pub(void) { return s_zero; }
const uint8_t *fl_identity_id(void) { return s_zero; }
const char *fl_identity_id_hex(void) { return ""; }
bool fl_identity_sign(const uint8_t hash[32], uint8_t sig[FL_SIG_LEN]) { return false; }
void fl_identity_evidence(fl_wbuf_t *w) {}
const char *fl_identity_assurance(void) { return "none"; }

size_t fl_identity_rollover_record(uint32_t seq, uint64_t not_before, uint64_t not_after, uint8_t *out, size_t cap,
                                   const char **why) {
    (void)seq; (void)not_before; (void)not_after; (void)out; (void)cap;
    if (why) *why = "this identity backend has no rollover";
    return 0;
}
