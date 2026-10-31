// Model server for a target that does not carry the TensorFlow Lite Micro
// runtime (ESP32-P4 in this tree). The interface in fl_models.h is kept; every
// model operation refuses and no model is ever active, so readings carry the
// all-zero model hash.

#include "fl_models.h"

esp_err_t fl_models_init(void) { return ESP_OK; }

static uint8_t refuse(fl_wbuf_t *r) {
    fl_w_u8(r, T_OK, 0);
    fl_w_str(r, T_REASON, "this target has no model runtime");
    return FL_MSG_RESULT;
}

uint8_t fl_models_offer(const uint8_t *tlv, size_t n, fl_wbuf_t *r) { (void)tlv; (void)n; return refuse(r); }
uint8_t fl_models_chunk(const uint8_t *tlv, size_t n, fl_wbuf_t *r) { (void)tlv; (void)n; return refuse(r); }
uint8_t fl_models_commit(fl_wbuf_t *r) { return refuse(r); }
uint8_t fl_models_rollback(fl_wbuf_t *r) { return refuse(r); }
uint8_t fl_models_infer(const uint8_t *tlv, size_t n, fl_wbuf_t *r) { (void)tlv; (void)n; return refuse(r); }
void fl_models_info(fl_wbuf_t *w) { (void)w; }
bool fl_models_ok(void) { return false; }
bool fl_models_active_sha(uint8_t out[32]) {
    for (int i = 0; i < 32; i++) out[i] = 0;
    return false;
}
