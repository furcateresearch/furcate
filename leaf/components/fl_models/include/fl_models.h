#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "fl_wire.h"
#include "fl_manifest.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FL_TFLM_RUNTIME_VERSION 1

esp_err_t fl_models_init(void);  // loads the active model, falls back to the previous one
// Command handlers; each writes a reply and returns its type.
uint8_t fl_models_offer(const uint8_t *tlv, size_t n, fl_wbuf_t *r);
uint8_t fl_models_chunk(const uint8_t *tlv, size_t n, fl_wbuf_t *r);
uint8_t fl_models_commit(fl_wbuf_t *r);
uint8_t fl_models_rollback(fl_wbuf_t *r);
uint8_t fl_models_infer(const uint8_t *tlv, size_t n, fl_wbuf_t *r);
void fl_models_info(fl_wbuf_t *w);
bool fl_models_ok(void);
// SHA-256 of the active model's artifact; 32 zero bytes (and false) when none is active.
bool fl_models_active_sha(uint8_t out[32]);

#ifdef __cplusplus
}
#endif
