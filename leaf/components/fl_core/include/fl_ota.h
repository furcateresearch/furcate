#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fl_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

// Firmware updates: release-signed manifest, A/B app slots, rollback.
void fl_ota_boot_check(bool healthy);  // marks a new image valid, or rolls back
uint8_t fl_ota_offer(const uint8_t *tlv, size_t n, fl_wbuf_t *r);
uint8_t fl_ota_chunk(const uint8_t *tlv, size_t n, fl_wbuf_t *r);
uint8_t fl_ota_commit(fl_wbuf_t *r);  // reboots on success
void fl_ota_info(fl_wbuf_t *w);

#ifdef __cplusplus
}
#endif
