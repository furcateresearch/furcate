#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Which eFuse key block feeds the leaf identity (ESP32-S3). purpose[i] is the
// key purpose of key block i (0..5). Returns the index of the FIRST block whose
// purpose equals hmac_up, or -1 when there is none. *count (optional) receives
// the number of matching blocks. Exactly one HMAC_UP block must ever be
// burned: with more than one, the lowest-numbered block wins, so a later burn
// into a lower block would silently change the identity. The caller must treat
// *count > 1 as an error. Pure function, tested on the host.
#define FL_KEY_BLOCKS 6
int fl_hmac_select_block(const uint8_t purpose[FL_KEY_BLOCKS], uint8_t hmac_up, int *count);

#ifdef __cplusplus
}
#endif
