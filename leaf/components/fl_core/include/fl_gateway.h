#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fl_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

// The leaf's requests to the model gateway on its cell's head
// (fl_request.h has the signed form). The gateway is the controller host
// from the signed site configuration, port 8750: the leaf asks no other
// address, and holds no token for it.
//
// Time comes from SNTP, started once the station has an address: the head
// (the controller host) first, then pool.ntp.org. With no synchronised clock
// the leaf makes no request.

// Starts SNTP; called by fl_net when the station gets an address.
void fl_time_start(const char *head);
// Seconds since the epoch, or 0 while the clock has not been set by SNTP.
uint64_t fl_time_now(void);

// GATEWAY_ASK (role command). In: T_METHOD, T_TARGET, optional T_DATA body.
// Out (RESULT): T_OK (HTTP 200), T_STATUS, T_CREDENTIAL (the header sent,
// already spent or void within 60 s), T_DATA (the answer body, first part),
// T_LATENCY_US, or T_REASON when no request was made.
uint8_t fl_gateway_ask(const uint8_t *tlv, size_t n, fl_wbuf_t *r);
void fl_gateway_info(fl_wbuf_t *w);

#ifdef __cplusplus
}
#endif
