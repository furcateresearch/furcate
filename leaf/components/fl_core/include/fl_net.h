#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fl_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

// Site network configuration, delivered only as an operator-signed CONFIG
// message inside an authorised session (FL_ROLE_CONFIG).
//
// Signed body: "FLC1" | leaf id (32, must be this leaf) | sequence (u32 BE,
// must be newer than the stored one) | TLV items:
//   1 Wi-Fi SSID (1..32 bytes)
//   2 Wi-Fi passphrase (8..63 bytes, or empty for an open network)
//   3 controller host (IPv4 dotted quad)
//   4 controller port (u16)
//   5 AUTH window in ms (u32, FL_AUTH_WINDOW_MIN_MS..FL_AUTH_WINDOW_MAX_MS)
//   6 Wi-Fi country code (2 letters; absent = the driver default)
// The whole configuration is replaced; items not present are cleared.
//
// The leaf only ever dials out: Wi-Fi station mode, one outbound TCP
// connection to the controller, no listening socket.

#define FL_AUTH_WINDOW_DEFAULT_MS 8000
#define FL_AUTH_WINDOW_MIN_MS 2000
#define FL_AUTH_WINDOW_MAX_MS 15000

// Loads the stored configuration and starts Wi-Fi when one is present.
void fl_net_init(void);
// Verifies and applies a CONFIG message; returns RESULT.
uint8_t fl_net_config(const uint8_t *tlv, size_t n, fl_wbuf_t *r);
// Station associated and holding an address, and a controller configured.
bool fl_net_ready(void);
// Opens the outbound connection to the controller; returns a socket or -1.
int fl_net_dial(int timeout_ms);
// Opens an outbound connection to another port on the controller host (the
// cell's head), e.g. its model gateway; returns a socket or -1.
int fl_net_dial_port(uint16_t port, int timeout_ms);
// The controller host from the signed configuration ("" when none).
const char *fl_net_host(void);
uint32_t fl_net_auth_window_ms(void);
void fl_net_info(fl_wbuf_t *w);

#ifdef __cplusplus
}
#endif
