// Network module for a target with no radio of its own (ESP32-P4). The leaf
// talks over the serial console only: no station, no controller socket, no
// SNTP. The interface in fl_net.h is kept so the link and gateway code are
// the same on every target; every call answers "no network".

#include "fl_net.h"

void fl_net_init(void) {}

uint8_t fl_net_config(const uint8_t *tlv, size_t n, fl_wbuf_t *r) {
    (void)tlv; (void)n;
    fl_w_u8(r, T_OK, 0);
    fl_w_str(r, T_REASON, "this target has no network interface");
    return FL_MSG_RESULT;
}

bool fl_net_ready(void) { return false; }
int fl_net_dial(int timeout_ms) { (void)timeout_ms; return -1; }
int fl_net_dial_port(uint16_t port, int timeout_ms) { (void)port; (void)timeout_ms; return -1; }
const char *fl_net_host(void) { return ""; }
uint32_t fl_net_auth_window_ms(void) { return FL_AUTH_WINDOW_DEFAULT_MS; }
void fl_net_info(fl_wbuf_t *w) { fl_w_u32(w, 77, FL_AUTH_WINDOW_DEFAULT_MS); }
