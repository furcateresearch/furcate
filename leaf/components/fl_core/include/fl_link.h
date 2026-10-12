#pragma once
#include <stddef.h>
#include <stdint.h>
#include "fl_trust.h"
#include "fl_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

// Handler for a decrypted command. Writes the reply into `reply` (already
// initialised with no type) and returns the reply type, or 0 for no reply.
typedef uint8_t (*fl_cmd_handler_t)(uint8_t type, const uint8_t *tlv, size_t n, const fl_grant_t *grant,
                                    fl_wbuf_t *reply);

// Runs the leaf's only communication loop. The leaf initiates every session:
// it announces itself, and talks only to a node that proves an operator
// grant. Nothing is accepted outside a session the leaf started. Never returns.
void fl_link_run(fl_cmd_handler_t handler);

// Log output goes through the same writer as frames, so lines never interleave.
void fl_link_console_init(void);

// "serial" or "wifi-tcp": the transport the current or last session used.
const char *fl_link_transport(void);
// True while a session is up on the serial console.
bool fl_link_serial_busy(void);

#ifdef __cplusplus
}
#endif
