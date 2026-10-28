#pragma once
// Wire format shared with the node side (host/furcate_leaf/wire.py).
//
// A message is one type byte followed by TLV fields: tag (u8), length (u16,
// big-endian), value. Frames travel as "FL1:" + base64(message) + "\n".

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    // handshake, plaintext
    FL_MSG_HELLO = 0x01,
    FL_MSG_AUTH = 0x02,
    FL_MSG_FINISH = 0x03,
    FL_MSG_REFUSE = 0x04,
    FL_MSG_SEALED = 0x10,
    // inside a sealed record
    FL_MSG_INFO_REQ = 0x20,
    FL_MSG_INFO = 0x21,
    FL_MSG_RESULT = 0x22,
    FL_MSG_MODEL_OFFER = 0x30,
    FL_MSG_MODEL_CHUNK = 0x31,
    FL_MSG_MODEL_COMMIT = 0x32,
    FL_MSG_MODEL_ROLLBACK = 0x33,
    FL_MSG_INFER = 0x40,
    FL_MSG_INFER_RESULT = 0x41,
    FL_MSG_OTA_OFFER = 0x50,
    FL_MSG_OTA_CHUNK = 0x51,
    FL_MSG_OTA_COMMIT = 0x52,
    FL_MSG_REVOKE = 0x60,
    FL_MSG_CONFIG = 0x61,  // operator-signed site configuration (fl_net.h)
    FL_MSG_SINK = 0x70,    // throughput test: the leaf counts the bytes and answers
    FL_MSG_GATEWAY_ASK = 0x71,  // signed request to the cell's model gateway (fl_gateway.h)
    FL_MSG_SENSE_REQ = 0x72,  // ask for signed readings of the leaf's own sensors (fl_sensors.h)
    FL_MSG_SENSE = 0x73,      // the readings
    FL_MSG_BYE = 0x7F,
};

enum {
    T_VERSION = 1,
    T_DEV_PUB = 2,
    T_EPH = 3,
    T_NONCE = 4,
    T_EVIDENCE = 5,
    T_NODE_PUB = 6,
    T_GRANT = 7,
    T_GRANT_SIG = 8,
    T_NODE_SIG = 9,
    T_DEV_SIG = 10,
    T_REASON = 11,
    T_OK = 12,
    T_COUNTER = 13,
    T_BOX = 14,
    T_SIGNED = 20,   // signed envelope (manifest, revocation)
    T_OFFSET = 21,
    T_DATA = 22,
    T_INPUT = 23,
    T_SCORES = 24,
    T_LATENCY_US = 25,
    T_LABEL = 26,
    T_DETAIL = 27,
    T_ROLE_NEEDED = 28,
    T_QPARAMS = 29,
    // envelope
    T_BODY = 30,
    T_SIG = 31,
    // gateway requests
    T_METHOD = 32,
    T_TARGET = 33,
    T_STATUS = 34,
    T_CREDENTIAL = 35,
};

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool overflow;
} fl_wbuf_t;

void fl_w_init(fl_wbuf_t *w, uint8_t *buf, size_t cap, uint8_t type);
void fl_w_bytes(fl_wbuf_t *w, uint8_t tag, const void *v, size_t n);
void fl_w_u8(fl_wbuf_t *w, uint8_t tag, uint8_t v);
void fl_w_u16(fl_wbuf_t *w, uint8_t tag, uint16_t v);
void fl_w_u32(fl_wbuf_t *w, uint8_t tag, uint32_t v);
void fl_w_str(fl_wbuf_t *w, uint8_t tag, const char *s);

typedef struct {
    const uint8_t *p;
    size_t n;
} fl_field_t;

// Finds the first (or index-th) field with this tag. Returns false if absent.
bool fl_r_find(const uint8_t *tlv, size_t len, uint8_t tag, int index, fl_field_t *out);
bool fl_r_u8(const uint8_t *tlv, size_t len, uint8_t tag, uint8_t *v);
bool fl_r_u16(const uint8_t *tlv, size_t len, uint8_t tag, uint16_t *v);
bool fl_r_u32(const uint8_t *tlv, size_t len, uint8_t tag, uint32_t *v);
bool fl_r_valid(const uint8_t *tlv, size_t len);

size_t fl_b64_encode(const uint8_t *in, size_t n, char *out);
// Returns decoded length or -1.
int fl_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap);

#ifdef __cplusplus
}
#endif
