#include "fl_wire.h"
#include <string.h>

void fl_w_init(fl_wbuf_t *w, uint8_t *buf, size_t cap, uint8_t type) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->overflow = cap < 1;
    if (!w->overflow) w->buf[w->len++] = type;
}

void fl_w_bytes(fl_wbuf_t *w, uint8_t tag, const void *v, size_t n) {
    if (w->overflow || n > 0xFFFF || w->len + 3 + n > w->cap) {
        w->overflow = true;
        return;
    }
    w->buf[w->len++] = tag;
    w->buf[w->len++] = (uint8_t)(n >> 8);
    w->buf[w->len++] = (uint8_t)n;
    if (n) memcpy(w->buf + w->len, v, n);
    w->len += n;
}

void fl_w_u8(fl_wbuf_t *w, uint8_t tag, uint8_t v) { fl_w_bytes(w, tag, &v, 1); }
void fl_w_u16(fl_wbuf_t *w, uint8_t tag, uint16_t v) {
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    fl_w_bytes(w, tag, b, 2);
}
void fl_w_u32(fl_wbuf_t *w, uint8_t tag, uint32_t v) {
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    fl_w_bytes(w, tag, b, 4);
}
void fl_w_str(fl_wbuf_t *w, uint8_t tag, const char *s) { fl_w_bytes(w, tag, s, strlen(s)); }

bool fl_r_valid(const uint8_t *tlv, size_t len) {
    size_t i = 0;
    while (i < len) {
        if (i + 3 > len) return false;
        size_t n = ((size_t)tlv[i + 1] << 8) | tlv[i + 2];
        i += 3 + n;
    }
    return i == len;
}

bool fl_r_find(const uint8_t *tlv, size_t len, uint8_t tag, int index, fl_field_t *out) {
    size_t i = 0;
    while (i + 3 <= len) {
        size_t n = ((size_t)tlv[i + 1] << 8) | tlv[i + 2];
        if (i + 3 + n > len) return false;
        if (tlv[i] == tag && index-- == 0) {
            out->p = tlv + i + 3;
            out->n = n;
            return true;
        }
        i += 3 + n;
    }
    return false;
}

bool fl_r_u8(const uint8_t *t, size_t l, uint8_t tag, uint8_t *v) {
    fl_field_t f;
    if (!fl_r_find(t, l, tag, 0, &f) || f.n != 1) return false;
    *v = f.p[0];
    return true;
}
bool fl_r_u16(const uint8_t *t, size_t l, uint8_t tag, uint16_t *v) {
    fl_field_t f;
    if (!fl_r_find(t, l, tag, 0, &f) || f.n != 2) return false;
    *v = (uint16_t)((f.p[0] << 8) | f.p[1]);
    return true;
}
bool fl_r_u32(const uint8_t *t, size_t l, uint8_t tag, uint32_t *v) {
    fl_field_t f;
    if (!fl_r_find(t, l, tag, 0, &f) || f.n != 4) return false;
    *v = ((uint32_t)f.p[0] << 24) | ((uint32_t)f.p[1] << 16) | ((uint32_t)f.p[2] << 8) | f.p[3];
    return true;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t fl_b64_encode(const uint8_t *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = i + 1 < n ? B64[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? B64[v & 63] : '=';
    }
    return o;
}

static int b64v(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int fl_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap) {
    if (n % 4) return -1;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int a = b64v(in[i]), b = b64v(in[i + 1]);
        int c = in[i + 2] == '=' ? 0 : b64v(in[i + 2]);
        int d = in[i + 3] == '=' ? 0 : b64v(in[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        if (o >= cap) return -1;
        out[o++] = (uint8_t)(v >> 16);
        if (in[i + 2] != '=') {
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(v >> 8);
        }
        if (in[i + 3] != '=') {
            if (o >= cap) return -1;
            out[o++] = (uint8_t)v;
        }
    }
    return (int)o;
}
