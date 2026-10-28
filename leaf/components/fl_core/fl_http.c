// HTTP/1.1 answer helpers (fl_http.h).

#include "fl_http.h"

#include <string.h>

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

static bool eq_ci(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (lower(a[i]) != lower(b[i])) return false;
    return true;
}

static bool is_ows(char c) { return c == ' ' || c == '\t'; }

bool fl_http_is_chunked(const char *h, size_t n) {
    static const char name[] = "transfer-encoding:";
    const size_t nl = sizeof name - 1;
    bool chunked = false;
    size_t i = 0;
    while (i < n) {
        size_t e = i;
        while (e < n && h[e] != '\n') e++;
        size_t end = (e > i && h[e - 1] == '\r') ? e - 1 : e;
        if (end - i > nl && eq_ci(h + i, name, nl)) {
            // The last coding in the list is the one that frames the body.
            size_t v = i + nl, ve = end;
            while (ve > v && is_ows(h[ve - 1])) ve--;
            size_t vs = ve;
            while (vs > v && h[vs - 1] != ',') vs--;
            while (vs < ve && is_ows(h[vs])) vs++;
            chunked = (ve - vs == 7 && eq_ci(h + vs, "chunked", 7));
        }
        i = e + 1;
    }
    return chunked;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = lower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// Finds the CRLF ending the line at in[i]; returns its offset or n.
static size_t line_end(const char *in, size_t n, size_t i) {
    while (i + 1 < n && !(in[i] == '\r' && in[i + 1] == '\n')) i++;
    return i + 1 < n ? i : n;
}

fl_http_err_t fl_http_dechunk(const char *in, size_t n, char *out, size_t cap, size_t *out_len) {
    size_t i = 0, total = 0;
    *out_len = 0;
    for (;;) {
        // Size line: hex digits, optional OWS and ";extensions", CRLF.
        size_t le = line_end(in, n, i);
        if (le == n) return i < n && hexval(in[i]) < 0 ? FL_HTTP_BAD_SIZE : FL_HTTP_TRUNCATED;
        size_t size = 0, digits = 0, p = i;
        int d;
        while (p < le && (d = hexval(in[p])) >= 0) {
            // Stop before it can wrap; anything over cap is refused below.
            if (size > cap / 16) return FL_HTTP_TOO_LARGE;
            size = size * 16 + (size_t)d;
            digits++;
            p++;
        }
        if (!digits) return FL_HTTP_BAD_SIZE;
        while (p < le && is_ows(in[p])) p++;
        if (p < le && in[p] != ';') return FL_HTTP_BAD_SIZE;
        if (size > cap || size > cap - total) return FL_HTTP_TOO_LARGE;
        i = le + 2;
        if (size == 0) break;
        if (n - i < size + 2) return FL_HTTP_TRUNCATED;
        if (in[i + size] != '\r' || in[i + size + 1] != '\n') return FL_HTTP_BAD_FRAMING;
        memmove(out + total, in + i, size);
        total += size;
        i += size + 2;
    }
    // Trailer lines, then the empty line.
    for (;;) {
        size_t le = line_end(in, n, i);
        if (le == n) return FL_HTTP_TRUNCATED;
        if (le == i) break;
        size_t c = i;
        while (c < le && in[c] != ':') c++;
        if (c == i || c == le) return FL_HTTP_BAD_FRAMING;
        i = le + 2;
    }
    *out_len = total;
    return FL_HTTP_OK;
}

const char *fl_http_err_str(fl_http_err_t e) {
    switch (e) {
        case FL_HTTP_OK: return "ok";
        case FL_HTTP_BAD_SIZE: return "chunked answer: bad chunk size line";
        case FL_HTTP_TOO_LARGE: return "chunked answer: larger than the answer buffer";
        case FL_HTTP_BAD_FRAMING: return "chunked answer: bad chunk or trailer framing";
        case FL_HTTP_TRUNCATED: return "chunked answer: ends before its last chunk";
    }
    return "chunked answer: error";
}
