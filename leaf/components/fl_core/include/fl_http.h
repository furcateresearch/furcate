#pragma once
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// HTTP/1.1 answer helpers for the gateway client (fl_gateway.c). Pure: no
// sockets, no allocation, so the host tests build it as is.

// True when the header block (status line and headers, without the blank
// line) carries Transfer-Encoding with "chunked" as its last coding.
// Header names and the coding compare without regard to case.
bool fl_http_is_chunked(const char *headers, size_t n);

typedef enum {
    FL_HTTP_OK = 0,
    FL_HTTP_BAD_SIZE,     // a size line that is not hex, or has no CRLF
    FL_HTTP_TOO_LARGE,    // a chunk, or the decoded total, over the cap
    FL_HTTP_BAD_FRAMING,  // data not followed by CRLF, or a bad trailer line
    FL_HTTP_TRUNCATED,    // the input ends before the last chunk and its final CRLF
} fl_http_err_t;

// Decodes a chunked body: size lines in hex with optional ";extensions",
// each chunk's data and its CRLF, the last chunk "0", optional trailer
// lines, and the final CRLF. Writes at most cap bytes to out (out may equal
// in: the decoded body is never longer than its input). Each chunk and the
// total must fit in cap. Bytes after the final CRLF are ignored.
fl_http_err_t fl_http_dechunk(const char *in, size_t n, char *out, size_t cap, size_t *out_len);

const char *fl_http_err_str(fl_http_err_t e);

#ifdef __cplusplus
}
#endif
