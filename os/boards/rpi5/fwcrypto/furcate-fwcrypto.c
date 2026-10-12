/*
 * furcate-fwcrypto: the OTP device key's signing broker, and its client.
 *
 *   furcate-fwcrypto serve     the broker (socket-activated by
 *                              furcate-fwcrypto-broker.socket, runs as root)
 *   furcate-fwcrypto pubkey    print the broker's answer for the public key
 *   furcate-fwcrypto sign      sign stdin (at most 1 MiB), print the answer
 *   furcate-fwcrypto request   send one JSON request line from stdin
 *
 * The broker owns the firmware mailbox (/dev/vcio, root only) so the node's
 * unprivileged services do not: whoever opens /dev/vcio can send the firmware
 * any request, not just a signature. It answers two requests, for OTP key 1
 * only, on /run/furcate-os/fwcrypto.sock (root:furcate-fwcrypto 0660), from
 * root or the furcate user (SO_PEERCRED), one JSON object per line:
 *
 *   {"op":"sign","key_id":1,"alg":"ecdsa-p256-sha256","msg_b64":"..."}
 *     -> {"ok":true,"key_id":1,"sig_der_b64":"...","sig_raw_b64":"..."}
 *        ECDSA P-256 over SHA-256(msg); sig_raw is r||s, 64 bytes
 *   {"op":"pubkey","key_id":1}
 *     -> {"ok":true,"key_id":1,"spki_der_b64":"..."}
 *   anything else -> {"ok":false,"error":"..."}
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include "rpifwcrypto.h"

#define SOCK_PATH "/run/furcate-os/fwcrypto.sock"
#define KEY_ID 1
#define MSG_MAX (1024 * 1024)
#define LINE_MAX_LEN (MSG_MAX / 3 * 4 + 8192)

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64enc(const uint8_t *in, size_t n)
{
    char *out = malloc((n + 2) / 3 * 4 + 1), *o = out;
    if (!out)
        return NULL;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = in[i] << 16 | (i + 1 < n ? in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        *o++ = B64[v >> 18 & 63];
        *o++ = B64[v >> 12 & 63];
        *o++ = i + 1 < n ? B64[v >> 6 & 63] : '=';
        *o++ = i + 2 < n ? B64[v & 63] : '=';
    }
    *o = 0;
    return out;
}

static int b64val(int c)
{
    const char *p = c ? strchr(B64, c) : NULL;
    return p ? (int)(p - B64) : -1;
}

/* Strict standard base64 with padding. Returns length or -1. */
static long b64dec(const char *in, size_t n, uint8_t *out, size_t max)
{
    size_t o = 0;
    if (n % 4)
        return -1;
    for (size_t i = 0; i < n; i += 4) {
        int a = b64val(in[i]), b = b64val(in[i + 1]);
        int pad2 = in[i + 2] == '=', pad3 = in[i + 3] == '=';
        int c = pad2 ? 0 : b64val(in[i + 2]), d = pad3 ? 0 : b64val(in[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 || (pad2 && !pad3) || ((pad2 || pad3) && i + 4 != n))
            return -1;
        uint32_t v = a << 18 | b << 12 | c << 6 | d;
        size_t k = pad2 ? 1 : pad3 ? 2 : 3;
        if (o + k > max)
            return -1;
        out[o++] = v >> 16;
        if (k > 1)
            out[o++] = v >> 8 & 255;
        if (k > 2)
            out[o++] = v & 255;
    }
    return (long)o;
}

/* The value of "key" in a flat JSON object: a string (quotes stripped, no
 * escapes allowed) or a bare number. Returns a pointer into line and sets
 * *len, or NULL when absent or malformed. */
static const char *field(const char *line, const char *key, size_t *len, int *is_string)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(line, pat);
    if (!p)
        return NULL;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p++ != ':')
        return NULL;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '"') {
        const char *e = ++p;
        while (*e && *e != '"' && *e != '\\')
            e++;
        if (*e != '"')
            return NULL;
        *len = (size_t)(e - p);
        *is_string = 1;
        return p;
    }
    const char *e = p;
    while (*e >= '0' && *e <= '9')
        e++;
    if (e == p)
        return NULL;
    *len = (size_t)(e - p);
    *is_string = 0;
    return p;
}

static int field_is(const char *line, const char *key, const char *want, int string)
{
    size_t n;
    int s;
    const char *v = field(line, key, &n, &s);
    return v && s == string && n == strlen(want) && !memcmp(v, want, n);
}

/* DER INTEGER content -> 32 bytes big-endian. */
static int der_int32(const uint8_t *p, size_t n, uint8_t out[32])
{
    while (n > 32 && *p == 0) {
        p++;
        n--;
    }
    if (n > 32 || n == 0)
        return -1;
    memset(out, 0, 32);
    memcpy(out + 32 - n, p, n);
    return 0;
}

/* ECDSA-Sig-Value DER -> r||s. */
static int der_to_raw(const uint8_t *d, size_t n, uint8_t raw[64])
{
    if (n < 8 || d[0] != 0x30 || d[1] != n - 2 || d[2] != 0x02)
        return -1;
    size_t rl = d[3];
    if (4 + rl + 2 > n || d[4 + rl] != 0x02)
        return -1;
    size_t sl = d[5 + rl];
    if (6 + rl + sl != n)
        return -1;
    if (der_int32(d + 4, rl, raw) || der_int32(d + 6 + rl, sl, raw + 32))
        return -1;
    return 0;
}

static size_t der_put_int(uint8_t *o, const uint8_t *v)
{
    size_t i = 0;
    while (i < 31 && v[i] == 0)
        i++;
    size_t n = 32 - i, pad = v[i] & 0x80 ? 1 : 0;
    o[0] = 0x02;
    o[1] = (uint8_t)(n + pad);
    if (pad)
        o[2] = 0;
    memcpy(o + 2 + pad, v + i, n);
    return 2 + pad + n;
}

static size_t raw_to_der(const uint8_t raw[64], uint8_t der[72])
{
    size_t n = 2;
    n += der_put_int(der + n, raw);
    n += der_put_int(der + n, raw + 32);
    der[0] = 0x30;
    der[1] = (uint8_t)(n - 2);
    return n;
}

static void reply_error(FILE *out, const char *e)
{
    fprintf(out, "{\"ok\":false,\"error\":\"%s\"}\n", e);
    fflush(out);
}

static void fw_error(FILE *out, const char *what)
{
    char e[256];
    const char *s = rpi_fw_crypto_strerror(rpi_fw_crypto_get_last_error());
    snprintf(e, sizeof e, "%s: %s", what, s ? s : "unknown");
    for (char *c = e; *c; c++)
        if (*c == '"' || *c == '\\' || (unsigned char)*c < 0x20)
            *c = ' ';
    reply_error(out, e);
}

static void handle(const char *line, FILE *out)
{
    size_t n;
    int s;
    const char *kid = field(line, "key_id", &n, &s);
    if (!kid || s || n != 1 || *kid != '0' + KEY_ID) {
        reply_error(out, "only key_id 1 is served");
        return;
    }
    if (field_is(line, "op", "pubkey", 1)) {
        uint8_t pub[RPI_FW_CRYPTO_PUBLIC_KEY_MAX_SIZE + 32];
        size_t len = 0;
        if (rpi_fw_crypto_get_pubkey(0, KEY_ID, pub, RPI_FW_CRYPTO_PUBLIC_KEY_MAX_SIZE, &len) < 0 || len == 0) {
            fw_error(out, "the firmware returned no public key");
            return;
        }
        if (len == 65 && pub[0] == 0x04) {
            /* A bare uncompressed point: wrap it as a P-256 SubjectPublicKeyInfo. */
            static const uint8_t pre[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                                          0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                                          0x42, 0x00};
            memmove(pub + sizeof pre, pub, len);
            memcpy(pub, pre, sizeof pre);
            len += sizeof pre;
        }
        char *b = b64enc(pub, len);
        fprintf(out, "{\"ok\":true,\"key_id\":1,\"spki_der_b64\":\"%s\"}\n", b ? b : "");
        fflush(out);
        free(b);
        return;
    }
    if (field_is(line, "op", "sign", 1)) {
        if (!field_is(line, "alg", "ecdsa-p256-sha256", 1)) {
            reply_error(out, "alg must be ecdsa-p256-sha256");
            return;
        }
        const char *m = field(line, "msg_b64", &n, &s);
        if (!m || !s) {
            reply_error(out, "msg_b64 missing");
            return;
        }
        size_t pad = n >= 2 && m[n - 1] == '=' ? (m[n - 2] == '=' ? 2 : 1) : 0;
        if (n % 4 == 0 && n / 4 * 3 - pad > MSG_MAX) {
            reply_error(out, "message larger than 1 MiB");
            return;
        }
        uint8_t *msg = malloc(MSG_MAX ? MSG_MAX : 1);
        long ml = msg ? b64dec(m, n, msg, MSG_MAX) : -1;
        if (ml < 0) {
            free(msg);
            reply_error(out, "msg_b64 is not base64 of at most 1 MiB");
            return;
        }
        uint8_t hash[32], sig[RPI_FW_CRYPTO_ECDSA_RESP_MAX_SIZE], raw[64], der[72];
        size_t sl = 0, dl;
        int rc = gnutls_hash_fast(GNUTLS_DIG_SHA256, msg, (size_t)ml, hash);
        free(msg);
        if (rc < 0) {
            reply_error(out, "sha256 failed");
            return;
        }
        if (rpi_fw_crypto_ecdsa_sign(0, KEY_ID, hash, sizeof hash, sig, sizeof sig, &sl) < 0) {
            fw_error(out, "the firmware did not sign");
            return;
        }
        if (sl == 64) {
            memcpy(raw, sig, 64);
            dl = raw_to_der(raw, der);
        } else if (sl <= sizeof der && der_to_raw(sig, sl, raw) == 0) {
            memcpy(der, sig, sl);
            dl = sl;
        } else {
            reply_error(out, "the firmware returned a signature in an unknown form");
            return;
        }
        char *bd = b64enc(der, dl), *br = b64enc(raw, 64);
        fprintf(out, "{\"ok\":true,\"key_id\":1,\"sig_der_b64\":\"%s\",\"sig_raw_b64\":\"%s\"}\n", bd ? bd : "",
                br ? br : "");
        fflush(out);
        free(bd);
        free(br);
        return;
    }
    reply_error(out, "only sign and pubkey are served");
}

static int serve(void)
{
    const char *lp = getenv("LISTEN_PID"), *lf = getenv("LISTEN_FDS");
    if (!lp || !lf || atol(lp) != (long)getpid() || atoi(lf) != 1) {
        fprintf(stderr, "furcate-fwcrypto serve: start me from furcate-fwcrypto-broker.socket\n");
        return 2;
    }
    int lfd = 3;
    const char *user = getenv("FURCATE_FWCRYPTO_USER");
    struct passwd *pw = getpwnam(user ? user : "furcate");
    uid_t allowed = pw ? pw->pw_uid : (uid_t)-1;
    if (!pw)
        fprintf(stderr, "<4>furcate-fwcrypto: no user %s; only root is served\n", user ? user : "furcate");
    char *line = malloc(LINE_MAX_LEN + 2);
    if (!line)
        return 1;
    for (;;) {
        int c = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            perror("accept");
            return 1;
        }
        struct ucred cr = {0};
        socklen_t cl = sizeof cr;
        struct timeval tv = {10, 0};
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        FILE *in = fdopen(c, "r"), *out = fdopen(dup(c), "w");
        if (!in || !out) {
            if (in)
                fclose(in);
            else
                close(c);
            if (out)
                fclose(out);
            continue;
        }
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0 || (cr.uid != 0 && cr.uid != allowed)) {
            fprintf(stderr, "<4>furcate-fwcrypto: refused peer pid %d uid %d gid %d\n", (int)cr.pid, (int)cr.uid,
                    (int)cr.gid);
            reply_error(out, "peer not allowed");
        } else {
            while (fgets(line, LINE_MAX_LEN + 2, in)) {
                size_t n = strlen(line);
                if (n && line[n - 1] != '\n' && !feof(in)) {
                    reply_error(out, "request line too long");
                    break;
                }
                handle(line, out);
            }
        }
        fclose(in);
        fclose(out);
    }
}

static int client(const char *req)
{
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    const char *path = getenv("FURCATE_FWCRYPTO_SOCKET");
    snprintf(a.sun_path, sizeof a.sun_path, "%s", path ? path : SOCK_PATH);
    if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
        fprintf(stderr, "furcate-fwcrypto: cannot reach the broker at %s: %s\n", a.sun_path, strerror(errno));
        return 1;
    }
    size_t n = strlen(req);
    for (size_t o = 0; o < n;) {
        ssize_t w = write(s, req + o, n - o);
        if (w <= 0) {
            perror("furcate-fwcrypto: write");
            return 1;
        }
        o += (size_t)w;
    }
    shutdown(s, SHUT_WR);
    char buf[4096];
    ssize_t r;
    int any = 0;
    while ((r = read(s, buf, sizeof buf)) > 0) {
        fwrite(buf, 1, (size_t)r, stdout);
        any = 1;
    }
    return any ? 0 : 1;
}

static char *slurp(size_t max, size_t *len)
{
    char *b = malloc(max + 1);
    size_t n = 0;
    if (!b)
        return NULL;
    for (;;) {
        size_t r = fread(b + n, 1, max + 1 - n, stdin);
        n += r;
        if (r == 0 || n > max)
            break;
    }
    if (n > max) {
        free(b);
        return NULL;
    }
    b[n] = 0;
    *len = n;
    return b;
}

int main(int argc, char **argv)
{
    const char *cmd = argc > 1 ? argv[1] : "";
    if (!strcmp(cmd, "serve"))
        return serve();
    if (!strcmp(cmd, "pubkey"))
        return client("{\"op\":\"pubkey\",\"key_id\":1}\n");
    if (!strcmp(cmd, "sign")) {
        size_t n;
        char *m = slurp(MSG_MAX, &n);
        if (!m) {
            fprintf(stderr, "furcate-fwcrypto sign: the message on stdin is over 1 MiB\n");
            return 1;
        }
        char *b = b64enc((uint8_t *)m, n);
        free(m);
        size_t rl = strlen(b) + 128;
        char *req = malloc(rl);
        snprintf(req, rl, "{\"op\":\"sign\",\"key_id\":1,\"alg\":\"ecdsa-p256-sha256\",\"msg_b64\":\"%s\"}\n", b);
        free(b);
        return client(req);
    }
    if (!strcmp(cmd, "request")) {
        size_t n;
        char *r = slurp(LINE_MAX_LEN, &n);
        if (!r) {
            fprintf(stderr, "furcate-fwcrypto request: request too long\n");
            return 1;
        }
        return client(r);
    }
    fprintf(stderr, "usage: furcate-fwcrypto serve | pubkey | sign < message | request < json-line\n");
    return 2;
}
