// Signed requests from the leaf to the model gateway (fl_gateway.h).

#include "fl_gateway.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include "esp_log.h"
#include "esp_netif_sntp.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "fl_http.h"
#include "fl_identity.h"
#include "fl_net.h"
#include "fl_request.h"
#include "lwip/sockets.h"

static const char *TAG = "fl-gw";

#define BODY_MAX 4096       // request body the leaf sends (the session record bounds it too)
#define ANSWER_MAX 3072     // answer bytes kept for the reply
#define CONNECT_MS 3000
#define ANSWER_DEADLINE_US 20000000
// 2026-01-01T00:00:00Z: a clock before this has not been set.
#define EPOCH_FLOOR 1767225600ULL

static char s_head[16];
static bool s_sntp_started;
static volatile bool s_synced;
static uint32_t s_asks, s_last_status;

static void on_sync(struct timeval *tv) {
    if (!s_synced) ESP_LOGI(TAG, "clock set by SNTP: %lld", (long long)tv->tv_sec);
    s_synced = true;
}

void fl_time_start(const char *head) {
    if (s_sntp_started) return;
    snprintf(s_head, sizeof s_head, "%s", head ? head : "");
    esp_sntp_config_t c = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(
        s_head[0] ? 2 : 1, ESP_SNTP_SERVER_LIST(s_head[0] ? s_head : "pool.ntp.org", "pool.ntp.org"));
    c.wait_for_sync = false;
    c.sync_cb = on_sync;
    esp_err_t e = esp_netif_sntp_init(&c);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "SNTP: %s", esp_err_to_name(e));
        return;
    }
    s_sntp_started = true;
    ESP_LOGI(TAG, "SNTP started (%s%s)", s_head[0] ? s_head : "", s_head[0] ? ", pool.ntp.org" : "pool.ntp.org");
}

uint64_t fl_time_now(void) {
    if (!s_synced) return 0;
    time_t t = time(NULL);
    return (uint64_t)t >= EPOCH_FLOOR ? (uint64_t)t : 0;
}

static bool send_all(int s, const void *p, size_t n) {
    const uint8_t *b = p;
    while (n) {
        int k = send(s, b, n, 0);
        if (k <= 0) return false;
        b += k;
        n -= (size_t)k;
    }
    return true;
}

static bool field_str(const uint8_t *tlv, size_t n, uint8_t tag, char *out, size_t cap) {
    fl_field_t f;
    if (!fl_r_find(tlv, n, tag, 0, &f) || f.n == 0 || f.n >= cap || memchr(f.p, 0, f.n)) return false;
    memcpy(out, f.p, f.n);
    out[f.n] = 0;
    return true;
}

static uint8_t refuse(fl_wbuf_t *r, const char *why) {
    fl_w_u8(r, T_OK, 0);
    fl_w_str(r, T_REASON, why);
    ESP_LOGW(TAG, "no gateway request: %s", why);
    return FL_MSG_RESULT;
}

uint8_t fl_gateway_ask(const uint8_t *tlv, size_t n, fl_wbuf_t *r) {
    char method[8], target[FL_REQ_TARGET_MAX + 1];
    if (!field_str(tlv, n, T_METHOD, method, sizeof method) || !fl_req_method_ok(method))
        return refuse(r, "method must be GET or POST");
    if (!field_str(tlv, n, T_TARGET, target, sizeof target) || !fl_req_target_ok(target))
        return refuse(r, "target must be /health or /v1/...");
    fl_field_t body = {.p = NULL, .n = 0};
    fl_r_find(tlv, n, T_DATA, 0, &body);
    if (body.n > BODY_MAX) return refuse(r, "body too large");
    if (!fl_identity_ready()) return refuse(r, "no identity");
    uint64_t now = fl_time_now();
    if (!now) return refuse(r, "clock not set by SNTP yet");
    const char *head = fl_net_host();
    if (!head[0]) return refuse(r, "no controller configured");

    uint8_t rnd[8];
    esp_fill_random(rnd, sizeof rnd);
    char nonce[17];
    for (int i = 0; i < 8; i++) snprintf(nonce + 2 * i, 3, "%02x", rnd[i]);
    uint64_t expires = now + FL_REQ_VALIDITY_S;
    static char cred[FL_REQ_CRED_MAX];
    if (!fl_req_credential(fl_identity_pub(), fl_identity_sign, method, target, body.p, body.n, nonce, expires,
                           cred, sizeof cred))
        return refuse(r, "signing failed");

    int64_t t0 = esp_timer_get_time();
    int s = fl_net_dial_port(FL_REQ_GATEWAY_PORT, CONNECT_MS);
    if (s < 0) return refuse(r, "gateway not reachable");
    struct timeval rt = {.tv_sec = 0, .tv_usec = 500000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rt, sizeof rt);
    static char head_buf[FL_REQ_TARGET_MAX + FL_REQ_CRED_MAX + 256];
    int hl = snprintf(head_buf, sizeof head_buf,
                      "%s %s HTTP/1.1\r\nHost: %s:%u\r\nContent-Length: %u\r\n%sX-Furcate-Credential: %s\r\n"
                      "Connection: close\r\n\r\n",
                      method, target, head, FL_REQ_GATEWAY_PORT, (unsigned)body.n,
                      body.n ? "Content-Type: application/json\r\n" : "", cred);
    if (hl <= 0 || (size_t)hl >= sizeof head_buf || !send_all(s, head_buf, (size_t)hl) ||
        (body.n && !send_all(s, body.p, body.n))) {
        close(s);
        return refuse(r, "send failed");
    }

    // The answer: status line, headers, body; kept up to ANSWER_MAX bytes,
    // read until the gateway closes or the deadline passes.
    static char ans[ANSWER_MAX + 1];
    size_t al = 0;
    bool closed = false, cut = false;
    while (esp_timer_get_time() - t0 < ANSWER_DEADLINE_US) {
        char tmp[512];
        int k = recv(s, tmp, sizeof tmp, 0);
        if (k == 0) {
            closed = true;
            break;
        }
        if (k < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        size_t take = (size_t)k < ANSWER_MAX - al ? (size_t)k : ANSWER_MAX - al;
        if (take < (size_t)k) cut = true;
        memcpy(ans + al, tmp, take);
        al += take;
    }
    close(s);
    ans[al] = 0;
    int64_t us = esp_timer_get_time() - t0;
    unsigned status = 0;
    if (sscanf(ans, "HTTP/1.%*c %u", &status) != 1) status = 0;
    const char *hend = strstr(ans, "\r\n\r\n");
    char *b = hend ? (char *)hend + 4 : ans + al;
    size_t bl = (size_t)(ans + al - b);
    s_asks++;
    s_last_status = status;
    // A chunked answer is handed back as its decoded body; one that is
    // malformed, or longer than the buffer, is refused with the status kept.
    bool chunked = hend && fl_http_is_chunked(ans, (size_t)(hend - ans));
    if (chunked) {
        size_t dl = 0;
        fl_http_err_t e = cut ? FL_HTTP_TOO_LARGE : fl_http_dechunk(b, bl, b, ANSWER_MAX, &dl);
        if (e != FL_HTTP_OK) {
            ESP_LOGW(TAG, "%s %s -> %u in %lld ms: %s", method, target, status, (long long)(us / 1000),
                     fl_http_err_str(e));
            fl_w_u8(r, T_OK, 0);
            fl_w_u32(r, T_STATUS, status);
            fl_w_str(r, T_REASON, fl_http_err_str(e));
            fl_w_str(r, T_CREDENTIAL, cred);
            fl_w_u32(r, T_LATENCY_US, (uint32_t)us);
            return FL_MSG_RESULT;
        }
        bl = dl;
    }
    ESP_LOGI(TAG, "%s %s -> %u in %lld ms (nonce %s, expires %" PRIu64 "%s%s)", method, target, status,
             (long long)(us / 1000), nonce, expires, chunked ? ", chunked" : "", closed ? "" : ", answer not closed");
    fl_w_u8(r, T_OK, status == 200);
    fl_w_u32(r, T_STATUS, status);
    fl_w_str(r, T_CREDENTIAL, cred);
    fl_w_bytes(r, T_DATA, b, bl);
    fl_w_u32(r, T_LATENCY_US, (uint32_t)us);
    return FL_MSG_RESULT;
}

void fl_gateway_info(fl_wbuf_t *w) {
    fl_w_u32(w, 82, (uint32_t)fl_time_now());
    fl_w_u32(w, 83, s_asks);
    fl_w_u32(w, 84, s_last_status);
}
