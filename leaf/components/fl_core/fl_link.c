// The leaf's communication channel.
//
// Transports: the serial console (frames are "FL1:" + base64 + newline, log
// lines are plain text), and, once the operator has configured Wi-Fi, one
// outbound TCP connection to the controller carrying the same frames. The
// leaf dials out; it never listens. Log lines stay on the serial console.
//
// The AUTH window (how long the leaf waits for AUTH after each HELLO) comes
// from the operator-signed configuration, within fixed limits (fl_net.h).
// Widening it does not weaken replay protection: every HELLO carries a fresh
// ephemeral key and nonce that the node's signature must cover.
//
// Handshake (the leaf starts it, every time):
//   HELLO   leaf -> node   leaf public key, ephemeral key, nonce, evidence
//   AUTH    node -> leaf   node public key, ephemeral key, operator-signed
//                          grant for that node key, node signature over the
//                          transcript
//   FINISH  leaf -> node   leaf signature over the transcript
// Then every message is AES-256-GCM with per-direction keys from
// HKDF(ECDH(ephemeral keys), transcript hash) and a counter nonce.
// A node that cannot show an operator grant gets REFUSE and nothing else.

#include "fl_link.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "fl_identity.h"
#include "fl_net.h"
#include "lwip/sockets.h"

static const char *TAG = "fl-link";

#define PORT UART_NUM_0
#define MAX_MSG 6144
#define MAX_LINE (MAX_MSG * 4 / 3 + 16)
#define TCP_MISSES_BEFORE_REDIAL 4
#define SESSION_IDLE_US 60000000

static SemaphoreHandle_t s_tx_lock;

static void tx_raw(const char *s, size_t n) {
    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    uart_write_bytes(PORT, s, n);
    xSemaphoreGive(s_tx_lock);
}

static int log_vprintf(const char *fmt, va_list ap) {
    char line[256];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    if (n < 0) return n;
    if (n >= (int)sizeof line) n = sizeof line - 1;
    tx_raw(line, (size_t)n);
    return n;
}

// The UART interrupt is allocated on the core that installs the driver. It is
// installed from a task on core 1, away from the Wi-Fi stack on core 0:
// with both on core 0, radio activity held the interrupt off long enough for
// the 128-byte receive FIFO to overrun mid-record (OTA and SINK streams
// stalled on 0.1.6 and 0.1.8).
static void uart_install_task(void *arg) {
    uart_driver_install(PORT, 16384, 8192, 0, NULL, 0);
    xTaskNotifyGive((TaskHandle_t)arg);
    vTaskDelete(NULL);
}

void fl_link_console_init(void) {
    s_tx_lock = xSemaphoreCreateMutex();
    xTaskCreatePinnedToCore(uart_install_task, "fl-uart", 3072, xTaskGetCurrentTaskHandle(), 10, NULL, 1);
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    esp_log_set_vprintf(log_vprintf);
}

// Outbound controller connection; -1 while the serial console is the transport.
static int s_sock = -1;
static volatile bool s_ses_up_serial;  // a session is up on the serial console
static bool s_dead;
static uint8_t s_rbuf[1460];
static size_t s_rpos, s_rlen;

static void tx_frame(const char *s, size_t n) {
    if (s_sock < 0) {
        tx_raw(s, n);
        return;
    }
    while (n && !s_dead) {
        int k = send(s_sock, s, n, 0);
        if (k <= 0) {
            s_dead = true;
            break;
        }
        s += k;
        n -= (size_t)k;
    }
}

// One byte from the current transport: 1, 0 on a quiet 50 ms, -1 when the
// connection has gone.
static int rx_byte(uint8_t *c) {
    if (s_sock < 0) return uart_read_bytes(PORT, c, 1, pdMS_TO_TICKS(50)) == 1;
    if (s_dead) return -1;
    if (s_rpos == s_rlen) {
        int k = recv(s_sock, s_rbuf, sizeof s_rbuf, 0);
        if (k == 0 || (k < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            s_dead = true;
            return -1;
        }
        if (k < 0) return 0;
        s_rpos = 0;
        s_rlen = (size_t)k;
    }
    *c = s_rbuf[s_rpos++];
    return 1;
}

const char *fl_link_transport(void) { return s_sock >= 0 ? "wifi-tcp" : "serial"; }

bool fl_link_serial_busy(void) { return s_ses_up_serial; }

static char s_line[MAX_LINE];
static uint8_t s_in[MAX_MSG + 64], s_out[MAX_MSG + 64], s_plain[MAX_MSG + 64];

static void send_msg(const uint8_t *m, size_t n) {
    static char enc[MAX_LINE];
    memcpy(enc, "FL1:", 4);
    size_t e = fl_b64_encode(m, n, enc + 4);
    enc[4 + e] = '\n';
    tx_frame(enc, 4 + e + 1);
}

// Reads one frame line; returns decoded length, 0 on timeout, -1 on junk.
static int recv_msg(uint8_t *out, size_t cap, int64_t deadline_us) {
    size_t n = 0;
    while (esp_timer_get_time() < deadline_us) {
        uint8_t c;
        int k = rx_byte(&c);
        if (k < 0) return 0;
        if (k == 0) continue;
        if (c == '\r') continue;
        if (c == '\n') {
            if (n > 4 && memcmp(s_line, "FL1:", 4) == 0) return fl_b64_decode(s_line + 4, n - 4, out, cap);
            n = 0;
            continue;
        }
        if (n < sizeof s_line) s_line[n++] = (char)c;
        else n = 0;
    }
    return 0;
}

typedef struct {
    bool up;
    uint8_t k_tx[32], k_rx[32];
    uint64_t c_tx, c_rx;
    fl_grant_t grant;
    int64_t last_us;
} session_t;

static session_t s_ses;

static void nonce_for(uint64_t c, uint8_t dir, uint8_t n[12]) {
    memset(n, 0, 12);
    n[0] = dir;
    for (int i = 0; i < 8; i++) n[4 + i] = (uint8_t)(c >> (56 - 8 * i));
}

static void send_sealed(const uint8_t *plain, size_t n) {
    static uint8_t box[MAX_MSG + 32];
    uint8_t nonce[12];
    nonce_for(s_ses.c_tx, 'L', nonce);
    if (!fl_seal(s_ses.k_tx, nonce, plain, n, box)) return;
    fl_wbuf_t w;
    fl_w_init(&w, s_out, sizeof s_out, FL_MSG_SEALED);
    fl_w_u32(&w, T_COUNTER, (uint32_t)s_ses.c_tx);
    fl_w_bytes(&w, T_BOX, box, n + 16);
    s_ses.c_tx++;
    if (!w.overflow) send_msg(s_out, w.len);
}

static void refuse(const char *why) {
    ESP_LOGW(TAG, "refused node: %s", why);
    fl_wbuf_t w;
    fl_w_init(&w, s_out, sizeof s_out, FL_MSG_REFUSE);
    fl_w_str(&w, T_REASON, why);
    send_msg(s_out, w.len);
}

static void end_session(void) {
    fl_wipe(&s_ses, sizeof s_ses);
}

// Runs one handshake attempt. Returns true when a session is up.
static bool handshake(void) {
    uint8_t eph_priv[32], eph_pub[FL_PUB_LEN], nonce[32];
    fl_p256_keygen(eph_priv, eph_pub);
    esp_fill_random(nonce, sizeof nonce);

    static uint8_t ev[512];
    fl_wbuf_t e;
    fl_w_init(&e, ev, sizeof ev, 0);
    fl_identity_evidence(&e);

    static uint8_t hello[1024];
    fl_wbuf_t w;
    fl_w_init(&w, hello, sizeof hello, FL_MSG_HELLO);
    fl_w_u8(&w, T_VERSION, 1);
    fl_w_bytes(&w, T_DEV_PUB, fl_identity_pub(), FL_PUB_LEN);
    fl_w_bytes(&w, T_EPH, eph_pub, FL_PUB_LEN);
    fl_w_bytes(&w, T_NONCE, nonce, 32);
    fl_w_bytes(&w, T_EVIDENCE, ev + 1, e.len - 1);
    send_msg(hello, w.len);

    int n = recv_msg(s_in, sizeof s_in, esp_timer_get_time() + (int64_t)fl_net_auth_window_ms() * 1000);
    if (n <= 1) goto fail;
    if (s_in[0] != FL_MSG_AUTH) goto fail;  // anything not answering our HELLO is ignored
    const uint8_t *t = s_in + 1;
    size_t tl = (size_t)n - 1;
    fl_field_t node_pub, node_eph, grant, gsig, nsig;
    if (!fl_r_valid(t, tl) || !fl_r_find(t, tl, T_NODE_PUB, 0, &node_pub) || node_pub.n != FL_PUB_LEN ||
        !fl_r_find(t, tl, T_EPH, 0, &node_eph) || node_eph.n != FL_PUB_LEN ||
        !fl_r_find(t, tl, T_GRANT, 0, &grant) || !fl_r_find(t, tl, T_GRANT_SIG, 0, &gsig) ||
        !fl_r_find(t, tl, T_NODE_SIG, 0, &nsig)) {
        refuse("malformed AUTH");
        goto fail;
    }
    fl_grant_t g;
    const char *why = fl_trust_check_grant(grant.p, grant.n, gsig.p, gsig.n, fl_identity_id(), &g);
    if (why) {
        refuse(why);
        goto fail;
    }
    if (memcmp(g.node_pub, node_pub.p, FL_PUB_LEN) != 0) {
        refuse("grant was issued to a different node key");
        goto fail;
    }
    // Transcript: everything both sides said, in order.
    fl_sha256_t th;
    uint8_t thash[32];
    fl_sha256_init(&th);
    fl_sha256_update(&th, "FL1 transcript", 14);
    fl_sha256_update(&th, hello, w.len);
    fl_sha256_update(&th, node_pub.p, node_pub.n);
    fl_sha256_update(&th, node_eph.p, node_eph.n);
    fl_sha256_update(&th, grant.p, grant.n);
    fl_sha256_final(&th, thash);
    uint8_t nh[32];
    {
        uint8_t m[14 + 32];
        memcpy(m, "FL1 node auth ", 14);
        memcpy(m + 14, thash, 32);
        fl_sha256(m, sizeof m, nh);
    }
    if (!fl_p256_verify_der(node_pub.p, nh, nsig.p, nsig.n)) {
        refuse("node signature does not verify");
        goto fail;
    }
    uint8_t shared[32];
    if (!fl_p256_ecdh(eph_priv, node_eph.p, shared)) {
        refuse("bad ephemeral key");
        goto fail;
    }
    fl_wipe(eph_priv, sizeof eph_priv);
    fl_hkdf(thash, 32, shared, 32, "FL1 leaf to node", s_ses.k_tx, 32);
    fl_hkdf(thash, 32, shared, 32, "FL1 node to leaf", s_ses.k_rx, 32);
    fl_wipe(shared, sizeof shared);

    uint8_t lh[32], sig[FL_SIG_LEN];
    {
        uint8_t m[14 + 32 + 72];
        memcpy(m, "FL1 leaf auth ", 14);
        memcpy(m + 14, thash, 32);
        size_t sn = nsig.n < 72 ? nsig.n : 72;
        memcpy(m + 46, nsig.p, sn);
        fl_sha256(m, 46 + sn, lh);
    }
    fl_identity_sign(lh, sig);
    fl_w_init(&w, s_out, sizeof s_out, FL_MSG_FINISH);
    fl_w_bytes(&w, T_DEV_SIG, sig, FL_SIG_LEN);
    send_msg(s_out, w.len);

    s_ses.grant = g;
    s_ses.c_tx = s_ses.c_rx = 0;
    s_ses.last_us = esp_timer_get_time();
    s_ses.up = true;
    ESP_LOGI(TAG, "session up over %s: node grant generation %u, roles 0x%02x", fl_link_transport(),
             (unsigned)g.generation, g.roles);
    return true;
fail:
    fl_wipe(eph_priv, sizeof eph_priv);
    return false;
}

static uint8_t required_role(uint8_t type) {
    switch (type) {
    case FL_MSG_INFO_REQ:
    case FL_MSG_BYE:
        return FL_ROLE_READ;
    case FL_MSG_INFER:
        return FL_ROLE_COMMAND;
    case FL_MSG_MODEL_OFFER:
    case FL_MSG_MODEL_CHUNK:
    case FL_MSG_MODEL_COMMIT:
    case FL_MSG_MODEL_ROLLBACK:
        return FL_ROLE_MODEL;
    case FL_MSG_REVOKE:
    case FL_MSG_CONFIG:
        return FL_ROLE_CONFIG;
    case FL_MSG_SINK:
        return FL_ROLE_READ;
    case FL_MSG_OTA_OFFER:
    case FL_MSG_OTA_CHUNK:
    case FL_MSG_OTA_COMMIT:
        return FL_ROLE_OTA;
    default:
        return 0xFF;
    }
}

static void serve(fl_cmd_handler_t handler) {
    s_ses_up_serial = s_sock < 0;
    while (s_ses.up && !s_dead) {
        int n = recv_msg(s_in, sizeof s_in, esp_timer_get_time() + 1000000);
        if (esp_timer_get_time() - s_ses.last_us > SESSION_IDLE_US) {
            ESP_LOGI(TAG, "session idle; closing");
            break;
        }
        if (n <= 1 || s_in[0] != FL_MSG_SEALED) continue;
        uint32_t ctr;
        fl_field_t box;
        if (!fl_r_u32(s_in + 1, n - 1, T_COUNTER, &ctr) || !fl_r_find(s_in + 1, n - 1, T_BOX, 0, &box) ||
            box.n < 17 || box.n - 16 > sizeof s_plain || ctr != (uint32_t)s_ses.c_rx) {
            ESP_LOGW(TAG, "dropped a record (bad framing or replayed counter)");
            continue;
        }
        uint8_t nonce[12];
        nonce_for(s_ses.c_rx, 'N', nonce);
        if (!fl_open(s_ses.k_rx, nonce, box.p, box.n, s_plain)) {
            ESP_LOGW(TAG, "dropped a record that failed authentication");
            continue;
        }
        s_ses.c_rx++;
        s_ses.last_us = esp_timer_get_time();
        size_t pl = box.n - 16;
        uint8_t type = s_plain[0];
        static uint8_t reply[MAX_MSG];
        fl_wbuf_t r;
        if (pl < 1 || !fl_r_valid(s_plain + 1, pl - 1)) continue;
        uint8_t need = required_role(type);
        if (need == 0xFF || !(s_ses.grant.roles & need)) {
            fl_w_init(&r, reply, sizeof reply, FL_MSG_RESULT);
            fl_w_u8(&r, T_OK, 0);
            fl_w_str(&r, T_REASON, need == 0xFF ? "unknown command" : "grant does not allow this command");
            fl_w_u8(&r, T_ROLE_NEEDED, need);
            send_sealed(reply, r.len);
            ESP_LOGW(TAG, "command 0x%02x refused: role 0x%02x not granted", type, need);
            continue;
        }
        if (type == FL_MSG_BYE) break;
        fl_w_init(&r, reply, sizeof reply, 0);
        uint8_t rt = handler(type, s_plain + 1, pl - 1, &s_ses.grant, &r);
        if (rt && !r.overflow) {
            reply[0] = rt;
            send_sealed(reply, r.len);
        }
        fl_wipe(s_plain, pl);
    }
    s_ses_up_serial = false;
    end_session();
}

static void close_tcp(const char *why) {
    if (s_sock < 0) return;
    close(s_sock);
    s_sock = -1;
    s_dead = false;
    s_rpos = s_rlen = 0;
    ESP_LOGI(TAG, "controller connection closed (%s)", why);
}

void fl_link_run(fl_cmd_handler_t handler) {
    int misses = 0;
    bool unreachable_logged = false;
    for (;;) {
        if (!fl_identity_ready()) {
            ESP_LOGE(TAG, "no identity; the leaf does not communicate");
            vTaskDelay(pdMS_TO_TICKS(10000));
            continue;
        }
        if (s_sock < 0 && fl_net_ready()) {
            int64_t t0 = esp_timer_get_time();
            int s = fl_net_dial(3000);
            if (s >= 0) {
                s_sock = s;
                s_dead = false;
                s_rpos = s_rlen = 0;
                misses = 0;
                unreachable_logged = false;
                ESP_LOGI(TAG, "connected out to the controller in %lld ms",
                         (long long)((esp_timer_get_time() - t0) / 1000));
            } else if (!unreachable_logged) {
                ESP_LOGW(TAG, "controller not reachable; serial link meanwhile");
                unreachable_logged = true;
            }
        }
        if (s_sock >= 0) {
            if (handshake()) {
                misses = 0;
                serve(handler);
            } else {
                misses++;
            }
            if (s_dead) close_tcp("connection lost");
            else if (misses >= TCP_MISSES_BEFORE_REDIAL) close_tcp("no AUTH; redialling after one serial turn");
            else continue;
        }
        // Serial turn: always available on the bench, and the only link
        // until the operator has configured Wi-Fi.
        if (handshake()) serve(handler);
    }
}
