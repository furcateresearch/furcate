// Wi-Fi station and the outbound controller connection.
//
// The configuration arrives only as an operator-signed CONFIG message inside
// an authorised session, and is kept in NVS. Without flash encryption, NVS
// is plaintext flash: anyone with the board in hand can read the Wi-Fi
// passphrase (docs/SECURITY.md, docs/LOCKDOWN-LIST.md).
//
// Wi-Fi's own credential storage is off (WIFI_STORAGE_RAM): the passphrase
// is kept in one place only. The leaf opens no listening socket.

#include "fl_net.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "fl_crypto.h"
#include "fl_identity.h"
#include "fl_link.h"
#include "fl_trust.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "nvs.h"

static const char *TAG = "fl-net";
#define NS "fl-net"

static struct {
    uint32_t seq;
    char ssid[33];
    char host[16];
    uint16_t port;
    uint32_t auth_window_ms;
    char country[3];
} s_cfg;

static bool s_started, s_has_ip;
static char s_ip[16];
static int64_t s_ip_at_us = -1;
static uint32_t s_disconnects;
static esp_netif_t *s_netif;
static bool s_scan_logged;
static uint32_t s_fails;         // join attempts since the last address
static uint8_t s_last_reason;    // last disconnect reason from the driver
static bool s_restarting;        // radio being stopped for a new configuration
static esp_timer_handle_t s_retry;

uint32_t fl_net_auth_window_ms(void) { return s_cfg.auth_window_ms; }
bool fl_net_ready(void) { return s_has_ip && s_cfg.host[0] && s_cfg.port; }

static void schedule_join(void);

// No join attempts while a serial session is up: association and calibration
// hold the CPU long enough for the UART FIFO to overrun mid-record (an OTA
// stalled that way on 0.1.6 and 0.1.8).
static void retry_cb(void *arg) {
    if (!s_cfg.ssid[0]) return;
    if (fl_link_serial_busy()) {
        schedule_join();
        return;
    }
    esp_wifi_connect();
}

// Regulatory domain, manual policy, set while the radio is stopped. The driver
// default ("01") keeps channels 12 and 13 passive. Countries outside the short
// list below allow channels 1-13.
static uint8_t country_nchan(const char *cc) {
    static const char *const eleven[] = {"US", "CA", "TW", "PR", "MX", "CO", "PA", "DO", "GT", "UZ"};
    for (size_t i = 0; i < sizeof eleven / sizeof eleven[0]; i++)
        if (!strcmp(cc, eleven[i])) return 11;
    return 13;
}

static void country_wanted(wifi_country_t *c) {
    memset(c, 0, sizeof *c);
    c->cc[0] = s_cfg.country[0];
    c->cc[1] = s_cfg.country[1];
    c->cc[2] = ' ';
    c->schan = 1;
    c->nchan = country_nchan(s_cfg.country);
    c->policy = WIFI_COUNTRY_POLICY_MANUAL;
}

static void set_country(void) {
    if (!s_cfg.country[0]) return;
    wifi_country_t c;
    country_wanted(&c);
    esp_err_t e = esp_wifi_set_country(&c);
    if (e != ESP_OK) ESP_LOGE(TAG, "country %s: %s", s_cfg.country, esp_err_to_name(e));
}

// Reads back what the driver uses; sets it again if a start reset it.
static void check_country(void) {
    wifi_country_t got = {0}, want;
    esp_wifi_get_country(&got);
    if (s_cfg.country[0]) {
        country_wanted(&want);
        if (got.cc[0] != want.cc[0] || got.cc[1] != want.cc[1] || got.schan != want.schan ||
            got.nchan != want.nchan || got.policy != want.policy) {
            ESP_LOGW(TAG, "driver reports country %.2s channels %u-%u after start; setting it again", got.cc,
                     got.schan, got.schan + got.nchan - 1);
            set_country();
            esp_wifi_get_country(&got);
        }
    }
    ESP_LOGI(TAG, "driver country %.2s, channels %u-%u, %s policy, max TX %d dBm", got.cc, got.schan,
             got.schan + got.nchan - 1, got.policy == WIFI_COUNTRY_POLICY_MANUAL ? "manual" : "auto",
             got.max_tx_power / 4);
}

static uint8_t radio_channel(void) {
    uint8_t ch = 0;
    wifi_second_chan_t sc;
    if (esp_wifi_get_channel(&ch, &sc) != ESP_OK) ch = 0;
    return ch;
}

// Next join attempt: 2 s at first, then one per 30 s after repeated failures.
static void schedule_join(void) {
    if (!s_cfg.ssid[0]) return;
    if (!s_retry) {
        const esp_timer_create_args_t a = {.callback = retry_cb, .name = "fl-net-retry"};
        esp_timer_create(&a, &s_retry);
    }
    esp_timer_stop(s_retry);
    esp_timer_start_once(s_retry, (s_fails > 5 ? 30000ULL : 2000ULL) * 1000);
}

static const char *auth_name(wifi_auth_mode_t m) {
    switch (m) {
    case WIFI_AUTH_OPEN: return "open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default: return "other";
    }
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        s_restarting = false;
        check_country();
        schedule_join();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) {
        wifi_event_sta_connected_t *c = data;
        ESP_LOGI(TAG, "associated: channel %u, BSSID %02x:%02x:%02x:%02x:%02x:%02x, AID %u, attempt %u", c->channel,
                 c->bssid[0], c->bssid[1], c->bssid[2], c->bssid[3], c->bssid[4], c->bssid[5], c->aid,
                 (unsigned)s_fails + 1);
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *d = data;
        if (s_restarting) {  // our own stop for a new configuration
            s_has_ip = false;
            return;
        }
        if (s_has_ip) ESP_LOGW(TAG, "Wi-Fi disconnected (reason %d)", d->reason);
        s_has_ip = false;
        s_disconnects++;
        s_fails++;
        s_last_reason = d->reason;
        if (s_fails <= 10 || s_fails % 20 == 0)
            ESP_LOGW(TAG, "cannot join \"%s\" (reason %d, channel %u, RSSI %d, attempt %u)", s_cfg.ssid, d->reason,
                     radio_channel(), d->rssi, (unsigned)s_fails);
        // Once: list what the radio can see, so the failure is on record.
        if (!s_scan_logged) {
            s_scan_logged = true;
            if (esp_wifi_scan_start(NULL, false) == ESP_OK) return;
        }
        schedule_join();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_SCAN_DONE) {
        // Static: the event task's stack is small (a 20-record array on it
        // overflowed it in 0.1.5).
        static wifi_ap_record_t recs[16];
        uint16_t n = 16;
        if (esp_wifi_scan_get_ap_records(&n, recs) == ESP_OK) {
            ESP_LOGW(TAG, "scan: %u networks visible", n);
            for (int i = 0; i < n; i++)
                ESP_LOGW(TAG, "scan: %s\"%s\" channel %d RSSI %d %s", strcmp((const char *)recs[i].ssid, s_cfg.ssid) ? "" : "TARGET ",
                         (const char *)recs[i].ssid, recs[i].primary, recs[i].rssi, auth_name(recs[i].authmode));
        }
        schedule_join();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data;
        esp_ip4addr_ntoa(&e->ip_info.ip, s_ip, sizeof s_ip);
        if (s_ip_at_us < 0) s_ip_at_us = esp_timer_get_time();
        s_has_ip = true;
        s_fails = 0;
        wifi_ap_record_t ap;
        int rssi = esp_wifi_sta_get_ap_info(&ap) == ESP_OK ? ap.rssi : 0;
        ESP_LOGI(TAG, "Wi-Fi up: %s, RSSI %d dBm, channel %d, %lld ms after boot", s_ip, rssi,
                 rssi ? ap.primary : 0, s_ip_at_us / 1000);
    }
}

// Reads the stored passphrase, hands it to the Wi-Fi driver, wipes the copy.
static void wifi_apply(void) {
    wifi_config_t wc = {0};
    memcpy(wc.sta.ssid, s_cfg.ssid, strlen(s_cfg.ssid));
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) == ESP_OK) {
        size_t n = sizeof wc.sta.password;
        if (nvs_get_str(h, "psk", (char *)wc.sta.password, &n) != ESP_OK) wc.sta.password[0] = 0;
        nvs_close(h);
    }
    wc.sta.threshold.authmode = wc.sta.password[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    wc.sta.pmf_cfg.capable = true;
    esp_wifi_set_config(WIFI_IF_STA, &wc);
    fl_wipe(&wc, sizeof wc);
}

// Country and station settings go in while the radio is stopped, and a new
// configuration restarts the radio the way a boot does. Re-joining with only
// a disconnect and set_config on a running station timed out at association
// on every attempt (0.1.9), while the same settings joined from a boot.
static void wifi_start(void) {
    if (!s_started) {
        esp_netif_init();
        esp_event_loop_create_default();
        s_netif = esp_netif_create_default_wifi_sta();
        esp_netif_set_hostname(s_netif, "furcate-leaf");
        wifi_init_config_t ic = WIFI_INIT_CONFIG_DEFAULT();
        if (esp_wifi_init(&ic) != ESP_OK) {
            ESP_LOGE(TAG, "Wi-Fi init failed");
            return;
        }
        esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
        esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL);
        esp_wifi_set_storage(WIFI_STORAGE_RAM);
        esp_wifi_set_mode(WIFI_MODE_STA);
        wifi_apply();
        set_country();
        esp_wifi_start();
        s_started = true;
    } else {
        if (s_retry) esp_timer_stop(s_retry);
        s_restarting = true;
        esp_wifi_stop();
        s_has_ip = false;
        s_fails = 0;
        s_scan_logged = false;
        wifi_apply();
        set_country();
        esp_wifi_start();
    }
    ESP_LOGI(TAG, "Wi-Fi station: joining \"%s\"; controller %s:%u", s_cfg.ssid, s_cfg.host, s_cfg.port);
}

static void load(void) {
    memset(&s_cfg, 0, sizeof s_cfg);
    s_cfg.auth_window_ms = FL_AUTH_WINDOW_DEFAULT_MS;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) return;
    size_t n;
    nvs_get_u32(h, "seq", &s_cfg.seq);
    n = sizeof s_cfg.ssid;
    if (nvs_get_str(h, "ssid", s_cfg.ssid, &n) != ESP_OK) s_cfg.ssid[0] = 0;
    n = sizeof s_cfg.host;
    if (nvs_get_str(h, "host", s_cfg.host, &n) != ESP_OK) s_cfg.host[0] = 0;
    nvs_get_u16(h, "port", &s_cfg.port);
    uint32_t aw;
    if (nvs_get_u32(h, "aw", &aw) == ESP_OK) s_cfg.auth_window_ms = aw;
    n = sizeof s_cfg.country;
    if (nvs_get_str(h, "cc", s_cfg.country, &n) != ESP_OK) s_cfg.country[0] = 0;
    nvs_close(h);
}

void fl_net_init(void) {
    load();
    ESP_LOGI(TAG, "config seq %u, AUTH window %u ms", (unsigned)s_cfg.seq, (unsigned)s_cfg.auth_window_ms);
    if (s_cfg.ssid[0]) wifi_start();
    else ESP_LOGI(TAG, "no Wi-Fi configured: serial link only");
}

static uint8_t result(fl_wbuf_t *r, bool ok, const char *why) {
    fl_w_u8(r, T_OK, ok);
    if (why) fl_w_str(r, T_REASON, why);
    return FL_MSG_RESULT;
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

uint8_t fl_net_config(const uint8_t *tlv, size_t n, fl_wbuf_t *r) {
    fl_field_t env, body, sig;
    if (!fl_r_find(tlv, n, T_SIGNED, 0, &env) || !fl_r_valid(env.p, env.n) ||
        !fl_r_find(env.p, env.n, T_BODY, 0, &body) || !fl_r_find(env.p, env.n, T_SIG, 0, &sig))
        return result(r, false, "malformed config");
    const uint8_t *b = body.p;
    if (body.n < 40 || memcmp(b, "FLC1", 4) != 0) return result(r, false, "malformed config");
    if (!fl_trust_operator_signed(b, body.n, sig.p, sig.n))
        return result(r, false, "config not signed by a pinned operator key");
    if (memcmp(b + 4, fl_identity_id(), 32) != 0) return result(r, false, "config is for a different leaf");
    uint32_t seq = be32(b + 36);
    if (seq <= s_cfg.seq) return result(r, false, "config replay refused (sequence not newer)");
    const uint8_t *it = b + 40;
    size_t il = body.n - 40;
    if (!fl_r_valid(it, il)) return result(r, false, "malformed config items");

    fl_field_t ssid = {0}, psk = {0}, host = {0}, cc = {0};
    uint16_t port = 0;
    uint32_t aw = FL_AUTH_WINDOW_DEFAULT_MS;
    fl_r_find(it, il, 1, 0, &ssid);
    fl_r_find(it, il, 2, 0, &psk);
    fl_r_find(it, il, 3, 0, &host);
    fl_r_u16(it, il, 4, &port);
    fl_r_u32(it, il, 5, &aw);
    fl_r_find(it, il, 6, 0, &cc);
    if (cc.n && (cc.n != 2 || cc.p[0] < 'A' || cc.p[0] > 'Z' || cc.p[1] < 'A' || cc.p[1] > 'Z'))
        return result(r, false, "bad country code");
    if (ssid.n > 32 || (ssid.n == 0 && psk.n)) return result(r, false, "bad SSID");
    if (psk.n && (psk.n < 8 || psk.n > 63)) return result(r, false, "bad passphrase length");
    char hs[16] = {0};
    if (host.n) {
        struct in_addr a;
        if (host.n >= sizeof hs) return result(r, false, "bad controller host");
        memcpy(hs, host.p, host.n);
        if (inet_aton(hs, &a) == 0) return result(r, false, "bad controller host");
    }
    if (aw < FL_AUTH_WINDOW_MIN_MS || aw > FL_AUTH_WINDOW_MAX_MS)
        return result(r, false, "AUTH window outside the signed limits");

    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return result(r, false, "storage unavailable");
    char tmp[64];
    memcpy(tmp, ssid.p, ssid.n);
    tmp[ssid.n] = 0;
    nvs_set_str(h, "ssid", tmp);
    memcpy(tmp, psk.p, psk.n);
    tmp[psk.n] = 0;
    nvs_set_str(h, "psk", tmp);
    fl_wipe(tmp, sizeof tmp);
    nvs_set_str(h, "host", hs);
    nvs_set_u16(h, "port", port);
    nvs_set_u32(h, "aw", aw);
    char ccs[3] = {0};
    if (cc.n) memcpy(ccs, cc.p, 2);
    nvs_set_str(h, "cc", ccs);
    nvs_set_u32(h, "seq", seq);
    esp_err_t e = nvs_commit(h);
    nvs_close(h);
    if (e != ESP_OK) return result(r, false, "storage write failed");

    bool had_wifi = s_cfg.ssid[0];
    load();
    ESP_LOGI(TAG, "operator config seq %u applied (SSID \"%s\", controller %s:%u, AUTH window %u ms, country %s)",
             (unsigned)seq, s_cfg.ssid, s_cfg.host, s_cfg.port, (unsigned)s_cfg.auth_window_ms,
             s_cfg.country[0] ? s_cfg.country : "driver default");
    if (s_cfg.ssid[0]) wifi_start();
    else if (had_wifi && s_started) {
        if (s_retry) esp_timer_stop(s_retry);
        s_restarting = true;
        esp_wifi_stop();  // stays initialised; a later configuration starts it again
        s_has_ip = false;
    }
    return result(r, true, NULL);
}

int fl_net_dial(int timeout_ms) {
    if (!fl_net_ready()) return -1;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(s_cfg.port)};
    if (inet_aton(s_cfg.host, &a.sin_addr) == 0) return -1;
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, fl | O_NONBLOCK);
    int rc = connect(s, (struct sockaddr *)&a, sizeof a);
    if (rc < 0 && errno != EINPROGRESS) goto fail;
    if (rc < 0) {
        fd_set w;
        FD_ZERO(&w);
        FD_SET(s, &w);
        struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
        if (select(s + 1, NULL, &w, NULL, &tv) <= 0) goto fail;
        int err = 0;
        socklen_t el = sizeof err;
        getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err) goto fail;
    }
    fcntl(s, F_SETFL, fl & ~O_NONBLOCK);
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    struct timeval rt = {.tv_sec = 0, .tv_usec = 50000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rt, sizeof rt);
    return s;
fail:
    close(s);
    return -1;
}

void fl_net_info(fl_wbuf_t *w) {
    fl_w_u32(w, 76, s_cfg.seq);
    fl_w_u32(w, 77, s_cfg.auth_window_ms);
    if (!s_cfg.ssid[0]) return;
    fl_w_str(w, 71, s_cfg.ssid);
    wifi_ap_record_t ap;
    if (s_has_ip && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        fl_w_u8(w, 72, (uint8_t)ap.rssi);
        fl_w_u8(w, 73, ap.primary);
    }
    fl_w_str(w, 74, s_has_ip ? s_ip : "");
    if (s_ip_at_us >= 0) fl_w_u32(w, 75, (uint32_t)(s_ip_at_us / 1000));
    fl_w_u32(w, 79, s_disconnects);
    fl_w_u8(w, 80, s_last_reason);
    fl_w_u32(w, 81, s_fails);
    char ep[24];
    snprintf(ep, sizeof ep, "%s:%u", s_cfg.host, s_cfg.port);
    fl_w_str(w, 78, ep);
}
