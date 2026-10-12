// SRAM start-up fingerprint and key reconstruction.
//
// A region of internal SRAM that neither the ROM nor the second-stage
// bootloader writes is read before anything else touches it. On a real
// power-up its contents are set by manufacturing variation in each cell, so
// the pattern is specific to this piece of silicon.
//
// The chip cannot cut its own power, but deep sleep powers the main SRAM
// down. If the region still holds the wipe marker written on the previous
// boot (an EN reset does not always remove power for long enough), the
// device sleeps briefly and reads again.
//
// Enrollment takes FL_PUF_ENROLL_READS readings across deep-sleep cycles and
// keeps only bits that never changed. Each secret bit is then carried by
// FL_PUF_REP stable cells: helper data stores the XOR of each extra cell with
// the first one, and reconstruction takes a majority vote. Helper data is
// not secret on its own; the secret is the cells' values, which never leave
// SRAM except as the derived key.

#include "fl_puf.h"

#include <string.h>
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "heap_memory_layout.h"
#include "nvs.h"

static const char *TAG = "fl-puf";

#define REGION_BYTES 2048
#define MARK 0xA5

// A fixed physical address, the same in every firmware image: helper data
// names cell positions, so the region must never move with the link layout.
// 0x3FFD0000-0x3FFDFFFF is internal DRAM that neither the ROM nor the
// second-stage bootloader uses, far above the app's static data; the range
// is reserved from the heap so nothing allocates it. (Up to 0.1.3 the region
// was a linker-placed variable; 0.1.3 moved it, see docs/TEST-RESULTS.md.)
#define REGION_ADDR 0x3FFDF000
SOC_RESERVE_MEMORY_REGION(REGION_ADDR, REGION_ADDR + REGION_BYTES, fl_puf_region);
static uint8_t *const s_region = (uint8_t *)REGION_ADDR;
extern uint8_t _bss_end;
// A reading that disagrees with enrollment in more cells than this is not
// this enrollment's region (a healthy boot flips about 1%).
#define MAX_FLIPPED_CELLS (FL_PUF_BITS * FL_PUF_REP * 15 / 100)

// Enrollment state survives deep sleep in RTC slow memory.
typedef struct {
    uint32_t magic;
    uint32_t reads;
    uint8_t ref[REGION_BYTES];
    uint8_t stable[REGION_BYTES];
} enroll_state_t;
static RTC_NOINIT_ATTR enroll_state_t s_enroll;
static RTC_NOINIT_ATTR uint32_t s_retry_magic;
static RTC_NOINIT_ATTR uint32_t s_retries;
#define ENROLL_MAGIC 0x464c5045u
#define RETRY_MAGIC 0x464c5052u

static uint8_t s_reading[REGION_BYTES];
static fl_puf_stats_t s_stats;

static int popcount8(uint8_t v) { return __builtin_popcount(v); }

static bool region_is_marked(const uint8_t *r) {
    int same = 0;
    for (int i = 0; i < REGION_BYTES; i++) same += (r[i] == MARK);
    return same > REGION_BYTES * 9 / 10;
}

static void sleep_and_reread(void) {
    esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_SLOW_MEM, ESP_PD_OPTION_ON);
    esp_sleep_enable_timer_wakeup(FL_PUF_SLEEP_US);
    esp_deep_sleep_start();
}

// Called first thing in app_main. May not return (deep sleep).
void fl_puf_capture(void) {
    if ((uintptr_t)&_bss_end > REGION_ADDR) {
        ESP_LOGE(TAG, "static data reaches the fingerprint region; no fingerprint");
        s_stats.valid = false;
        return;
    }
    memcpy(s_reading, s_region, REGION_BYTES);
    memset(s_region, MARK, REGION_BYTES);

    if (s_retry_magic != RETRY_MAGIC) {
        s_retry_magic = RETRY_MAGIC;
        s_retries = 0;
    }
    if (region_is_marked(s_reading)) {
        s_stats.retained_boots++;
        if (s_retries < 5) {
            s_retries++;
            ESP_LOGW(TAG, "SRAM kept its contents across reset; power-cycling SRAM via deep sleep");
            sleep_and_reread();
        }
        ESP_LOGE(TAG, "SRAM never powered down; no fingerprint this boot");
        s_stats.valid = false;
        return;
    }
    s_stats.sleep_cycles = s_retries;
    s_retries = 0;
    s_stats.valid = true;
    int ones = 0;
    for (int i = 0; i < REGION_BYTES; i++) ones += popcount8(s_reading[i]);
    s_stats.ones_permille = (uint16_t)(ones * 1000 / (REGION_BYTES * 8));
}

// Enrollment across deep-sleep cycles. Returns true when complete; may not
// return while it is still collecting readings.
static bool enroll_step(void) {
    if (s_enroll.magic != ENROLL_MAGIC) {
        memcpy(s_enroll.ref, s_reading, REGION_BYTES);
        memset(s_enroll.stable, 0xFF, REGION_BYTES);
        s_enroll.reads = 1;
        s_enroll.magic = ENROLL_MAGIC;
    } else {
        for (int i = 0; i < REGION_BYTES; i++) s_enroll.stable[i] &= ~(s_enroll.ref[i] ^ s_reading[i]);
        s_enroll.reads++;
    }
    if (s_enroll.reads < FL_PUF_ENROLL_READS) {
        ESP_LOGI(TAG, "enrollment reading %u of %d", (unsigned)s_enroll.reads, FL_PUF_ENROLL_READS);
        sleep_and_reread();
    }
    return true;
}

// Helper data layout in NVS: positions[FL_PUF_BITS][FL_PUF_REP] (u16) and
// parity[FL_PUF_BITS] (u8 bitmask of FL_PUF_REP-1 XOR bits).
typedef struct {
    uint16_t pos[FL_PUF_BITS][FL_PUF_REP];
    uint8_t parity[FL_PUF_BITS];
} helper_t;

static int bit_at(const uint8_t *buf, int pos) { return (buf[pos >> 3] >> (pos & 7)) & 1; }

esp_err_t fl_puf_secret(uint8_t out[FL_PUF_BITS / 8], fl_puf_stats_t *stats) {
    if (!s_stats.valid) return ESP_ERR_INVALID_STATE;
    static helper_t h;
    nvs_handle_t nv;
    ESP_ERROR_CHECK(nvs_open("fl-puf", NVS_READWRITE, &nv));
    size_t len = sizeof h;
    esp_err_t e = nvs_get_blob(nv, "helper2", &h, &len);
    if (e != ESP_OK || len != sizeof h) {
        size_t ol = 0;
        if (nvs_get_blob(nv, "helper", NULL, &ol) == ESP_OK)
            ESP_LOGW(TAG, "helper data belongs to the old linker-placed region; enrolling the fixed region "
                          "at 0x%08x: this leaf's id changes once", REGION_ADDR);
        enroll_step();  // returns only when enrollment has enough readings
        int stable_bits = 0;
        for (int i = 0; i < REGION_BYTES; i++) stable_bits += popcount8(s_enroll.stable[i]);
        s_stats.enroll_stable_permille = (uint16_t)(stable_bits * 1000 / (REGION_BYTES * 8));
        if (stable_bits < FL_PUF_BITS * FL_PUF_REP) {
            ESP_LOGE(TAG, "only %d stable cells; need %d", stable_bits, FL_PUF_BITS * FL_PUF_REP);
            s_enroll.magic = 0;
            nvs_close(nv);
            return ESP_ERR_INVALID_SIZE;
        }
        // Spread the chosen cells across the region rather than taking the first ones.
        int stride = stable_bits / (FL_PUF_BITS * FL_PUF_REP);
        int seen = 0, k = 0;
        for (int p = 0; p < REGION_BYTES * 8 && k < FL_PUF_BITS * FL_PUF_REP; p++) {
            if (!bit_at(s_enroll.stable, p)) continue;
            if (seen++ % stride) continue;
            h.pos[k / FL_PUF_REP][k % FL_PUF_REP] = (uint16_t)p;
            k++;
        }
        for (int b = 0; b < FL_PUF_BITS; b++) {
            uint8_t par = 0;
            int first = bit_at(s_enroll.ref, h.pos[b][0]);
            for (int j = 1; j < FL_PUF_REP; j++)
                par |= (uint8_t)((bit_at(s_enroll.ref, h.pos[b][j]) ^ first) << (j - 1));
            h.parity[b] = par;
        }
        ESP_ERROR_CHECK(nvs_set_blob(nv, "helper2", &h, sizeof h));
        ESP_ERROR_CHECK(nvs_set_u32(nv, "addr", REGION_ADDR));
        nvs_erase_key(nv, "helper");
        ESP_ERROR_CHECK(nvs_set_u16(nv, "stable", s_stats.enroll_stable_permille));
        ESP_ERROR_CHECK(nvs_commit(nv));
        memset(&s_enroll, 0, sizeof s_enroll);
        s_stats.enrolled_now = true;
        ESP_LOGI(TAG, "enrolled: %u/1000 cells stable over %d readings", s_stats.enroll_stable_permille,
                 FL_PUF_ENROLL_READS);
    } else {
        nvs_get_u16(nv, "stable", &s_stats.enroll_stable_permille);
    }
    nvs_close(nv);

    memset(out, 0, FL_PUF_BITS / 8);
    int flipped_cells = 0, corrected = 0;
    for (int b = 0; b < FL_PUF_BITS; b++) {
        int first = bit_at(s_reading, h.pos[b][0]);
        int votes1 = 0;
        // Each cell votes for the value of the first cell at enrollment.
        for (int j = 0; j < FL_PUF_REP; j++) {
            int v = bit_at(s_reading, h.pos[b][j]);
            if (j > 0) v ^= (h.parity[b] >> (j - 1)) & 1;
            votes1 += v;
        }
        int bit = votes1 * 2 > FL_PUF_REP;
        int minority = bit ? FL_PUF_REP - votes1 : votes1;
        flipped_cells += minority;
        if (minority) corrected++;
        (void)first;
        out[b >> 3] |= (uint8_t)(bit << (b & 7));
    }
    s_stats.cells_flipped = (uint16_t)flipped_cells;
    s_stats.bits_corrected = (uint16_t)corrected;
    memset(s_reading, 0, REGION_BYTES);
    if (flipped_cells > MAX_FLIPPED_CELLS) {
        memset(out, 0, FL_PUF_BITS / 8);
        ESP_LOGE(TAG, "fingerprint does not match enrollment (%d of %d cells differ); no identity", flipped_cells,
                 FL_PUF_BITS * FL_PUF_REP);
        return ESP_ERR_INVALID_CRC;
    }
    if (stats) *stats = s_stats;
    return ESP_OK;
}

esp_err_t fl_puf_forget(void) {
    nvs_handle_t nv;
    esp_err_t e = nvs_open("fl-puf", NVS_READWRITE, &nv);
    if (e != ESP_OK) return e;
    nvs_erase_all(nv);
    nvs_commit(nv);
    nvs_close(nv);
    return ESP_OK;
}

const fl_puf_stats_t *fl_puf_stats(void) { return &s_stats; }

bool fl_puf_enrolled(void) {
    nvs_handle_t nv;
    size_t len = 0;
    bool ok = false;
    if (nvs_open("fl-puf", NVS_READONLY, &nv) == ESP_OK) {
        ok = nvs_get_blob(nv, "helper2", NULL, &len) == ESP_OK && len > 0;
        nvs_close(nv);
    }
    return ok;
}
