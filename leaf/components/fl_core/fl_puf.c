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
#include "fl_puf_core.h"

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

// Helper data in NVS, namespace "fl-puf":
//   helper3  fl_puf_blob_t: cell positions, parities, region address, and a
//            check value over the secret. Written by every new enrollment.
//   helper2  fl_puf_helper_t alone (enrollments of 0.1.4 to 0.1.x). Still
//            read, unchanged, so leaves enrolled before keep their identity;
//            it has no check value.
// NVS lives in flash, which erase-flash wipes. The helper data is public, so
// the parent keeps a copy (fl_puf_helper_export) and puts it back with
// fl_puf_helper_import. Without it a wiped leaf enrolls afresh and gets a new id.
static fl_puf_blob_t s_blob;
static bool s_has_check;

static esp_err_t load_helper(nvs_handle_t nv) {
    size_t len = sizeof s_blob;
    if (nvs_get_blob(nv, "helper3", &s_blob, &len) == ESP_OK && len == sizeof s_blob &&
        fl_puf_blob_valid(&s_blob, REGION_ADDR)) {
        s_has_check = true;
        return ESP_OK;
    }
    len = sizeof s_blob.h;
    if (nvs_get_blob(nv, "helper2", &s_blob.h, &len) == ESP_OK && len == sizeof s_blob.h) {
        s_has_check = false;
        return ESP_OK;
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t fl_puf_secret(uint8_t out[FL_PUF_BITS / 8], fl_puf_stats_t *stats) {
    if (!s_stats.valid) return ESP_ERR_INVALID_STATE;
    nvs_handle_t nv;
    ESP_ERROR_CHECK(nvs_open("fl-puf", NVS_READWRITE, &nv));
    if (load_helper(nv) != ESP_OK) {
        size_t ol = 0;
        if (nvs_get_blob(nv, "helper", NULL, &ol) == ESP_OK)
            ESP_LOGW(TAG, "helper data belongs to the old linker-placed region; enrolling the fixed region "
                          "at 0x%08x: this leaf's id changes once", REGION_ADDR);
        ESP_LOGW(TAG, "no helper data in flash: enrolling afresh. A leaf whose flash was erased gets a NEW id "
                      "unless its escrowed helper data is imported first");
        enroll_step();  // returns only when enrollment has enough readings
        int stable_bits = 0;
        for (int i = 0; i < REGION_BYTES; i++) stable_bits += popcount8(s_enroll.stable[i]);
        s_stats.enroll_stable_permille = (uint16_t)(stable_bits * 1000 / (REGION_BYTES * 8));
        if (!fl_puf_core_enroll(s_enroll.ref, s_enroll.stable, &s_blob.h)) {
            ESP_LOGE(TAG, "only %d stable cells; need %d", stable_bits, FL_PUF_BITS * FL_PUF_REP);
            s_enroll.magic = 0;
            nvs_close(nv);
            return ESP_ERR_INVALID_SIZE;
        }
        uint8_t enrolled_secret[FL_PUF_BITS / 8];
        fl_puf_core_reconstruct(&s_blob.h, s_enroll.ref, enrolled_secret, NULL, NULL);
        s_blob.magic = FL_PUF_BLOB_MAGIC;
        s_blob.addr = REGION_ADDR;
        fl_puf_core_check(enrolled_secret, s_blob.check);
        memset(enrolled_secret, 0, sizeof enrolled_secret);
        s_has_check = true;
        ESP_ERROR_CHECK(nvs_set_blob(nv, "helper3", &s_blob, sizeof s_blob));
        ESP_ERROR_CHECK(nvs_set_u32(nv, "addr", REGION_ADDR));
        nvs_erase_key(nv, "helper");
        nvs_erase_key(nv, "helper2");
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

    fl_puf_core_reconstruct(&s_blob.h, s_reading, out, &s_stats.cells_flipped, &s_stats.bits_corrected);
    memset(s_reading, 0, REGION_BYTES);
    if (s_stats.cells_flipped > MAX_FLIPPED_CELLS) {
        memset(out, 0, FL_PUF_BITS / 8);
        ESP_LOGE(TAG, "fingerprint does not match enrollment (%d of %d cells differ); no identity",
                 s_stats.cells_flipped, FL_PUF_BITS * FL_PUF_REP);
        return ESP_ERR_INVALID_CRC;
    }
    if (s_has_check && !fl_puf_core_check_ok(out, s_blob.check)) {
        memset(out, 0, FL_PUF_BITS / 8);
        ESP_LOGE(TAG, "rebuilt secret fails the check value (wrong die, wrong helper data, or a bad reading); "
                      "no identity");
        return ESP_ERR_INVALID_CRC;
    }
    if (stats) *stats = s_stats;
    return ESP_OK;
}

esp_err_t fl_puf_helper_export(fl_puf_blob_t *out) {
    nvs_handle_t nv;
    esp_err_t e = nvs_open("fl-puf", NVS_READONLY, &nv);
    if (e != ESP_OK) return e;
    size_t len = sizeof *out;
    e = nvs_get_blob(nv, "helper3", out, &len);
    nvs_close(nv);
    if (e != ESP_OK || len != sizeof *out) return ESP_ERR_NOT_FOUND;
    return fl_puf_blob_valid(out, REGION_ADDR) ? ESP_OK : ESP_ERR_INVALID_STATE;
}

esp_err_t fl_puf_helper_import(const fl_puf_blob_t *in) {
    if (!fl_puf_blob_valid(in, REGION_ADDR)) return ESP_ERR_INVALID_ARG;
    if (fl_puf_enrolled()) return ESP_ERR_INVALID_STATE;
    nvs_handle_t nv;
    esp_err_t e = nvs_open("fl-puf", NVS_READWRITE, &nv);
    if (e != ESP_OK) return e;
    e = nvs_set_blob(nv, "helper3", in, sizeof *in);
    if (e == ESP_OK) e = nvs_set_u32(nv, "addr", REGION_ADDR);
    if (e == ESP_OK) e = nvs_commit(nv);
    nvs_close(nv);
    return e;
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
        ok = (nvs_get_blob(nv, "helper3", NULL, &len) == ESP_OK && len > 0) ||
             (nvs_get_blob(nv, "helper2", NULL, &len) == ESP_OK && len > 0);
        nvs_close(nv);
    }
    return ok;
}
