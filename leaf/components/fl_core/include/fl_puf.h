#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FL_PUF_BITS 256          // secret bits reconstructed from the fingerprint
#define FL_PUF_REP 7             // cells per secret bit (majority vote)
#define FL_PUF_ENROLL_READS 8    // power-ups compared during enrollment
#define FL_PUF_SLEEP_US 200000   // deep-sleep length used to power SRAM down

typedef struct {
    bool valid;                      // a fresh power-up pattern was read this boot
    bool enrolled_now;               // enrollment completed on this boot
    uint16_t ones_permille;          // share of 1 bits in the region (bias)
    uint16_t enroll_stable_permille; // share of cells that never changed during enrollment
    uint16_t cells_flipped;          // cells that disagreed with enrollment this boot
    uint16_t bits_corrected;         // secret bits where at least one cell disagreed
    uint32_t sleep_cycles;           // deep-sleep power cycles needed this boot
    uint32_t retained_boots;         // boots where SRAM had not powered down
} fl_puf_stats_t;

void fl_puf_capture(void);
esp_err_t fl_puf_secret(uint8_t out[FL_PUF_BITS / 8], fl_puf_stats_t *stats);
esp_err_t fl_puf_forget(void);
const fl_puf_stats_t *fl_puf_stats(void);
// Helper data for the fixed region exists (enrollment done).
bool fl_puf_enrolled(void);

#ifdef __cplusplus
}
#endif
