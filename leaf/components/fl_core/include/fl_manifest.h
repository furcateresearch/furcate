#pragma once

#ifdef __cplusplus
extern "C" {
#endif
// Tags of a release-signed manifest body (models and firmware).

// Manifest body tags (inside a release-signed envelope).
enum {
    M_KIND = 1,  // 1 = model, 2 = firmware
    M_ID = 2,
    M_VERSION = 3,
    M_SIZE = 4,
    M_SHA256 = 5,
    M_RUNTIME = 6,
    M_RUNTIME_MIN = 7,
    M_TARGET = 8,     // repeated
    M_ARENA_KB = 9,
    M_NEEDS_PSRAM = 10,
    M_INPUT = 11,     // h u16, w u16, c u16, dtype u8 (1 = int8)
    M_LABELS = 12,    // comma separated
    M_PRE = 13,
    M_POST = 14,
    M_ST_SEED = 15,
    M_ST_EXPECT = 16, // expected int8 outputs for the self-test input
    M_POLICY = 17,    // 0 results only, 1 results + features, 2 raw allowed
    M_LICENCE = 18,
    M_OPS = 19,       // builtin operator codes the model uses
    M_ST_TOL = 20,
};

#define FL_MODEL_KIND 1
#define FL_FIRMWARE_KIND 2

#ifdef __cplusplus
}
#endif
