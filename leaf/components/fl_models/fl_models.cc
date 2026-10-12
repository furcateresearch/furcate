// The leaf's model server.
//
// Models are separate signed artifacts kept in their own flash partition,
// with two slots and a slot table. A model arrives through the authenticated
// channel, is checked against what this leaf can run, written to the
// inactive slot, verified, self-tested and only then activated. If anything
// fails, the previous model keeps running. No reflash and no reboot.

#include "fl_models.h"

#include <string.h>
#include "sdkconfig.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_rom_crc.h"
#include "esp_timer.h"
#include "fl_crypto.h"
#include "fl_trust.h"
#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"
#include "tensorflow/lite/schema/schema_generated.h"

static const char *TAG = "fl-models";

#define TABLE_MAGIC 0x464c4d54u
#define SLOT_BASE 0x10000
// Upper bound for the tensor arena. Without PSRAM the classic ESP32 has no
// contiguous 160 KB block (its DRAM is split into regions of at most ~120 KB),
// so the arena takes the largest internal block available at boot, up to
// this bound, minus a margin for the rest of the firmware.
#define ARENA_MAX_KB 160
#define ARENA_MIN_KB 64
#define ARENA_MARGIN_KB 8
static uint32_t s_arena_kb;

typedef struct {
    uint8_t state;  // 0 empty, 1 written, 2 good, 3 failed
    uint8_t policy;
    uint8_t st_n, st_tol;
    uint32_t size, version, st_seed;
    uint8_t sha[32];
    char id[32];
    char labels[96];
    uint16_t arena_kb, in_h, in_w, in_c;
    int8_t st_expect[16];
} slot_meta_t;

typedef struct {
    uint32_t magic, seq;
    int8_t active, previous;
    uint8_t pad[2];
    slot_meta_t slot[2];
    uint32_t crc;
} table_t;

static const esp_partition_t *s_part;
static uint32_t s_slot_size;
static table_t s_tab;
static uint8_t *s_arena;
static tflite::MicroInterpreter *s_interp;
alignas(tflite::MicroInterpreter) static uint8_t s_interp_mem[sizeof(tflite::MicroInterpreter)];
static esp_partition_mmap_handle_t s_map;
static bool s_mapped;
static int s_loaded = -1;
static uint32_t s_arena_used, s_last_latency_us, s_last_load_us;
static char s_last_event[96] = "none";

// Staging state for an offer in progress.
static struct {
    bool open;
    int slot;
    slot_meta_t meta;
    uint32_t written;
    fl_sha256_t sha;
} s_stage;

static tflite::MicroMutableOpResolver<16> &resolver() {
    static tflite::MicroMutableOpResolver<16> r;
    static bool done;
    if (!done) {
        r.AddAveragePool2D();
        r.AddConv2D();
        r.AddDepthwiseConv2D();
        r.AddReshape();
        r.AddSoftmax();
        r.AddFullyConnected();
        r.AddMaxPool2D();
        r.AddQuantize();
        r.AddDequantize();
        r.AddLogistic();
        r.AddAdd();
        r.AddMul();
        r.AddMean();
        r.AddRelu();
        r.AddPad();
        done = true;
    }
    return r;
}

static const tflite::BuiltinOperator kSupported[] = {
    tflite::BuiltinOperator_AVERAGE_POOL_2D, tflite::BuiltinOperator_CONV_2D,
    tflite::BuiltinOperator_DEPTHWISE_CONV_2D, tflite::BuiltinOperator_RESHAPE,
    tflite::BuiltinOperator_SOFTMAX, tflite::BuiltinOperator_FULLY_CONNECTED,
    tflite::BuiltinOperator_MAX_POOL_2D, tflite::BuiltinOperator_QUANTIZE,
    tflite::BuiltinOperator_DEQUANTIZE, tflite::BuiltinOperator_LOGISTIC,
    tflite::BuiltinOperator_ADD, tflite::BuiltinOperator_MUL,
    tflite::BuiltinOperator_MEAN, tflite::BuiltinOperator_RELU,
    tflite::BuiltinOperator_PAD,
};

static bool op_supported(int code) {
    for (auto s : kSupported)
        if ((int)s == code) return true;
    return false;
}

static uint32_t slot_off(int s) { return SLOT_BASE + (uint32_t)s * s_slot_size; }

static uint32_t table_crc(const table_t *t) {
    return esp_rom_crc32_le(0, (const uint8_t *)t, offsetof(table_t, crc));
}

static void table_load(void) {
    table_t a, b;
    esp_partition_read(s_part, 0, &a, sizeof a);
    esp_partition_read(s_part, 0x1000, &b, sizeof b);
    bool va = a.magic == TABLE_MAGIC && a.crc == table_crc(&a);
    bool vb = b.magic == TABLE_MAGIC && b.crc == table_crc(&b);
    if (va && (!vb || a.seq >= b.seq)) s_tab = a;
    else if (vb) s_tab = b;
    else {
        memset(&s_tab, 0, sizeof s_tab);
        s_tab.magic = TABLE_MAGIC;
        s_tab.active = s_tab.previous = -1;
    }
}

// Two table copies, alternating, so a power cut during a write leaves the other.
static void table_save(void) {
    s_tab.seq++;
    s_tab.crc = table_crc(&s_tab);
    uint32_t off = (s_tab.seq & 1) ? 0x1000 : 0;
    esp_partition_erase_range(s_part, off, 0x1000);
    esp_partition_write(s_part, off, &s_tab, sizeof s_tab);
}

static void unload(void) {
    if (s_interp) {
        s_interp->~MicroInterpreter();
        s_interp = nullptr;
    }
    if (s_mapped) {
        esp_partition_munmap(s_map);
        s_mapped = false;
    }
    s_loaded = -1;
}

static void st_input(int8_t *in, size_t n, uint32_t seed) {
    uint32_t x = seed;
    for (size_t i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        in[i] = (int8_t)((x >> 16) & 0xFF);
    }
}

// Maps, checks and self-tests a slot. Leaves it loaded on success.
static const char *load_slot(int s, bool selftest) {
    unload();
    const slot_meta_t &m = s_tab.slot[s];
    if (m.state == 0) return "slot is empty";
    int64_t t0 = esp_timer_get_time();
    const void *ptr;
    if (esp_partition_mmap(s_part, slot_off(s), m.size, ESP_PARTITION_MMAP_DATA, &ptr, &s_map) != ESP_OK)
        return "cannot map slot";
    s_mapped = true;
    uint8_t h[32];
    fl_sha256(ptr, m.size, h);
    if (memcmp(h, m.sha, 32) != 0) {
        unload();
        return "digest does not match the manifest";
    }
    const tflite::Model *model = tflite::GetModel(ptr);
    if (model->version() != TFLITE_SCHEMA_VERSION) {
        unload();
        return "model schema version not supported";
    }
    auto codes = model->operator_codes();
    for (unsigned i = 0; codes && i < codes->size(); i++) {
        int c = std::max((int)codes->Get(i)->builtin_code(), (int)codes->Get(i)->deprecated_builtin_code());
        if (!op_supported(c)) {
            unload();
            return "model uses an operator this firmware does not have";
        }
    }
    if (!s_arena) {
        unload();
        return "no tensor arena on this leaf";
    }
    s_interp = new (s_interp_mem) tflite::MicroInterpreter(model, resolver(), s_arena, s_arena_kb * 1024);
    if (s_interp->AllocateTensors() != kTfLiteOk) {
        unload();
        return "tensor arena too small for this model";
    }
    s_arena_used = s_interp->arena_used_bytes();
    TfLiteTensor *in = s_interp->input(0);
    if (in->type != kTfLiteInt8 || in->bytes != (size_t)m.in_h * m.in_w * m.in_c) {
        unload();
        return "input tensor does not match the manifest";
    }
    s_last_load_us = (uint32_t)(esp_timer_get_time() - t0);
    if (selftest) {
        st_input(in->data.int8, in->bytes, m.st_seed);
        if (s_interp->Invoke() != kTfLiteOk) {
            unload();
            return "self-test inference failed";
        }
        TfLiteTensor *out = s_interp->output(0);
        if (m.st_n == 0 || m.st_n > out->bytes) {
            unload();
            return "self-test expectation missing";
        }
        for (int i = 0; i < m.st_n; i++) {
            int d = out->data.int8[i] - m.st_expect[i];
            if (d < 0) d = -d;
            if (d > m.st_tol) {
                ESP_LOGW(TAG, "self-test output %d: got %d, expected %d", i, out->data.int8[i], m.st_expect[i]);
                unload();
                return "self-test output does not match the manifest";
            }
        }
    }
    s_loaded = s;
    return nullptr;
}

extern "C" esp_err_t fl_models_init(void) {
    s_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)0x40, "models");
    if (!s_part) {
        ESP_LOGE(TAG, "no models partition");
        return ESP_ERR_NOT_FOUND;
    }
    s_slot_size = ((s_part->size - SLOT_BASE) / 2) & ~0xFFFu;
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) / 1024;
    s_arena_kb = largest > ARENA_MARGIN_KB ? (uint32_t)(largest - ARENA_MARGIN_KB) : 0;
    if (s_arena_kb > ARENA_MAX_KB) s_arena_kb = ARENA_MAX_KB;
    if (s_arena_kb >= ARENA_MIN_KB)
        s_arena = (uint8_t *)heap_caps_aligned_alloc(16, s_arena_kb * 1024, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!s_arena) {
        ESP_LOGE(TAG, "cannot allocate a tensor arena (largest internal block %u KB)", (unsigned)largest);
        s_arena_kb = 0;
        return ESP_ERR_NO_MEM;
    }
    table_load();
    if (s_tab.active >= 0) {
        const char *why = load_slot(s_tab.active, true);
        if (why) {
            ESP_LOGE(TAG, "active model failed (%s); falling back", why);
            snprintf(s_last_event, sizeof s_last_event, "boot: active failed (%s)", why);
            s_tab.slot[s_tab.active].state = 3;
            int prev = s_tab.previous;
            s_tab.active = -1;
            if (prev >= 0 && !load_slot(prev, true)) {
                s_tab.active = prev;
                s_tab.previous = -1;
            }
            table_save();
        }
    }
    ESP_LOGI(TAG, "models partition %u KB, two slots of %u KB, arena %u KB; active slot %d",
             (unsigned)(s_part->size / 1024), (unsigned)(s_slot_size / 1024), (unsigned)s_arena_kb, s_tab.active);
    return ESP_OK;
}

extern "C" bool fl_models_ok(void) { return s_part && s_arena; }

static uint8_t result(fl_wbuf_t *r, bool ok, const char *why) {
    fl_w_u8(r, T_OK, ok);
    if (why) fl_w_str(r, T_REASON, why);
    return FL_MSG_RESULT;
}

static bool has_target(const uint8_t *b, size_t n, const char *want) {
    fl_field_t f;
    for (int i = 0; fl_r_find(b, n, M_TARGET, i, &f); i++)
        if (f.n == strlen(want) && memcmp(f.p, want, f.n) == 0) return true;
    return false;
}

static bool field_is(const uint8_t *b, size_t n, uint8_t tag, const char *want) {
    fl_field_t f;
    return fl_r_find(b, n, tag, 0, &f) && f.n == strlen(want) && memcmp(f.p, want, f.n) == 0;
}

extern "C" uint8_t fl_models_offer(const uint8_t *tlv, size_t n, fl_wbuf_t *r) {
    fl_field_t env;
    if (!fl_r_find(tlv, n, T_SIGNED, 0, &env)) return result(r, false, "no manifest");
    const uint8_t *b;
    size_t bl;
    int signers = 0;
    const char *why = fl_trust_check_release(env.p, env.n, &b, &bl, &signers);
    fl_w_u32(r, T_LATENCY_US, fl_trust_last_verify_us());
    if (why) return result(r, false, why);
    uint8_t kind = 0, psram = 0, policy = 0, tol = 0;
    uint32_t version = 0, size = 0, rtmin = 0, seed = 0;
    uint16_t arena = 0;
    fl_field_t id, sha, input, labels, expect, ops;
    if (!fl_r_u8(b, bl, M_KIND, &kind) || kind != FL_MODEL_KIND) return result(r, false, "not a model manifest");
    if (!fl_r_find(b, bl, M_ID, 0, &id) || id.n == 0 || id.n >= 32 || !fl_r_u32(b, bl, M_VERSION, &version) ||
        !fl_r_u32(b, bl, M_SIZE, &size) || !fl_r_find(b, bl, M_SHA256, 0, &sha) || sha.n != 32 ||
        !fl_r_find(b, bl, M_INPUT, 0, &input) || input.n != 7 || !fl_r_u16(b, bl, M_ARENA_KB, &arena) ||
        !fl_r_u32(b, bl, M_ST_SEED, &seed) || !fl_r_find(b, bl, M_ST_EXPECT, 0, &expect) || expect.n > 16)
        return result(r, false, "manifest is missing required fields");
    // Capability check: only models this leaf can run are accepted.
    if (!field_is(b, bl, M_RUNTIME, "tflm")) return result(r, false, "runtime not available on this leaf");
    fl_r_u32(b, bl, M_RUNTIME_MIN, &rtmin);
    if (rtmin > FL_TFLM_RUNTIME_VERSION) return result(r, false, "model needs a newer runtime; update firmware first");
    if (!has_target(b, bl, CONFIG_IDF_TARGET)) return result(r, false, "model is not built for this chip");
    fl_r_u8(b, bl, M_NEEDS_PSRAM, &psram);
    if (psram && heap_caps_get_total_size(MALLOC_CAP_SPIRAM) == 0) return result(r, false, "model needs PSRAM; this leaf has none");
    if (!s_arena) return result(r, false, "no tensor arena on this leaf");
    if (arena > s_arena_kb) return result(r, false, "model needs more working memory than this leaf has");
    if (size > s_slot_size) return result(r, false, "model is larger than a model slot");
    if (fl_r_find(b, bl, M_OPS, 0, &ops))
        for (size_t i = 0; i < ops.n; i++)
            if (!op_supported(ops.p[i])) return result(r, false, "model lists an operator this firmware does not have");
    if (input.p[6] != 1) return result(r, false, "only int8 input is supported");
    fl_r_u8(b, bl, M_POLICY, &policy);
    fl_r_u8(b, bl, M_ST_TOL, &tol);

    int slot = s_tab.active == 0 ? 1 : 0;
    memset(&s_stage, 0, sizeof s_stage);
    slot_meta_t &m = s_stage.meta;
    memcpy(m.id, id.p, id.n);
    m.version = version;
    m.size = size;
    memcpy(m.sha, sha.p, 32);
    m.arena_kb = arena;
    m.in_h = (uint16_t)((input.p[0] << 8) | input.p[1]);
    m.in_w = (uint16_t)((input.p[2] << 8) | input.p[3]);
    m.in_c = (uint16_t)((input.p[4] << 8) | input.p[5]);
    if (fl_r_find(b, bl, M_LABELS, 0, &labels) && labels.n < sizeof m.labels) memcpy(m.labels, labels.p, labels.n);
    m.st_seed = seed;
    m.st_n = (uint8_t)expect.n;
    memcpy(m.st_expect, expect.p, expect.n);
    m.st_tol = tol;
    m.policy = policy;
    m.state = 1;
    s_stage.slot = slot;
    fl_sha256_init(&s_stage.sha);
    uint32_t erase = (size + 0xFFF) & ~0xFFFu;
    if (esp_partition_erase_range(s_part, slot_off(slot), erase) != ESP_OK) return result(r, false, "erase failed");
    s_stage.open = true;
    ESP_LOGI(TAG, "accepted offer %s v%u (%u bytes, %d signatures) into slot %d", m.id, (unsigned)version,
             (unsigned)size, signers, slot);
    return result(r, true, nullptr);
}

extern "C" uint8_t fl_models_chunk(const uint8_t *tlv, size_t n, fl_wbuf_t *r) {
    uint32_t off;
    fl_field_t d;
    if (!s_stage.open) return result(r, false, "no offer in progress");
    if (!fl_r_u32(tlv, n, T_OFFSET, &off) || !fl_r_find(tlv, n, T_DATA, 0, &d)) return result(r, false, "bad chunk");
    if (off != s_stage.written || off + d.n > s_stage.meta.size) return result(r, false, "chunk out of order");
    if (esp_partition_write(s_part, slot_off(s_stage.slot) + off, d.p, d.n) != ESP_OK)
        return result(r, false, "flash write failed");
    fl_sha256_update(&s_stage.sha, d.p, d.n);
    s_stage.written += d.n;
    return result(r, true, nullptr);
}

extern "C" uint8_t fl_models_commit(fl_wbuf_t *r) {
    if (!s_stage.open || s_stage.written != s_stage.meta.size) return result(r, false, "model incomplete");
    s_stage.open = false;
    uint8_t h[32];
    fl_sha256_final(&s_stage.sha, h);
    int slot = s_stage.slot;
    if (memcmp(h, s_stage.meta.sha, 32) != 0) {
        esp_partition_erase_range(s_part, slot_off(slot), (s_stage.meta.size + 0xFFF) & ~0xFFFu);
        snprintf(s_last_event, sizeof s_last_event, "rejected %s: digest mismatch", s_stage.meta.id);
        return result(r, false, "digest does not match the manifest; slot erased");
    }
    int old = s_tab.active;
    s_tab.slot[slot] = s_stage.meta;
    int64_t t0 = esp_timer_get_time();
    const char *why = load_slot(slot, true);  // inference pauses here: one arena, one model
    uint32_t swap_us = (uint32_t)(esp_timer_get_time() - t0);
    fl_w_u32(r, T_LATENCY_US, swap_us);
    if (why) {
        s_tab.slot[slot].state = 3;
        const char *back = old >= 0 ? load_slot(old, false) : "no previous model";
        snprintf(s_last_event, sizeof s_last_event, "rejected %s v%u: %s; kept previous", s_tab.slot[slot].id,
                 (unsigned)s_tab.slot[slot].version, why);
        table_save();
        ESP_LOGW(TAG, "%s (previous reloaded: %s)", s_last_event, back ? back : "yes");
        fl_w_str(r, T_DETAIL, back ? back : "previous model running");
        return result(r, false, why);
    }
    s_tab.slot[slot].state = 2;
    s_tab.previous = old;
    s_tab.active = slot;
    table_save();
    snprintf(s_last_event, sizeof s_last_event, "activated %s v%u in slot %d", s_tab.slot[slot].id,
             (unsigned)s_tab.slot[slot].version, slot);
    ESP_LOGI(TAG, "%s; arena used %u bytes; swap took %u us", s_last_event, (unsigned)s_arena_used,
             (unsigned)swap_us);
    return result(r, true, nullptr);
}

extern "C" uint8_t fl_models_rollback(fl_wbuf_t *r) {
    int prev = s_tab.previous;
    if (prev < 0 || s_tab.slot[prev].state != 2) return result(r, false, "no previous model");
    const char *why = load_slot(prev, true);
    if (why) {
        if (s_tab.active >= 0) load_slot(s_tab.active, false);
        return result(r, false, why);
    }
    s_tab.previous = s_tab.active;
    s_tab.active = prev;
    table_save();
    snprintf(s_last_event, sizeof s_last_event, "rolled back to %s v%u", s_tab.slot[prev].id,
             (unsigned)s_tab.slot[prev].version);
    return result(r, true, nullptr);
}

extern "C" uint8_t fl_models_infer(const uint8_t *tlv, size_t n, fl_wbuf_t *r) {
    if (s_loaded < 0) return result(r, false, "no model loaded");
    fl_field_t in;
    TfLiteTensor *t = s_interp->input(0);
    if (!fl_r_find(tlv, n, T_INPUT, 0, &in)) return result(r, false, "no input");
    // An input larger than one record arrives in order, in parts carrying
    // T_OFFSET; inference runs when the last part completes the tensor.
    static size_t s_in_filled;
    uint32_t off = 0;
    bool parted = fl_r_u32(tlv, n, T_OFFSET, &off);
    if (!parted && in.n != t->bytes) return result(r, false, "input size mismatch");
    if (parted) {
        if (off == 0) s_in_filled = 0;
        if (off != s_in_filled || off + in.n > t->bytes) return result(r, false, "input part out of order");
    }
    memcpy(t->data.int8 + off, in.p, in.n);
    if (parted) {
        s_in_filled = off + in.n;
        if (s_in_filled < t->bytes) return result(r, true, nullptr);
        s_in_filled = 0;
    }
    int64_t t0 = esp_timer_get_time();
    TfLiteStatus st = s_interp->Invoke();
    s_last_latency_us = (uint32_t)(esp_timer_get_time() - t0);
    if (st != kTfLiteOk) return result(r, false, "inference failed");
    TfLiteTensor *o = s_interp->output(0);
    int best = 0;
    for (size_t i = 1; i < o->bytes; i++)
        if (o->data.int8[i] > o->data.int8[best]) best = (int)i;
    // Results only: the input is not echoed or kept.
    fl_w_bytes(r, T_SCORES, o->data.int8, o->bytes);
    float sc = o->params.scale;
    int32_t zp = o->params.zero_point;
    uint8_t q[8];
    memcpy(q, &sc, 4);
    memcpy(q + 4, &zp, 4);
    fl_w_bytes(r, T_QPARAMS, q, 8);
    fl_w_u32(r, T_LATENCY_US, s_last_latency_us);
    const slot_meta_t &m = s_tab.slot[s_loaded];
    // Label of the best class from the manifest's comma-separated list.
    const char *p = m.labels;
    for (int i = 0; i < best && p; i++) {
        p = strchr(p, ',');
        if (p) p++;
    }
    if (p) {
        const char *e = strchr(p, ',');
        fl_w_bytes(r, T_LABEL, p, e ? (size_t)(e - p) : strlen(p));
    }
    fl_w_u8(r, T_OK, 1);
    return FL_MSG_INFER_RESULT;
}

extern "C" void fl_models_info(fl_wbuf_t *w) {
    for (int s = 0; s < 2; s++) {
        const slot_meta_t &m = s_tab.slot[s];
        uint8_t row[48];
        memset(row, 0, sizeof row);
        row[0] = (uint8_t)s;
        row[1] = m.state;
        row[2] = (uint8_t)(s == s_tab.active ? 1 : (s == s_tab.previous ? 2 : 0));
        row[3] = (uint8_t)(m.version);
        memcpy(row + 4, m.id, 32);
        fl_w_bytes(w, 40, row, 36);
    }
    fl_w_u32(w, 41, s_arena_used);
    fl_w_u32(w, 42, s_last_latency_us);
    fl_w_u32(w, 43, s_last_load_us);
    fl_w_str(w, 44, s_last_event);
    fl_w_u32(w, 45, heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    fl_w_u32(w, 46, heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
}
