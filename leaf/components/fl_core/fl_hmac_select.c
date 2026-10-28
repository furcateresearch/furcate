#include "fl_hmac_select.h"

int fl_hmac_select_block(const uint8_t purpose[FL_KEY_BLOCKS], uint8_t hmac_up, int *count) {
    int first = -1, n = 0;
    for (int b = 0; b < FL_KEY_BLOCKS; b++) {
        if (purpose[b] == hmac_up) {
            if (first < 0) first = b;
            n++;
        }
    }
    if (count) *count = n;
    return first;
}
