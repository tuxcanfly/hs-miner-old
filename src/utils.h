#ifndef _HS_MINER_UTILS_H
#define _HS_MINER_UTILS_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

char
to_char(uint8_t n);

bool
hs_hex_encode(const uint8_t *data, size_t data_len, char *str);

void
hs_share_print(hs_share_t *share);

// TODO: conflicting types
void
hs_xor(const uint8_t *left, const uint8_t *right, uint8_t *out, uint8_t out_len);

#ifdef __cplusplus
}
#endif

#endif // _HS_MINER_UTILS_H
