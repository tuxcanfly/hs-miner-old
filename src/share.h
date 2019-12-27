#ifndef _HS_MINER_SHARE_H
#define _HS_MINER_SHARE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct hs_share_s {
  uint32_t nonce;
  uint64_t time;
  uint8_t pad[20];
  uint8_t prev_block[32];
  uint8_t name_root[32];
  uint8_t commit_hash[32];
} hs_share_t;

bool
hs_share_read(uint8_t **data, size_t *data_len, hs_share_t *share);

bool
hs_share_decode(const uint8_t *data, size_t data_len, hs_share_t *share);

int
hs_share_write(const hs_share_t *share, uint8_t **data);

int
hs_share_encode(const hs_share_t *share, uint8_t *data);

void
hs_share_init(hs_share_t *share);

hs_share_t*
hs_share_alloc(void);

void
hs_hash_share(const uint8_t *data, size_t data_len, uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif // _HS_MINER_SHARE_H
