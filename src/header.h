#ifndef _HS_MINER_HEADER_H
#define _HS_MINER_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct hs_header_s {
  // Preheader
  uint32_t nonce;
  uint64_t time;
  uint8_t prev_block[32];
  uint8_t name_root[32];
  // Subheader
  uint8_t extra_nonce[24];
  uint8_t reserved_root[32];
  uint8_t witness_root[32];
  uint8_t merkle_root[32];
  uint32_t version;
  uint32_t bits;
  // Mask
  uint8_t mask[32];
} hs_header_t;

void
hs_header_init(hs_header_t *hdr);

hs_header_t *
hs_header_alloc(void);

int
hs_header_write(const hs_header_t *hdr, uint8_t **data);

int
hs_header_encode(const hs_header_t *hdr, uint8_t *data);

bool
hs_header_read(uint8_t **data, size_t *data_len, hs_header_t *hdr);

bool
hs_header_decode(const uint8_t *data, size_t data_len, hs_header_t *hdr);

int
hs_header_pre_write(const hs_header_t *hdr, uint8_t **data);

void
hs_header_padding(const hs_header_t *hdr, uint8_t *pad, size_t size);

int
hs_header_sub_write(const hs_header_t *hdr, uint8_t **data);

int
hs_header_sub_encode(const hs_header_t *hdr, uint8_t *data);

void
hs_header_sub_hash(const hs_header_t *hdr, uint8_t *hash);

void
hs_header_mask_hash(const hs_header_t *hdr, uint8_t *hash);

void
hs_header_commit_hash(const hs_header_t *hdr, uint8_t *hash);

int
hs_header_pre_size(const hs_header_t *hdr);

int
hs_header_pre_encode(const hs_header_t *hdr, uint8_t *data);

void
hs_hash_header(const hs_header_t *hdr, uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif // _HS_MINER_HEADER_H
