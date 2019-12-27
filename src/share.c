#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "blake2b/blake2b.h"
#include "sha3/sha3.h"
#include "share.h"
#include "bio.h"

bool
hs_share_read(uint8_t **data, size_t *data_len, hs_share_t *share) {
  if (!read_u32(data, data_len, &share->nonce))
    return false;

  if (!read_u64(data, data_len, &share->time))
    return false;

  if (!read_bytes(data, data_len, share->pad, 20))
    return false;

  if (!read_bytes(data, data_len, share->prev_block, 32))
    return false;

  if (!read_bytes(data, data_len, share->name_root, 32))
    return false;

  if (!read_bytes(data, data_len, share->commit_hash, 32))
    return false;

  return true;
}

bool
hs_share_decode(const uint8_t *data, size_t data_len, hs_share_t *share) {
  return hs_share_read((uint8_t **)&data, &data_len, share);
}

int
hs_share_write(const hs_share_t *share, uint8_t **data) {
  int s = 0;
  s += write_u32(data, share->nonce);
  s += write_u64(data, share->time);
  s += write_bytes(data, share->pad, 20);
  s += write_bytes(data, share->name_root, 32);
  s += write_bytes(data, share->prev_block, 32);
  s += write_bytes(data, share->commit_hash, 32);
  return s;
}

int
hs_share_encode(const hs_share_t *share, uint8_t *data) {
    return hs_share_write(share, &data);
}

void
hs_share_init(hs_share_t *share) {
  if (!share)
    return;

  share->nonce = 0;
  share->time = 0;
  memset(share->pad, 0, 20);
  memset(share->prev_block, 0, 32);
  memset(share->name_root, 0, 32);
  memset(share->commit_hash, 0, 32);
}

hs_share_t*
hs_share_alloc(void) {
  hs_share_t *share = (hs_share_t*) malloc(sizeof(hs_share_t));
  hs_share_init(share);
  return share;
}

void
hs_hash_share(const uint8_t *data, size_t data_len, uint8_t *hash) {
  uint8_t pad8[8];
  uint8_t pad32[32];
  uint8_t left[64];
  uint8_t right[32];

  // TODO:
  // This should probably live outside of this fn
  hs_share_t *share = hs_share_alloc();
  hs_share_init(share);
  hs_share_decode(data, data_len, share);

  hs_xor(share->prev_block, share->name_root, pad8, 8);
  hs_xor(share->prev_block, share->name_root, pad32, 32);

  // Generate left
  hs_blake2b_ctx left_ctx;
  assert(hs_blake2b_init(&left_ctx, 64) == 0);
  hs_blake2b_update(&left_ctx, data, 128);
  assert(hs_blake2b_final(&left_ctx, left, 64) == 0);

  // Generate right
  hs_sha3_ctx right_ctx;
  hs_sha3_256_init(&right_ctx);
  hs_sha3_update(&right_ctx, data, 128);
  hs_sha3_update(&right_ctx, pad8, 8);
  hs_sha3_final(&right_ctx, right);

  // Generate hash
  hs_blake2b_ctx b_ctx;
  assert(hs_blake2b_init(&b_ctx, 32) == 0);
  hs_blake2b_update(&b_ctx, left, 64);
  hs_blake2b_update(&b_ctx, pad32, 32);
  hs_blake2b_update(&b_ctx, right, 32);
  assert(hs_blake2b_final(&b_ctx, hash, 32) == 0);

  free(share);
}
