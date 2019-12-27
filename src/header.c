#include "bio.h"
#include "header.h"
#include "share.h"
#include "blake2b/blake2b.h"

void
hs_header_init(hs_header_t *hdr) {
  if (!hdr)
    return;

  // Preheader.
  hdr->nonce = 0;
  hdr->time = 0;
  memset(hdr->prev_block, 0, 32);
  memset(hdr->name_root, 0, 32);

  // Subheader.
  memset(hdr->extra_nonce, 0, 24);
  memset(hdr->reserved_root, 0, 32);
  memset(hdr->witness_root, 0, 32);
  memset(hdr->merkle_root, 0, 32);
  hdr->version = 0;
  hdr->bits = 0;

  // Mask.
  memset(hdr->mask, 0, 32);
}

hs_header_t *
hs_header_alloc(void) {
  hs_header_t *hdr = (hs_header_t*) malloc(sizeof(hs_header_t));
  hs_header_init(hdr);
  return hdr;
}

int
hs_header_write(const hs_header_t *hdr, uint8_t **data) {
  int s = 0;
  s += write_u32(data, hdr->nonce);
  s += write_u64(data, hdr->time);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->name_root, 32);
  s += write_bytes(data, hdr->extra_nonce, 24);
  s += write_bytes(data, hdr->reserved_root, 32);
  s += write_bytes(data, hdr->witness_root, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_u32(data, hdr->version);
  s += write_u32(data, hdr->bits);
  s += write_bytes(data, hdr->mask, 32);
  return s;
}

int
hs_header_encode(const hs_header_t *hdr, uint8_t *data) {
  return hs_header_write(hdr, &data);
}

bool
hs_header_read(uint8_t **data, size_t *data_len, hs_header_t *hdr) {
  if (!read_u32(data, data_len, &hdr->nonce))
    return false;

  if (!read_u64(data, data_len, &hdr->time))
    return false;

  if (!read_bytes(data, data_len, hdr->prev_block, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->name_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->extra_nonce, 24))
    return false;

  if (!read_bytes(data, data_len, hdr->reserved_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->witness_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->merkle_root, 32))
    return false;

  if (!read_u32(data, data_len, &hdr->version))
    return false;

  if (!read_u32(data, data_len, &hdr->bits))
    return false;

  if (!read_bytes(data, data_len, hdr->mask, 32))
    return false;

  return true;
}

bool
hs_header_decode(const uint8_t *data, size_t data_len, hs_header_t *hdr) {
  return hs_header_read((uint8_t **)&data, &data_len, hdr);
}

int
hs_header_pre_write(const hs_header_t *hdr, uint8_t **data) {
  int s = 0;
  uint8_t pad[20];
  uint8_t commit_hash[32];

  hs_header_padding(hdr, pad, 20);
  hs_header_commit_hash(hdr, commit_hash);

  s += write_u32(data, hdr->nonce);
  s += write_u64(data, hdr->time);
  s += write_bytes(data, pad, 20);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->name_root, 32);
  s += write_bytes(data, commit_hash, 32);
  return s;
}

void
hs_header_padding(const hs_header_t *hdr, uint8_t *pad, size_t size) {
  assert(hdr && pad);

  size_t i;

  for (i = 0; i < size; i++)
    pad[i] = hdr->prev_block[i % 32] ^ hdr->name_root[i % 32];
}

int
hs_header_sub_write(const hs_header_t *hdr, uint8_t **data) {
  int s = 0;
  s += write_bytes(data, hdr->extra_nonce, 24);
  s += write_bytes(data, hdr->reserved_root, 32);
  s += write_bytes(data, hdr->witness_root, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_u32(data, hdr->version);
  s += write_u32(data, hdr->bits);
  return s;
}

int
hs_header_sub_encode(const hs_header_t *hdr, uint8_t *data) {
  return hs_header_sub_write(hdr, &data);
}

void
hs_header_sub_hash(const hs_header_t *hdr, uint8_t *hash) {
  uint8_t sub[128];
  hs_header_sub_encode(hdr, sub);

  hs_blake2b_ctx ctx;
  assert(hs_blake2b_init(&ctx, 32) == 0);
  hs_blake2b_update(&ctx, sub, 128);
  assert(hs_blake2b_final(&ctx, hash, 32) == 0);
}

void
hs_header_mask_hash(const hs_header_t *hdr, uint8_t *hash) {
  hs_blake2b_ctx ctx;
  assert(hs_blake2b_init(&ctx, 32) == 0);
  hs_blake2b_update(&ctx, hdr->prev_block, 32);
  hs_blake2b_update(&ctx, hdr->mask, 32);
  assert(hs_blake2b_final(&ctx, hash, 32) == 0);
}

void
hs_header_commit_hash(const hs_header_t *hdr, uint8_t *hash) {
  uint8_t sub_hash[32];
  uint8_t mask_hash[32];

  hs_header_sub_hash(hdr, sub_hash);
  hs_header_mask_hash(hdr, mask_hash);

  hs_blake2b_ctx ctx;
  assert(hs_blake2b_init(&ctx, 32) == 0);
  hs_blake2b_update(&ctx, sub_hash, 32);
  hs_blake2b_update(&ctx, mask_hash, 32);
  assert(hs_blake2b_final(&ctx, hash, 32) == 0);
}

int
hs_header_pre_size(const hs_header_t *hdr) {
  return hs_header_pre_write(hdr, NULL);
}

int
hs_header_pre_encode(const hs_header_t *hdr, uint8_t *data) {
  return hs_header_pre_write(hdr, &data);
}

void
hs_hash_header(const hs_header_t *hdr, uint8_t *hash) {
  int size = hs_header_pre_size(hdr);
  uint8_t pre[size];

  hs_header_pre_encode(hdr, pre);

  hs_hash_share(pre, size, hash);
}

