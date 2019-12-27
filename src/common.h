#ifndef _HS_MINER_COMMON_H
#define _HS_MINER_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "blake2b/blake2b.h"
#include "sha3/sha3.h"
#include "bio.h"

// TODO: check hsd code for this
#ifndef MIN_HEADER_SIZE
#define MIN_HEADER_SIZE 4
#endif

// TODO: check hsd code for this
#ifndef MAX_HEADER_SIZE
#define MAX_HEADER_SIZE 512
#endif

#ifndef HS_NETWORK
#define HS_NETWORK main
#endif

#define HS_QUOTE(name) #name
#define HS_STR(macro) HS_QUOTE(macro)

#define HS_SUCCESS 0
#define HS_ENOMEM 1
#define HS_EFAILURE 2
#define HS_EBADARGS 3
#define HS_ENODEVICE 4
#define HS_EBADPROPS 5
#define HS_ENOSUPPORT 6
#define HS_EMAXLOAD 7
#define HS_EBADPATH 8
#define HS_ENOSOLUTION 9

// try to get rid of scoped enum?
// turn this into has_cuda and has_opencl
enum struct backend { cpu = 0, cuda, opencl };

typedef struct hs_options_s {
  size_t header_len;
  uint8_t header[MAX_HEADER_SIZE];
  uint32_t nonce;
  uint32_t range;
  uint8_t target[32];
  uint32_t threads;
  uint32_t trims;
  uint32_t device;
  bool log;
  uint8_t type;
  bool running;
} hs_options_t;

typedef int32_t (*hs_miner_func)(
  hs_options_t *options,
  uint8_t *solution,
  uint32_t *result,
  bool *match
);

#ifdef HS_HAS_CUDA
typedef struct hs_device_info_s {
  char name[513];
  uint64_t memory;
  uint32_t bits;
  uint32_t clock_rate;
} hs_device_info_t;
#endif

#ifdef HS_HAS_OPENCL
int32_t
hs_opencl_run(
  hs_options_t *options,
  uint8_t *solution,
  uint32_t *result,
  bool *match
);
#endif

int32_t
hs_cpu_run(
  hs_options_t *options,
  uint8_t *solution,
  uint32_t *result,
  bool *match
);

#ifdef HS_HAS_CUDA
uint32_t
hs_device_count(void);

bool
hs_device_info(uint32_t device, hs_device_info_t *info);

int32_t
hs_cuda_run(
  hs_options_t *options,
  uint8_t *solution,
  uint32_t *result,
  bool *match
);
#endif

int32_t
hs_verify(
  const uint8_t *hdr,
  size_t hdr_len,
  const uint8_t *solution,
  const uint8_t *target
);

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

typedef struct hs_share_s {
  uint32_t nonce;
  uint64_t time;
  uint8_t pad[20];
  uint8_t prev_block[32];
  uint8_t name_root[32];
  uint8_t commit_hash[32];
} hs_share_t;

static inline void
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

static inline void
hs_header_padding(const hs_header_t *hdr, uint8_t *pad, size_t size) {
  assert(hdr && pad);

  size_t i;

  for (i = 0; i < size; i++)
    pad[i] = hdr->prev_block[i % 32] ^ hdr->name_root[i % 32];
}


static inline int
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

static inline int
hs_header_sub_encode(const hs_header_t *hdr, uint8_t *data) {
  return hs_header_sub_write(hdr, &data);
}

static inline void
hs_header_sub_hash(const hs_header_t *hdr, uint8_t *hash) {
  uint8_t sub[128];
  hs_header_sub_encode(hdr, sub);

  hs_blake2b_ctx ctx;
  assert(hs_blake2b_init(&ctx, 32) == 0);
  hs_blake2b_update(&ctx, sub, 128);
  assert(hs_blake2b_final(&ctx, hash, 32) == 0);
}

static inline void
hs_header_mask_hash(const hs_header_t *hdr, uint8_t *hash) {
  hs_blake2b_ctx ctx;
  assert(hs_blake2b_init(&ctx, 32) == 0);
  hs_blake2b_update(&ctx, hdr->prev_block, 32);
  hs_blake2b_update(&ctx, hdr->mask, 32);
  assert(hs_blake2b_final(&ctx, hash, 32) == 0);
}

static inline void
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

static inline hs_header_t *
hs_header_alloc(void) {
  hs_header_t *hdr = (hs_header_t*) malloc(sizeof(hs_header_t));
  hs_header_init(hdr);
  return hdr;
}

static inline int
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

static inline int
hs_header_encode(const hs_header_t *hdr, uint8_t *data) {
  return hs_header_write(hdr, &data);
}

static inline bool
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

static inline bool
hs_header_decode(const uint8_t *data, size_t data_len, hs_header_t *hdr) {
  return hs_header_read((uint8_t **)&data, &data_len, hdr);
}

static inline int
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

static inline bool
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

static inline bool
hs_share_decode(const uint8_t *data, size_t data_len, hs_share_t *share) {
  return hs_share_read((uint8_t **)&data, &data_len, share);
}

static inline int
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

static inline int
hs_share_encode(const hs_share_t *share, uint8_t *data) {
    return hs_share_write(share, &data);
}

static inline int
hs_header_pre_size(const hs_header_t *hdr) {
  return hs_header_pre_write(hdr, NULL);
}

static inline void
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

static inline hs_share_t*
hs_share_alloc(void) {
  hs_share_t *share = (hs_share_t*) malloc(sizeof(hs_share_t));
  hs_share_init(share);
  return share;
}

static inline int
hs_header_pre_encode(const hs_header_t *hdr, uint8_t *data) {
  return hs_header_pre_write(hdr, &data);
}


static inline void
hs_xor(const uint8_t *left, const uint8_t *right, uint8_t *out, uint8_t out_len) {
    size_t i;
    for (i = 0; i < out_len; i++)
      out[i] = left[i % 32] ^ right[i % 32];
}

static inline char
to_char(uint8_t n) {
  if (n >= 0x00 && n <= 0x09)
    return n + '0';

  if (n >= 0x0a && n <= 0x0f)
    return (n - 0x0a) + 'a';

  return -1;
}

static inline bool
hs_hex_encode(const uint8_t *data, size_t data_len, char *str) {
  if (data == NULL && data_len != 0)
    return false;

  if (str == NULL)
    return false;

  size_t size = data_len << 1;

  int i;
  int p = 0;

  for (i = 0; i < size; i++) {
    char ch;

    if (i & 1) {
      ch = to_char(data[p] & 15);
      p += 1;
    } else {
      ch = to_char(data[p] >> 4);
    }

    if (ch == -1)
      return false;

    str[i] = ch;
  }

  str[i] = '\0';

  return true;
}

static inline void
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

  /*
  char left_hex[129];
  hs_hex_encode(left, 64, left_hex);
  printf("left: %s\n", left_hex);
  */

  // Generate right
  hs_sha3_ctx right_ctx;
  hs_sha3_256_init(&right_ctx);
  hs_sha3_update(&right_ctx, data, 128);
  hs_sha3_update(&right_ctx, pad8, 8);
  hs_sha3_final(&right_ctx, right);

  /*
  char right_hex[65];
  hs_hex_encode(right, 32, right_hex);
  printf("right: %s\n", right_hex);
  */

  // Generate hash
  hs_blake2b_ctx b_ctx;
  assert(hs_blake2b_init(&b_ctx, 32) == 0);
  hs_blake2b_update(&b_ctx, left, 64);
  hs_blake2b_update(&b_ctx, pad32, 32);
  hs_blake2b_update(&b_ctx, right, 32);
  assert(hs_blake2b_final(&b_ctx, hash, 32) == 0);

  /*
  char hash_hex[65];
  hs_hex_encode(hash, 32, hash_hex);
  printf("hash: %s\n", hash_hex);
  */

  free(share);
}

// TODO: define HEADER_SIZE
static inline void
hs_hash_header(const hs_header_t *hdr, uint8_t *hash) {
  int size = hs_header_pre_size(hdr);
  uint8_t pre[size];

  hs_header_pre_encode(hdr, pre);

  hs_hash_share(pre, size, hash);
}

static inline void
hs_share_print(hs_share_t *share) {
  assert(share);

  printf("nonce: %u\n", share->nonce);
  printf("time: %lu\n", share->time);
  char pad_hex[21];
  hs_hex_encode(share->pad, 20, pad_hex);
  printf("pad20: %s\n", pad_hex);
  char name_root_hex[65];
  hs_hex_encode(share->name_root, 32, name_root_hex);
  printf("name root: %s\n", name_root_hex);
  char prev_block_hex[65];
  hs_hex_encode(share->prev_block, 32, prev_block_hex);
  printf("prev block: %s\n", prev_block_hex);
  char commit_hash_hex[65];
  hs_hex_encode(share->commit_hash, 32, commit_hash_hex);
  printf("commit hash: %s\n", commit_hash_hex);
}

#endif
