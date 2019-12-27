#include "utils.h"
#include "common.h"

char
to_char(uint8_t n) {
  if (n >= 0x00 && n <= 0x09)
    return n + '0';

  if (n >= 0x0a && n <= 0x0f)
    return (n - 0x0a) + 'a';

  return -1;
}


bool
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

void
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

void
hs_xor(const uint8_t *left, const uint8_t *right, uint8_t *out, uint8_t out_len) {
    size_t i;
    for (i = 0; i < out_len; i++)
      out[i] = left[i % 32] ^ right[i % 32];
}
