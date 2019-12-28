#include <unistd.h>
#include <stdbool.h>
#include "blake2b/blake2b.h"
#include "common.h"

// TODO: fix this

int32_t
hs_verify(
  const uint8_t *hdr,
  size_t hdr_len,
  const uint8_t *target
) {
  uint8_t hash[32];

  // TODO: implement
  /*
  hs_pow_hash(hdr, hdr_len, hash);
  */

  if (memcmp(hash, target, 32) > 0)
    return HS_SUCCESS;

  return HS_ENOSOLUTION;
}
