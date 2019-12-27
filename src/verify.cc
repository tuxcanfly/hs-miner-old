#include <unistd.h>
#include <stdbool.h>
#include "blake2b/blake2b.h"
#include "common.h"

// TODO: fix this

int32_t
hs_verify(
  const uint8_t *hdr,
  size_t hdr_len,
  const uint8_t *solution,
  const uint8_t *target
) {
  uint8_t hash[32];

  // TODO: fix this
  /*
  hs_pow_hash(hdr, hdr_len, hash);
  */

  // This does not seem right.
  if (memcmp(hash, target, 32) > 0)
    return HS_SUCCESS;

  return HS_ENOSOLUTION;
}
