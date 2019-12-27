#include <unistd.h>
#include <stdbool.h>
#include "common.h"

int32_t
hs_cpu_run(
  hs_options_t *options,
  uint8_t *solution,
  uint32_t *result,
  bool *match
) {
  // TODO: do we need a nonce here?
  //uint32_t nonce = options->nonce;
  uint32_t range = 1;
  size_t header_len = options->header_len;
  uint8_t header[HEADER_SIZE];
  uint8_t hash[32];
  uint8_t chash[32];

  memset(hash, 0xff, 32);

  if (header_len != HEADER_SIZE)
    return HS_EBADARGS;

  memcpy(header, options->header, header_len);

  if (options->range)
    range = options->range;

  bool has_sol = false;

  for (uint32_t r = 0; r < range; r++) {
    if (!options->running)
      break;

    // TODO: fix this
    /*
    hs_pow_hash(header, header_len, chash);
    */

    // Target must be share target
    if (memcmp(chash, options->target, 32) <= 0) {
      *match = true;
      return HS_SUCCESS;
    }
  }

  if (has_sol)
    return HS_SUCCESS;

  return HS_ENOSOLUTION;
}
