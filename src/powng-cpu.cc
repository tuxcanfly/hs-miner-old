#include <unistd.h>
#include <stdbool.h>
#include "common.h"
#include "header.h"
#include "share.h"

// TODO: optimize this

int32_t
hs_cpu_run(
  hs_options_t *options,
  uint8_t *solution,
  uint32_t *result,
  bool *match
) {
  // TODO: rewrite this to mine stuff
  uint32_t nonce = options->nonce;
  uint32_t range = 1;
  size_t header_len = options->header_len;
  uint8_t header[header_len];
  uint8_t hash[32];
  uint8_t chash[32];

  memset(hash, 0xff, 32);

  if (header_len != MINER_SIZE)
    return HS_EBADARGS;

  memcpy(header, options->header, header_len);

  if (options->range)
    range = options->range;

  bool has_sol = false;

  hs_share_t *share = hs_share_alloc();
  hs_share_decode(header, header_len, share);

  for (uint32_t r = 0; r < range; r++) {
    if (!options->running)
      break;

    hs_hash_share(share, chash);

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
