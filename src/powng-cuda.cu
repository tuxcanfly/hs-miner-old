#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include "common.h"

int32_t
hs_cuda_run(
  hs_options_t *options,
  uint8_t *solution,
  bool *match
) {
#ifdef HS_HAS_CUDA
  uint8_t header[MAX_HEADER_SIZE];
  size_t header_len = options->header_len;
  uint32_t nonce = options->nonce;
  uint32_t range = 1;
  uint32_t device = options->device;
  uint8_t hash[32];
  uint8_t chash[32];

  memset(hash, 0xff, 32);

  if (header_len < MIN_HEADER_SIZE || header_len > MAX_HEADER_SIZE)
    return HS_EBADARGS;

  memcpy(header, options->header, header_len);

  int32_t device_count = 0;
  cudaGetDeviceCount(&device_count);

  if (device_count < 0 || device >= device_count)
    return HS_ENODEVICE;

  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, device);

  if (options->range)
    range = options->range;

  cudaSetDevice(device);

  *match = false;

  for (uint32_t r = 0; r < range; r++) {
    if (!options->running)
      break;

    int32_t rc = verify(sol, &ctx.trimmer->sip_keys);

    if (rc == POW_OK) {
      return HS_SUCCESS;
    }

    if (memcmp(chash, options->target, 32) <= 0) {
      *match = true;
      return HS_SUCCESS;
    }
  }

  return HS_ENOSOLUTION;
#else
  return HS_ENOSUPPORT;
#endif
}
