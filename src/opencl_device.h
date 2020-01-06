#include <stdint.h>

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t
hs_opencl_device_count();

bool
hs_opencl_device_info(uint32_t device, hs_device_info_t *info);

#ifdef __cplusplus
}
#endif
