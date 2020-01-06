#include <stdio.h>

#ifdef HS_HAS_OPENCL

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif // __APPLE__

#include "common.h"

uint32_t
hs_opencl_device_count() {
  cl_uint platformCount, deviceCount;
  cl_platform_id *platformids;
  cl_int ret;

  cl_uint total = 0;

  ret = clGetPlatformIDs(0, NULL, &platformCount);
  if (ret != CL_SUCCESS || !platformCount) {
    return 0;
  }

  platformids = (cl_platform_id *)malloc(sizeof(cl_platform_id) * platformCount);

  ret = clGetPlatformIDs(platformCount, platformids, NULL);
  if (ret != CL_SUCCESS) {
    free(platformids);
    return 0;
  }

  cl_uint i;
  for (i = 0; i < platformCount; i++) {
    ret = clGetDeviceIDs(platformids[i], CL_DEVICE_TYPE_GPU, 0, NULL, &deviceCount);
    if (ret != CL_SUCCESS) {
      continue;
    }

    total += deviceCount;
  }

  free(platformids);
  return total;
}

bool
hs_opencl_device_info(uint32_t device, hs_device_info_t *info) {
  cl_uint platformCount, deviceCount;
  cl_platform_id *platformids;
  cl_device_id *deviceids;
  cl_int ret;

  // Get the platform count
  ret = clGetPlatformIDs(0, NULL, &platformCount);
  if (ret != CL_SUCCESS || !platformCount) {
    return false;
  }

  // Get the platform ids
  platformids = (cl_platform_id *)malloc(sizeof(cl_platform_id) * platformCount);

  ret = clGetPlatformIDs(platformCount, platformids, NULL);
  if (ret != CL_SUCCESS) {
    free(platformids);
    return false;
  }

  cl_uint i;
  cl_uint total = 0;
  // For each platform, get the devices on it
  for (i = 0; i < platformCount; i++) {
    ret = clGetDeviceIDs(platformids[i], CL_DEVICE_TYPE_GPU, 0, NULL, &deviceCount);

    // Why check deviceCount here?
    if (ret != CL_SUCCESS || !deviceCount) {
      continue;
    }

    deviceids = (cl_device_id *)malloc(sizeof(cl_device_id) * deviceCount);

    // deviceCount is number of devices on that platform
    ret = clGetDeviceIDs(platformids[i], CL_DEVICE_TYPE_GPU, deviceCount, deviceids, NULL);

    if (ret != CL_SUCCESS) {
      free(deviceids);
      continue;
    }

    ret = clGetDeviceIDs(platformids[i], CL_DEVICE_TYPE_GPU, deviceCount, deviceids, NULL);

    if (total + deviceCount > device) {
      // index in the current device ids list
      int index = device - total;

      ret = clGetDeviceInfo(deviceids[index], CL_DEVICE_NAME, sizeof(info->name), info->name, NULL);

      cl_ulong mem;
      //ret = clGetDeviceInfo(deviceids[index], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(cl_ulong), (cl_ulong*)info->memory, NULL);
      ret = clGetDeviceInfo(deviceids[index], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(mem), &mem, NULL);
      info->memory= (uint64_t)mem;

      // TODO: figure out how to query for memory bus size and
      // set at info->bits. I can't seem to find a good api for it,
      // just set to 0 for now.
      info->bits = 0;

      cl_uint freq;
      ret = clGetDeviceInfo(deviceids[index], CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(freq), &freq, NULL);
      info->clock_rate = (uint32_t)freq;

      return true;
    }

    total += deviceCount;
  }

  return false;
}

#endif // HS_HAS_OPENCL
