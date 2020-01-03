#include <stdio.h>

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include "common.h"

uint32_t
hs_opencl_device_count() {
  cl_uint platformCount, deviceCount;
  cl_platform_id *platformids;
  cl_int ret;

  uint32_t total = 0;

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

  int i;
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

  ret = clGetPlatformIDs(0, NULL, &platformCount);
  if (ret != CL_SUCCESS || !platformCount) {
    return false;
  }

  platformids = (cl_platform_id *)malloc(sizeof(cl_platform_id) * platformCount);

  ret = clGetPlatformIDs(platformCount, platformids, NULL);
  if (ret != CL_SUCCESS) {
    free(platformids);
    return false;
  }

  // Iterate through each platform and print its devices
  int i,j;
  for (i = 0; i < platformCount; i++) {
    char str[80];
    // Print platform info.
    ret = clGetPlatformInfo(platformids[i], CL_PLATFORM_NAME, 80, str, NULL);
    if (ret != CL_SUCCESS) {
      printf("\tError while fetching platform info.\n");
      continue;
    }
    printf("Devices on platform %d, \"%s\":\n", i, str);
    ret = clGetDeviceIDs(platformids[i], CL_DEVICE_TYPE_GPU, 0, NULL, &deviceCount);
    if (ret != CL_SUCCESS) {
      printf("\tError while fetching device ids.\n");
        continue;
    }
    if (!deviceCount) {
      printf("\tNo devices found for this platform.\n");
      continue;
    }
    deviceids = (cl_device_id *)malloc(sizeof(cl_device_id) * deviceCount);

    ret = clGetDeviceIDs(platformids[i], CL_DEVICE_TYPE_GPU, deviceCount, deviceids, NULL);
    if (ret != CL_SUCCESS) {
      printf("\tError while getting device ids.\n");
      free(deviceids);
      continue;
    }

    for (j = 0; j < deviceCount; j++) {
      // Print platform info.
      ret = clGetDeviceInfo(deviceids[j], CL_DEVICE_NAME, 80, str, NULL);
      if (ret != CL_SUCCESS) {
        printf("\tError while getting device info.\n");
        free(deviceids);
        continue;
      }
      printf("\tDevice %d: %s\n", j, str);
    }
    free(deviceids);
  }
  free(platformids);
  return 0;

  return 0;
}
