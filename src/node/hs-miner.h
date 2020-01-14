#ifndef _HS_MINER_HS_MINER_H
#define _HS_MINER_HS_MINER_H

#include <node.h>
#include <nan.h>

NAN_METHOD(mine);
NAN_METHOD(mine_async);
NAN_METHOD(is_running);
NAN_METHOD(stop);
NAN_METHOD(stop_all);
NAN_METHOD(verify);
NAN_METHOD(blake2b);
NAN_METHOD(sha3);
NAN_METHOD(hash_header);
NAN_METHOD(get_network);
NAN_METHOD(get_backends);
NAN_METHOD(has_cuda);
NAN_METHOD(has_opencl);
NAN_METHOD(has_device);
NAN_METHOD(get_cuda_device_count);
NAN_METHOD(get_opencl_device_count);
NAN_METHOD(get_cuda_devices);
NAN_METHOD(get_opencl_devices);

#endif
