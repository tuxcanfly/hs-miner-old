/**
 * hs-miner.cc
 * Copyright (c) 2018, Christopher Jeffrey (MIT License)
 */

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <mutex>
#include <unordered_map>

#include <node.h>
#include <nan.h>

#include "hs-miner.h"
#include "../blake2b/blake2b.h"
#include "../common.h"
#include "../header.h"
#include "../share.h"

typedef std::unordered_map<uint32_t, hs_options_t *> job_map_t;

static std::mutex m;
static job_map_t job_map;
static uint16_t job_counter = 0;

class MinerWorker : public Nan::AsyncWorker {
public:
  MinerWorker (
    hs_options_t *options,
    hs_miner_func mine_func,
    Nan::Callback *callback
  );

  virtual ~MinerWorker();
  virtual void Execute();
  void HandleOKCallback();

private:
  hs_options_t *options;
  hs_miner_func mine_func;
  int32_t rc;
  uint8_t solution[32];
  uint32_t nonce;
  bool match;
};

MinerWorker::MinerWorker (
  hs_options_t *options,
  hs_miner_func mine_func,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback)
  , options(options)
  , mine_func(mine_func)
  , rc(0)
  , nonce(0)
  , match(false)
{
  Nan::HandleScope scope;
  memset(solution, 0, 32);
}

MinerWorker::~MinerWorker() {
  assert(options);
  free(options);
  options = NULL;
}

void
MinerWorker::Execute() {
  m.lock();

  job_map_t::iterator it = job_map.find(options->device);

  if (it != job_map.end()) {
    m.unlock();
    SetErrorMessage("Job already in progress.");
    return;
  }

  job_map.insert(job_map_t::value_type(options->device, options));

  m.unlock();

  rc = mine_func(options, solution, &nonce, &match);

  m.lock();

  assert(job_map.erase(options->device) == 1);

  m.unlock();

  switch (rc) {
    case HS_SUCCESS: {
      break;
    }
    case HS_ENOMEM: {
      SetErrorMessage("Miner out of memory.");
      break;
    }
    case HS_EFAILURE: {
      SetErrorMessage("Miner failed.");
      break;
    }
    case HS_EBADARGS: {
      SetErrorMessage("Invalid mining arguments.");
      break;
    }
    case HS_ENODEVICE: {
      SetErrorMessage("No CUDA devices found.");
      break;
    }
    case HS_EBADPROPS: {
      SetErrorMessage("Invalid CUDA device properties.");
      break;
    }
    case HS_ENOSUPPORT: {
      SetErrorMessage("Miner not supported with current cuckoo params.");
      break;
    }
    case HS_EMAXLOAD: {
      SetErrorMessage("Max load exceeded.");
      break;
    }
    case HS_EBADPATH: {
      SetErrorMessage("Invalid path length.");
      break;
    }
    case HS_ENOSOLUTION: {
      break;
    }
    default: {
      if (rc < 0) {
        char err[25];
        sprintf(err, "CUDA error: %d.", -rc);
        SetErrorMessage(err);
        break;
      }
      SetErrorMessage("Unknown miner error.");
      break;
    }
  }
}

void
MinerWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  if (rc == HS_ENOSOLUTION) {
    v8::Local<v8::Array> ret = Nan::New<v8::Array>();
    Nan::Set(ret, 0, Nan::Null());
    Nan::Set(ret, 1, Nan::New<v8::Uint32>(0));
    Nan::Set(ret, 2, Nan::New<v8::Boolean>(false));
    v8::Local<v8::Value> argv[] = { Nan::Null(), ret };
    callback->Call(2, argv, async_resource);
    return;
  }

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0,
    Nan::CopyBuffer((char *)solution, 32).ToLocalChecked());
  Nan::Set(ret, 1, Nan::New<v8::Uint32>(nonce));
  Nan::Set(ret, 2, Nan::New<v8::Boolean>(match));

  v8::Local<v8::Value> argv[] = { Nan::Null(), ret };

  callback->Call(2, argv, async_resource);
}

// TODO: refactor this to work with an
// enum type instead of bool is_cuda
static hs_miner_func
get_miner_func(const char *backend, bool *is_cuda) {
#ifdef HS_HAS_CUDA
  if (strcmp(backend, "cuda") == 0) {
    if (is_cuda)
      *is_cuda = true;
    return hs_cuda_run;
  }
#endif

// TODO: this breaks if HS_HAS_OPENCL is defined
#ifdef HS_HAS_OPENCL
  if (strcmp(backend, "opencl") == 0) {
    if (is_cuda)
      *is_cuda = false;
    return hs_opencl_run;
  }
#endif

  if (strcmp(backend, "cpu") == 0) {
    if (is_cuda)
      *is_cuda = false;
    return hs_cpu_run;
  }

  return NULL;
}

NAN_METHOD(mine) {
  if (info.Length() < 8)
    return Nan::ThrowError("mine() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("`backend` must be a string.");

  v8::Local<v8::Object> hdr_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(hdr_buf))
    return Nan::ThrowTypeError("`header` must be a buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("`nonce` must be a number.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("`range` must be a number.");

  v8::Local<v8::Object> target_buf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(target_buf))
    return Nan::ThrowTypeError("`target` must be a buffer.");

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("`threads` must be a number.");

  if (!info[6]->IsNumber())
    return Nan::ThrowTypeError("`trims` must be a number.");

  if (!info[7]->IsNumber())
    return Nan::ThrowTypeError("`device` must be a number.");

  const uint8_t *hdr = (const uint8_t *)node::Buffer::Data(hdr_buf);
  size_t hdr_len = node::Buffer::Length(hdr_buf);

  if (hdr_len != HEADER_SIZE)
    return Nan::ThrowError("Invalid header size.");

  if ((hdr_len % 4) != 0)
    return Nan::ThrowError("Invalid header size.");

  const uint8_t *target = (const uint8_t *)node::Buffer::Data(target_buf);
  size_t target_len = node::Buffer::Length(target_buf);

  if (target_len != 32)
    return Nan::ThrowError("Invalid target size.");

  Nan::Utf8String backend_(info[0]);
  const char *backend = (const char *)*backend_;
  hs_miner_func mine_func = get_miner_func(backend, NULL);

  if (mine_func == NULL)
    return Nan::ThrowError("Unknown miner function.");

  uint32_t nonce = Nan::To<uint32_t>(info[2]).FromJust();
  uint32_t range = Nan::To<uint32_t>(info[3]).FromJust();
  uint32_t threads = Nan::To<uint32_t>(info[5]).FromJust();
  uint32_t trims = Nan::To<uint32_t>(info[6]).FromJust();
  uint32_t device = Nan::To<uint32_t>(info[7]).FromJust();

  hs_options_t options;
  options.header_len = hdr_len;
  memcpy(&options.header[0], hdr, hdr_len);
  options.nonce = nonce;
  options.range = range;
  memcpy(&options.target[0], target, 32);
  options.threads = threads;
  options.trims = trims;
  options.device = device;
  options.log = false;
  //options.has_cuda = false;
  options.running = true;

  uint8_t solution[32];
  bool match;

  int32_t rc = mine_func(&options, solution, &nonce, &match);

  switch (rc) {
    case HS_SUCCESS: {
      break;
    }
    case HS_ENOMEM: {
      return Nan::ThrowError("Miner out of memory.");
    }
    case HS_EFAILURE: {
      return Nan::ThrowError("Miner failed.");
    }
    case HS_EBADARGS: {
      return Nan::ThrowError("Invalid mining arguments.");
    }
    case HS_ENODEVICE: {
      return Nan::ThrowError("No CUDA devices found.");
    }
    case HS_EBADPROPS: {
      return Nan::ThrowError("Invalid CUDA device properties.");
    }
    case HS_ENOSUPPORT: {
      return Nan::ThrowError("Miner not supported with current cuckoo params.");
    }
    case HS_EMAXLOAD: {
      return Nan::ThrowError("Max load exceeded.");
    }
    case HS_EBADPATH: {
      return Nan::ThrowError("Invalid path length.");
    }
    case HS_ENOSOLUTION: {
      v8::Local<v8::Array> ret = Nan::New<v8::Array>();
      Nan::Set(ret, 0, Nan::Null());
      Nan::Set(ret, 1, Nan::New<v8::Uint32>(0));
      Nan::Set(ret, 2, Nan::New<v8::Boolean>(false));
      return info.GetReturnValue().Set(ret);
    }
    default: {
      if (rc < 0) {
        char err[25];
        sprintf(err, "CUDA error: %d.", -rc);
        return Nan::ThrowError(err);
      }
      return Nan::ThrowError("Unknown miner error.");
    }
  }

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0,
    Nan::CopyBuffer((char *)solution, 32).ToLocalChecked());
  Nan::Set(ret, 1, Nan::New<v8::Uint32>(nonce));
  Nan::Set(ret, 2, Nan::New<v8::Boolean>(match));

  info.GetReturnValue().Set(ret);
}

// TODO: most important function
// allow for both shares and headers to be passed in
NAN_METHOD(mine_async) {
  if (info.Length() < 9)
    return Nan::ThrowError("mine_async() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("`backend` must be a string.");

  v8::Local<v8::Object> hdr_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(hdr_buf))
    return Nan::ThrowTypeError("`header` must be a buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("`nonce` must be a number.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("`range` must be a number.");

  v8::Local<v8::Object> target_buf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(target_buf))
    return Nan::ThrowTypeError("`target` must be a buffer.");

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("`threads` must be a number.");

  if (!info[6]->IsNumber())
    return Nan::ThrowTypeError("`trims` must be a number.");

  if (!info[7]->IsNumber())
    return Nan::ThrowTypeError("`device` must be a number.");

  if (!info[8]->IsFunction())
    return Nan::ThrowTypeError("`callback` must be a function.");

  const uint8_t *hdr = (const uint8_t *)node::Buffer::Data(hdr_buf);
  size_t hdr_len = node::Buffer::Length(hdr_buf);

  if (hdr_len != HEADER_SIZE)
    return Nan::ThrowError("Invalid header size.");

  const uint8_t *target = (const uint8_t *)node::Buffer::Data(target_buf);
  size_t target_len = node::Buffer::Length(target_buf);

  if (target_len != 32)
    return Nan::ThrowError("Invalid target size.");

  Nan::Utf8String backend_(info[0]);
  const char *backend = (const char *)*backend_;

  bool has_cuda;
  hs_miner_func mine_func = get_miner_func(backend, &has_cuda);

  if (mine_func == NULL)
    return Nan::ThrowError("Unknown miner function.");

  uint32_t nonce = Nan::To<uint32_t>(info[2]).FromJust();
  uint32_t range = Nan::To<uint32_t>(info[3]).FromJust();
  uint32_t threads = Nan::To<uint32_t>(info[5]).FromJust();
  uint32_t trims = Nan::To<uint32_t>(info[6]).FromJust();
  uint32_t device = Nan::To<uint32_t>(info[7]).FromJust();

  v8::Local<v8::Function> callback = info[8].As<v8::Function>();

  hs_options_t *options = (hs_options_t *)malloc(sizeof(hs_options_t));

  if (options == NULL)
    return Nan::ThrowError("Out of memory.");

  options->header_len = hdr_len;
  memcpy(&options->header[0], hdr, hdr_len);
  options->nonce = nonce;
  options->range = range;
  memcpy(&options->target[0], target, 32);
  options->threads = threads;
  options->trims = trims;
  options->device = device;
  options->log = false;
  // options->is_cuda
  options->running = true;

  /*
  if type is cpu?
  if (!is_cuda) {
    options->device = job_counter;
    options->device |= 1 << 31;
    job_counter += 1;
  }
  */

  MinerWorker *worker = new MinerWorker(
    options,
    mine_func,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(is_running) {
  if (info.Length() != 1)
    return Nan::ThrowError("is_running() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("`device` must be a number.");

  uint32_t device = Nan::To<uint32_t>(info[0]).FromJust();
  bool ret = false;

  m.lock();

  job_map_t::iterator it = job_map.find(device);

  if (it != job_map.end())
    ret = true;

  m.unlock();

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(ret));
}

NAN_METHOD(stop) {
  if (info.Length() != 1)
    return Nan::ThrowError("stop() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("`device` must be a number.");

  uint32_t device = Nan::To<uint32_t>(info[0]).FromJust();
  bool ret = false;

  m.lock();

  job_map_t::iterator it = job_map.find(device);

  if (it != job_map.end()) {
    it->second->running = false;
    ret = true;
  }

  m.unlock();

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(ret));
}

NAN_METHOD(stop_all) {
  if (info.Length() != 0)
    return Nan::ThrowError("stop_all() requires no arguments.");

  bool ret = false;

  m.lock();

  job_map_t::iterator it = job_map.begin();

  while (it != job_map.end()) {
    it->second->running = false;
    ret = true;
    it++;
  }

  m.unlock();

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(ret));
}

// TODO: this needs to be fixed
NAN_METHOD(verify) {
  if (info.Length() < 3)
    return Nan::ThrowError("verify() requires arguments.");

  v8::Local<v8::Object> hdr_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sol_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> target_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(hdr_buf))
    return Nan::ThrowTypeError("`header` must be a buffer.");

  if (!node::Buffer::HasInstance(sol_buf))
    return Nan::ThrowTypeError("`solution` must be a buffer.");

  if (!node::Buffer::HasInstance(target_buf))
    return Nan::ThrowTypeError("`target` must be a buffer.");

  const uint8_t *hdr = (const uint8_t *)node::Buffer::Data(hdr_buf);
  size_t hdr_len = node::Buffer::Length(hdr_buf);

  if (hdr_len != HEADER_SIZE)
    return Nan::ThrowTypeError("Invalid header size.");

  const uint8_t *solution = (const uint8_t *)node::Buffer::Data(sol_buf);
  size_t solution_len = node::Buffer::Length(sol_buf);

  if (solution_len != 32)
    return Nan::ThrowTypeError("Invalid proof size.");

  const uint8_t *target = (const uint8_t *)node::Buffer::Data(target_buf);
  size_t target_len = node::Buffer::Length(target_buf);

  if (target_len != 32)
    return Nan::ThrowTypeError("Invalid target size.");

  int32_t rc = hs_verify(
    (uint8_t *)hdr,
    hdr_len,
    (uint8_t *)solution,
    (uint8_t *)target
  );

  info.GetReturnValue().Set(Nan::New<v8::Uint32>((uint32_t)rc));
}

NAN_METHOD(blake2b) {
  if (info.Length() != 1)
    return Nan::ThrowError("blake2b() requires arguments.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("`data` must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  uint8_t hash[64];

  hs_blake2b(
    (void *)hash,
    sizeof(hash),
    (const void *)data,
    data_len,
    NULL,
    0
  );

  info.GetReturnValue().Set(Nan::CopyBuffer((char *)hash, 64).ToLocalChecked());
}

NAN_METHOD(sha3) {
  if (info.Length() != 1)
    return Nan::ThrowError("sha3() requires arguments.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("`data` must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  uint8_t hash[32];

  hs_sha3(data, data_len, hash);

  info.GetReturnValue().Set(Nan::CopyBuffer((char *)hash, 32).ToLocalChecked());
}

NAN_METHOD(hash_header) {
  if (info.Length() != 1)
    return Nan::ThrowError("pow_hash() requires arguments.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("`data` must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  if (data_len != 236)
    return Nan::ThrowTypeError("header must be 236 bytes.");

  uint8_t hash[32];

  hs_header_t *hdr = hs_header_alloc();
  hs_header_decode(data, data_len, hdr);

  hs_hash_header(hdr, hash);

  free(hdr);

  info.GetReturnValue().Set(Nan::CopyBuffer((char *)hash, 32).ToLocalChecked());
}

NAN_METHOD(hash_share) {
  if (info.Length() != 1)
    return Nan::ThrowError("pow_hash() requires arguments.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("`data` must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  if (data_len != 128)
    return Nan::ThrowTypeError("share must be 128 bytes.");

  uint8_t hash[32];

  hs_share_t *share = hs_share_alloc();
  hs_share_decode(data, data_len, share);

  hs_hash_share(share, hash);

  free(share);

  info.GetReturnValue().Set(Nan::CopyBuffer((char *)hash, 32).ToLocalChecked());
}

NAN_METHOD(get_network) {
  if (info.Length() != 0)
    return Nan::ThrowError("get_network() requires no arguments.");

  const char *name = HS_STR(HS_NETWORK);

  info.GetReturnValue().Set(
    Nan::New<v8::String>(name, strlen(name)).ToLocalChecked());
}

NAN_METHOD(get_backends) {
  if (info.Length() != 0)
    return Nan::ThrowError("get_backends() requires no arguments.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  int32_t i = 0;

  Nan::Set(ret, i++, Nan::New<v8::String>("simple").ToLocalChecked());

#if EDGEBITS >= 5
  Nan::Set(ret, i++, Nan::New<v8::String>("lean").ToLocalChecked());
#endif

#if EDGEBITS >= 28
  Nan::Set(ret, i++, Nan::New<v8::String>("mean").ToLocalChecked());
#endif

#ifdef HS_HAS_CUDA
#if EDGEBITS >= 5
  Nan::Set(ret, i++, Nan::New<v8::String>("lean-cuda").ToLocalChecked());
#endif

#if EDGEBITS >= 28
  Nan::Set(ret, i++, Nan::New<v8::String>("mean-cuda").ToLocalChecked());
#endif
#endif

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(has_cuda) {
  if (info.Length() != 0)
    return Nan::ThrowError("has_cuda() requires no arguments.");

#ifdef HS_HAS_CUDA
  info.GetReturnValue().Set(Nan::New<v8::Boolean>(true));
#else
  info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
#endif
}

NAN_METHOD(has_device) {
  if (info.Length() != 0)
    return Nan::ThrowError("has_device() requires no arguments.");

#ifdef HS_HAS_CUDA
  info.GetReturnValue().Set(Nan::New<v8::Boolean>(hs_device_count()));
#else
  info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
#endif
}

NAN_METHOD(get_device_count) {
  if (info.Length() != 0)
    return Nan::ThrowError("get_device_count() requires no arguments.");

#ifdef HS_HAS_CUDA
  info.GetReturnValue().Set(Nan::New<v8::Uint32>(hs_device_count()));
#else
  info.GetReturnValue().Set(Nan::New<v8::Uint32>(0));
#endif
}

NAN_METHOD(get_devices) {
  if (info.Length() != 0)
    return Nan::ThrowError("get_devices() requires no arguments.");

  v8::Local<v8::Array> rets = Nan::New<v8::Array>();

#ifdef HS_HAS_CUDA
  uint32_t count = hs_device_count();

  hs_device_info_t dev;

  for (uint32_t i = 0; i < count; i++) {
    if (!hs_device_info(i, &dev))
      break;

    v8::Local<v8::Array> ret = Nan::New<v8::Array>();

    Nan::Set(ret, 0, Nan::New<v8::String>(dev.name).ToLocalChecked());
    Nan::Set(ret, 1, Nan::New<v8::Number>(dev.memory));
    Nan::Set(ret, 2, Nan::New<v8::Uint32>(dev.bits));
    Nan::Set(ret, 3, Nan::New<v8::Uint32>(dev.clock_rate));

    Nan::Set(rets, i, ret);
  }
#endif

  info.GetReturnValue().Set(rets);
}

NAN_MODULE_INIT(init) {
  Nan::Export(target, "mine", mine);
  Nan::Export(target, "mineAsync", mine_async);
  Nan::Export(target, "isRunning", is_running);
  Nan::Export(target, "stop", stop);
  Nan::Export(target, "stopAll", stop_all);
  Nan::Export(target, "verify", verify);
  Nan::Export(target, "blake2b", blake2b);
  Nan::Export(target, "sha3", sha3);
  Nan::Export(target, "hashHeader", hash_header);
  Nan::Export(target, "hashShare", hash_share);
  Nan::Export(target, "getNetwork", get_network);
  Nan::Export(target, "getBackends", get_backends);
  Nan::Export(target, "hasCUDA", has_cuda);
  Nan::Export(target, "hasDevice", has_device);
  Nan::Export(target, "getDeviceCount", get_device_count);
  Nan::Export(target, "getDevices", get_devices);
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(hsminer, init)
#else
NODE_MODULE(hsminer, init)
#endif
