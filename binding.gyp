{
  "variables": {
    "hs_endian%": "<!(./scripts/get endian)",
    "hs_cudahas%": "<!(./scripts/get cuda_has)",
    "hs_cudalib%": "<!(./scripts/get cuda_lib)",
    "hs_network%": "<!(./scripts/get network)",
    "hs_oclhas%": "<!(./scripts/get ocl_has)"
  },
  "targets": [{
    "target_name": "hsminer",
    "sources": [
      "./src/node/hs-miner.cc",
      "./src/blake2b-ref.c",
      "./src/sha3.c",
      "./src/header.c",
      "./src/verify.cc",
      "./src/device.c",
      "./src/simple.cc",
      "./src/utils.c"
    ],
    "cflags": [
      "-Wall",
      "-Wno-implicit-fallthrough",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wno-unused-value",
      "-Wextra",
      "-O3"
    ],
    "cflags_c": [
      "-std=c99"
    ],
    "cflags_cc+": [
      "-std=c++11",
      "-Wno-maybe-uninitialized",
      "-Wno-cast-function-type",
      "-Wno-unused-parameter",
      "-Wno-unknown-warning-option"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")"
    ],
    "defines": [
      "HS_NETWORK=<(hs_network)",
      "ATOMIC"
    ],
    "conditions": [
      ["hs_endian=='little'", {
        "defines": [
          "HS_LITTLE_ENDIAN"
        ]
      }, {
        "defines": [
          "HS_BIG_ENDIAN"
        ]
      }],
      ["hs_cudahas==1", {
        "defines": [
          "HS_HAS_CUDA"
        ],
        "libraries": [
          "<(module_root_dir)/src/device.a",
          "<(module_root_dir)/src/cuda.a",
          "-L<(hs_cudalib)",
          "-lcudart"
        ]
      }],
      ["hs_oclhas==1", {
        "defines": [
          "HS_HAS_OPENCL"
        ],
        "libraries": [
          "-lOpenCL"
        ]
      }]
    ]
  }]
}
