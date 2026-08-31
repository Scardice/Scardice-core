#ifndef SCARDICE_NATIVE_BRIDGE_H
#define SCARDICE_NATIVE_BRIDGE_H

#include <stdint.h>
#include "../../../runtimeabi/include/scardice_runtime_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SC_NATIVE_OK = 0,
    SC_NATIVE_MISSING_LIBRARY = -1001,
    SC_NATIVE_MISSING_SYMBOL = -1002,
    SC_NATIVE_RUNTIME_ABI = -1003,
    SC_NATIVE_HOST_ABI = -1004,
    SC_NATIVE_DESCRIPTOR = -1005,
    SC_NATIVE_CREATE = -1009,
    SC_NATIVE_CORRUPT_VTABLE = -1010,
    SC_NATIVE_TOO_SMALL = -1011,
    SC_NATIVE_INTERNAL = -1099
};

typedef struct sc_native_descriptor {
    uint32_t abi_major;
    uint32_t abi_minor;
    uint32_t host_abi_major;
    uint32_t host_abi_minor;
    uint64_t capabilities;
    char id[256];
    char name[256];
    char version[128];
    char language[64];
} sc_native_descriptor;

/* The identity is an integer owned by C. It is never a Go pointer. */
int sc_native_open(const char *path, uint64_t *out_library, char *error, uint64_t capacity);
int sc_native_query(uint64_t library, uint32_t runtime_major, uint32_t runtime_minor,
                    uint32_t host_major, uint32_t host_minor,
                    sc_native_descriptor *out, char *error, uint64_t capacity);
int sc_native_create(uint64_t library, const char *options, uint64_t options_len,
                     uint64_t *out_runtime, char *error, uint64_t capacity);
int sc_native_start(uint64_t library, uint64_t runtime, char *error, uint64_t capacity);
int sc_native_stop(uint64_t library, uint64_t runtime, char *error, uint64_t capacity);
int sc_native_destroy(uint64_t library, uint64_t runtime, char *error, uint64_t capacity);
uint64_t sc_native_resident_count(void);

#ifdef __cplusplus
}
#endif
#endif
