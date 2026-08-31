#ifndef _WIN32
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

typedef void *sc_platform_library;

sc_platform_library sc_platform_load(const char *path, char *error, uint64_t capacity) {
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (library == NULL && error != NULL && capacity != 0) {
        (void)snprintf(error, (size_t)capacity, "dlopen(%s): %s", path != NULL ? path : "", dlerror());
    }
    return library;
}

void *sc_platform_symbol(sc_platform_library library, const char *name) {
    dlerror();
    return dlsym(library, name);
}
#endif
