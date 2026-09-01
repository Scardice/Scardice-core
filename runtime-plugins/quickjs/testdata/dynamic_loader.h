#ifndef SCARDICE_TEST_DYNAMIC_LOADER_H
#define SCARDICE_TEST_DYNAMIC_LOADER_H

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace scardice_test {

#if defined(_WIN32)
using library_handle = HMODULE;

inline library_handle open_library(const char *path) noexcept {
    return LoadLibraryA(path);
}

inline void *lookup_symbol(library_handle library, const char *name) noexcept {
    return reinterpret_cast<void *>(GetProcAddress(library, name));
}

inline bool library_is_open(library_handle library) noexcept {
    return library != nullptr;
}
#else
using library_handle = void *;

inline library_handle open_library(const char *path) noexcept {
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}

inline void *lookup_symbol(library_handle library, const char *name) noexcept {
    return dlsym(library, name);
}

inline bool library_is_open(library_handle library) noexcept {
    return library != nullptr;
}
#endif

} // namespace scardice_test

#endif // SCARDICE_TEST_DYNAMIC_LOADER_H
