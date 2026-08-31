#ifdef _WIN32
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

typedef HMODULE sc_platform_library;

sc_platform_library sc_platform_load(const char *path, char *error, uint64_t capacity) {
    int length;
    wchar_t *wide_path;
    HMODULE library;
    if (path == NULL) return NULL;
    length = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    if (length <= 0) return NULL;
    wide_path = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)length * sizeof(wchar_t));
    if (wide_path == NULL) return NULL;
    (void)MultiByteToWideChar(CP_UTF8, 0, path, -1, wide_path, length);
    library = LoadLibraryExW(wide_path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    HeapFree(GetProcessHeap(), 0, wide_path);
    if (library == NULL && error != NULL && capacity != 0) {
        (void)snprintf(error, (size_t)capacity, "LoadLibraryExW failed for %s", path);
    }
    return library;
}

void *sc_platform_symbol(sc_platform_library library, const char *name) {
    return (void *)(uintptr_t)GetProcAddress(library, name);
}
#endif
