cmake_minimum_required(VERSION 3.16)
project(scardice_runtime_quickjs LANGUAGES C CXX)

set(QUICKJS_ROOT "" CACHE PATH "Path to a QuickJS-NG source tree")
if(NOT QUICKJS_ROOT)
    message(FATAL_ERROR "QUICKJS_ROOT must point to a pinned QuickJS-NG source tree")
endif()
get_filename_component(QUICKJS_ROOT "${QUICKJS_ROOT}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
if(NOT EXISTS "${QUICKJS_ROOT}/quickjs.h")
    message(FATAL_ERROR "QUICKJS_ROOT must point to a QuickJS-NG source tree containing quickjs.h")
endif()
get_filename_component(SCARDICE_RUNTIMEABI_INCLUDE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../runtimeabi/include" ABSOLUTE)
if(NOT EXISTS "${SCARDICE_RUNTIMEABI_INCLUDE}/scardice_runtime_v1.h")
    message(FATAL_ERROR "runtimeabi/include/scardice_runtime_v1.h was not found")
endif()
get_filename_component(SCARDICE_RUNTIMEABI_COMPAT_V1_INCLUDE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../runtimeabi/compat/v1" ABSOLUTE)
if(NOT EXISTS "${SCARDICE_RUNTIMEABI_COMPAT_V1_INCLUDE}/scardice_runtime_v1.h")
    message(FATAL_ERROR "runtimeabi/compat/v1/scardice_runtime_v1.h was not found")
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(QJS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_CLI_STATIC OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_LIBC OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_WERROR OFF CACHE BOOL "" FORCE)
set(QJS_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory("${QUICKJS_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/quickjs")

add_library(scardice-runtime-quickjs SHARED quickjs_runtime.cpp)
target_compile_features(scardice-runtime-quickjs PRIVATE cxx_std_17)
target_include_directories(scardice-runtime-quickjs PRIVATE
    "${SCARDICE_RUNTIMEABI_INCLUDE}"
    "${QUICKJS_ROOT}"
)
target_link_libraries(scardice-runtime-quickjs PRIVATE qjs)
if(UNIX AND NOT APPLE)
    target_link_options(scardice-runtime-quickjs PRIVATE
        "-Wl,--exclude-libs,ALL"
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/runtime-exports.map")
endif()
set_target_properties(scardice-runtime-quickjs PROPERTIES
    OUTPUT_NAME "scardice-runtime-quickjs"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

include(GNUInstallDirs)
install(TARGETS scardice-runtime-quickjs
    LIBRARY DESTINATION quickjs
    RUNTIME DESTINATION quickjs
    ARCHIVE DESTINATION quickjs)
install(FILES runtime.json DESTINATION quickjs)
if(EXISTS "${QUICKJS_ROOT}/LICENSE")
    install(FILES "${QUICKJS_ROOT}/LICENSE"
        DESTINATION quickjs/LICENSES
        RENAME quickjs-ng.txt)
endif()

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/runtime.json" SCARDICE_RUNTIME_MANIFEST)
string(REGEX MATCH "\"version\"[ \t]*:[ \t]*\"([^\"]+)\"" _ "${SCARDICE_RUNTIME_MANIFEST}")
if(NOT CMAKE_MATCH_1)
    message(FATAL_ERROR "runtime.json must contain a package version")
endif()
set(SCARDICE_RUNTIME_VERSION "${CMAKE_MATCH_1}")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(SCARDICE_RUNTIME_OS "linux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(SCARDICE_RUNTIME_OS "darwin")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(SCARDICE_RUNTIME_OS "windows")
else()
    string(TOLOWER "${CMAKE_SYSTEM_NAME}" SCARDICE_RUNTIME_OS)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    set(SCARDICE_RUNTIME_ARCH "amd64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
    set(SCARDICE_RUNTIME_ARCH "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(i[3-6]86|x86)$")
    set(SCARDICE_RUNTIME_ARCH "386")
else()
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" SCARDICE_RUNTIME_ARCH)
endif()

set(CPACK_PACKAGE_NAME "Scardice-runtime-quickjs")
set(CPACK_PACKAGE_VENDOR "Scardice")
set(CPACK_PACKAGE_VERSION "${SCARDICE_RUNTIME_VERSION}")
set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${SCARDICE_RUNTIME_OS}-${SCARDICE_RUNTIME_ARCH}")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
if(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ")
endif()
include(CPack)

option(SCARDICE_QUICKJS_BUILD_TESTS "Build the native QuickJS ABI smoke test" ON)
if(SCARDICE_QUICKJS_BUILD_TESTS)
    enable_testing()
    add_executable(scardice-runtime-quickjs-smoke testdata/smoke.cpp)
    target_compile_features(scardice-runtime-quickjs-smoke PRIVATE cxx_std_17)
    target_include_directories(scardice-runtime-quickjs-smoke PRIVATE "${SCARDICE_RUNTIMEABI_INCLUDE}")
    target_link_libraries(scardice-runtime-quickjs-smoke PRIVATE ${CMAKE_DL_LIBS})
    add_test(NAME scardice-runtime-quickjs-smoke
        COMMAND scardice-runtime-quickjs-smoke $<TARGET_FILE:scardice-runtime-quickjs>)
    add_executable(scardice-runtime-quickjs-options-smoke testdata/options_smoke.cpp)
    target_compile_features(scardice-runtime-quickjs-options-smoke PRIVATE cxx_std_17)
    target_include_directories(scardice-runtime-quickjs-options-smoke PRIVATE "${SCARDICE_RUNTIMEABI_INCLUDE}")
    target_link_libraries(scardice-runtime-quickjs-options-smoke PRIVATE ${CMAKE_DL_LIBS})
    foreach(option_case IN ITEMS malformed unknown out-of-range timeout memory stack full)
        add_test(NAME scardice-runtime-quickjs-options-${option_case}
            COMMAND scardice-runtime-quickjs-options-smoke $<TARGET_FILE:scardice-runtime-quickjs> ${option_case})
        set_tests_properties(scardice-runtime-quickjs-options-${option_case} PROPERTIES TIMEOUT 5)
    endforeach()
    add_library(scardice-runtime-quickjs-compat-v1 SHARED quickjs_runtime.cpp)
    target_compile_features(scardice-runtime-quickjs-compat-v1 PRIVATE cxx_std_17)
    target_include_directories(scardice-runtime-quickjs-compat-v1 PRIVATE
        "${SCARDICE_RUNTIMEABI_COMPAT_V1_INCLUDE}"
        "${QUICKJS_ROOT}")
    target_link_libraries(scardice-runtime-quickjs-compat-v1 PRIVATE qjs)
    if(UNIX AND NOT APPLE)
        target_link_options(scardice-runtime-quickjs-compat-v1 PRIVATE
            "-Wl,--exclude-libs,ALL"
            "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/runtime-exports.map")
    endif()
    set_target_properties(scardice-runtime-quickjs-compat-v1 PROPERTIES
        OUTPUT_NAME "scardice-runtime-quickjs-compat-v1"
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES)

    add_executable(scardice-runtime-quickjs-compat-v1-smoke testdata/compat_v1_smoke.cpp)
    target_compile_features(scardice-runtime-quickjs-compat-v1-smoke PRIVATE cxx_std_17)
    target_include_directories(scardice-runtime-quickjs-compat-v1-smoke PRIVATE
        "${SCARDICE_RUNTIMEABI_COMPAT_V1_INCLUDE}")
    target_link_libraries(scardice-runtime-quickjs-compat-v1-smoke PRIVATE ${CMAKE_DL_LIBS})
    add_test(NAME scardice-runtime-quickjs-compat-v1-smoke
        COMMAND scardice-runtime-quickjs-compat-v1-smoke $<TARGET_FILE:scardice-runtime-quickjs-compat-v1>)
endif()
