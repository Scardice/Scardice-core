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

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(QJS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_CLI_STATIC OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_LIBC OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_WERROR OFF CACHE BOOL "" FORCE)
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
install(TARGETS scardice-runtime-quickjs LIBRARY DESTINATION . RUNTIME DESTINATION . ARCHIVE DESTINATION .)
install(FILES runtime.json DESTINATION .)
option(SCARDICE_QUICKJS_BUILD_TESTS "Build the native QuickJS ABI smoke test" ON)
if(SCARDICE_QUICKJS_BUILD_TESTS)
    enable_testing()
    add_executable(scardice-runtime-quickjs-smoke testdata/smoke.cpp)
    target_compile_features(scardice-runtime-quickjs-smoke PRIVATE cxx_std_17)
    target_include_directories(scardice-runtime-quickjs-smoke PRIVATE "${SCARDICE_RUNTIMEABI_INCLUDE}")
    target_link_libraries(scardice-runtime-quickjs-smoke PRIVATE ${CMAKE_DL_LIBS})
    add_test(NAME scardice-runtime-quickjs-smoke
        COMMAND scardice-runtime-quickjs-smoke $<TARGET_FILE:scardice-runtime-quickjs>)
endif()
