cmake_minimum_required(VERSION 3.16)
project(echo_runtime_fixture C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(echo_runtime SHARED echo_runtime.c)
target_include_directories(echo_runtime PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)
set_target_properties(echo_runtime PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    OUTPUT_NAME echo_runtime
)

add_executable(echo_runtime_harness harness.c)
target_include_directories(echo_runtime_harness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)
target_link_libraries(echo_runtime_harness PRIVATE ${CMAKE_DL_LIBS})

enable_testing()
add_test(NAME echo_runtime_integration COMMAND echo_runtime_harness
    $<TARGET_FILE:echo_runtime>)
