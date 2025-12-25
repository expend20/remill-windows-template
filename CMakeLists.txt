cmake_minimum_required(VERSION 3.15)
project(RemillLifting LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Variables
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(GFLAGS_USE_TARGET_NAMESPACE ON)

# Packages
find_package(LLVM-Wrapper REQUIRED)
find_package(remill REQUIRED)

# Common lifting library
add_library(lifting_common STATIC
    src/lifting/lifting_context.cpp
    src/lifting/instruction_lifter.cpp
    src/lifting/wrapper_builder.cpp
    src/optimization/optimizer.cpp
    src/utils/module_utils.cpp
    src/utils/pe_reader.cpp
)

target_include_directories(lifting_common PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(lifting_common PUBLIC
    LLVM-Wrapper
    remill
)

# Find tools for tests
find_program(CLANG_EXECUTABLE clang HINTS "${LLVM_TOOLS_BINARY_DIR}")
find_program(ML64_EXECUTABLE ml64)
if(ML64_EXECUTABLE)
    get_filename_component(ML64_DIR "${ML64_EXECUTABLE}" DIRECTORY)
    find_program(MSVC_LINK_EXECUTABLE link.exe HINTS "${ML64_DIR}" NO_DEFAULT_PATH)
endif()
if(NOT MSVC_LINK_EXECUTABLE)
    find_program(MSVC_LINK_EXECUTABLE link.exe)
endif()

if(NOT CLANG_EXECUTABLE)
    message(STATUS "clang not found, test targets will not be available")
elseif(NOT ML64_EXECUTABLE)
    message(STATUS "ml64 not found, assembly tests will not be available")
elseif(NOT MSVC_LINK_EXECUTABLE)
    message(STATUS "link not found, assembly tests will not be available")
else()
    message(STATUS "Found clang: ${CLANG_EXECUTABLE}")
    message(STATUS "Found ml64: ${ML64_EXECUTABLE}")
    message(STATUS "Found link: ${MSVC_LINK_EXECUTABLE}")

    enable_testing()
    include(add_asm_lifting_test)

    add_asm_lifting_test(
        NAME mov_const
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/mov_const.asm
        LIFTER_SRC ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/main.cpp
        RUNNER_SRC ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/test_main.cpp
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME or_const
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/or_const.asm
        LIFTER_SRC ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/main.cpp
        RUNNER_SRC ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/test_main.cpp
        EXPECTED_EXIT_CODE 4919
    )
endif()
