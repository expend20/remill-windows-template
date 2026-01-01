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
    src/lifting/control_flow_lifter.cpp
    src/lifting/block_decoder.cpp
    src/lifting/block_terminator.cpp
    src/lifting/function_splitter.cpp
    src/lifting/indirect_jump_resolver.cpp
    src/lifting/wrapper_builder.cpp
    src/lifting/memory_lowering.cpp
    src/lifting/variable_config.cpp
    src/lifting/external_call_handler.cpp
    src/optimization/optimizer.cpp
    src/optimization/stack_slot_splitter.cpp
    src/utils/debug_flag.cpp
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
find_program(CLANG_CL_EXECUTABLE clang-cl HINTS "${LLVM_TOOLS_BINARY_DIR}" "${CMAKE_PREFIX_PATH}/bin")
find_program(LLVM_OPT_EXECUTABLE opt HINTS "${LLVM_TOOLS_BINARY_DIR}" "${CMAKE_PREFIX_PATH}/bin")
find_program(LLC_EXECUTABLE llc HINTS "${LLVM_TOOLS_BINARY_DIR}" "${CMAKE_PREFIX_PATH}/bin")
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
    include(add_cpp_lifting_test)
    include(add_variable_test)
    include(add_external_call_test)

    # Unified lifter executable for all tests (const and variable modes)
    add_executable(lifter ${CMAKE_SOURCE_DIR}/src/tests/lifter.cpp)
    target_link_libraries(lifter PRIVATE lifting_common)

    # IR checker tool for verifying optimized IR (supports both strict and config-based modes)
    add_executable(variable_ir_checker ${CMAKE_SOURCE_DIR}/src/tools/variable_ir_checker.cpp)
    target_include_directories(variable_ir_checker PRIVATE ${CMAKE_PREFIX_PATH}/include)
    target_link_libraries(variable_ir_checker PRIVATE LLVM-Wrapper)

    # Pluto obfuscation passes (static library) and obfuscator tool
    # This replaces the llvm-ob-passes plugin approach to avoid ODR violations
    add_subdirectory(src/obfuscation/pluto)
    add_executable(obfuscator ${CMAKE_SOURCE_DIR}/src/obfuscation/obfuscator.cpp)
    target_include_directories(obfuscator PRIVATE ${CMAKE_PREFIX_PATH}/include)
    target_link_libraries(obfuscator PRIVATE pluto_passes LLVM-Wrapper)

    # ASM lifting tests (only need ml64/link)
    # Test definitions in: src/tests/const/asm_tests.cmake
    include(${CMAKE_SOURCE_DIR}/src/tests/const/asm_tests.cmake)

    # Variable input tests (non-constant register values)
    if(LLC_EXECUTABLE)
        message(STATUS "Found llc: ${LLC_EXECUTABLE}")
        # Test definitions in: src/tests/variable/variable_tests.cmake
        include(${CMAKE_SOURCE_DIR}/src/tests/variable/variable_tests.cmake)
    else()
        message(STATUS "llc not found, variable tests will not be available")
    endif()

    # External call tests (functions that call external APIs like puts)
    # Test definitions in: src/tests/variable/external_call_tests.cmake
    include(${CMAKE_SOURCE_DIR}/src/tests/variable/external_call_tests.cmake)

    if(CLANG_CL_EXECUTABLE)
        message(STATUS "Found clang-cl: ${CLANG_CL_EXECUTABLE}")

        # C++ lifting tests
        # Test definitions in: src/tests/const/cpp_tests.cmake
        include(${CMAKE_SOURCE_DIR}/src/tests/const/cpp_tests.cmake)

        # Obfuscation pass tests (require opt)
        if(LLVM_OPT_EXECUTABLE)
            message(STATUS "Found opt: ${LLVM_OPT_EXECUTABLE}")

            # Z3 bin directory for runtime DLL loading (libz3.dll)
            if(LLVM_Z3_INSTALL_DIR)
                set(Z3_BIN_DIR "${LLVM_Z3_INSTALL_DIR}/bin" CACHE PATH "Z3 bin directory")
            else()
                list(GET CMAKE_PREFIX_PATH 0 _first_prefix)
                set(Z3_BIN_DIR "${_first_prefix}/bin" CACHE PATH "Z3 bin directory")
            endif()
            message(STATUS "Z3 bin directory: ${Z3_BIN_DIR}")

            include(add_cpp_obfuscated_test)
            include(add_pluto_test)

            # Obfuscated lifting tests
            # Test definitions in: src/tests/const/obfuscated_tests.cmake
            include(${CMAKE_SOURCE_DIR}/src/tests/const/obfuscated_tests.cmake)

            # Pluto-only tests (verify obfuscation preserves semantics without lifting)
            # Test definitions in: src/tests/obfuscation/pluto/pluto_tests.cmake
            include(${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/pluto_tests.cmake)
        else()
            message(STATUS "opt not found, obfuscation tests will not be available")
        endif()
    else()
        message(STATUS "clang-cl not found, C++ tests will not be available")
    endif()
endif()
