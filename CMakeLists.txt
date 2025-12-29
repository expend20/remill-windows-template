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

    # Shared lifter executable for all tests
    add_executable(lifter ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/main.cpp)
    target_link_libraries(lifter PRIVATE lifting_common)

    # IR checker tool for verifying optimized IR
    add_executable(ir_checker ${CMAKE_SOURCE_DIR}/src/tools/ir_checker.cpp)
    target_include_directories(ir_checker PRIVATE ${CMAKE_PREFIX_PATH}/include)
    target_link_libraries(ir_checker PRIVATE LLVM-Wrapper)

    # Pluto obfuscation passes (static library) and obfuscator tool
    # This replaces the llvm-ob-passes plugin approach to avoid ODR violations
    add_subdirectory(src/obfuscation/pluto)
    add_executable(obfuscator ${CMAKE_SOURCE_DIR}/src/obfuscation/obfuscator.cpp)
    target_include_directories(obfuscator PRIVATE ${CMAKE_PREFIX_PATH}/include)
    target_link_libraries(obfuscator PRIVATE pluto_passes LLVM-Wrapper)

    # Basic return value tests (basic_return.asm)
    add_asm_lifting_test(
        NAME basic_mov_const
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/basic_return.asm
        ENTRY mov_const
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME basic_alu_const
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/basic_return.asm
        ENTRY alu_const
        EXPECTED_EXIT_CODE 4919
    )

    # Global memory access tests (global_memory.asm)
    add_asm_lifting_test(
        NAME global_bytewise_write
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY bytewise_write
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_unaligned_read
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY unaligned_read
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_wordwise_write
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY wordwise_write
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_qword_access
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY qword_access
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_dword_to_bytes
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY dword_to_bytes
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_zero_extend_byte
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY zero_extend_byte
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_zero_extend_word
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY zero_extend_word
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_sign_extend_byte
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY sign_extend_byte
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_read_modify_write
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY read_modify_write
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_read_initialized
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY read_initialized
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_array_const_index
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY array_const_index
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_array_reg_index
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY array_reg_index
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_unaligned_qword
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY unaligned_qword
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_multi_global
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY multi_global
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME global_overlapping_write
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_memory.asm
        ENTRY overlapping_write
        EXPECTED_EXIT_CODE 4919
    )

    # Stack memory access tests (stack_memory.asm)
    add_asm_lifting_test(
        NAME stack_bytewise_write
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/stack_memory.asm
        ENTRY bytewise_write
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME stack_unaligned_read
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/stack_memory.asm
        ENTRY unaligned_read
        EXPECTED_EXIT_CODE 4919
    )

    # Cross-section memory tests (rdata_to_stack.asm)
    add_asm_lifting_test(
        NAME rdata_to_stack
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/rdata_to_stack.asm
        ENTRY rdata_to_stack
        EXPECTED_EXIT_CODE 4919
    )

    # Loop handling tests (loops.asm)
    add_asm_lifting_test(
        NAME loop_sum
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/loops.asm
        ENTRY sum_loop
        EXPECTED_EXIT_CODE 4919
    )

    # Direct branch tests (direct_branch.asm)
    add_asm_lifting_test(
        NAME call_direct
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/direct_branch.asm
        ENTRY call_helper
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME jmp_direct
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/direct_branch.asm
        ENTRY direct_jmp
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME jmp_chain
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/direct_branch.asm
        ENTRY jmp_chain
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME call_chain
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/direct_branch.asm
        ENTRY call_chain
        EXPECTED_EXIT_CODE 4919
    )

    # Indirect branch tests (indirect_branch.asm)
    add_asm_lifting_test(
        NAME indirect_register_jmp
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/indirect_branch.asm
        ENTRY register_jmp
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME indirect_push_ret
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/indirect_branch.asm
        ENTRY push_ret
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME indirect_jump_table
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/indirect_branch.asm
        ENTRY jump_table
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME indirect_jump_table_index
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/indirect_branch.asm
        ENTRY jump_table_index
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME indirect_jmp_chain
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/indirect_branch.asm
        ENTRY indirect_jmp_chain
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME indirect_call_register
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/indirect_branch.asm
        ENTRY indirect_call_register
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME indirect_call_memory
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/indirect_branch.asm
        ENTRY indirect_call_memory
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME indirect_call_indexed
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/indirect_branch.asm
        ENTRY indirect_call_indexed
        EXPECTED_EXIT_CODE 4919
    )

    add_asm_lifting_test(
        NAME indirect_call_indexed_offset
        ASM ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/indirect_branch.asm
        ENTRY indirect_call_indexed_offset
        EXPECTED_EXIT_CODE 4919
    )

    if(CLANG_CL_EXECUTABLE)
        message(STATUS "Found clang-cl: ${CLANG_CL_EXECUTABLE}")

        add_cpp_lifting_test(
            NAME ret_const
            CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/ret_const.cpp
            ENTRY test_me
            EXPECTED_EXIT_CODE 4919
        )

        add_cpp_lifting_test(
            NAME global_var
            CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_var.cpp
            ENTRY test_me
            EXPECTED_EXIT_CODE 4919
        )

        add_cpp_lifting_test(
            NAME xtea_roundtrip
            CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/xtea_roundtrip.cpp
            ENTRY test_me
            EXPECTED_EXIT_CODE 4919
        )

        # NOTE: xtea_noinline test - uses function inlining approach
        # See FUNCTION_INLINING.md for details
        add_cpp_lifting_test(
            NAME xtea_noinline
            CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/xtea_noinline.cpp
            ENTRY test_me
            EXPECTED_EXIT_CODE 4919
        )

        # Obfuscation pass tests (require opt and llvm-ob-passes)
        if(LLVM_OPT_EXECUTABLE)
            message(STATUS "Found opt: ${LLVM_OPT_EXECUTABLE}")

            # Z3 bin directory for runtime DLL loading (libz3.dll)
            # Derive from LLVM_Z3_INSTALL_DIR or use superbuild location
            if(LLVM_Z3_INSTALL_DIR)
                set(Z3_BIN_DIR "${LLVM_Z3_INSTALL_DIR}/bin" CACHE PATH "Z3 bin directory")
            else()
                # Default to superbuild location
                list(GET CMAKE_PREFIX_PATH 0 _first_prefix)
                set(Z3_BIN_DIR "${_first_prefix}/bin" CACHE PATH "Z3 bin directory")
            endif()
            message(STATUS "Z3 bin directory: ${Z3_BIN_DIR}")

            # Note: llvm-ob-passes plugin is replaced by pluto_passes static library
            # to avoid ODR violations. The obfuscator tool is used instead of opt with plugin.
            # add_subdirectory(src/deps/llvm-ob-passes)

            include(add_cpp_obfuscated_test)

            add_cpp_obfuscated_test(
                NAME global_var_pluto
                CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/global_var_pluto.cpp
                ENTRY test_me
                PASSES "pluto-substitution,pluto-substitution,pluto-substitution,pluto-substitution,pluto-substitution"
                        EXPECTED_EXIT_CODE 4919
            )

            add_cpp_obfuscated_test(
                NAME xtea_substitution
                CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/xtea_substitution.cpp
                ENTRY test_me
                PASSES "pluto-substitution"
                        EXPECTED_EXIT_CODE 4919
            )

            add_cpp_obfuscated_test(
                NAME xtea_flattening
                CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/xtea_flattening.cpp
                ENTRY test_me
                PASSES "pluto-flattening"
                        EXPECTED_EXIT_CODE 4919
            )

            # DISABLED: bogus-control-flow creates large stack frames requiring __chkstk
            # which is not available with custom entry point (no CRT)
            # add_cpp_obfuscated_test(
            #     NAME xtea_bogus_cfg
            #     CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/xtea_bogus_cfg.cpp
            #     ENTRY test_me
            #     PASSES "pluto-bogus-control-flow"
            #     EXPECTED_EXIT_CODE 4919
            # )

            add_cpp_obfuscated_test(
                NAME xtea_global_encryption
                CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/xtea_global_encryption.cpp
                ENTRY test_me
                PASSES "pluto-global-encryption"
                        EXPECTED_EXIT_CODE 4919
            )

            add_cpp_obfuscated_test(
                NAME xtea_indirect_call
                CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/xtea_indirect_call.cpp
                ENTRY test_me
                PASSES "pluto-indirect-call"
                        EXPECTED_EXIT_CODE 4919
            )

            add_cpp_obfuscated_test(
                NAME xtea_mba
                CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/xtea_mba.cpp
                ENTRY test_me
                PASSES "pluto-mba-obfuscation"
                        EXPECTED_EXIT_CODE 4919
            )

            # All Pluto passes combined (except MBA which crashes when combined, and
            # bogus-control-flow which creates large stack frames requiring __chkstk)
            # Note: module passes (indirect-call, global-encryption) need to be separated
            # from function passes using module(function(...)) wrapper syntax
            add_cpp_obfuscated_test(
                NAME xtea_all_pluto
                CPP ${CMAKE_SOURCE_DIR}/src/tests/ret_with_code/xtea_all_pluto.cpp
                ENTRY test_me
                PASSES "module(function(pluto-substitution,pluto-flattening)),pluto-indirect-call,pluto-global-encryption"
                        EXPECTED_EXIT_CODE 4919
            )

            # Pluto-only tests (verify obfuscation preserves semantics without lifting)
            # These tests compile and run obfuscated code directly, keeping input.ll
            # and obfuscated.ll for inspection in build/tests/pluto/<name>/
            include(add_pluto_test)

            add_pluto_test(
                NAME pluto_substitution
                CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
                PASSES "pluto-substitution"
                EXPECTED_EXIT_CODE 4919
            )

            add_pluto_test(
                NAME pluto_flattening
                CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
                PASSES "pluto-flattening"
                EXPECTED_EXIT_CODE 4919
            )

            add_pluto_test(
                NAME pluto_bogus_cfg
                CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
                PASSES "pluto-bogus-control-flow"
                EXPECTED_EXIT_CODE 4919
            )

            add_pluto_test(
                NAME pluto_global_encryption
                CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
                PASSES "pluto-global-encryption"
                EXPECTED_EXIT_CODE 4919
            )

            add_pluto_test(
                NAME pluto_indirect_call
                CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
                PASSES "pluto-indirect-call"
                EXPECTED_EXIT_CODE 4919
            )

            add_pluto_test(
                NAME pluto_mba
                CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
                PASSES "pluto-mba-obfuscation"
                EXPECTED_EXIT_CODE 4919
            )

            add_pluto_test(
                NAME pluto_all
                CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
                PASSES "module(function(pluto-substitution,pluto-flattening,pluto-bogus-control-flow,pluto-mba-obfuscation)),pluto-indirect-call,pluto-global-encryption"
                EXPECTED_EXIT_CODE 4919
            )

        else()
            message(STATUS "opt not found, obfuscation tests will not be available")
        endif()
    else()
        message(STATUS "clang-cl not found, C++ tests will not be available")
    endif()
endif()
