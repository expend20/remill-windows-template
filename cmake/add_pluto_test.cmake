# add_pluto_test(
#   NAME <test_name>
#   CPP <path_to_cpp>
#   PASSES <llvm_passes>
#   EXPECTED_EXIT_CODE <exit_code>
# )
#
# This function creates a test that:
# 1. Compiles C++ to LLVM IR (input.ll - kept for inspection)
# 2. Applies obfuscation passes (obfuscated.ll - kept for inspection)
# 3. Compiles obfuscated IR to executable
# 4. Runs and verifies the returned value
#
# Unlike add_cpp_obfuscated_test, this does NOT lift - it just verifies
# that obfuscation preserves program semantics.
#
# Tests are grouped under build/tests/pluto/<test_name>/
function(add_pluto_test)
    cmake_parse_arguments(ARG "" "NAME;CPP;PASSES;EXPECTED_EXIT_CODE" "" ${ARGN})

    set(BUILD_DIR ${CMAKE_BINARY_DIR}/tests/pluto/${ARG_NAME})
    file(MAKE_DIRECTORY ${BUILD_DIR})

    set(INPUT_LL ${BUILD_DIR}/input.ll)
    set(OBFUSCATED_LL ${BUILD_DIR}/obfuscated.ll)
    set(EXE_FILE ${BUILD_DIR}/${ARG_NAME}.exe)

    # Step 1: Generate .cpp -> .ll (unoptimized LLVM IR)
    add_custom_command(
        OUTPUT ${INPUT_LL}
        COMMAND ${CLANG_EXECUTABLE} -S -emit-llvm -O0 -o ${INPUT_LL} ${ARG_CPP}
        DEPENDS ${ARG_CPP}
        COMMENT "[${ARG_NAME}] Generating input.ll..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 2: Apply obfuscation passes using obfuscator tool
    add_custom_command(
        OUTPUT ${OBFUSCATED_LL}
        COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH};${Z3_BIN_DIR}"
            $<TARGET_FILE:obfuscator>
            ${INPUT_LL}
            ${OBFUSCATED_LL}
            --passes="${ARG_PASSES}"
        DEPENDS ${INPUT_LL} obfuscator
        COMMENT "[${ARG_NAME}] Applying obfuscation: ${ARG_PASSES}..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 3: Compile obfuscated .ll -> .exe (with main, so use normal entry)
    add_custom_command(
        OUTPUT ${EXE_FILE}
        COMMAND ${CLANG_EXECUTABLE} -O0 ${OBFUSCATED_LL} -o ${EXE_FILE}
        DEPENDS ${OBFUSCATED_LL}
        COMMENT "[${ARG_NAME}] Compiling ${ARG_NAME}.exe..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Create custom target to build the test executable (ALL ensures it's built by default)
    add_custom_target(${ARG_NAME}_build ALL DEPENDS ${EXE_FILE})

    # Test: verify exit code matches expected value
    add_test(
        NAME ${ARG_NAME}_test
        COMMAND ${CMAKE_COMMAND}
            -DTEST_EXECUTABLE=${EXE_FILE}
            -DEXPECTED_EXIT_CODE=${ARG_EXPECTED_EXIT_CODE}
            -P ${CMAKE_SOURCE_DIR}/cmake/check_exit_code.cmake
    )

    # Make sure test depends on building the executable
    set_tests_properties(${ARG_NAME}_test PROPERTIES DEPENDS ${ARG_NAME}_build)
endfunction()
