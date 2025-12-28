# add_cpp_obfuscated_test(
#   NAME <test_name>
#   CPP <path_to_cpp>
#   ENTRY <function_name>
#   PASSES <llvm_passes>
#   RUNNER_SRC <path_to_test_main.cpp>
#   EXPECTED_EXIT_CODE <exit_code>
# )
#
# This function creates a test that:
# 1. Compiles C++ to LLVM IR
# 2. Applies obfuscation passes (e.g., pluto-substitution)
# 3. Compiles obfuscated IR to object file
# 4. Links to executable
# 5. Lifts executable back to LLVM IR (using shared lifter)
# 6. Verifies the lifted code produces the expected result
#
# Tests are grouped under build/tests/obfuscated/<test_name>/
function(add_cpp_obfuscated_test)
    cmake_parse_arguments(ARG "" "NAME;CPP;ENTRY;PASSES;RUNNER_SRC;EXPECTED_EXIT_CODE" "" ${ARGN})

    set(BUILD_DIR ${CMAKE_BINARY_DIR}/tests/obfuscated/${ARG_NAME})
    file(MAKE_DIRECTORY ${BUILD_DIR})

    set(INPUT_LL ${BUILD_DIR}/input.ll)
    set(OBFUSCATED_LL ${BUILD_DIR}/obfuscated.ll)
    set(OBJ_FILE ${BUILD_DIR}/shellcode.obj)
    set(EXE_FILE ${BUILD_DIR}/shellcode.exe)
    set(OPTIMIZED_LL ${BUILD_DIR}/test_optimized.ll)
    set(OPTIMIZED_O ${BUILD_DIR}/test_optimized.o)

    # Step 1: Generate .cpp -> .ll (unoptimized LLVM IR)
    add_custom_command(
        OUTPUT ${INPUT_LL}
        COMMAND ${CLANG_EXECUTABLE} -S -emit-llvm -O0 -o ${INPUT_LL} ${ARG_CPP}
        DEPENDS ${ARG_CPP}
        COMMENT "[${ARG_NAME}] Generating input.ll (unoptimized)..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 2: Apply obfuscation passes using opt
    # Note: We use cmake -E env to add Z3 bin directory to PATH for libz3.dll
    add_custom_command(
        OUTPUT ${OBFUSCATED_LL}
        COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH};${Z3_BIN_DIR}"
            ${LLVM_OPT_EXECUTABLE}
            -load-pass-plugin=$<TARGET_FILE:passes>
            -passes "${ARG_PASSES}"
            ${INPUT_LL} -S -o ${OBFUSCATED_LL}
        DEPENDS ${INPUT_LL} passes
        COMMENT "[${ARG_NAME}] Applying obfuscation passes: ${ARG_PASSES}..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 3: Compile obfuscated .ll -> .obj (no optimization to preserve obfuscation)
    add_custom_command(
        OUTPUT ${OBJ_FILE}
        COMMAND ${CLANG_EXECUTABLE} -c -O0 ${OBFUSCATED_LL} -o ${OBJ_FILE}
        DEPENDS ${OBFUSCATED_LL}
        COMMENT "[${ARG_NAME}] Compiling obfuscated IR (no optimization)..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 4: Link .obj -> .exe with specified entry point
    add_custom_command(
        OUTPUT ${EXE_FILE}
        COMMAND ${MSVC_LINK_EXECUTABLE} /nologo /SUBSYSTEM:CONSOLE /ENTRY:${ARG_ENTRY}
            /OUT:${EXE_FILE} ${OBJ_FILE} kernel32.lib
        DEPENDS ${OBJ_FILE}
        COMMENT "[${ARG_NAME}] Linking shellcode.exe with entry ${ARG_ENTRY}..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 5: Lift .exe -> .ll/.bc (using shared lifter)
    add_custom_command(
        OUTPUT
            ${OPTIMIZED_LL}
            ${BUILD_DIR}/test_optimized.bc
            ${BUILD_DIR}/lifted.ll
            ${BUILD_DIR}/lifted.bc
        COMMAND lifter ${EXE_FILE}
        DEPENDS lifter ${EXE_FILE}
        COMMENT "[${ARG_NAME}] Lifting..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 6: Compile .ll -> .o
    add_custom_command(
        OUTPUT ${OPTIMIZED_O}
        COMMAND ${CLANG_EXECUTABLE} -c -O2 ${OPTIMIZED_LL} -o ${OPTIMIZED_O}
        DEPENDS ${OPTIMIZED_LL}
        COMMENT "[${ARG_NAME}] Compiling lifted IR..."
    )

    add_custom_target(${ARG_NAME}_object DEPENDS ${OPTIMIZED_O})

    # Runner executable
    add_executable(${ARG_NAME}_runner ${ARG_RUNNER_SRC})
    set_target_properties(${ARG_NAME}_runner PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})
    add_dependencies(${ARG_NAME}_runner ${ARG_NAME}_object)
    target_link_libraries(${ARG_NAME}_runner PRIVATE ${OPTIMIZED_O})

    # Test
    add_test(
        NAME ${ARG_NAME}_test
        COMMAND ${CMAKE_COMMAND}
            -DTEST_EXECUTABLE=$<TARGET_FILE:${ARG_NAME}_runner>
            -DEXPECTED_EXIT_CODE=${ARG_EXPECTED_EXIT_CODE}
            -P ${CMAKE_SOURCE_DIR}/cmake/check_exit_code.cmake
    )
endfunction()
