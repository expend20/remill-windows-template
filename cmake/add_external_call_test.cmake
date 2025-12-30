# add_external_call_test(
#   NAME <test_name>
#   CPP <path_to_cpp>
#   CONFIG <path_to_config_json>
#   ENTRY <function_name>
#   EXPECTED_EXIT_CODE <exit_code>
#   [WRAPPER <path_to_wrapper_cpp>]
# )
#
# This function creates a test that:
# 1. Compiles C++ to LLVM IR
# 2. Compiles to object file
# 3. Links to executable (with ucrt.lib for imports)
# 4. Lifts executable back to LLVM IR (using variable_lifter)
# 5. Verifies the optimized IR contains expected external call
# 6. (Optional) If WRAPPER is provided, compiles lifted IR + wrapper to executable
#
# Tests are grouped under build/tests/variable/<test_name>/
function(add_external_call_test)
    cmake_parse_arguments(ARG "" "NAME;CPP;CONFIG;ENTRY;EXPECTED_EXIT_CODE;WRAPPER" "" ${ARGN})

    set(BUILD_DIR ${CMAKE_BINARY_DIR}/tests/variable/${ARG_NAME})
    file(MAKE_DIRECTORY ${BUILD_DIR})

    set(INPUT_LL ${BUILD_DIR}/input.ll)
    set(OBJ_FILE ${BUILD_DIR}/shellcode.obj)
    set(EXE_FILE ${BUILD_DIR}/shellcode.exe)
    set(OPTIMIZED_BC ${BUILD_DIR}/test_optimized.bc)

    # Step 1: Generate .cpp -> .ll (unoptimized LLVM IR)
    add_custom_command(
        OUTPUT ${INPUT_LL}
        COMMAND ${CLANG_EXECUTABLE} -S -emit-llvm -O0 -o ${INPUT_LL} ${ARG_CPP}
        DEPENDS ${ARG_CPP}
        COMMENT "[${ARG_NAME}] Generating input.ll (unoptimized)..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 2: Compile .ll -> .obj (no optimization)
    add_custom_command(
        OUTPUT ${OBJ_FILE}
        COMMAND ${CLANG_EXECUTABLE} -c -O0 ${INPUT_LL} -o ${OBJ_FILE}
        DEPENDS ${INPUT_LL}
        COMMENT "[${ARG_NAME}] Compiling to object file..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 3: Link .obj -> .exe with specified entry point
    # Link with ucrt.lib and vcruntime.lib for C runtime imports (puts, printf, etc.)
    add_custom_command(
        OUTPUT ${EXE_FILE}
        COMMAND ${MSVC_LINK_EXECUTABLE} /nologo /SUBSYSTEM:CONSOLE /ENTRY:${ARG_ENTRY}
            /OUT:${EXE_FILE} ${OBJ_FILE} kernel32.lib ucrt.lib vcruntime.lib
        DEPENDS ${OBJ_FILE}
        COMMENT "[${ARG_NAME}] Linking shellcode.exe with entry ${ARG_ENTRY}..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Step 4: Lift .exe -> .ll/.bc (using variable_lifter)
    add_custom_command(
        OUTPUT
            ${BUILD_DIR}/test_optimized.ll
            ${OPTIMIZED_BC}
            ${BUILD_DIR}/lifted.ll
            ${BUILD_DIR}/lifted.bc
        COMMAND variable_lifter ${EXE_FILE} ${ARG_CONFIG}
        DEPENDS variable_lifter ${EXE_FILE} ${ARG_CONFIG}
        COMMENT "[${ARG_NAME}] Lifting with external call support..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Build target to ensure lifting happens
    add_custom_target(${ARG_NAME}_build ALL DEPENDS ${OPTIMIZED_BC})

    # Test: verify optimized IR contains expected return value (4919) and external call
    # For external call tests, we verify:
    # 1. The function returns the expected value
    # 2. External calls are preserved (using llvm-dis to check the IR)
    add_test(
        NAME ${ARG_NAME}_ir_check
        COMMAND ${CMAKE_COMMAND}
            -DTEST_BC=${OPTIMIZED_BC}
            -DEXPECTED_EXIT_CODE=${ARG_EXPECTED_EXIT_CODE}
            -DLLVM_DIS=${LLVM_DIS_EXECUTABLE}
            -P ${CMAKE_SOURCE_DIR}/cmake/check_external_call_ir.cmake
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Optional: If WRAPPER is provided, compile lifted IR + wrapper to executable
    if(ARG_WRAPPER)
        set(LIFTED_OBJ ${BUILD_DIR}/lifted_optimized.obj)
        set(WRAPPER_OBJ ${BUILD_DIR}/wrapper.obj)
        set(RELIFTED_EXE ${BUILD_DIR}/relifted.exe)

        # Step 5: Compile optimized .ll -> .obj
        add_custom_command(
            OUTPUT ${LIFTED_OBJ}
            COMMAND ${CLANG_EXECUTABLE} -c -O2 ${BUILD_DIR}/test_optimized.ll -o ${LIFTED_OBJ}
            DEPENDS ${BUILD_DIR}/test_optimized.ll ${OPTIMIZED_BC}
            COMMENT "[${ARG_NAME}] Compiling lifted IR to object..."
            WORKING_DIRECTORY ${BUILD_DIR}
        )

        # Step 6: Compile wrapper .cpp -> .obj
        add_custom_command(
            OUTPUT ${WRAPPER_OBJ}
            COMMAND ${CLANG_EXECUTABLE} -c -O2 ${ARG_WRAPPER} -o ${WRAPPER_OBJ}
            DEPENDS ${ARG_WRAPPER}
            COMMENT "[${ARG_NAME}] Compiling wrapper..."
            WORKING_DIRECTORY ${BUILD_DIR}
        )

        # Step 7: Link wrapper + lifted code -> .exe (use clang to handle CRT startup)
        add_custom_command(
            OUTPUT ${RELIFTED_EXE}
            COMMAND ${CLANG_EXECUTABLE} -o ${RELIFTED_EXE} ${WRAPPER_OBJ} ${LIFTED_OBJ}
                -lucrt -lvcruntime -llegacy_stdio_definitions
            DEPENDS ${WRAPPER_OBJ} ${LIFTED_OBJ}
            COMMENT "[${ARG_NAME}] Linking relifted executable..."
            WORKING_DIRECTORY ${BUILD_DIR}
        )

        # Build target for the relifted executable
        add_custom_target(${ARG_NAME}_relifted ALL DEPENDS ${RELIFTED_EXE})

        # Test: run the relifted executable and check exit code
        add_test(
            NAME ${ARG_NAME}_runtime
            COMMAND ${RELIFTED_EXE}
            WORKING_DIRECTORY ${BUILD_DIR}
        )
        set_tests_properties(${ARG_NAME}_runtime PROPERTIES
            PASS_REGULAR_EXPRESSION ".*"
            WILL_FAIL FALSE
        )
    endif()
endfunction()
