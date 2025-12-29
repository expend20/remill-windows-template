# add_cpp_lifting_test(
#   NAME <test_name>
#   CPP <path_to_cpp>
#   ENTRY <function_name>
#   EXPECTED_EXIT_CODE <exit_code>
# )
# Note: Uses the shared 'lifter' target defined in CMakeLists.txt
# Tests are grouped under build/tests/cpp/<test_name>/
# Only verifies the optimized IR contains "ret i32 <expected>"
function(add_cpp_lifting_test)
    cmake_parse_arguments(ARG "" "NAME;CPP;ENTRY;EXPECTED_EXIT_CODE" "" ${ARGN})

    set(BUILD_DIR ${CMAKE_BINARY_DIR}/tests/cpp/${ARG_NAME})
    file(MAKE_DIRECTORY ${BUILD_DIR})

    set(INPUT_LL ${BUILD_DIR}/input.ll)
    set(OBJ_FILE ${BUILD_DIR}/shellcode.obj)
    set(EXE_FILE ${BUILD_DIR}/shellcode.exe)
    set(OPTIMIZED_BC ${BUILD_DIR}/test_optimized.bc)

    # Generate .cpp -> .ll (unoptimized LLVM IR for inspection)
    add_custom_command(
        OUTPUT ${INPUT_LL}
        COMMAND ${CLANG_EXECUTABLE} -S -emit-llvm -O0 -o ${INPUT_LL} ${ARG_CPP}
        DEPENDS ${ARG_CPP}
        COMMENT "[${ARG_NAME}] Generating input.ll (unoptimized)..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Compile .cpp -> .obj using clang-cl
    # /GS- disables security cookies which we can't handle in lifted code
    add_custom_command(
        OUTPUT ${OBJ_FILE}
        COMMAND ${CLANG_CL_EXECUTABLE} /c /O2 /GS- /nologo /Fo${OBJ_FILE} ${ARG_CPP}
        DEPENDS ${ARG_CPP} ${INPUT_LL}
        COMMENT "[${ARG_NAME}] Compiling ${ARG_CPP}..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Link .obj -> .exe with specified entry point
    add_custom_command(
        OUTPUT ${EXE_FILE}
        COMMAND ${MSVC_LINK_EXECUTABLE} /nologo /SUBSYSTEM:CONSOLE /ENTRY:${ARG_ENTRY}
            /OUT:${EXE_FILE} ${OBJ_FILE} kernel32.lib
        DEPENDS ${OBJ_FILE}
        COMMENT "[${ARG_NAME}] Linking shellcode.exe with entry ${ARG_ENTRY}..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Lift .exe -> .ll/.bc (using shared lifter)
    add_custom_command(
        OUTPUT
            ${BUILD_DIR}/test_optimized.ll
            ${OPTIMIZED_BC}
            ${BUILD_DIR}/lifted.ll
            ${BUILD_DIR}/lifted.bc
        COMMAND lifter ${EXE_FILE}
        DEPENDS lifter ${EXE_FILE}
        COMMENT "[${ARG_NAME}] Lifting..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Build target to ensure lifting happens
    add_custom_target(${ARG_NAME}_build ALL DEPENDS ${OPTIMIZED_BC})

    # Test: verify optimized IR contains only "ret i32 <expected>"
    add_test(
        NAME ${ARG_NAME}_ir_check
        COMMAND ir_checker ${OPTIMIZED_BC} ${ARG_EXPECTED_EXIT_CODE}
    )
endfunction()
