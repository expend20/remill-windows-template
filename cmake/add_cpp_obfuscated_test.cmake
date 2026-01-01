# add_cpp_obfuscated_test(
#   NAME <test_name>
#   CPP <path_to_cpp>
#   ENTRY <function_name>
#   PASSES <llvm_passes>
#   EXPECTED_EXIT_CODE <exit_code>
# )
#
# This function creates a test that:
# 1. Compiles C++ to LLVM IR
# 2. Applies obfuscation passes (e.g., pluto-substitution)
# 3. Compiles obfuscated IR to object file
# 4. Links to executable
# 5. Lifts executable back to LLVM IR (using shared lifter)
# 6. Verifies the optimized IR contains "ret i32 <expected>"
#
# Tests are grouped under build/tests/obfuscated/<test_name>/
function(add_cpp_obfuscated_test)
    cmake_parse_arguments(ARG "" "NAME;CPP;ENTRY;PASSES;EXPECTED_EXIT_CODE" "" ${ARGN})

    set(BUILD_DIR ${CMAKE_BINARY_DIR}/tests/obfuscated/${ARG_NAME})
    file(MAKE_DIRECTORY ${BUILD_DIR})

    set(INPUT_LL ${BUILD_DIR}/input.ll)
    set(OBFUSCATED_LL ${BUILD_DIR}/obfuscated.ll)
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

    # Step 2: Apply obfuscation passes using obfuscator tool
    # Note: We use cmake -E env to add Z3 bin directory to PATH for libz3.dll
    # The obfuscator tool links Pluto passes statically, avoiding ODR violations
    add_custom_command(
        OUTPUT ${OBFUSCATED_LL}
        COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH};${Z3_BIN_DIR}"
            $<TARGET_FILE:obfuscator>
            ${INPUT_LL}
            ${OBFUSCATED_LL}
            --passes="${ARG_PASSES}"
        DEPENDS ${INPUT_LL} obfuscator
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
        COMMAND variable_ir_checker ${OPTIMIZED_BC} ${ARG_EXPECTED_EXIT_CODE}
    )
endfunction()
