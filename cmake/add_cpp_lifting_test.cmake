# add_cpp_lifting_test(
#   NAME <test_name>
#   CPP <path_to_cpp>
#   ENTRY <function_name>
#   RUNNER_SRC <path_to_test_main.cpp>
#   EXPECTED_EXIT_CODE <exit_code>
# )
# Note: Uses the shared 'lifter' target defined in CMakeLists.txt
function(add_cpp_lifting_test)
    cmake_parse_arguments(ARG "" "NAME;CPP;ENTRY;RUNNER_SRC;EXPECTED_EXIT_CODE" "" ${ARGN})

    set(BUILD_DIR ${CMAKE_BINARY_DIR}/tests/${ARG_NAME})
    file(MAKE_DIRECTORY ${BUILD_DIR})

    set(INPUT_LL ${BUILD_DIR}/input.ll)
    set(OBJ_FILE ${BUILD_DIR}/shellcode.obj)
    set(EXE_FILE ${BUILD_DIR}/shellcode.exe)
    set(OPTIMIZED_LL ${BUILD_DIR}/test_optimized.ll)
    set(OPTIMIZED_O ${BUILD_DIR}/test_optimized.o)

    # Generate .cpp -> .ll (unoptimized LLVM IR for inspection)
    add_custom_command(
        OUTPUT ${INPUT_LL}
        COMMAND ${CLANG_EXECUTABLE} -S -emit-llvm -O0 -o ${INPUT_LL} ${ARG_CPP}
        DEPENDS ${ARG_CPP}
        COMMENT "[${ARG_NAME}] Generating input.ll (unoptimized)..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Compile .cpp -> .obj using clang-cl
    add_custom_command(
        OUTPUT ${OBJ_FILE}
        COMMAND ${CLANG_CL_EXECUTABLE} /c /O2 /nologo /Fo${OBJ_FILE} ${ARG_CPP}
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
            ${OPTIMIZED_LL}
            ${BUILD_DIR}/test_optimized.bc
            ${BUILD_DIR}/lifted.ll
            ${BUILD_DIR}/lifted.bc
        COMMAND lifter ${EXE_FILE}
        DEPENDS lifter ${EXE_FILE}
        COMMENT "[${ARG_NAME}] Lifting..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Compile .ll -> .o
    add_custom_command(
        OUTPUT ${OPTIMIZED_O}
        COMMAND ${CLANG_EXECUTABLE} -c -O2 ${OPTIMIZED_LL} -o ${OPTIMIZED_O}
        DEPENDS ${OPTIMIZED_LL}
        COMMENT "[${ARG_NAME}] Compiling lifted IR..."
    )

    add_custom_target(${ARG_NAME}_object DEPENDS ${OPTIMIZED_O})

    # Runner executable
    add_executable(${ARG_NAME}_runner ${ARG_RUNNER_SRC})
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
