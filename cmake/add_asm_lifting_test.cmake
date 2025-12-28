# add_asm_lifting_test(
#   NAME <test_name>
#   ASM <path_to_asm>
#   ENTRY <entry_point>  # Optional, defaults to "main"
#   RUNNER_SRC <path_to_test_main.cpp>
#   EXPECTED_EXIT_CODE <exit_code>
# )
# Note: Uses the shared 'lifter' target defined in CMakeLists.txt
# Tests are grouped by ASM filename: build/tests/<asm_basename>/<test_name>/
function(add_asm_lifting_test)
    cmake_parse_arguments(ARG "" "NAME;ASM;ENTRY;RUNNER_SRC;EXPECTED_EXIT_CODE" "" ${ARGN})

    # Default entry point to "main" if not specified
    if(NOT ARG_ENTRY)
        set(ARG_ENTRY "main")
    endif()

    # Derive group name from ASM filename (without extension)
    get_filename_component(ASM_BASENAME ${ARG_ASM} NAME_WE)

    set(BUILD_DIR ${CMAKE_BINARY_DIR}/tests/${ASM_BASENAME}/${ARG_NAME})
    file(MAKE_DIRECTORY ${BUILD_DIR})

    set(OBJ_FILE ${BUILD_DIR}/shellcode.obj)
    set(EXE_FILE ${BUILD_DIR}/shellcode.exe)
    set(OPTIMIZED_LL ${BUILD_DIR}/test_optimized.ll)
    set(OPTIMIZED_O ${BUILD_DIR}/test_optimized.o)

    # Assemble .asm -> .obj
    add_custom_command(
        OUTPUT ${OBJ_FILE}
        COMMAND ${ML64_EXECUTABLE} /c /nologo /Fo${OBJ_FILE} ${ARG_ASM}
        DEPENDS ${ARG_ASM}
        COMMENT "[${ARG_NAME}] Assembling ${ARG_ASM}..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Link .obj -> .exe
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
