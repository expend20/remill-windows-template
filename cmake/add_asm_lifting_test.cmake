# add_asm_lifting_test(
#   NAME <test_name>
#   ASM <path_to_asm>
#   ENTRY <entry_point>  # Optional, defaults to "main"
#   EXPECTED_EXIT_CODE <exit_code>
# )
# Note: Uses the shared 'lifter' target defined in CMakeLists.txt
# Tests are grouped under: build/tests/asm/<asm_basename>/<test_name>/
# Only verifies the optimized IR contains "ret i32 <expected>"
function(add_asm_lifting_test)
    cmake_parse_arguments(ARG "" "NAME;ASM;ENTRY;EXPECTED_EXIT_CODE" "" ${ARGN})

    # Default entry point to "main" if not specified
    if(NOT ARG_ENTRY)
        set(ARG_ENTRY "main")
    endif()

    # Derive group name from ASM filename (without extension)
    get_filename_component(ASM_BASENAME ${ARG_ASM} NAME_WE)

    set(BUILD_DIR ${CMAKE_BINARY_DIR}/tests/asm/${ASM_BASENAME}/${ARG_NAME})
    file(MAKE_DIRECTORY ${BUILD_DIR})

    set(OBJ_FILE ${BUILD_DIR}/shellcode.obj)
    set(EXE_FILE ${BUILD_DIR}/shellcode.exe)
    set(OPTIMIZED_BC ${BUILD_DIR}/test_optimized.bc)

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
