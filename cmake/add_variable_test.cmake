# add_variable_test(
#   NAME <test_name>
#   ASM <path_to_asm>
#   CONFIG <path_to_config.json>
#   ENTRY <entry_point>  # Optional, defaults to "main"
#   TESTS <test_cases>   # List of "input:expected" pairs, e.g., "0:4919|100:5019"
# )
# Note: Uses the shared 'variable_lifter' target defined in CMakeLists.txt
# Tests are grouped under: build/tests/variable/<test_name>/
function(add_variable_test)
    cmake_parse_arguments(ARG "" "NAME;ASM;CONFIG;ENTRY;TESTS" "" ${ARGN})

    # Default entry point to "main" if not specified
    if(NOT ARG_ENTRY)
        set(ARG_ENTRY "main")
    endif()

    # CONFIG is required
    if(NOT ARG_CONFIG)
        message(FATAL_ERROR "add_variable_test: CONFIG argument is required")
    endif()

    set(BUILD_DIR ${CMAKE_BINARY_DIR}/tests/variable/${ARG_NAME})
    file(MAKE_DIRECTORY ${BUILD_DIR})

    set(OBJ_FILE ${BUILD_DIR}/shellcode.obj)
    set(EXE_FILE ${BUILD_DIR}/shellcode.exe)
    set(OPTIMIZED_BC ${BUILD_DIR}/test_optimized.bc)
    set(RUNNER_BC ${BUILD_DIR}/test_runner.bc)
    set(RUNNER_OBJ ${BUILD_DIR}/test_runner.obj)
    set(RUNNER_EXE ${BUILD_DIR}/test_runner.exe)

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

    # Lift .exe -> .ll/.bc with variable support
    add_custom_command(
        OUTPUT
            ${BUILD_DIR}/test_optimized.ll
            ${OPTIMIZED_BC}
            ${BUILD_DIR}/test_runner.ll
            ${RUNNER_BC}
            ${BUILD_DIR}/lifted.ll
            ${BUILD_DIR}/lifted.bc
        COMMAND variable_lifter ${EXE_FILE} ${ARG_CONFIG}
        DEPENDS variable_lifter ${EXE_FILE} ${ARG_CONFIG}
        COMMENT "[${ARG_NAME}] Lifting with variable support..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Compile test_runner.bc -> test_runner.obj using LLC
    add_custom_command(
        OUTPUT ${RUNNER_OBJ}
        COMMAND ${LLC_EXECUTABLE} -filetype=obj -o ${RUNNER_OBJ} ${RUNNER_BC}
        DEPENDS ${RUNNER_BC}
        COMMENT "[${ARG_NAME}] Compiling test_runner.bc to object file..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Link test_runner.obj -> test_runner.exe
    add_custom_command(
        OUTPUT ${RUNNER_EXE}
        COMMAND ${MSVC_LINK_EXECUTABLE} /nologo /SUBSYSTEM:CONSOLE
            /OUT:${RUNNER_EXE} ${RUNNER_OBJ}
            msvcrt.lib kernel32.lib legacy_stdio_definitions.lib
        DEPENDS ${RUNNER_OBJ}
        COMMENT "[${ARG_NAME}] Linking test_runner.exe..."
        WORKING_DIRECTORY ${BUILD_DIR}
    )

    # Build target to ensure everything is built
    add_custom_target(${ARG_NAME}_build ALL DEPENDS ${RUNNER_EXE})

    # Test: run tests from TESTS argument (format: "input:expected|input:expected|...")
    # Uses pipe as separator to avoid CMake list escaping issues
    if(ARG_TESTS)
        add_test(
            NAME ${ARG_NAME}_runtime
            COMMAND ${CMAKE_COMMAND}
                -DTEST_RUNNER=${RUNNER_EXE}
                "-DTEST_CASES=${ARG_TESTS}"
                -P ${CMAKE_SOURCE_DIR}/cmake/run_variable_tests.cmake
        )
    endif()
endfunction()
