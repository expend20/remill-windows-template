# CMake script to check exit code of an executable
# Usage: cmake -DTEST_EXECUTABLE=<path> -DEXPECTED_EXIT_CODE=<code> -P check_exit_code.cmake

if(NOT DEFINED TEST_EXECUTABLE)
    message(FATAL_ERROR "TEST_EXECUTABLE not defined")
endif()

if(NOT DEFINED EXPECTED_EXIT_CODE)
    message(FATAL_ERROR "EXPECTED_EXIT_CODE not defined")
endif()

execute_process(
    COMMAND "${TEST_EXECUTABLE}"
    RESULT_VARIABLE actual_exit_code
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error_output
)

if(output)
    message(STATUS "Output: ${output}")
endif()

if(error_output)
    message(STATUS "Errors: ${error_output}")
endif()

message(STATUS "Expected exit code: ${EXPECTED_EXIT_CODE} (0x${EXPECTED_EXIT_CODE})")
message(STATUS "Actual exit code: ${actual_exit_code}")

# Convert expected to hex for display
math(EXPR expected_hex "${EXPECTED_EXIT_CODE}" OUTPUT_FORMAT HEXADECIMAL)
message(STATUS "Expected (hex): ${expected_hex}")

if(NOT "${actual_exit_code}" STREQUAL "${EXPECTED_EXIT_CODE}")
    message(FATAL_ERROR "Exit code mismatch! Expected ${EXPECTED_EXIT_CODE}, got ${actual_exit_code}")
endif()

message(STATUS "SUCCESS: Exit code matches expected value ${EXPECTED_EXIT_CODE}")
