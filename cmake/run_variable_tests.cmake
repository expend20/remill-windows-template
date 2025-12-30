# run_variable_tests.cmake
# Runs tests for variable lifting
# Usage: cmake -DTEST_RUNNER=<exe> -DTEST_CASES=<input:expected,input:expected,...> -P run_variable_tests.cmake

if(NOT TEST_RUNNER)
    message(FATAL_ERROR "TEST_RUNNER not set")
endif()

if(NOT EXISTS "${TEST_RUNNER}")
    message(FATAL_ERROR "Test runner not found: ${TEST_RUNNER}")
endif()

if(NOT TEST_CASES)
    message(FATAL_ERROR "TEST_CASES not set (format: input:expected,input:expected,...)")
endif()

# Parse TEST_CASES (pipe-separated list of input:expected pairs)
string(REPLACE "|" ";" test_list "${TEST_CASES}")

set(test_index 0)
set(all_passed TRUE)

foreach(test_case IN LISTS test_list)
    # Split by colon
    string(REPLACE ":" ";" parts "${test_case}")
    list(GET parts 0 input)
    list(GET parts 1 expected)

    message(STATUS "Test ${test_index}: input=${input}, expected=${expected}")

    execute_process(
        COMMAND "${TEST_RUNNER}" ${input}
        RESULT_VARIABLE exit_code
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error_output
        TIMEOUT 10
    )

    if(NOT exit_code EQUAL expected)
        message(STATUS "  FAILED: got ${exit_code}, expected ${expected}")
        set(all_passed FALSE)
    else()
        message(STATUS "  PASSED")
    endif()

    math(EXPR test_index "${test_index} + 1")
endforeach()

if(test_index EQUAL 0)
    message(FATAL_ERROR "No tests found")
endif()

if(NOT all_passed)
    message(FATAL_ERROR "Some tests failed")
endif()

message(STATUS "All ${test_index} tests passed")
