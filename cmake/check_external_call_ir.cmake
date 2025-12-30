# Check external call test IR
# Verifies:
# 1. The function returns the expected value (e.g., 4919)
# 2. External calls are preserved (e.g., @puts is called)

if(NOT DEFINED TEST_BC)
    message(FATAL_ERROR "TEST_BC not defined")
endif()

if(NOT DEFINED EXPECTED_EXIT_CODE)
    message(FATAL_ERROR "EXPECTED_EXIT_CODE not defined")
endif()

# Read the .ll file (same name as .bc but with .ll extension)
string(REGEX REPLACE "\\.bc$" ".ll" TEST_LL "${TEST_BC}")

if(NOT EXISTS "${TEST_LL}")
    message(FATAL_ERROR "Test IR file not found: ${TEST_LL}")
endif()

file(READ "${TEST_LL}" IR_CONTENT)

# Check 1: Verify external call is present (call to @puts or similar)
string(FIND "${IR_CONTENT}" "call" CALL_POS)
if(CALL_POS EQUAL -1)
    message(FATAL_ERROR "No external call found in optimized IR.\nExpected a call instruction to be preserved.\nIR content:\n${IR_CONTENT}")
endif()

# Check 2: Verify return value
string(FIND "${IR_CONTENT}" "ret i32 ${EXPECTED_EXIT_CODE}" RET_POS)
if(RET_POS EQUAL -1)
    message(FATAL_ERROR "Expected return value 'ret i32 ${EXPECTED_EXIT_CODE}' not found.\nIR content:\n${IR_CONTENT}")
endif()

message(STATUS "SUCCESS: External call preserved and returns ${EXPECTED_EXIT_CODE}")
