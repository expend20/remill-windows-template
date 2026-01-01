# External call tests (functions that call external APIs like puts)
# Included from root CMakeLists.txt - do not use add_subdirectory()

add_external_call_test(
    NAME external_puts
    CPP ${CMAKE_SOURCE_DIR}/src/tests/variable/puts_global_const.cpp
    CONFIG ${CMAKE_SOURCE_DIR}/src/tests/variable/puts_global_const.config.json
    ENTRY test_proc
    EXPECTED_EXIT_CODE 4919
    WRAPPER ${CMAKE_SOURCE_DIR}/src/tests/variable/main_wrapper.cpp
)

add_external_call_test(
    NAME external_puts_stack
    CPP ${CMAKE_SOURCE_DIR}/src/tests/variable/puts_stack.cpp
    CONFIG ${CMAKE_SOURCE_DIR}/src/tests/variable/puts_stack.config.json
    ENTRY test_proc
    EXPECTED_EXIT_CODE 4919
    WRAPPER ${CMAKE_SOURCE_DIR}/src/tests/variable/main_wrapper.cpp
)

add_external_call_test(
    NAME external_puts_xorstr
    CPP ${CMAKE_SOURCE_DIR}/src/tests/variable/puts_xorstr.cpp
    CONFIG ${CMAKE_SOURCE_DIR}/src/tests/variable/puts_xorstr.config.json
    ENTRY test_proc
    EXPECTED_EXIT_CODE 4919
    WRAPPER ${CMAKE_SOURCE_DIR}/src/tests/variable/main_wrapper.cpp
)
