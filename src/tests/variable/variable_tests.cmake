# Variable input tests (require llc)
# Included from root CMakeLists.txt - do not use add_subdirectory()

add_variable_test(
    NAME variable_add_const
    ASM ${CMAKE_SOURCE_DIR}/src/tests/variable/add_const.asm
    CONFIG ${CMAKE_SOURCE_DIR}/src/tests/variable/add_const.config.json
    ENTRY test_proc
    TESTS "0:4919|100:5019|1000:5919"
)
