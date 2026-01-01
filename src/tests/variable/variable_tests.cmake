# Variable input tests (require llc)
# Included from root CMakeLists.txt - do not use add_subdirectory()

add_variable_test(
    NAME variable_add_const
    ASM ${CMAKE_SOURCE_DIR}/src/tests/variable/add_const.asm
    CONFIG ${CMAKE_SOURCE_DIR}/src/tests/variable/add_const.config.json
    ENTRY test_proc
    TESTS "0:4919|100:5019|1000:5919"
)

# Global variable tests - lifted mode (uses mutable globals)
add_variable_test(
    NAME variable_global_var
    ASM ${CMAKE_SOURCE_DIR}/src/tests/variable/global_var.asm
    CONFIG ${CMAKE_SOURCE_DIR}/src/tests/variable/global_var.config.json
    ENTRY test_proc
    TESTS "0:4919|100:5019|1000:5919"
)

# Global variable tests - original_va mode (uses inttoptr)
# Note: No runtime tests - inttoptr to original VAs can't run on host
add_variable_test(
    NAME variable_global_var_original_va
    ASM ${CMAKE_SOURCE_DIR}/src/tests/variable/global_var.asm
    CONFIG ${CMAKE_SOURCE_DIR}/src/tests/variable/global_var_original_va.config.json
    ENTRY test_proc
)
