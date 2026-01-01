# C++ obfuscated lifting tests (require clang-cl + opt)
# Included from root CMakeLists.txt - do not use add_subdirectory()

add_cpp_obfuscated_test(
    NAME global_var_pluto
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/global_var_pluto.cpp
    ENTRY test_me
    PASSES "pluto-substitution,pluto-substitution,pluto-substitution,pluto-substitution,pluto-substitution"
    EXPECTED_EXIT_CODE 4919
)

add_cpp_obfuscated_test(
    NAME xtea_substitution
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/xtea_substitution.cpp
    ENTRY test_me
    PASSES "pluto-substitution"
    EXPECTED_EXIT_CODE 4919
)

add_cpp_obfuscated_test(
    NAME xtea_flattening
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/xtea_flattening.cpp
    ENTRY test_me
    PASSES "pluto-flattening"
    EXPECTED_EXIT_CODE 4919
)

# DISABLED: bogus-control-flow creates large stack frames requiring __chkstk
# which is not available with custom entry point (no CRT)
# add_cpp_obfuscated_test(
#     NAME xtea_bogus_cfg
#     CPP ${CMAKE_SOURCE_DIR}/src/tests/const/xtea_bogus_cfg.cpp
#     ENTRY test_me
#     PASSES "pluto-bogus-control-flow"
#     EXPECTED_EXIT_CODE 4919
# )

add_cpp_obfuscated_test(
    NAME xtea_global_encryption
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/xtea_global_encryption.cpp
    ENTRY test_me
    PASSES "pluto-global-encryption"
    EXPECTED_EXIT_CODE 4919
)

add_cpp_obfuscated_test(
    NAME xtea_indirect_call
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/xtea_indirect_call.cpp
    ENTRY test_me
    PASSES "pluto-indirect-call"
    EXPECTED_EXIT_CODE 4919
)

add_cpp_obfuscated_test(
    NAME xtea_mba
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/xtea_mba.cpp
    ENTRY test_me
    PASSES "pluto-mba-obfuscation"
    EXPECTED_EXIT_CODE 4919
)

# All Pluto passes combined (except MBA which crashes when combined, and
# bogus-control-flow which creates large stack frames requiring __chkstk)
add_cpp_obfuscated_test(
    NAME xtea_all_pluto
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/xtea_all_pluto.cpp
    ENTRY test_me
    PASSES "module(function(pluto-substitution,pluto-flattening)),pluto-indirect-call,pluto-global-encryption"
    EXPECTED_EXIT_CODE 4919
)
