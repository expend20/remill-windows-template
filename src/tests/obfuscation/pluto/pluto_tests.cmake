# Pluto obfuscation pass tests
# Included from root CMakeLists.txt - do not use add_subdirectory()
# These tests verify that Pluto passes preserve program semantics without lifting

add_pluto_test(
    NAME pluto_substitution
    CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
    PASSES "pluto-substitution"
    EXPECTED_EXIT_CODE 4919
)

add_pluto_test(
    NAME pluto_flattening
    CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
    PASSES "pluto-flattening"
    EXPECTED_EXIT_CODE 4919
)

add_pluto_test(
    NAME pluto_bogus_cfg
    CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
    PASSES "pluto-bogus-control-flow"
    EXPECTED_EXIT_CODE 4919
)

add_pluto_test(
    NAME pluto_global_encryption
    CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
    PASSES "pluto-global-encryption"
    EXPECTED_EXIT_CODE 4919
)

add_pluto_test(
    NAME pluto_indirect_call
    CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
    PASSES "pluto-indirect-call"
    EXPECTED_EXIT_CODE 4919
)

add_pluto_test(
    NAME pluto_mba
    CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
    PASSES "pluto-mba-obfuscation"
    EXPECTED_EXIT_CODE 4919
)

add_pluto_test(
    NAME pluto_all
    CPP ${CMAKE_SOURCE_DIR}/src/tests/obfuscation/pluto/xtea_roundtrip.cpp
    PASSES "module(function(pluto-substitution,pluto-flattening,pluto-bogus-control-flow,pluto-mba-obfuscation)),pluto-indirect-call,pluto-global-encryption"
    EXPECTED_EXIT_CODE 4919
)
