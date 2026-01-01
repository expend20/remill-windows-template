# C++ lifting tests (require clang-cl)
# Included from root CMakeLists.txt - do not use add_subdirectory()

add_cpp_lifting_test(
    NAME ret_const
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/ret_const.cpp
    ENTRY test_me
    EXPECTED_EXIT_CODE 4919
)

add_cpp_lifting_test(
    NAME global_var
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/global_var.cpp
    ENTRY test_me
    EXPECTED_EXIT_CODE 4919
)

add_cpp_lifting_test(
    NAME xtea_roundtrip
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/xtea_roundtrip.cpp
    ENTRY test_me
    EXPECTED_EXIT_CODE 4919
)

# NOTE: xtea_noinline test - uses function inlining approach
# See FUNCTION_INLINING.md for details
add_cpp_lifting_test(
    NAME xtea_noinline
    CPP ${CMAKE_SOURCE_DIR}/src/tests/const/xtea_noinline.cpp
    ENTRY test_me
    EXPECTED_EXIT_CODE 4919
)
