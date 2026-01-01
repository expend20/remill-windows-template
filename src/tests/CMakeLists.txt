# Test configuration and executables
# This file sets up test tools and includes subdirectory test definitions

# Unified lifter executable for all tests (const and variable modes)
add_executable(lifter ${CMAKE_CURRENT_SOURCE_DIR}/lifter.cpp)
target_link_libraries(lifter PRIVATE lifting_common)
set_target_properties(lifter PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# IR checker tool for verifying optimized IR (supports both strict and config-based modes)
add_executable(variable_ir_checker ${CMAKE_SOURCE_DIR}/src/tools/variable_ir_checker.cpp)
target_include_directories(variable_ir_checker PRIVATE ${CMAKE_PREFIX_PATH}/include)
target_link_libraries(variable_ir_checker PRIVATE LLVM-Wrapper)
set_target_properties(variable_ir_checker PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Pluto obfuscation passes (static library) and obfuscator tool
add_subdirectory(${CMAKE_SOURCE_DIR}/src/obfuscation/pluto ${CMAKE_BINARY_DIR}/obfuscation/pluto)
add_executable(obfuscator ${CMAKE_SOURCE_DIR}/src/obfuscation/obfuscator.cpp)
target_include_directories(obfuscator PRIVATE ${CMAKE_PREFIX_PATH}/include)
target_link_libraries(obfuscator PRIVATE pluto_passes LLVM-Wrapper)
set_target_properties(obfuscator PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Include test modules
include(add_asm_lifting_test)
include(add_cpp_lifting_test)
include(add_variable_test)
include(add_external_call_test)

# Add test subdirectories
add_subdirectory(const)
add_subdirectory(variable)

# Obfuscation tests require opt
if(LLVM_OPT_EXECUTABLE)
    add_subdirectory(obfuscation)
endif()
