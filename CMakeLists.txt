cmake_minimum_required(VERSION 3.15)
project(HelloWorld LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Variables
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(GFLAGS_USE_TARGET_NAMESPACE ON)

# Packages
find_package(LLVM-Wrapper REQUIRED)
find_package(remill REQUIRED)

add_executable(hello_world src/helloworld/main.cpp)

if(NOT TARGET LLVM-Wrapper)
    message(FATAL_ERROR "Target \"LLVM-Wrapper\" referenced by \"hello_world\" does not exist!")
endif()

if(NOT TARGET remill)
    message(FATAL_ERROR "Target \"remill\" referenced by \"hello_world\" does not exist!")
endif()

target_link_libraries(hello_world PRIVATE
    LLVM-Wrapper
    remill
)

# Find clang for compiling LLVM IR
find_program(CLANG_EXECUTABLE clang HINTS "${LLVM_TOOLS_BINARY_DIR}")
if(NOT CLANG_EXECUTABLE)
    message(STATUS "clang not found, test_lifted target will not be available")
else()
    message(STATUS "Found clang: ${CLANG_EXECUTABLE}")

    # Custom target to generate lifted IR
    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/lifted.bc ${CMAKE_BINARY_DIR}/lifted.ll
        COMMAND hello_world
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        DEPENDS hello_world
        COMMENT "Generating lifted IR..."
    )

    # Custom target to compile runtime.ll
    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/runtime.bc
        COMMAND ${CLANG_EXECUTABLE} -c -emit-llvm -O2
            ${CMAKE_SOURCE_DIR}/src/helloworld/runtime.ll
            -o ${CMAKE_BINARY_DIR}/runtime.bc
        DEPENDS ${CMAKE_SOURCE_DIR}/src/helloworld/runtime.ll
        COMMENT "Compiling runtime.ll..."
    )

    # Test executable that links lifted code with test harness
    add_executable(test_lifted
        src/helloworld/test_harness.cpp
    )
    target_include_directories(test_lifted PRIVATE
        ${CMAKE_PREFIX_PATH}/include
    )
    target_compile_definitions(test_lifted PRIVATE
        ${LLVM_DEFINITIONS}
    )

    # Find llvm-link
    find_program(LLVM_LINK_EXECUTABLE llvm-link HINTS "${LLVM_TOOLS_BINARY_DIR}")

    # Link bitcode files together
    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/combined.bc
        COMMAND ${LLVM_LINK_EXECUTABLE}
            ${CMAKE_BINARY_DIR}/lifted.bc
            ${CMAKE_BINARY_DIR}/runtime.bc
            -o ${CMAKE_BINARY_DIR}/combined.bc
        DEPENDS ${CMAKE_BINARY_DIR}/lifted.bc ${CMAKE_BINARY_DIR}/runtime.bc
        COMMENT "Linking bitcode files..."
    )

    # Compile combined bitcode to object file
    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/lifted_combined.o
        COMMAND ${CLANG_EXECUTABLE} -c -O2
            ${CMAKE_BINARY_DIR}/combined.bc
            -o ${CMAKE_BINARY_DIR}/lifted_combined.o
        DEPENDS ${CMAKE_BINARY_DIR}/combined.bc
        COMMENT "Compiling lifted code to object file..."
    )

    add_custom_target(lifted_object DEPENDS ${CMAKE_BINARY_DIR}/lifted_combined.o)
    add_dependencies(test_lifted lifted_object)

    target_link_libraries(test_lifted PRIVATE
        ${CMAKE_BINARY_DIR}/lifted_combined.o
    )

    # Enable testing
    enable_testing()
    add_test(NAME test_lifted_execution COMMAND test_lifted)
endif()
