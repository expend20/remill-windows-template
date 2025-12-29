# Pluto obfuscation passes - built as static library
# This eliminates ODR violations by linking directly with the host executable
# instead of loading as a plugin (which embeds a separate copy of LLVM)

set(PLUTO_SOURCES
    BogusControlFlowPass.cpp
    CryptoUtils.cpp
    Flattening.cpp
    GlobalEncryption.cpp
    IndirectCall.cpp
    MBAObfuscation.cpp
    MBAUtils.cpp
    Substitution.cpp
)

add_library(pluto_passes STATIC ${PLUTO_SOURCES})

target_include_directories(pluto_passes PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Z3 is required for MBA obfuscation
find_package(Z3 REQUIRED)
target_include_directories(pluto_passes PRIVATE ${Z3_INCLUDE_DIR})

# Link against LLVM-Wrapper (provides all LLVM components) and Z3
target_link_libraries(pluto_passes PUBLIC
    LLVM-Wrapper
    ${Z3_LIBRARIES}
)

if(WIN32)
    target_link_libraries(pluto_passes PUBLIC ntdll)
endif()
