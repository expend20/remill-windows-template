# ASM constant-folding tests
# Included from root CMakeLists.txt - do not use add_subdirectory()

# =============================================================================
# ASM Tests - Basic return values (basic_return.asm)
# =============================================================================
add_asm_lifting_test(
    NAME basic_mov_const
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/basic_return.asm
    ENTRY mov_const
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME basic_alu_const
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/basic_return.asm
    ENTRY alu_const
    EXPECTED_EXIT_CODE 4919
)

# =============================================================================
# ASM Tests - Global memory access (global_memory.asm)
# =============================================================================
add_asm_lifting_test(
    NAME global_bytewise_write
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY bytewise_write
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_unaligned_read
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY unaligned_read
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_wordwise_write
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY wordwise_write
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_qword_access
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY qword_access
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_dword_to_bytes
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY dword_to_bytes
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_zero_extend_byte
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY zero_extend_byte
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_zero_extend_word
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY zero_extend_word
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_sign_extend_byte
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY sign_extend_byte
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_read_modify_write
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY read_modify_write
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_read_initialized
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY read_initialized
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_array_const_index
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY array_const_index
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_array_reg_index
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY array_reg_index
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_unaligned_qword
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY unaligned_qword
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_multi_global
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY multi_global
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME global_overlapping_write
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/global_memory.asm
    ENTRY overlapping_write
    EXPECTED_EXIT_CODE 4919
)

# =============================================================================
# ASM Tests - Stack memory access (stack_memory.asm)
# =============================================================================
add_asm_lifting_test(
    NAME stack_bytewise_write
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/stack_memory.asm
    ENTRY bytewise_write
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME stack_unaligned_read
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/stack_memory.asm
    ENTRY unaligned_read
    EXPECTED_EXIT_CODE 4919
)

# =============================================================================
# ASM Tests - Cross-section memory (rdata_to_stack.asm)
# =============================================================================
add_asm_lifting_test(
    NAME rdata_to_stack
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/rdata_to_stack.asm
    ENTRY rdata_to_stack
    EXPECTED_EXIT_CODE 4919
)

# =============================================================================
# ASM Tests - Loop handling (loops.asm)
# =============================================================================
add_asm_lifting_test(
    NAME loop_sum
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/loops.asm
    ENTRY sum_loop
    EXPECTED_EXIT_CODE 4919
)

# =============================================================================
# ASM Tests - Direct branches (direct_branch.asm)
# =============================================================================
add_asm_lifting_test(
    NAME call_direct
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/direct_branch.asm
    ENTRY call_helper
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME jmp_direct
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/direct_branch.asm
    ENTRY direct_jmp
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME jmp_chain
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/direct_branch.asm
    ENTRY jmp_chain
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME call_chain
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/direct_branch.asm
    ENTRY call_chain
    EXPECTED_EXIT_CODE 4919
)

# =============================================================================
# ASM Tests - Indirect branches (indirect_branch.asm)
# =============================================================================
add_asm_lifting_test(
    NAME indirect_register_jmp
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/indirect_branch.asm
    ENTRY register_jmp
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME indirect_push_ret
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/indirect_branch.asm
    ENTRY push_ret
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME indirect_jump_table
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/indirect_branch.asm
    ENTRY jump_table
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME indirect_jump_table_index
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/indirect_branch.asm
    ENTRY jump_table_index
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME indirect_jmp_chain
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/indirect_branch.asm
    ENTRY indirect_jmp_chain
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME indirect_call_register
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/indirect_branch.asm
    ENTRY indirect_call_register
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME indirect_call_memory
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/indirect_branch.asm
    ENTRY indirect_call_memory
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME indirect_call_indexed
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/indirect_branch.asm
    ENTRY indirect_call_indexed
    EXPECTED_EXIT_CODE 4919
)

add_asm_lifting_test(
    NAME indirect_call_indexed_offset
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/indirect_branch.asm
    ENTRY indirect_call_indexed_offset
    EXPECTED_EXIT_CODE 4919
)

# =============================================================================
# ASM Tests - Non-returning calls (non_returning_call.asm)
# Tests for obfuscation patterns where CALL doesn't return normally
# =============================================================================
add_asm_lifting_test(
    NAME non_ret_call_retf
    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/non_returning_call.asm
    ENTRY non_ret_call_retf
    EXPECTED_EXIT_CODE 4919
)

# Disabled - uses different pattern (modify ret addr + RET), not yet supported
# add_asm_lifting_test(
#     NAME non_ret_call_modify_ret
#     ASM ${CMAKE_SOURCE_DIR}/src/tests/const/non_returning_call.asm
#     ENTRY non_ret_call_modify_ret
#     EXPECTED_EXIT_CODE 4919
# )

#add_asm_lifting_test(
#    NAME non_ret_tail_jump
#    ASM ${CMAKE_SOURCE_DIR}/src/tests/const/non_returning_call.asm
#    ENTRY non_ret_tail_jump
#    EXPECTED_EXIT_CODE 4919
#)
