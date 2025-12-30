; Tests for indirect jump handling
; All tests return 0x1337 (4919)

.data
; Global variable holding a jump target address (simulates jump table entry)
jump_target dq target_for_table

; Jump table with multiple entries for indexed access test
jump_table_indexed dq target_case0
                   dq target_case1
                   dq target_case2  ; index 2 -> returns 0x1337

.code

; Helper target with nop prefix (for computed address test)
; The nop is at target_with_nop, actual code starts at target_with_nop+1
target_with_nop PROC
    nop                      ; 1 byte - will be skipped by inc rax
    mov eax, 1337h
    ret
target_with_nop ENDP

; Helper target for push_ret test
target_for_push PROC
    mov eax, 1337h
    ret
target_for_push ENDP

; Helper target for jump table test
target_for_table PROC
    mov eax, 1337h
    ret
target_for_table ENDP

; Helper targets for indexed jump table test
target_case0 PROC
    mov eax, 0
    ret
target_case0 ENDP

target_case1 PROC
    mov eax, 1
    ret
target_case1 ENDP

target_case2 PROC
    mov eax, 1337h           ; This is the target we'll jump to
    ret
target_case2 ENDP

; Test: Indirect jump through register with computed address
; Loads address, modifies it, then jumps
register_jmp PROC
    lea rax, target_with_nop ; Load address of target into rax
    inc rax                  ; Skip the nop - now points to mov instruction
    jmp rax                  ; Indirect jump through register
register_jmp ENDP

; Test: Push address and ret (indirect jump via stack)
; Simulates call-like behavior using push/ret
push_ret PROC
    lea rax, target_for_push
    push rax
    ret
push_ret ENDP

; Test: Jump through global variable (jump table pattern)
; Reads target address from global variable and jumps to it
jump_table PROC
    lea rax, jump_target     ; Get address of global variable
    mov rax, [rax]           ; Load target address from global
    jmp rax                  ; Indirect jump to target
jump_table ENDP

; Test: Jump table with index using [base + index*scale] addressing
; Uses indexed addressing: mov rax, [base + rcx*8]
jump_table_index PROC
    mov ecx, 2               ; Index = 2 (selects target_case2)
    lea rax, jump_table_indexed
    mov rax, [rax + rcx*8]   ; Load target from table[index]
    jmp rax                  ; Indirect jump to selected target
jump_table_index ENDP

; Chain of 10 indirect jumps - each loads next target address and jumps
ind_jmp10 PROC
    mov eax, 1337h           ; Final target sets return value
    ret
ind_jmp10 ENDP

ind_jmp9 PROC
    lea rax, ind_jmp10
    jmp rax
ind_jmp9 ENDP

ind_jmp8 PROC
    lea rax, ind_jmp9
    jmp rax
ind_jmp8 ENDP

ind_jmp7 PROC
    lea rax, ind_jmp8
    jmp rax
ind_jmp7 ENDP

ind_jmp6 PROC
    lea rax, ind_jmp7
    jmp rax
ind_jmp6 ENDP

ind_jmp5 PROC
    lea rax, ind_jmp6
    jmp rax
ind_jmp5 ENDP

ind_jmp4 PROC
    lea rax, ind_jmp5
    jmp rax
ind_jmp4 ENDP

ind_jmp3 PROC
    lea rax, ind_jmp4
    jmp rax
ind_jmp3 ENDP

ind_jmp2 PROC
    lea rax, ind_jmp3
    jmp rax
ind_jmp2 ENDP

ind_jmp1 PROC
    lea rax, ind_jmp2
    jmp rax
ind_jmp1 ENDP

; Test: Chain of 10 indirect jumps
; Entry -> ind_jmp1 -> ind_jmp2 -> ... -> ind_jmp10 -> returns 0x1337
indirect_jmp_chain PROC
    lea rax, ind_jmp1
    jmp rax
indirect_jmp_chain ENDP

; Helper function for indirect call test - returns 0x1337
call_target PROC
    mov eax, 1337h
    ret
call_target ENDP

; Test: Indirect call through register
; Loads function address into register and calls it
indirect_call_register PROC
    sub rsp, 28h             ; Shadow space for Windows x64 calling convention
    lea rax, call_target     ; Load address of target function
    call rax                 ; Indirect call through register
    add rsp, 28h
    ret
indirect_call_register ENDP

; Test: Indirect call through memory (global pointer)
; Reads function address from global and calls it
.data
call_target_ptr dq call_target

; Function pointer table for indexed call test
; Layout: [dummy0, dummy1, call_target, dummy3] with 16-byte offset before table
call_table_padding dq 0, 0           ; 16 bytes of padding (offset)
call_table         dq call_target_bad1  ; index 0
                   dq call_target_bad2  ; index 1
                   dq call_target       ; index 2 -> returns 0x1337
                   dq call_target_bad3  ; index 3

.code
indirect_call_memory PROC
    sub rsp, 28h
    lea rax, call_target_ptr ; Get address of global pointer
    mov rax, [rax]           ; Load function address from global
    call rax                 ; Indirect call through loaded address
    add rsp, 28h
    ret
indirect_call_memory ENDP

; Helper targets for indexed call test (wrong values to verify correct index)
call_target_bad1 PROC
    mov eax, 1111h
    ret
call_target_bad1 ENDP

call_target_bad2 PROC
    mov eax, 2222h
    ret
call_target_bad2 ENDP

call_target_bad3 PROC
    mov eax, 3333h
    ret
call_target_bad3 ENDP

; Test: Indirect call with complex addressing mode
; Uses: call qword ptr [base + index*8 + offset]
; This pattern is common for vtable calls and function pointer arrays
indirect_call_indexed PROC
    sub rsp, 28h
    lea rax, call_table_padding  ; Base: start of padded area
    mov rcx, 4                   ; Index: 4 (skips 2 padding + 2 table entries)
                                 ; 4*8 = 32 bytes = 16 (padding) + 16 (2 entries)
                                 ; So index 4 with base at padding = table[2] = call_target
    call qword ptr [rax + rcx*8] ; call [base + index*8]
    add rsp, 28h
    ret
indirect_call_indexed ENDP

; Test: Indirect call with base + index*scale + displacement
; Uses explicit offset in the addressing mode
indirect_call_indexed_offset PROC
    sub rsp, 28h
    lea rax, call_table      ; Base: start of call_table (after padding)
    mov rcx, 2               ; Index: 2
    call qword ptr [rax + rcx*8 + 0]  ; call [base + index*8 + 0] -> table[2]
    add rsp, 28h
    ret
indirect_call_indexed_offset ENDP

END
