.data
; Global variable holding a jump target address (simulates jump table entry)
jump_target dq target_test3

.code

; Target of indirect jump - returns 0x1337
; The nop is at target_label, actual code starts at target_label+1
target_label PROC
    nop                      ; 1 byte - will be skipped by inc rax
    mov eax, 1337h
    ret
target_label ENDP

; Main entry point - uses indirect jump with modification
main PROC
    lea rax, target_label    ; Load address of target into rax
    inc rax                  ; Skip the nop - now points to mov instruction
    jmp rax                  ; Indirect jump through register
main ENDP

target_test2 PROC
    mov eax, 1337h
    ret
target_test2 ENDP

push_ret PROC
    lea rax, target_test2
    push rax
    ret
push_ret ENDP

; Target for jump table test
target_test3 PROC
    mov eax, 1337h
    ret
target_test3 ENDP

; Jump table test - reads target address from global variable
jump_table_test PROC
    lea rax, jump_target     ; Get address of global variable
    mov rax, [rax]           ; Load target address from global
    jmp rax                  ; Indirect jump to target
jump_table_test ENDP

END
