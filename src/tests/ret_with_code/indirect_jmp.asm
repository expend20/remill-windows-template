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

END
