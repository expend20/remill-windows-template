.code

; Target of indirect jump - returns 0x1337
target_label PROC
    mov eax, 1337h
    ret
target_label ENDP

; Main entry point - uses indirect jump
main PROC
    lea rax, target_label    ; Load address of target into rax
    jmp rax                  ; Indirect jump through register
main ENDP

END
