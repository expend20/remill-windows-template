; global_var.asm
; Takes rcx as input, stores to global, reads back, adds 0x1337 (4919), returns in rax
; Tests global variable read/write handling
; Expected: test(rcx) = rcx + 4919

.data
g_value QWORD 0

.code
test_proc PROC
    ; Store input to global variable
    lea r8, g_value
    mov [r8], rcx

    ; Read back from global variable
    mov rax, [r8]

    ; Add constant
    add rax, 1337h
    ret
test_proc ENDP
END
