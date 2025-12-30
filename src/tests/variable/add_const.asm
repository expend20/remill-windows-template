; add_const.asm
; Takes rcx as input, adds 0x1337 (4919), returns in rax
; Expected: test(rcx) = rcx + 4919

.code
test_proc PROC
    mov rax, rcx
    add rax, 1337h
    ret
test_proc ENDP
END
