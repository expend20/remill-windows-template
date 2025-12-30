; Tests for basic return value computation
; All tests return 0x1337 (4919)

.code

; Test: Return constant directly
; mov eax, 0x1337; ret
mov_const PROC
    mov eax, 1337h
    ret
mov_const ENDP

; Test: Compute constant using ALU operations
; mov eax, 0x1300; or eax, 0x37; ret
alu_const PROC
    mov eax, 1300h
    or eax, 37h
    ret
alu_const ENDP

END
