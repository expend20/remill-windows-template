; Tests for loop handling
; All tests return 0x1337 (4919)

.code

; Test: Sum loop with conditional jump
; Computes sum(1..37) = 703 = 0x2BF
; Then adds 0x1078 to get 0x1337 (4919)
sum_loop PROC
    xor eax, eax        ; eax = 0 (accumulator)
    mov ecx, 37         ; ecx = loop counter

loop_start:
    add eax, ecx        ; eax += ecx
    dec ecx             ; ecx--
    jnz loop_start      ; jump if ecx != 0

    ; At this point eax = 1+2+...+37 = 703 = 0x2BF
    add eax, 1078h      ; eax += 0x1078 -> 0x2BF + 0x1078 = 0x1337
    ret
sum_loop ENDP

END
