.code

; Simple loop test: sum 1 to 37 (37*38/2 = 703 = 0x2BF)
; Then add 0x1078 to get 0x1337 (4919)
main PROC
    xor eax, eax        ; eax = 0 (accumulator)
    mov ecx, 37         ; ecx = loop counter

loop_start:
    add eax, ecx        ; eax += ecx
    dec ecx             ; ecx--
    jnz loop_start      ; jump if ecx != 0 (conditional jump)

    ; At this point eax = 1+2+...+37 = 703 = 0x2BF
    add eax, 1078h      ; eax += 0x1078 -> 0x2BF + 0x1078 = 0x1337
    ret
main ENDP

END
