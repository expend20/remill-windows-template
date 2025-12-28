; Tests for direct branches (call, jmp)
; All tests return 0x1337 (4919)

.code

; Helper function that returns 0x37 in eax
get_value PROC
    mov eax, 37h
    ret
get_value ENDP

; Test: Call helper function and combine result
; Calls get_value() which returns 0x37
; Then OR with 0x1300 to get 0x1337 (4919)
call_helper PROC
    call get_value    ; eax = 0x37
    or eax, 1300h     ; eax = 0x37 | 0x1300 = 0x1337 = 4919
    ret
call_helper ENDP

; Test: Direct unconditional jump
; Uses jmp to skip over dead code
direct_jmp PROC
    mov eax, 1337h
    jmp done
    mov eax, 0        ; dead code - should be skipped
done:
    ret
direct_jmp ENDP

; Test: Chain of 10 jumps
; Each jump leads to the next, finally returning 0x1337
jmp_chain PROC
    mov eax, 1337h
    jmp jmp1
jmp1:
    jmp jmp2
jmp2:
    jmp jmp3
jmp3:
    jmp jmp4
jmp4:
    jmp jmp5
jmp5:
    jmp jmp6
jmp6:
    jmp jmp7
jmp7:
    jmp jmp8
jmp8:
    jmp jmp9
jmp9:
    jmp jmp10
jmp10:
    ret
jmp_chain ENDP

; Helper functions for call chain (each calls the next)
call_f10 PROC
    mov eax, 1337h    ; final function sets the return value
    ret
call_f10 ENDP

call_f9 PROC
    call call_f10
    ret
call_f9 ENDP

call_f8 PROC
    call call_f9
    ret
call_f8 ENDP

call_f7 PROC
    call call_f8
    ret
call_f7 ENDP

call_f6 PROC
    call call_f7
    ret
call_f6 ENDP

call_f5 PROC
    call call_f6
    ret
call_f5 ENDP

call_f4 PROC
    call call_f5
    ret
call_f4 ENDP

call_f3 PROC
    call call_f4
    ret
call_f3 ENDP

call_f2 PROC
    call call_f3
    ret
call_f2 ENDP

call_f1 PROC
    call call_f2
    ret
call_f1 ENDP

; Test: Chain of 10 calls
; Entry point calls f1 -> f2 -> ... -> f10 -> returns 0x1337
call_chain PROC
    call call_f1
    ret
call_chain ENDP

END
