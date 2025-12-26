.code

; Helper function that returns 0x37 in eax
get_value PROC
    mov eax, 37h
    ret
get_value ENDP

; Main entry point
main PROC
    call get_value    ; eax = 0x37
    or eax, 1300h     ; eax = 0x37 | 0x1300 = 0x1337 = 4919
    ret
main ENDP

END
