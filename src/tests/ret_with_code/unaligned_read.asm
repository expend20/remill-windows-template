.data
    g_var1 DWORD 0
    g_var2 DWORD 0

.code

main PROC
    ; Test: Write two dwords, read unaligned dword spanning both
    ; g_var1 = 0x13370000, stored as bytes: 00 00 37 13
    ; g_var2 = 0x00000000, stored as bytes: 00 00 00 00
    ; Read at g_var1+2: bytes [37, 13, 00, 00] = 0x00001337 = 4919
    mov dword ptr [g_var1], 13370000h
    mov dword ptr [g_var2], 00000000h
    mov eax, dword ptr [g_var1+2]  ; unaligned read spanning both dwords
    ret
main ENDP

END
