.data
    g_var DWORD 0

.code

main PROC
    ; Test: Write each byte separately, read as dword
    ; Write bytes: 0x37, 0x13, 0x00, 0x00 (little-endian)
    ; Read as dword: 0x00001337 = 4919
    mov byte ptr [g_var], 37h      ; byte 0
    mov byte ptr [g_var+1], 13h    ; byte 1
    mov byte ptr [g_var+2], 00h    ; byte 2
    mov byte ptr [g_var+3], 00h    ; byte 3
    mov eax, dword ptr [g_var]     ; read full dword
    ret
main ENDP

END
