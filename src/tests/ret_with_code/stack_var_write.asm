.code

main PROC
    ; Test: Write each byte separately to stack, read as dword
    ; Allocate 8 bytes on stack
    sub rsp, 8

    ; Write bytes: 0x37, 0x13, 0x00, 0x00 (little-endian)
    ; RSP+0 = 0x37, RSP+1 = 0x13, RSP+2 = 0x00, RSP+3 = 0x00
    mov byte ptr [rsp], 37h      ; byte 0
    mov byte ptr [rsp+1], 13h    ; byte 1
    mov byte ptr [rsp+2], 00h    ; byte 2
    mov byte ptr [rsp+3], 00h    ; byte 3

    ; Read as dword: 0x00001337 = 4919
    mov eax, dword ptr [rsp]

    ; Clean up stack
    add rsp, 8
    ret
main ENDP

END
