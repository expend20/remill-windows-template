.code

main PROC
    ; Test: Write two dwords to stack, read unaligned dword spanning both
    ; Allocate 16 bytes on stack
    sub rsp, 16

    ; Write at RSP+0: 0x13370000 (bytes: 00 00 37 13)
    ; Write at RSP+4: 0x00000000 (bytes: 00 00 00 00)
    mov dword ptr [rsp], 13370000h
    mov dword ptr [rsp+4], 00000000h

    ; Unaligned read at RSP+2: bytes [37, 13, 00, 00] = 0x00001337 = 4919
    mov eax, dword ptr [rsp+2]

    ; Clean up stack
    add rsp, 16
    ret
main ENDP

END
