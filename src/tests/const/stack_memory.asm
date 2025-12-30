; Tests for stack memory access
; All tests return 0x1337 (4919)

.code

; Test: Write bytes separately to stack, read as dword
; Write bytes: 0x37, 0x13, 0x00, 0x00 (little-endian)
; Read as dword: 0x00001337 = 4919
bytewise_write PROC
    sub rsp, 8
    mov byte ptr [rsp], 37h      ; byte 0
    mov byte ptr [rsp+1], 13h    ; byte 1
    mov byte ptr [rsp+2], 00h    ; byte 2
    mov byte ptr [rsp+3], 00h    ; byte 3
    mov eax, dword ptr [rsp]     ; read full dword
    add rsp, 8
    ret
bytewise_write ENDP

; Test: Unaligned dword read from stack
; Write at RSP+0: 0x13370000 (bytes: 00 00 37 13)
; Write at RSP+4: 0x00000000 (bytes: 00 00 00 00)
; Read at RSP+2: bytes [37, 13, 00, 00] = 0x00001337 = 4919
unaligned_read PROC
    sub rsp, 16
    mov dword ptr [rsp], 13370000h
    mov dword ptr [rsp+4], 00000000h
    mov eax, dword ptr [rsp+2]   ; unaligned read
    add rsp, 16
    ret
unaligned_read ENDP

END
