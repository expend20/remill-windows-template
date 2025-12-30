; Tests for reading from read-only section and writing to stack
; All tests return 0x1337 (4919)

CONST SEGMENT READONLY
    g_const DWORD 1337h          ; read-only constant
CONST ENDS

.code

; Test: Read from rdata, copy to stack, return from stack
rdata_to_stack PROC
    sub rsp, 8
    mov eax, dword ptr [g_const]  ; read from .rdata
    mov dword ptr [rsp], eax      ; write to stack
    mov eax, dword ptr [rsp]      ; read from stack
    add rsp, 8
    ret
rdata_to_stack ENDP

END
