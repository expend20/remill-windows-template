; Tests for global variable memory access
; All tests return 0x1337 (4919)

.data
    g_var DWORD 0
    g_var2 DWORD 0
    g_qword QWORD 0
    g_array DWORD 4 DUP(0)           ; array of 4 dwords
    g_initialized DWORD 1337h        ; pre-initialized global
    g_byte_arr BYTE 8 DUP(0)         ; byte array for mixed access

.code

; Test: Write bytes separately to global, read as dword
; Write bytes: 0x37, 0x13, 0x00, 0x00 (little-endian)
; Read as dword: 0x00001337 = 4919
bytewise_write PROC
    mov byte ptr [g_var], 37h      ; byte 0
    mov byte ptr [g_var+1], 13h    ; byte 1
    mov byte ptr [g_var+2], 00h    ; byte 2
    mov byte ptr [g_var+3], 00h    ; byte 3
    mov eax, dword ptr [g_var]     ; read full dword
    ret
bytewise_write ENDP

; Test: Unaligned dword read spanning two globals
; g_var = 0x13370000, stored as bytes: 00 00 37 13
; g_var2 = 0x00000000, stored as bytes: 00 00 00 00
; Read at g_var+2: bytes [37, 13, 00, 00] = 0x00001337 = 4919
unaligned_read PROC
    mov dword ptr [g_var], 13370000h
    mov dword ptr [g_var2], 00000000h
    mov eax, dword ptr [g_var+2]  ; unaligned read spanning both dwords
    ret
unaligned_read ENDP

; Test: Write as words (16-bit), read as dword
; Write 0x1337 as low word, 0x0000 as high word
wordwise_write PROC
    mov word ptr [g_var], 1337h    ; low word
    mov word ptr [g_var+2], 0000h  ; high word
    mov eax, dword ptr [g_var]
    ret
wordwise_write ENDP

; Test: 64-bit (qword) read/write
; Write 0x1337 as qword, read back lower 32 bits
qword_access PROC
    mov qword ptr [g_qword], 1337h
    mov rax, qword ptr [g_qword]
    ; eax now contains lower 32 bits = 0x1337
    ret
qword_access ENDP

; Test: Write dword, read back as bytes and reconstruct
; Tests that byte reads from a dword-written location work
dword_to_bytes PROC
    mov dword ptr [g_var], 12001337h  ; write dword
    movzx eax, byte ptr [g_var]       ; read byte 0 = 0x37
    movzx ecx, byte ptr [g_var+1]     ; read byte 1 = 0x13
    shl ecx, 8
    or eax, ecx                        ; eax = 0x1337
    ret
dword_to_bytes ENDP

; Test: Zero-extend byte to dword (movzx)
; Write 0x37 as byte, zero-extend to eax, then OR with 0x1300
zero_extend_byte PROC
    mov byte ptr [g_var], 37h
    movzx eax, byte ptr [g_var]   ; eax = 0x00000037
    or eax, 1300h                 ; eax = 0x1337
    ret
zero_extend_byte ENDP

; Test: Zero-extend word to dword (movzx)
zero_extend_word PROC
    mov word ptr [g_var], 1337h
    movzx eax, word ptr [g_var]   ; eax = 0x00001337
    ret
zero_extend_word ENDP

; Test: Sign-extend byte to dword (movsx)
; Write -1 (0xFF) as byte, sign-extend, mask to get 0x1337
sign_extend_byte PROC
    mov byte ptr [g_var], 37h     ; positive byte
    movsx eax, byte ptr [g_var]   ; sign-extend: eax = 0x00000037
    or eax, 1300h
    ret
sign_extend_byte ENDP

; Test: Read-modify-write pattern
; Load value, add to it, store back, then read final
read_modify_write PROC
    mov dword ptr [g_var], 1000h
    mov eax, dword ptr [g_var]    ; read
    add eax, 337h                 ; modify
    mov dword ptr [g_var], eax    ; write
    mov eax, dword ptr [g_var]    ; read again = 0x1337
    ret
read_modify_write ENDP

; Test: Read from pre-initialized global
; g_initialized is set to 0x1337 in .data section
read_initialized PROC
    mov eax, dword ptr [g_initialized]
    ret
read_initialized ENDP

; Test: Array access with constant index
; Write to array[2], read back
array_const_index PROC
    mov dword ptr [g_array + 8], 1337h  ; array[2] at offset 8
    mov eax, dword ptr [g_array + 8]
    ret
array_const_index ENDP

; Test: Array access with register index
; Uses scaled index addressing: [base + reg*scale]
array_reg_index PROC
    mov ecx, 2                          ; index = 2
    lea rax, g_array                    ; load base address
    mov dword ptr [rax + rcx*4], 1337h  ; write array[index]
    mov eax, dword ptr [rax + rcx*4]    ; read array[index]
    ret
array_reg_index ENDP

; Test: Unaligned qword read
; Write two dwords, read as unaligned qword spanning them
unaligned_qword PROC
    mov dword ptr [g_byte_arr], 37001337h    ; bytes: 37 13 00 37
    mov dword ptr [g_byte_arr+4], 00000013h  ; bytes: 13 00 00 00
    mov rax, qword ptr [g_byte_arr+1]        ; unaligned read at offset 1
    ; bytes at offset 1: 13 00 37 13 00 00 00 XX -> low dword = 0x13370013
    ; We want 0x1337, so extract differently:
    mov dword ptr [g_byte_arr], 00133700h    ; bytes: 00 37 13 00
    mov dword ptr [g_byte_arr+4], 00000000h
    movzx eax, word ptr [g_byte_arr+1]       ; read word at offset 1 = 0x1337
    ret
unaligned_qword ENDP

; Test: Multiple globals in sequence
; Write to multiple globals, combine results
multi_global PROC
    mov dword ptr [g_var], 1300h
    mov dword ptr [g_var2], 37h
    mov eax, dword ptr [g_var]
    or eax, dword ptr [g_var2]    ; 0x1300 | 0x37 = 0x1337
    ret
multi_global ENDP

; Test: Overlapping writes (later write overwrites earlier)
; Tests that memory model handles write ordering correctly
overlapping_write PROC
    mov dword ptr [g_var], 0FFFFFFFFh  ; write all 1s
    mov word ptr [g_var], 1337h        ; overwrite low word
    mov word ptr [g_var+2], 0          ; overwrite high word
    mov eax, dword ptr [g_var]         ; read back = 0x1337
    ret
overlapping_write ENDP

END
