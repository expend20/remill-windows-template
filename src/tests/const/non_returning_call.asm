; Tests for non-returning calls (VMProtect-style obfuscation patterns)
; All tests should return 0x1337 (4919)
;
; This simulates obfuscated code where:
; 1. CALL pushes return address but the callee manipulates it
; 2. Fall-through after CALL contains junk code (RETF, invalid opcodes, etc.)
; 3. The callee either jumps elsewhere or modifies return address on stack

.code

; =============================================================================
; Test: Non-returning call with RETF after
; The callee pops and discards the return address, then jumps to actual code.
; Fall-through contains RETF which would crash if executed.
; =============================================================================

; Helper that computes the result
compute_result PROC
    mov eax, 1337h
    ret
compute_result ENDP

; The "trampoline" - called by entry, but doesn't return normally
; It pops the pushed return address and jumps directly to compute_result
non_ret_trampoline PROC
    ; Pop the return address pushed by CALL (we discard it)
    add rsp, 8
    ; Jump directly to compute_result (not call, so no return address pushed)
    jmp compute_result
non_ret_trampoline ENDP

; Entry point - calls trampoline, has RETF junk after
; If lifter follows fall-through, it will try to lift RETF which is wrong
non_ret_call_retf PROC
    ; This CALL pushes return address, but trampoline pops it and jumps away
    call non_ret_trampoline
    ; === JUNK CODE - never executed ===
    ; RETF (far return) - would crash if reached
    ; Using db to emit the opcode directly since MASM might complain
    db 0CBh  ; RETF opcode
    db 0CCh  ; INT3 - breakpoint (more junk)
    db 0CCh  ; INT3
    db 0CCh  ; INT3
    ; === END JUNK CODE ===
non_ret_call_retf ENDP

; =============================================================================
; Test: Non-returning call with modified return address
; The callee modifies the return address on the stack to skip junk code
; =============================================================================

; Target after junk code
after_junk PROC
    mov eax, 1337h
    ret
after_junk ENDP

; Trampoline that modifies return address to skip junk
modify_ret_trampoline PROC
    ; Get return address from stack (at [rsp])
    ; We need to add an offset to skip the junk bytes after the call
    ; The junk is 4 bytes (RETF + 3x INT3), so add 4 to return address
    add qword ptr [rsp], 4
    ret  ; Now returns to after_junk instead of the junk
modify_ret_trampoline ENDP

; Entry point - calls trampoline which modifies return to skip junk
non_ret_call_modify_ret PROC
    call modify_ret_trampoline
    ; === JUNK CODE (4 bytes) - skipped via modified return address ===
    db 0CBh  ; RETF
    db 0CCh  ; INT3
    db 0CCh  ; INT3
    db 0CCh  ; INT3
    ; === After junk - this is where we actually return ===
    jmp after_junk
non_ret_call_modify_ret ENDP

; =============================================================================
; Test: Call that tail-jumps (common in obfuscated code)
; The callee ends with JMP instead of RET
; =============================================================================

; Final computation
tail_result PROC
    mov eax, 1337h
    ret
tail_result ENDP

; Middle function that tail-jumps
tail_jump_middle PROC
    ; Pop return address (won't be used)
    add rsp, 8
    ; Tail jump to result
    jmp tail_result
tail_jump_middle ENDP

; Entry with tail-jumping callee
non_ret_tail_jump PROC
    call tail_jump_middle
    ; === JUNK - never reached ===
    db 0CBh  ; RETF
    mov eax, 0DEADh  ; Would give wrong result
    ret
non_ret_tail_jump ENDP

END
