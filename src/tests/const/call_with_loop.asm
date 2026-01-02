; Test: CALL to helper function containing a loop with stack-based counter
; This isolates the issue where:
; 1. Direct CALL creates a helper function during lifting
; 2. Helper function contains a loop with stack memory accesses
; 3. After inlining, memory intrinsics in loop phi nodes can't be lowered
; 4. LLVM can't determine loop trip count and may mark function as noreturn
;
; Expected result: 0x1337 (4919)
; The loop computes: sum(1..32) = 528, then adds 0x1127 = 0x1337

.code

; Helper function with loop and stack-based counter
; Uses stack to store loop counter (like XTEA does)
helper_with_loop PROC
    ; Allocate stack space for loop counter
    sub rsp, 16

    ; Initialize: counter = 32, sum = 0
    mov dword ptr [rsp], 32      ; counter at [rsp]
    mov dword ptr [rsp+4], 0     ; sum at [rsp+4]

loop_start:
    ; Load counter
    mov ecx, dword ptr [rsp]

    ; Check if counter == 0
    test ecx, ecx
    jz loop_done

    ; sum += counter
    mov eax, dword ptr [rsp+4]
    add eax, ecx
    mov dword ptr [rsp+4], eax

    ; counter--
    dec ecx
    mov dword ptr [rsp], ecx

    jmp loop_start

loop_done:
    ; Load sum into eax (sum = 1+2+...+32 = 528 = 0x210)
    mov eax, dword ptr [rsp+4]

    ; Restore stack and return
    add rsp, 16
    ret
helper_with_loop ENDP

; Entry point - calls helper and adjusts result
call_with_loop PROC
    ; Call the helper function
    call helper_with_loop

    ; eax now contains 528 (0x210)
    ; Add 0x1127 to get 0x1337
    add eax, 1127h

    ret
call_with_loop ENDP

END
