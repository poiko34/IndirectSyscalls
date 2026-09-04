.code

PUBLIC UniversalSyscall

UniversalSyscall PROC
    ; 1. Save non-volatile registers according to Windows x64 ABI
    push rbx
    push rsi

    ; 2. Allocate stack space: 32 bytes (shadow space) + 16 bytes (for Arg5 and Arg6) = 48 bytes.
    sub rsp, 48

    ; 3. Populate syscall arguments from the passed structure (rcx)
    mov eax, dword ptr [rcx]           ; SSN (System Service Number)
    mov r11, qword ptr [rcx + 8]       ; Gadget address

    mov r10, qword ptr [rcx + 16]      ; Arg1 -> r10
    mov rdx, qword ptr [rcx + 24]      ; Arg2 -> rdx
    mov r8,  qword ptr [rcx + 32]      ; Arg3 -> r8
    mov r9,  qword ptr [rcx + 40]      ; Arg4 -> r9

    ; Arguments 5 and 6 are written to the allocated space (above shadow space)
    mov rbx, qword ptr [rcx + 48]
    mov qword ptr [rsp + 32], rbx
    
    mov rbx, qword ptr [rcx + 56]
    mov qword ptr [rsp + 40], rbx

    ; 4. Call the gadget (syscall ; ret) via call.
    call r11                           

    ; 5. Clean up local stack and restore registers
    add rsp, 48
    pop rsi
    pop rbx
    
    ret
UniversalSyscall ENDP

END