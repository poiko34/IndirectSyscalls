.intel_syntax noprefix
.global UniversalSyscall

UniversalSyscall:
    # 1. Сохраняем не-волатильные регистры по стандарту Windows x64 ABI
    push rbx
    push rsi

    # 2. Выделяем пространство на стеке: 32 байта (shadow space) + 16 байт (для Arg5 и Arg6) = 48 байт.
    # Так как мы сделали 2 push (16 байт) + call из C++ уже сдвинул стек на 8, 
    # текущий rsp выровнен с учетом требований ABI.
    sub rsp, 48

    # 3. Заполняем аргументы сискола из переданной структуры (rcx)
    mov eax, dword ptr [rcx + 0]       # SSN (System Service Number)
    mov r11, qword ptr [rcx + 8]       # Gadget address

    mov r10, qword ptr [rcx + 16]      # Arg1 -> r10
    mov rdx, qword ptr [rcx + 24]      # Arg2 -> rdx
    mov r8,  qword ptr [rcx + 32]      # Arg3 -> r8
    mov r9,  qword ptr [rcx + 40]      # Arg4 -> r9

    # Аргументы 5 и 6 записываем в выделенное пространство (выше shadow space)
    mov rbx, qword ptr [rcx + 48]
    mov qword ptr [rsp + 32], rbx
    
    mov rbx, qword ptr [rcx + 56]
    mov qword ptr [rsp + 40], rbx

    # 4. Вызываем гаджет (syscall ; ret) через call.
    # Гаджет выполнит системный вызов, сделает ret, и выполнение вернется СЮДА.
    call r11                           

    # 5. Очищаем локальный стек и восстанавливаем регистры
    add rsp, 48
    pop rsi
    pop rbx
    
    ret