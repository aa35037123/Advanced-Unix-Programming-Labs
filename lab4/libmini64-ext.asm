global time
time:
    xor rdi, rdi    ;  clean rdi to 0, pass null parameter
    mov rax, 201    ;  syscall number for clock_gettime
    syscall            ;  call kernel
    ret              ;  put time_t in %rax, return

global srand
srand:
    mov rax, rdi    ;  get the seed from rdi
    dec rax          ;  decrement it
    mov [rel seed], rax  ;  store it in the seed variable   
    ret 

global grand
grand:
    mov rax, [rel seed] ;  get the seed
    ret

global rand
rand:
    mov rax, [rel seed] ;  get the seed
    mov rcx, 6364136223846793005 ;  multiplier
    mul rcx          ;  rdx:rax = rax * rcx. high bytes in rdx, low bytes in rax
    add rax, 1
    mov [rel seed], rax;
    shr rax, 33     ; shift right
    ret

global sigemptyset
sigemptyset:
    mov qword [rdi], 0      ; rdi: the first argument. qword: 8 bytes word. []: get or set the value of the memory adderss 
    xor eax, eax
    ret

global sigfillset
sigfillset:
    mov qword [rdi], 0xffffffff
    xor eax, eax
    ret

; set bit <1 << (signum - 1)> to 1
global sigaddset
sigaddset:
    cmp esi, 1         ; esi: lower 32 bit of rsi. rsi: 2nd arg, signal number
    jl error_common           ; if signal number < 1, jump to error_common
    cmp esi, 32
    jg error_common           ; if signal number > 32. jump to error_common
    mov ecx, esi        ; put signum into ecx
    dec ecx             ; signum - 1
    mov eax, 1          ; eax: lower 32 bits of rax
    shl rax, cl         ; cl : lower 8 bits of ecx. shift value needs to put in cl
    or [rdi], rax       ; rdi: 1st arg

    xor eax, eax        ; set return value to 0
    ret

; set bit <1 << (signum - 1)> to 0
global sigdelset
sigdelset:
    cmp esi, 1
    jl error_common
    cmp esi, 32
    jg error_common
    mov ecx, esi
    dec ecx             ; cl = signum -1
    mov rax, 1
    shl rax, cl         ; rax = 1 << (signum -1)
    not rax             ; rax = ~(1 << (signum -1))
    and [rdi], rax      ; set bit (1 << (signum -1)) in set.sigflag to 0
    xor eax, eax        ; return 0
    ret 

; return 0 if  bit <1 << (signum - 1)> is unset, else return 1
global sigismember
sigismember:
    cmp esi, 1
    jl error_common
    cmp esi, 32
    jg error_common

    mov ecx, esi        ; get signum
    dec ecx
    mov rax, 1
    shl rax, cl
    test [rdi], rax     ; do bitwise and [rdi] & rax. If result != 0, bit is set, return 1, else means bit is unset return 0
    setnz al            ; al: lower 8 bit of rax. If retval of the prev instruction ret value not 0, set al to 1
    movzx eax, al       ; move + zero extension to high bits
    ret 


error_common:
    mov eax, -1
    ret                 ; return -1

global sigprocmask
sigprocmask:
    ; how:   rdi
    ; newset: rsi
    ; oldset: rdx
    ; sigsetsize = 8 bytes

    mov r10, 8          ; sizeof(sigset_t)
    mov rax, 14         ; syscall no for rt_sigprocmask
    syscall
    ret


global setjmp
setjmp:
    ; rdi = jmp_buf pointer
    mov [rdi + 0], rbx    ; save rbx
    mov [rdi + 8], rbp    ; save rbp
    mov [rdi + 16], r12   ; save r12
    mov [rdi + 24], r13   ; save r13
    mov [rdi + 32], r14   ; save r14
    mov [rdi + 40], r15   ; save r15
    mov [rdi + 48], rsp   ; save rsp

    ; save return address
    mov rax, [rsp]      ; Get return address from top of stack
    mov [rdi + 56], rax ; save return address
    
    ; save signal mask
    mov eax, 14     ;   syscall no for rt_sigprocmask
    xor rsi, rsi    ;   newset = NULL(no change to current mask)
    lea rdx, [rdi + 64] ;   oldset = &jmp_buf->mask (address of sigset_t) set oldset to jmp_buf + 64
    xor edi, edi    ;   how = SIG_BLOCK(0), put newset into current mask, but newset is NULL, so no change
    mov r10, 8          ;   sizeof(sigset_t)
    syscall

    xor eax, eax    ;   return 0
    ret

global longjmp
longjmp:
    ; rdi = jmp_buf pointer
    ; rsi = return value
    ; restore registers
    mov rbx, [rdi + 0]
    mov rbp, [rdi + 8]
    mov r12, [rdi + 16]
    mov r13, [rdi + 24]
    mov r14, [rdi + 32]
    mov r15, [rdi + 40]

    mov rsp, [rdi + 48]     ; restore stack pointer

    ; restore return value
    mov r8, rsi
    
    ; ; jmp to return address
    mov r9, [rdi + 56]  ; saved rip

    ; restore signal mask
    mov eax, 14         ; syscall no for rt_sigprocmask
    lea rsi, [rdi + 64] ; set = &jmp_buf->mask. set newset to previous signal mask store in jmp_buf
    xor rdx, rdx        ; oldset = NULL
    mov edi, 2         ; how = SIG_SETMASK(2), put newset into current mask
    mov r10, 8          ; sizeof(sigset_t)
    syscall

    mov rax, r8        ; return value
    
    jmp r9              ; jump to where setjmp would have returned


section .data
seed dq 0
