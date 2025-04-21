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

section .data
seed dq 0
