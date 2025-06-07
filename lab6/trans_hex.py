from pwn import *

p = process('./bof1', env={"NO_SANDBOX":"1"})
p.recvuntil(b"What's your name? ")
p.send(cyclic(100))
p.interactive()
