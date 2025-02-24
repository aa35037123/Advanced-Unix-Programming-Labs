#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

import sys
import zlib
from pwn import *
from solpow import solve_pow

def recv_msg(r):
    msg = r.recvline().strip()
    msg = base64.b64decode(msg)
    mlen = int.from_bytes(msg[0:4], 'big')
    if len(msg) - 4 != mlen:
        print("Message length mismatch. Exiting.")
        sys.exit(1)
    m = zlib.decompress(msg[4:])
    return m.decode()

#def recv_msg(r):
#    """Receive and decode server message"""
#    msg = r.recvline().strip().decode()
#    decoded_msg = base64.b64decode(msg.encode())
#    mlen = int.from_bytes(decoded_msg[0:4], 'little')
#    compressed_msg = decoded_msg[4:]
#    return zlib.decompress(compressed_msg).decode()

def send_msg(r, msg):
    zm = zlib.compress(msg.encode())
    mlen = len(zm)
    r.sendline(base64.b64encode(mlen.to_bytes(4, 'little') + zm))

#def send_msg(r, msg):
#    """Encode and send 4-digit guess to server"""
#    compressed = zlib.compress(msg.encode())  # Compress input
#    length_bytes = len(compressed).to_bytes(4, 'big')  # Convert length to little-endian
#    encoded_msg = base64.b64encode(length_bytes + compressed).decode()  # Base64 encode
#    r.sendline(encoded_msg)  # Send properly formatted message

def play_game(r):

#    print("[*] Identifying MSG1 by sending test guess ('0000')...")
#    send_guess(r, "0000")  # Send a test guess
#    msg1 = recv_msg(r)  # Store the first response (MSG1)
#    print(f"[+] Identified MSG1: {msg1}")  
    
    print("Receiving MSG0 from server...")
    msg0 = recv_msg(r)  # First message (MSG0)
    print(f"[+] Server sent: {msg0}")
    count = 0
    while True:
        prompt = recv_msg(r)
        print(f"[+] Server prompt: {prompt}")
        guess = input("Enter 4 digits: ").strip()
        send_msg(r, guess)
        response = recv_msg(r)
        print(f"[+] Server sent: {response}")
        count += 1
        if count > 10:
            break

if len(sys.argv) > 1:
    ## for remote access
    r = remote('up.zoolab.org', 10155)
    solve_pow(r)
else:
    ## for local testing
    r = process('./guess.dist.py', shell=False)

print('*** Implement your solver here ...')

play_game(r)  # play the guessing game

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
