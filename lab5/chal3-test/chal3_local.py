#!/usr/bin/env python3
from pwn import *
import re

context.log_level = 'info'

def extract_seed(response):
    match = re.search(r"Set-Cookie: challenge=(\d+);", response)
    if not match:
        log.error("No Set-Cookie: challenge found")
        return None
    return int(match.group(1))

def compute_cookie(seed):
    # 模擬 C 的 unsigned long long 乘法溢位（64-bit）
    result = (seed * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF
    return result >> 33

def build_request(path="/secret/FLAG.txt", cookie=None, with_auth=False):
    lines = [f"GET {path} HTTP/1.1"]
    if with_auth:
        lines.append("Authorization: Basic YWRtaW46U3VwZXJTZWNyZXRQYXNzd29yZA==")
    if cookie is not None:
        lines.append(f"Cookie: response={cookie}")
    lines.append("")  # 空行結束 header
    lines.append("")
    return "\r\n".join(lines).encode()

# 開一條連線完成所有動作
io = remote("localhost", 8888)

# Step 1: 發送第一次 request（不帶 auth，只為取得 seed）
log.info("Sending first dummy request")
io.send(build_request(cookie=0, with_auth=False))
resp1 = io.recvuntil(b"\r\n\r\n", timeout=2).decode()

print("\n=== Dummy Response ===")
print(resp1)

# Step 2: 擷取 seed 並計算正確 cookie
seed = extract_seed(resp1)

print(f"seed is: {seed}")
if seed is None:
    io.close()
    exit(1)

cookie = compute_cookie(seed)
log.success(f"reqseed = {seed}, cookie = {cookie}")

# Step 3: 發送第二筆 request（含 auth 和正確 cookie）
log.info("Sending real request with auth and valid cookie")
io.send(build_request(cookie=cookie, with_auth=True))

# Step 4: 讀取 flag response
response2 = io.recvall(timeout=2).decode()
print("\n=== Flag Response ===")
print(response2)

io.close()
