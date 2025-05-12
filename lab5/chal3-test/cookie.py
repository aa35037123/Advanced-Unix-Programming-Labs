def compute_cookie(seed):
    # 模擬 C 的 unsigned long long 乘法溢位（64-bit）
    result = (seed * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF
    return result >> 33

print(compute_cookie(454794))