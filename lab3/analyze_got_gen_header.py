from pwn import *

elf = ELF('./gotoku')
main_offset = elf.symbols['main']

got_entries = []
for i in range(1200):
   sym = f"gop_{i+1}"
   if sym in elf.got:
      got_entries.append((i, elf.got[sym]))

# Find the smallest offset
min_offset = min(got_entries, key=lambda x: x[1])[1]
largest_offset = max(got_entries, key=lambda x: x[1])[1]

with open("got_offsets.h", "w") as f:
   f.write("// Auto-generated GOT offset table\n")
   f.write("#pragma once\n\n")
   f.write(f"#define MAIN_OFFSET 0x{main_offset:x}\n")
   f.write(f"#define MINEST_GOT_OFFSET 0x{min_offset:x}\n\n")  # Added line
   f.write(f"#define LARGEST_GOT_OFFSET 0x{largest_offset:x}\n\n")  # Added line
   f.write("const unsigned int gop_got_offsets[] = {\n")
   for i, offset in got_entries:
      f.write(f"    [{i}] = 0x{offset:x},  // gop_{i+1}\n")
   f.write("};\n")
