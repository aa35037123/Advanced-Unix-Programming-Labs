from pwn import *

elf = ELF('./gotoku.local')
main_offset = elf.symbols['main']

got_entries = []
for i in range(1200):
   sym = f"gop_{i+1}"
   if sym in elf.got:
      got_entries.append((i, elf.got[sym]))

with open("got_offsets.h", "w") as f:
   f.write("// Auto-generated GOT offset table\n")
   f.write("#pragma once\n\n")
   f.write(f"#define MAIN_OFFSET 0x{main_offset:x}\n\n")
   f.write("const unsigned int gop_got_offsets[] = {\n")
   for i, offset in got_entries:
      f.write(f"    [{i}] = 0x{offset:x},  // gop_{i+1}\n")
   f.write("};\n")
