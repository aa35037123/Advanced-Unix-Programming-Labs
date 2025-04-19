#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

#define PAGE_SIZE 4096
#define TRAMPOLINE_ADDR ((void *)0x0)
#define NR_syscalls 512


__attribute__((noinline))
void asm_syscall_hook(void) {
    printf("Hello from trampoline!\n");
    
}

__attribute__((constructor))
void setup_trampoline() {
    if (getenv("ZDEBUG")) {
        asm("int3");
    }
    void *mem = mmap((void *)0x0, 4096,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                        -1, 0);
    if(mem == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }

    // fill first 512 bytes start from 0x0 is nop(0x90)
    for (int i = 0; i < NR_syscalls; i++)
			((uint8_t *) mem)[i] = 0x90;
    
     // 2. trampoline assembly logic, start at offset 512
    uint8_t *t = (uint8_t *)mem + NR_syscalls;
    // this code jump to asm_syscall_hook
    // movabs $addr, %r11
    t[0]  = 0x49;
    t[1]  = 0xbb;
    // put asm_syscall_hook addr 
    uint64_t hook_addr = (uint64_t)asm_syscall_hook;
    for (int i = 0; i < 8; i++)
        t[2 + i] = (hook_addr >> (8 * i)) & 0xff;

   // call %r11
   t[10] = 0x41; t[11] = 0xFF; t[12] = 0xD3;
    
    // ret
    t[13] = 0xC3;

}