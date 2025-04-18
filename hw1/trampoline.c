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
    // exit(0); 
}

__attribute__((constructor))
void setup_trampoline() {
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
    t[0] = 0xCC;
     // sub $0x80, %rsp
     t[0] = 0x48;
     t[1] = 0x81;
     t[2] = 0xec;
     t[3] = 0x80;
     t[4] = 0x00;
     t[5] = 0x00;
     t[6] = 0x00;
 
     // this code jump to asm_syscall_hook
     // movabs $addr, %r11
     t[7]  = 0x49;
     t[8]  = 0xbb;
     // put asm_syscall_hook addr 
     uint64_t hook_addr = (uint64_t)asm_syscall_hook;
     for (int i = 0; i < 8; i++)
         t[9 + i] = (hook_addr >> (8 * i)) & 0xff;
 
    // just jump, don't link
    // // jmp *%r11
    // t[17] = 0x41;
    // t[18] = 0xff;
    // t[19] = 0xe3;

    // call %r11
    t[17] = 0x41; t[18] = 0xFF; t[19] = 0xD3;
    // add rsp, 0x80
    t[20] = 0x48; t[21] = 0x81; t[22] = 0xC4;
    t[23] = 0x80; t[24] = 0x00; t[25] = 0x00; t[26] = 0x00;

    // ret
    t[27] = 0xC3;

}