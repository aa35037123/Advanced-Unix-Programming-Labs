#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <sys/mman.h>
#include <capstone/capstone.h>


#define PAGE_SIZE 4096
#define TRAMPOLINE_ADDR ((void *)0x0)
#define NR_syscalls 512
#define MAX_SYSCALLS 1000000

void decode_leetspeak(char *buf, size_t len) {
    for(size_t i = 0; i < len; ++i) {
        switch(buf[i]) {
            case '0': buf[i] = 'o'; break;
            case '1': buf[i] = 'i'; break;
            case '2': buf[i] = 'z'; break;
            case '3': buf[i] = 'e'; break;
            case '4': buf[i] = 'a'; break;
            case '5': buf[i] = 's'; break;
            case '6': buf[i] = 'g'; break;
            case '7': buf[i] = 't'; break;
            default: break;
        }
    }
}

/* 
    syscall abi: 
    this function translate system v function syscall to linux syscall abi
    rax, rdi, rsi, rdx, $r10, %r8, %r9 to system call
*/
extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t,
    int64_t, int64_t, int64_t);

extern void asm_syscall_hook(void);

void __raw_asm() {
    asm volatile(
        ".globl trigger_syscall \n"
        "trigger_syscall:\n"
        "mov %rdi, %rax\n"
        "mov %rsi, %rdi\n"
        "mov %rdx, %rsi\n"
        "mov %rcx, %rdx\n"
        "mov %r8, %r10\n"
        "mov %r9, %r8\n"
        "mov 8(%rsp), %r9\n"  // because c calling convention. args after 7 should be put on stack
        "syscall\n"
        "ret\n"
    );

    asm volatile(
        ".globl asm_syscall_hook\n"
        "asm_syscall_hook:\n"
        "pushq %rbp\n"  // rbp: frame pointer, point to current stack's base
        "movq %rsp, %rbp\n"  // move stack point of last function to rbp 

        "andq $-16, %rsp\n"  // stack align to 16(floor)

        // push syscall args
        "pushq %r11\n"
        "pushq %r9\n"
        "pushq %r8\n"
        "pushq %rdi\n"
        "pushq %rsi\n"
        "pushq %rdx\n"
        "pushq %rcx\n"

        // stack push extra args
        "pushq 8(%rbp)\n"  // return address(produced by call %r11 in trampoline)
        "pushq %rax\n"  // syscall number
        "pushq %r10\n"  // syscall arg4

        "callq handler@PLT\n"

        "popq %r10\n"
        "addq $16, %rsp\n"  // pop syscall number and return address, doesn't need to use

        "popq %rcx\n"
        "popq %rdx\n"
        "popq %rsi\n"
        "popq %rdi\n"
        "popq %r8\n"
        "popq %r9\n"
        "popq %r11\n"

        /*
            it means 
            movq %rbp, %rsp; // restore rsp to previous caller's one
            popq %rbp; // remove rbp on the stack
        */
        "leaveq\n"  
        "retq\n"  // pop a 8 bytes from stack, and jump to it --> get back to next instruction of call %r11
    );
}

int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx,
                  int64_t __rcx __attribute__((unused)),
                  int64_t r8, int64_t r9,
                  int64_t r10_on_stack,
                  int64_t rax_on_stack,
                  int64_t retptr) {
    // rax: syscall no, rdi: stdout fd
    if(rax_on_stack == 1 && rdi == 1) {
        // do leetspeak decode
        // rsi: pointer to data, rdx: the length of data
        decode_leetspeak((char *)rsi, rdx);
    }
    return trigger_syscall(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
}

void rewrite_syscall() {
    
    FILE *maps = fopen("/proc/self/maps", "r");
    if(!maps) {
        perror("fopen");
        return;
    }   

    uintptr_t syscall_addrs[MAX_SYSCALLS];
    int syscall_count = 0;

    char line[512];
    /* 
        start: pointer to a memory that code placed at 
        read 1 line from /proc/self/maps every loop
        %lx	read a unsigned long(with hex form)
        ex:
        555b29337000-555b2933c000 r-xp 00002000 00:38 15741506                   /usr/bin/cat
        it can read 
        start: 555b29337000
        end: 555b2933c000
        perms: r-xp

        And find memory region with 'x' flag, which means its executable instruction
        if not, continue to find next line in /proc/self/maps 
    */
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char perms[5];
        // we do not touch stack, vsyscall, and vsdo
        if(strstr(line, "[stack]") || strstr(line, "[vsyscall]") || strstr(line, "[vsdo]") || strstr(line, "libzpoline.so"))
            continue;

        if(sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;
    
        /* 
            strchr return first position of char appear
            if the char doesn't appear, it return NULL 
        */
        if(!strchr(perms, 'x'))
            continue;

        size_t size = end - start;
        /* cast start to a byte pointer, then it reads a byte every time */
        uint8_t *region = (uint8_t *)start;

        /* 
            make memory region writable each time we want to modify the value of executable region
            align floor to page size
        */
        // uintptr_t page_start = start & ~(PAGE_SIZE - 1);
        // size_t aligned_size = ((end - page_start + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

        uintptr_t page_start = (start + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);  // align up
        uintptr_t page_end   = end & ~(PAGE_SIZE - 1);                      // align down

        size_t protect_size = page_end - page_start;

        if (mprotect((void *)page_start, protect_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            perror("mprotect");
            continue;
        }

        csh handle;
        if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            fprintf(stderr, "Failed to initialize Capstone\n");
            continue;
        }

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

        cs_insn *insn;
        size_t count = cs_disasm(handle, region, size, start, 0, &insn);

        if(count > 0 && insn != NULL) {
            for(size_t i = 0; i < count; ++i) {
                if (insn[i].id == X86_INS_SYSCALL) {
                    syscall_addrs[syscall_count++] = insn[i].address;
                    // uintptr_t addr = insn[i].address;
                    // /* 
                    //     modify the first 2 bytes of syscall
                    //     -> change it to "call %rax" instruction
                    // */
                    // uint8_t *patch = (uint8_t *)addr;
                    // patch[0] = 0xFF;
                    // patch[1] = 0xD0;
                    // // if (insn[i].size < 2 || insn[i].size > 15) continue;

                    // // /* fill NOP to the last bytes*/
                    // // for (size_t j = 2; j < insn[i].size; j++)
                    // //     patch[j] = 0x90;
                }
            }
            cs_free(insn, count);
        }
        cs_close(&handle);

    }

    for (int i = 0; i < syscall_count; i++) {
        uint8_t *patch = (uint8_t *)syscall_addrs[i];
        patch[0] = 0xFF;
        patch[1] = 0xD0;
    }

    fclose(maps);
}

__attribute__((constructor))
void setup_trampoline() {
    if (getenv("ZDEBUG")) {
        asm("int3");
    }
    /* map a memory with size 4096 at 0x0*/
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
 
    // just jump, don't link
    // jmp %r11
    t[10] = 0x41;
    t[11] = 0xff;
    t[12] = 0xe3;


    rewrite_syscall();
}

