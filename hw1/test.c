#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

int main() {
    // 替換成你提供的記憶體區段
    uintptr_t start = 0x55e894b0c000;
    uintptr_t end   = 0x55e894b11000;

    size_t pagesize = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = start & ~(pagesize - 1);
    size_t size = end - page_start;

    printf("Trying to mprotect %p - %p (%zu bytes) to RWX...\n",
           (void *)page_start, (void *)(page_start + size), size);

    if (mprotect((void *)page_start, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("❌ mprotect failed");
        return 1;
    }

    printf("✅ mprotect succeeded! You can now write to this region.\n");
    return 0;
}
