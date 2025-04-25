#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <ctype.h>

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t,
    int64_t, int64_t, int64_t,
    int64_t);

static syscall_hook_fn_t original_syscall = NULL;

static void escape_buffer(const char *buf, size_t len, char *out, size_t out_size) {
    size_t out_idx = 0;

    /*
        need to watch out_idx + 5 is because there may be a situation that 
        we transfer a hex form 1 byte stuff(e.g.0x2b) to /x2b, which costs 4 bytes for each char
        and we still need to reserve 1 byte for \0
    */
    for(size_t i = 0; i < len && out_idx + 5 < out_size; i++) {
        unsigned char c = buf[i];
        if (c == '\n') {
            out[out_idx++] = '\\';
            out[out_idx++] = 'n';
        } else if (c == '\r') {
            out[out_idx++] = '\\';
            out[out_idx++] = 'r';
        } else if (c == '\t') {
            out[out_idx++] = '\\';
            out[out_idx++] = 't';
        } else if (isprint(c)) {  
            out[out_idx++] = c;
        } else {  // is not printable like hex form byte (e.g 0xhc)
            /*
                snprintf retrun the number of bytes written in 
                arg1: pointer to buffer start
                arg2: maximum writable size
            */
            out_idx += snprintf(out+out_idx, out_size - out_idx, "\\x%02x", c);
        }
    }
    out[out_idx] = '\0';
}

static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx,
                                int64_t r10, int64_t r8, int64_t r9,
                                int64_t rax) {
    if(rax == 59) {  // execve
        fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n",
            (char *)rdi, (void *) rsi, (void *) rdx);
        return original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    }
    // call the syscall to get return value
    int64_t ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    // fprintf(stderr, "rax: %ld\n", rax);
    // fprintf(stderr, "rdi: %d\n", (int)rdi);
    switch (rax) {
        case 257:  // openat
            int dirfd = (int)rdi;  // transfer rdi to 32 bits integer
            char dirfd_str[32];
            if(dirfd == -100) {
                strcpy(dirfd_str, "AT_FDCWD");
            } else {
                snprintf(dirfd_str, sizeof(dirfd_str), "%d", dirfd);
            }
            fprintf(stderr, "[logger] openat(%s, \"%s\", 0x%lx, %#o) = %ld\n",
                        dirfd_str, (char *)rsi, rdx, (unsigned int)r10, ret);
            break;
        case 0:  // read, return val: #bytes read in
            if (ret > 0) {
                char escaped[256] = {0};
                escape_buffer((char *)rsi, ret > 32 ? 32 : ret, escaped, sizeof(escaped));
                fprintf(stderr, "[logger] read(%ld, \"%s\"%s, %ld) = %ld\n",
                        rdi, escaped, (ret > 32 ? "..." : ""), rdx, ret); 
            } else {
                fprintf(stderr, "[logger] read(%ld, \"\", %ld) = %ld\n", rdi, rdx, ret); 
            }
            break;
        case 1:  // write, return val: #bytes write in
            if(ret > 0) {
                char escaped[256] = {0};
                escape_buffer((char *)rsi, ret > 32 ? 32 : ret, escaped, sizeof(escaped));
                fprintf(stderr, "[logger] write(%ld, \"%s\"%s, %ld) = %ld\n",
                        rdi, escaped, (ret > 32 ? "..." : ""), rdx, ret);
            } else {
                fprintf(stderr, "[logger] write(%ld, \"\", %ld) = %ld\n", rdi, rdx, ret);
            }
            break;
        case 42:  // connect 
            struct sockaddr *addr = (struct sockaddr *)rsi;  // arg2
            char buf[256] = {0};
            if(addr->sa_family == AF_INET) {  // ipv4
                struct sockaddr_in *in = (struct sockaddr_in *)addr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));  // convert ip from binary form to dec string form(e.g. 192.168.30.21) 
                snprintf(buf, sizeof(buf), "\"%s:%d\"", ip, ntohs(in->sin_port));  // convert port# from network byte form to host form
            } else if(addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(in6->sin6_addr), ip, sizeof(ip));
                snprintf(buf, sizeof(buf), "\"%s:%d\"", ip, ntohs(in6->sin6_port));  // convert port# from network byte form to host form
            } else if(addr->sa_family == AF_UNIX) {
                struct sockaddr_un *un = (struct sockaddr_un *)addr;
                snprintf(buf, sizeof(buf), "\"UNIX:%s\"", un->sun_path);  // unit socket path
            } else {
                snprintf(buf, sizeof(buf), "\"UNKNOWN\"");
            }
            fprintf(stderr, "[logger] connect(%ld, %s, %ld) = %ld\n",
                rdi, buf, rdx, ret);
            break;
        
    }
    return ret;
}

void __hook_init(const syscall_hook_fn_t trigger_syscall,
                    syscall_hook_fn_t *hooked_syscall) {
    original_syscall = trigger_syscall;
    
    // wrap execve separately
    *hooked_syscall = syscall_hook_fn;
}