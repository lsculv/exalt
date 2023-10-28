#include "../include/exsyscall.h"

u64 sys_write(unsigned int fd, const char* buf, usize count) {
    u64 result;
    asm volatile("movq $1, %%rax;"
                 "movl %[fd], %%edi;"
                 "movq %[count], %%rdx;"
                 "movq %[buf], %%rsi;"
                 "syscall;"
                 "movq %%rax, %[result];"
                 : [result] "=r"(result)
                 : [fd] "r"(fd), [buf] "r"(buf), [count] "r"(count)
                 : "%rax", "%rdi", "%rsi", "%rdx");
    return result;
}
