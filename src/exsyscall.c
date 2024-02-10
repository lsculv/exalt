// These are typed wrappers around raw syscalls.
#include <ex/sys/syscall.h>
#include <exalt.h>

isize sys_read(u32 fd, void* buf, usize count) {
    return (isize)syscall3(SYS_READ, (void*)(usize)fd, buf, (void*)count);
}

isize sys_write(u32 fd, const char* buf, usize count) {
    return (isize)syscall3(SYS_WRITE, (void*)(usize)fd, (void*)buf, (void*)count);
}

i32 sys_open(const char* filename, i32 flags, u32 mode) {
    return (i32)(isize)syscall3(SYS_OPEN, (void*)filename, (void*)(usize)flags, (void*)(isize)mode);
}

i32 sys_close(u32 fd) {
    return (i32)(isize)syscall1(SYS_CLOSE, (void*)(usize)fd);
}

Offset sys_lseek(u32 fd, Offset offset, u32 whence) {
    return (Offset)syscall3(SYS_LSEEK, (void*)(usize)fd, (void*)offset, (void*)(usize)whence);
}
