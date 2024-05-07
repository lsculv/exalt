// These are typed wrappers around raw syscalls.
#include <ex/sys/kernel_types.h>
#include <ex/sys/syscall.h>
#include <exalt.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual" // The kernel doesn't care

long sys_io_setup(u32 nr_reqs, aio_context_t* ctx) {
    return (long)syscall2(SYS_io_setup, (void*)(usize)nr_reqs, (void*)ctx);
}
long sys_io_destroy(aio_context_t ctx) {
    return (long)syscall1(SYS_io_destroy, (void*)ctx);
}
long sys_io_submit(aio_context_t ctx_id, i64 nr, struct iocb** iocbpp) {
    return (long)syscall3(SYS_io_submit, (void*)ctx_id, (void*)nr, (void*)iocbpp);
}
long sys_io_cancel(aio_context_t ctx_id, struct iocb* iocb, struct io_event* result) {
    return (long)syscall3(SYS_io_cancel, (void*)ctx_id, (void*)iocb, (void*)result);
}
long sys_io_getevents(
    aio_context_t ctx_id, i64 min_nr, i64 nr, struct io_event* events, struct __kernel_timespec* timeout) {
    return (long)syscall5(SYS_io_getevents, (void*)ctx_id, (void*)min_nr, (void*)nr, (void*)events, (void*)timeout);
}
long sys_io_pgetevents(aio_context_t ctx_id,
                       i64 min_nr,
                       i64 nr,
                       struct io_event* events,
                       struct __kernel_timespec* timeout,
                       const struct __aio_sigset* sig) {
    return (long)syscall6(
        SYS_io_pgetevents, (void*)ctx_id, (void*)min_nr, (void*)nr, (void*)events, (void*)timeout, (void*)sig);
}
long sys_io_uring_setup(u32 entries, struct io_uring_params* p) {
    return (long)syscall2(SYS_io_uring_setup, (void*)(usize)entries, (void*)p);
}
long sys_io_uring_enter(u32 fd, u32 to_submit, u32 min_complete, u32 flags, const void* argp, usize argsz) {
    return (long)syscall6(SYS_io_uring_enter,
                          (void*)(usize)fd,
                          (void*)(usize)to_submit,
                          (void*)(usize)min_complete,
                          (void*)(usize)flags,
                          (void*)argp,
                          (void*)argsz);
}
long sys_io_uring_register(u32 fd, u32 op, void* arg, u32 nr_args) {
    return (long)syscall4(SYS_io_uring_register, (void*)(usize)fd, (void*)(usize)op, (void*)arg, (void*)(usize)nr_args);
}
long sys_setxattr(const char* path, const char* name, const void* value, usize size, i32 flags) {
    return (long)syscall5(SYS_setxattr, (void*)path, (void*)name, (void*)value, (void*)size, (void*)(usize)flags);
}
long sys_lsetxattr(const char* path, const char* name, const void* value, usize size, i32 flags) {
    return (long)syscall5(SYS_lsetxattr, (void*)path, (void*)name, (void*)value, (void*)size, (void*)(usize)flags);
}
long sys_fsetxattr(i32 fd, const char* name, const void* value, usize size, i32 flags) {
    return (long)syscall5(SYS_fsetxattr, (void*)(usize)fd, (void*)name, (void*)value, (void*)size, (void*)(usize)flags);
}
long sys_getxattr(const char* path, const char* name, void* value, usize size) {
    return (long)syscall4(SYS_getxattr, (void*)path, (void*)name, (void*)value, (void*)size);
}
long sys_lgetxattr(const char* path, const char* name, void* value, usize size) {
    return (long)syscall4(SYS_lgetxattr, (void*)path, (void*)name, (void*)value, (void*)size);
}
long sys_fgetxattr(i32 fd, const char* name, void* value, usize size) {
    return (long)syscall4(SYS_fgetxattr, (void*)(usize)fd, (void*)name, (void*)value, (void*)size);
}
long sys_listxattr(const char* path, char* list, usize size) {
    return (long)syscall3(SYS_listxattr, (void*)path, (void*)list, (void*)size);
}
long sys_llistxattr(const char* path, char* list, usize size) {
    return (long)syscall3(SYS_llistxattr, (void*)path, (void*)list, (void*)size);
}
long sys_flistxattr(i32 fd, char* list, usize size) {
    return (long)syscall3(SYS_flistxattr, (void*)(usize)fd, (void*)list, (void*)size);
}
long sys_removexattr(const char* path, const char* name) {
    return (long)syscall2(SYS_removexattr, (void*)path, (void*)name);
}
long sys_lremovexattr(const char* path, const char* name) {
    return (long)syscall2(SYS_lremovexattr, (void*)path, (void*)name);
}
long sys_fremovexattr(i32 fd, const char* name) {
    return (long)syscall2(SYS_fremovexattr, (void*)(usize)fd, (void*)name);
}
long sys_getcwd(char* buf, u64 size) {
    return (long)syscall2(SYS_getcwd, (void*)buf, (void*)size);
}
long sys_eventfd2(u32 count, i32 flags) {
    return (long)syscall2(SYS_eventfd2, (void*)(usize)count, (void*)(usize)flags);
}
long sys_epoll_create1(i32 flags) {
    return (long)syscall1(SYS_epoll_create1, (void*)(usize)flags);
}
long sys_epoll_ctl(i32 epfd, i32 op, i32 fd, struct epoll_event* event) {
    return (long)syscall4(SYS_epoll_ctl, (void*)(usize)epfd, (void*)(usize)op, (void*)(usize)fd, (void*)event);
}
long sys_epoll_pwait(
    i32 epfd, struct epoll_event* events, i32 maxevents, i32 timeout, const sigset_t* sigmask, usize sigsetsize) {
    return (long)syscall6(SYS_epoll_pwait,
                          (void*)(usize)epfd,
                          (void*)events,
                          (void*)(usize)maxevents,
                          (void*)(usize)timeout,
                          (void*)sigmask,
                          (void*)sigsetsize);
}
long sys_epoll_pwait2(i32 epfd,
                      struct epoll_event* events,
                      i32 maxevents,
                      const struct __kernel_timespec* timeout,
                      const sigset_t* sigmask,
                      usize sigsetsize) {
    return (long)syscall6(SYS_epoll_pwait2,
                          (void*)(usize)epfd,
                          (void*)events,
                          (void*)(usize)maxevents,
                          (void*)timeout,
                          (void*)sigmask,
                          (void*)sigsetsize);
}
long sys_dup(u32 fildes) {
    return (long)syscall1(SYS_dup, (void*)(usize)fildes);
}
long sys_dup3(u32 oldfd, u32 newfd, i32 flags) {
    return (long)syscall3(SYS_dup3, (void*)(usize)oldfd, (void*)(usize)newfd, (void*)(usize)flags);
}
long sys_fcntl(u32 fd, u32 cmd, u64 arg) {
    return (long)syscall3(SYS_fcntl, (void*)(usize)fd, (void*)(usize)cmd, (void*)arg);
}
long sys_inotify_init1(i32 flags) {
    return (long)syscall1(SYS_inotify_init1, (void*)(usize)flags);
}
long sys_inotify_add_watch(i32 fd, const char* path, u32 mask) {
    return (long)syscall3(SYS_inotify_add_watch, (void*)(usize)fd, (void*)path, (void*)(usize)mask);
}
long sys_inotify_rm_watch(i32 fd, i32 wd) {
    return (long)syscall2(SYS_inotify_rm_watch, (void*)(usize)fd, (void*)(usize)wd);
}
long sys_ioctl(u32 fd, u32 cmd, u64 arg) {
    return (long)syscall3(SYS_ioctl, (void*)(usize)fd, (void*)(usize)cmd, (void*)arg);
}
long sys_ioprio_set(i32 which, i32 who, i32 ioprio) {
    return (long)syscall3(SYS_ioprio_set, (void*)(usize)which, (void*)(usize)who, (void*)(usize)ioprio);
}
long sys_ioprio_get(i32 which, i32 who) {
    return (long)syscall2(SYS_ioprio_get, (void*)(usize)which, (void*)(usize)who);
}
long sys_flock(u32 fd, u32 cmd) {
    return (long)syscall2(SYS_flock, (void*)(usize)fd, (void*)(usize)cmd);
}
long sys_mknodat(i32 dfd, const char* filename, umode_t mode, u32 dev) {
    return (long)syscall4(SYS_mknodat, (void*)(usize)dfd, (void*)filename, (void*)(usize)mode, (void*)(usize)dev);
}
long sys_mkdirat(i32 dfd, const char* pathname, umode_t mode) {
    return (long)syscall3(SYS_mkdirat, (void*)(usize)dfd, (void*)pathname, (void*)(usize)mode);
}
long sys_unlinkat(i32 dfd, const char* pathname, i32 flag) {
    return (long)syscall3(SYS_unlinkat, (void*)(usize)dfd, (void*)pathname, (void*)(usize)flag);
}
long sys_symlinkat(const char* oldname, i32 newdfd, const char* newname) {
    return (long)syscall3(SYS_symlinkat, (void*)oldname, (void*)(usize)newdfd, (void*)newname);
}
long sys_linkat(i32 olddfd, const char* oldname, i32 newdfd, const char* newname, i32 flags) {
    return (long)syscall5(
        SYS_linkat, (void*)(usize)olddfd, (void*)oldname, (void*)(usize)newdfd, (void*)newname, (void*)(usize)flags);
}
long sys_renameat(i32 olddfd, const char* oldname, i32 newdfd, const char* newname) {
    return (long)syscall4(SYS_renameat, (void*)(usize)olddfd, (void*)oldname, (void*)(usize)newdfd, (void*)newname);
}
long sys_umount2(char* name, i32 flags) {
    return (long)syscall2(SYS_umount2, (void*)name, (void*)(usize)flags);
}
long sys_mount(char* dev_name, char* dir_name, char* type, u64 flags, void* data) {
    return (long)syscall5(SYS_mount, (void*)dev_name, (void*)dir_name, (void*)type, (void*)flags, (void*)data);
}
long sys_pivot_root(const char* new_root, const char* put_old) {
    return (long)syscall2(SYS_pivot_root, (void*)new_root, (void*)put_old);
}
long sys_statfs(const char* path, struct statfs* buf) {
    return (long)syscall2(SYS_statfs, (void*)path, (void*)buf);
}
long sys_fstatfs(u32 fd, struct statfs* buf) {
    return (long)syscall2(SYS_fstatfs, (void*)(usize)fd, (void*)buf);
}
long sys_statmount(const struct mnt_id_req* req, struct statmount* buf, usize bufsize, u32 flags) {
    return (long)syscall4(SYS_statmount, (void*)req, (void*)buf, (void*)bufsize, (void*)(usize)flags);
}
long sys_listmount(const struct mnt_id_req* req, u64* mnt_ids, usize nr_mnt_ids, u32 flags) {
    return (long)syscall4(SYS_listmount, (void*)req, (void*)mnt_ids, (void*)nr_mnt_ids, (void*)(usize)flags);
}
long sys_truncate(const char* path, loff_t length) {
    return (long)syscall2(SYS_truncate, (void*)path, (void*)length);
}
long sys_ftruncate(u32 fd, loff_t length) {
    return (long)syscall2(SYS_ftruncate, (void*)(usize)fd, (void*)length);
}
long sys_fallocate(i32 fd, i32 mode, loff_t offset, loff_t len) {
    return (long)syscall4(SYS_fallocate, (void*)(usize)fd, (void*)(usize)mode, (void*)offset, (void*)len);
}
long sys_faccessat(i32 dfd, const char* filename, i32 mode) {
    return (long)syscall3(SYS_faccessat, (void*)(usize)dfd, (void*)filename, (void*)(usize)mode);
}
long sys_faccessat2(i32 dfd, const char* filename, i32 mode, i32 flags) {
    return (long)syscall4(SYS_faccessat2, (void*)(usize)dfd, (void*)filename, (void*)(usize)mode, (void*)(usize)flags);
}
long sys_chdir(const char* filename) {
    return (long)syscall1(SYS_chdir, (void*)filename);
}
long sys_fchdir(u32 fd) {
    return (long)syscall1(SYS_fchdir, (void*)(usize)fd);
}
long sys_chroot(const char* filename) {
    return (long)syscall1(SYS_chroot, (void*)filename);
}
long sys_fchmod(u32 fd, umode_t mode) {
    return (long)syscall2(SYS_fchmod, (void*)(usize)fd, (void*)(usize)mode);
}
long sys_fchmodat(i32 dfd, const char* filename, umode_t mode) {
    return (long)syscall3(SYS_fchmodat, (void*)(usize)dfd, (void*)filename, (void*)(usize)mode);
}
long sys_fchmodat2(i32 dfd, const char* filename, umode_t mode, u32 flags) {
    return (long)syscall4(SYS_fchmodat2, (void*)(usize)dfd, (void*)filename, (void*)(usize)mode, (void*)(usize)flags);
}
long sys_fchownat(i32 dfd, const char* filename, uid_t user, gid_t group, i32 flag) {
    return (long)syscall5(
        SYS_fchownat, (void*)(usize)dfd, (void*)filename, (void*)(usize)user, (void*)(usize)group, (void*)(usize)flag);
}
long sys_fchown(u32 fd, uid_t user, gid_t group) {
    return (long)syscall3(SYS_fchown, (void*)(usize)fd, (void*)(usize)user, (void*)(usize)group);
}
i32 sys_openat(i32 dfd, const char* filename, i32 flags, umode_t mode) {
    return (i32)(usize)syscall4(
        SYS_openat, (void*)(usize)dfd, (void*)filename, (void*)(usize)flags, (void*)(usize)mode);
}
long sys_openat2(i32 dfd, const char* filename, struct open_how* how, usize size) {
    return (long)syscall4(SYS_openat2, (void*)(usize)dfd, (void*)filename, (void*)how, (void*)size);
}
long sys_close(u32 fd) {
    return (long)syscall1(SYS_close, (void*)(usize)fd);
}
long sys_close_range(u32 fd, u32 max_fd, u32 flags) {
    return (long)syscall3(SYS_close_range, (void*)(usize)fd, (void*)(usize)max_fd, (void*)(usize)flags);
}
long sys_vhangup(void) {
    return (long)syscall0(SYS_vhangup);
}
long sys_pipe2(i32* fildes, i32 flags) {
    return (long)syscall2(SYS_pipe2, (void*)fildes, (void*)(usize)flags);
}
long sys_quotactl(u32 cmd, const char* special, qid_t id, void* addr) {
    return (long)syscall4(SYS_quotactl, (void*)(usize)cmd, (void*)special, (void*)(usize)id, (void*)addr);
}
long sys_quotactl_fd(u32 fd, u32 cmd, qid_t id, void* addr) {
    return (long)syscall4(SYS_quotactl_fd, (void*)(usize)fd, (void*)(usize)cmd, (void*)(usize)id, (void*)addr);
}
long sys_getdents64(u32 fd, struct linux_dirent64* dirent, u32 count) {
    return (long)syscall3(SYS_getdents64, (void*)(usize)fd, (void*)dirent, (void*)(usize)count);
}
long sys_lseek(u32 fd, off_t offset, u32 whence) {
    return (long)syscall3(SYS_lseek, (void*)(usize)fd, (void*)offset, (void*)(usize)whence);
}
isize sys_read(u32 fd, char* buf, usize count) {
    return (isize)syscall3(SYS_read, (void*)(usize)fd, (void*)buf, (void*)count);
}
long sys_write(u32 fd, const char* buf, usize count) {
    return (long)syscall3(SYS_write, (void*)(usize)fd, (void*)buf, (void*)count);
}
long sys_readv(u64 fd, const struct iovec* vec, u64 vlen) {
    return (long)syscall3(SYS_readv, (void*)fd, (void*)vec, (void*)vlen);
}
long sys_writev(u64 fd, const struct iovec* vec, u64 vlen) {
    return (long)syscall3(SYS_writev, (void*)fd, (void*)vec, (void*)vlen);
}
long sys_pread64(u32 fd, char* buf, usize count, loff_t pos) {
    return (long)syscall4(SYS_pread64, (void*)(usize)fd, (void*)buf, (void*)count, (void*)pos);
}
long sys_pwrite64(u32 fd, const char* buf, usize count, loff_t pos) {
    return (long)syscall4(SYS_pwrite64, (void*)(usize)fd, (void*)buf, (void*)count, (void*)pos);
}
long sys_preadv(u64 fd, const struct iovec* vec, u64 vlen, u64 pos_l, u64 pos_h) {
    return (long)syscall5(SYS_preadv, (void*)fd, (void*)vec, (void*)vlen, (void*)pos_l, (void*)pos_h);
}
long sys_pwritev(u64 fd, const struct iovec* vec, u64 vlen, u64 pos_l, u64 pos_h) {
    return (long)syscall5(SYS_pwritev, (void*)fd, (void*)vec, (void*)vlen, (void*)pos_l, (void*)pos_h);
}
long sys_sendfile(i32 out_fd, i32 in_fd, loff_t* offset, usize count) {
    return (long)syscall4(SYS_sendfile, (void*)(usize)out_fd, (void*)(usize)in_fd, (void*)offset, (void*)count);
}
long sys_pselect6(i32, fd_set*, fd_set*, fd_set*, struct __kernel_timespec*, void*) {
    return (long)syscall0(SYS_pselect6);
}
long sys_ppoll(
    struct pollfd* fds, u32 nfds, struct __kernel_timespec* tmo_p, const sigset_t* sigmask, usize sigsetsize) {
    return (long)syscall5(SYS_ppoll, (void*)fds, (void*)(usize)nfds, (void*)tmo_p, (void*)sigmask, (void*)sigsetsize);
}
long sys_signalfd4(i32 ufd, sigset_t* user_mask, usize sizemask, i32 flags) {
    return (long)syscall4(SYS_signalfd4, (void*)(usize)ufd, (void*)user_mask, (void*)sizemask, (void*)(usize)flags);
}
long sys_vmsplice(i32 fd, const struct iovec* iov, u64 nr_segs, u32 flags) {
    return (long)syscall4(SYS_vmsplice, (void*)(usize)fd, (void*)iov, (void*)nr_segs, (void*)(usize)flags);
}
long sys_splice(i32 fd_in, loff_t* off_in, i32 fd_out, loff_t* off_out, usize len, u32 flags) {
    return (long)syscall6(SYS_splice,
                          (void*)(usize)fd_in,
                          (void*)off_in,
                          (void*)(usize)fd_out,
                          (void*)off_out,
                          (void*)len,
                          (void*)(usize)flags);
}
long sys_tee(i32 fdin, i32 fdout, usize len, u32 flags) {
    return (long)syscall4(SYS_tee, (void*)(usize)fdin, (void*)(usize)fdout, (void*)len, (void*)(usize)flags);
}
isize sys_readlinkat(i32 dfd, const char* path, char* buf, i32 bufsiz) {
    return (isize)syscall4(SYS_readlinkat, (void*)(usize)dfd, (void*)path, (void*)buf, (void*)(usize)bufsiz);
}
i32 sys_newfstatat(i32 dfd, const char* filename, struct stat* statbuf, i32 flag) {
    return (i32)(usize)syscall4(SYS_newfstatat, (void*)(usize)dfd, (void*)filename, (void*)statbuf, (void*)(usize)flag);
}
long sys_sync(void) {
    return (long)syscall0(SYS_sync);
}
long sys_fsync(u32 fd) {
    return (long)syscall1(SYS_fsync, (void*)(usize)fd);
}
long sys_fdatasync(u32 fd) {
    return (long)syscall1(SYS_fdatasync, (void*)(usize)fd);
}
long sys_sync_file_range(i32 fd, loff_t offset, loff_t nbytes, u32 flags) {
    return (long)syscall4(SYS_sync_file_range, (void*)(usize)fd, (void*)offset, (void*)nbytes, (void*)(usize)flags);
}
long sys_timerfd_create(i32 clockid, i32 flags) {
    return (long)syscall2(SYS_timerfd_create, (void*)(usize)clockid, (void*)(usize)flags);
}
long sys_timerfd_settime(i32 ufd, i32 flags, const struct __kernel_itimerspec* utmr, struct __kernel_itimerspec* otmr) {
    return (long)syscall4(SYS_timerfd_settime, (void*)(usize)ufd, (void*)(usize)flags, (void*)utmr, (void*)otmr);
}
long sys_timerfd_gettime(i32 ufd, struct __kernel_itimerspec* otmr) {
    return (long)syscall2(SYS_timerfd_gettime, (void*)(usize)ufd, (void*)otmr);
}
long sys_utimensat(i32 dfd, const char* filename, struct __kernel_timespec* utimes, i32 flags) {
    return (long)syscall4(SYS_utimensat, (void*)(usize)dfd, (void*)filename, (void*)utimes, (void*)(usize)flags);
}
long sys_acct(const char* name) {
    return (long)syscall1(SYS_acct, (void*)name);
}
long sys_capget(cap_user_header_t header, cap_user_data_t dataptr) {
    return (long)syscall2(SYS_capget, (void*)header, (void*)dataptr);
}
long sys_capset(cap_user_header_t header, const cap_user_data_t data) {
    return (long)syscall2(SYS_capset, (void*)header, (void*)data);
}
long sys_personality(u32 personality) {
    return (long)syscall1(SYS_personality, (void*)(usize)personality);
}
__attribute__((noreturn)) void sys_exit(i32 error_code) {
    (void)syscall1(SYS_exit, (void*)(usize)error_code);
    __builtin_unreachable();
}
__attribute__((noreturn)) void sys_exit_group(i32 error_code) {
    (void)syscall1(SYS_exit_group, (void*)(usize)error_code);
    __builtin_unreachable();
}
long sys_waitid(i32 which, pid_t pid, struct siginfo* infop, i32 options, struct rusage* ru) {
    return (long)syscall5(
        SYS_waitid, (void*)(usize)which, (void*)(usize)pid, (void*)infop, (void*)(usize)options, (void*)ru);
}
long sys_set_tid_address(i32* tidptr) {
    return (long)syscall1(SYS_set_tid_address, (void*)tidptr);
}
long sys_unshare(u64 unshare_flags) {
    return (long)syscall1(SYS_unshare, (void*)unshare_flags);
}
long sys_futex(u32* uaddr, i32 op, u32 val, const struct __kernel_timespec* utime, u32* uaddr2, u32 val3) {
    return (long)syscall6(
        SYS_futex, (void*)uaddr, (void*)(usize)op, (void*)(usize)val, (void*)utime, (void*)uaddr2, (void*)(usize)val3);
}
long sys_get_robust_list(i32 pid, struct robust_list_head** head_ptr, usize* len_ptr) {
    return (long)syscall3(SYS_get_robust_list, (void*)(usize)pid, (void*)head_ptr, (void*)len_ptr);
}
long sys_set_robust_list(struct robust_list_head* head, usize len) {
    return (long)syscall2(SYS_set_robust_list, (void*)head, (void*)len);
}
long sys_futex_waitv(
    struct futex_waitv* waiters, u32 nr_futexes, u32 flags, struct __kernel_timespec* timeout, clockid_t clockid) {
    return (long)syscall5(SYS_futex_waitv,
                          (void*)waiters,
                          (void*)(usize)nr_futexes,
                          (void*)(usize)flags,
                          (void*)timeout,
                          (void*)(usize)clockid);
}
long sys_futex_wake(void* uaddr, u64 mask, i32 nr, u32 flags) {
    return (long)syscall4(SYS_futex_wake, (void*)uaddr, (void*)mask, (void*)(usize)nr, (void*)(usize)flags);
}
long sys_futex_wait(void* uaddr, u64 val, u64 mask, u32 flags, struct __kernel_timespec* timespec, clockid_t clockid) {
    return (long)syscall6(SYS_futex_wait,
                          (void*)uaddr,
                          (void*)val,
                          (void*)mask,
                          (void*)(usize)flags,
                          (void*)timespec,
                          (void*)(usize)clockid);
}
long sys_futex_requeue(struct futex_waitv* waiters, u32 flags, i32 nr_wake, i32 nr_requeue) {
    return (long)syscall4(
        SYS_futex_requeue, (void*)waiters, (void*)(usize)flags, (void*)(usize)nr_wake, (void*)(usize)nr_requeue);
}
long sys_nanosleep(struct __kernel_timespec* rqtp, struct __kernel_timespec* rmtp) {
    return (long)syscall2(SYS_nanosleep, (void*)rqtp, (void*)rmtp);
}
long sys_getitimer(i32 which, struct __kernel_old_itimerval* value) {
    return (long)syscall2(SYS_getitimer, (void*)(usize)which, (void*)value);
}
long sys_setitimer(i32 which, struct __kernel_old_itimerval* value, struct __kernel_old_itimerval* ovalue) {
    return (long)syscall3(SYS_setitimer, (void*)(usize)which, (void*)value, (void*)ovalue);
}
long sys_kexec_load(u64 entry, u64 nr_segments, struct kexec_segment* segments, u64 flags) {
    return (long)syscall4(SYS_kexec_load, (void*)entry, (void*)nr_segments, (void*)segments, (void*)flags);
}
long sys_init_module(void* umod, u64 len, const char* uargs) {
    return (long)syscall3(SYS_init_module, (void*)umod, (void*)len, (void*)uargs);
}
long sys_delete_module(const char* name_user, u32 flags) {
    return (long)syscall2(SYS_delete_module, (void*)name_user, (void*)(usize)flags);
}
long sys_timer_create(clockid_t which_clock, struct sigevent* timer_event_spec, timer_t* created_timer_id) {
    return (long)syscall3(
        SYS_timer_create, (void*)(usize)which_clock, (void*)timer_event_spec, (void*)created_timer_id);
}
long sys_timer_gettime(timer_t timer_id, struct __kernel_itimerspec* setting) {
    return (long)syscall2(SYS_timer_gettime, (void*)(usize)timer_id, (void*)setting);
}
long sys_timer_getoverrun(timer_t timer_id) {
    return (long)syscall1(SYS_timer_getoverrun, (void*)(usize)timer_id);
}
long sys_timer_settime(timer_t timer_id,
                       i32 flags,
                       const struct __kernel_itimerspec* new_setting,
                       struct __kernel_itimerspec* old_setting) {
    return (long)syscall4(
        SYS_timer_settime, (void*)(usize)timer_id, (void*)(usize)flags, (void*)new_setting, (void*)old_setting);
}
long sys_timer_delete(timer_t timer_id) {
    return (long)syscall1(SYS_timer_delete, (void*)(usize)timer_id);
}
long sys_clock_settime(clockid_t which_clock, const struct __kernel_timespec* tp) {
    return (long)syscall2(SYS_clock_settime, (void*)(usize)which_clock, (void*)tp);
}
long sys_clock_gettime(clockid_t which_clock, struct __kernel_timespec* tp) {
    return (long)syscall2(SYS_clock_gettime, (void*)(usize)which_clock, (void*)tp);
}
long sys_clock_getres(clockid_t which_clock, struct __kernel_timespec* tp) {
    return (long)syscall2(SYS_clock_getres, (void*)(usize)which_clock, (void*)tp);
}
long sys_clock_nanosleep(clockid_t which_clock,
                         i32 flags,
                         const struct __kernel_timespec* rqtp,
                         struct __kernel_timespec* rmtp) {
    return (long)syscall4(
        SYS_clock_nanosleep, (void*)(usize)which_clock, (void*)(usize)flags, (void*)rqtp, (void*)rmtp);
}
long sys_syslog(i32 type, char* buf, i32 len) {
    return (long)syscall3(SYS_syslog, (void*)(usize)type, (void*)buf, (void*)(usize)len);
}
long sys_ptrace(i64 request, i64 pid, u64 addr, u64 data) {
    return (long)syscall4(SYS_ptrace, (void*)request, (void*)pid, (void*)addr, (void*)data);
}
long sys_sched_setparam(pid_t pid, struct sched_param* param) {
    return (long)syscall2(SYS_sched_setparam, (void*)(usize)pid, (void*)param);
}
long sys_sched_setscheduler(pid_t pid, i32 policy, struct sched_param* param) {
    return (long)syscall3(SYS_sched_setscheduler, (void*)(usize)pid, (void*)(usize)policy, (void*)param);
}
long sys_sched_getscheduler(pid_t pid) {
    return (long)syscall1(SYS_sched_getscheduler, (void*)(usize)pid);
}
long sys_sched_getparam(pid_t pid, struct sched_param* param) {
    return (long)syscall2(SYS_sched_getparam, (void*)(usize)pid, (void*)param);
}
long sys_sched_setaffinity(pid_t pid, u32 len, u64* user_mask_ptr) {
    return (long)syscall3(SYS_sched_setaffinity, (void*)(usize)pid, (void*)(usize)len, (void*)user_mask_ptr);
}
long sys_sched_getaffinity(pid_t pid, u32 len, u64* user_mask_ptr) {
    return (long)syscall3(SYS_sched_getaffinity, (void*)(usize)pid, (void*)(usize)len, (void*)user_mask_ptr);
}
long sys_sched_yield(void) {
    return (long)syscall0(SYS_sched_yield);
}
long sys_sched_get_priority_max(i32 policy) {
    return (long)syscall1(SYS_sched_get_priority_max, (void*)(usize)policy);
}
long sys_sched_get_priority_min(i32 policy) {
    return (long)syscall1(SYS_sched_get_priority_min, (void*)(usize)policy);
}
long sys_sched_rr_get_interval(pid_t pid, struct __kernel_timespec* interval) {
    return (long)syscall2(SYS_sched_rr_get_interval, (void*)(usize)pid, (void*)interval);
}
long sys_restart_syscall(void) {
    return (long)syscall0(SYS_restart_syscall);
}
long sys_kill(pid_t pid, i32 sig) {
    return (long)syscall2(SYS_kill, (void*)(usize)pid, (void*)(usize)sig);
}
long sys_tkill(pid_t pid, i32 sig) {
    return (long)syscall2(SYS_tkill, (void*)(usize)pid, (void*)(usize)sig);
}
long sys_tgkill(pid_t tgid, pid_t pid, i32 sig) {
    return (long)syscall3(SYS_tgkill, (void*)(usize)tgid, (void*)(usize)pid, (void*)(usize)sig);
}
long sys_sigaltstack(const struct sigaltstack* uss, struct sigaltstack* uoss) {
    return (long)syscall2(SYS_sigaltstack, (void*)uss, (void*)uoss);
}
long sys_rt_sigsuspend(sigset_t* unewset, usize sigsetsize) {
    return (long)syscall2(SYS_rt_sigsuspend, (void*)unewset, (void*)sigsetsize);
}
long sys_rt_sigaction(i32, const struct sigaction*, struct sigaction*, usize) {
    return (long)syscall0(SYS_rt_sigaction);
}
long sys_rt_sigprocmask(i32 how, sigset_t* set, sigset_t* oset, usize sigsetsize) {
    return (long)syscall4(SYS_rt_sigprocmask, (void*)(usize)how, (void*)set, (void*)oset, (void*)sigsetsize);
}
long sys_rt_sigpending(sigset_t* set, usize sigsetsize) {
    return (long)syscall2(SYS_rt_sigpending, (void*)set, (void*)sigsetsize);
}
long sys_rt_sigtimedwait(const sigset_t* uthese,
                         siginfo_t* uinfo,
                         const struct __kernel_timespec* uts,
                         usize sigsetsize) {
    return (long)syscall4(SYS_rt_sigtimedwait, (void*)uthese, (void*)uinfo, (void*)uts, (void*)sigsetsize);
}
long sys_rt_sigqueueinfo(pid_t pid, i32 sig, siginfo_t* uinfo) {
    return (long)syscall3(SYS_rt_sigqueueinfo, (void*)(usize)pid, (void*)(usize)sig, (void*)uinfo);
}
long sys_setpriority(i32 which, i32 who, i32 niceval) {
    return (long)syscall3(SYS_setpriority, (void*)(usize)which, (void*)(usize)who, (void*)(usize)niceval);
}
long sys_getpriority(i32 which, i32 who) {
    return (long)syscall2(SYS_getpriority, (void*)(usize)which, (void*)(usize)who);
}
long sys_reboot(i32 magic1, i32 magic2, u32 cmd, void* arg) {
    return (long)syscall4(SYS_reboot, (void*)(usize)magic1, (void*)(usize)magic2, (void*)(usize)cmd, (void*)arg);
}
long sys_setregid(gid_t rgid, gid_t egid) {
    return (long)syscall2(SYS_setregid, (void*)(usize)rgid, (void*)(usize)egid);
}
long sys_setgid(gid_t gid) {
    return (long)syscall1(SYS_setgid, (void*)(usize)gid);
}
long sys_setreuid(uid_t ruid, uid_t euid) {
    return (long)syscall2(SYS_setreuid, (void*)(usize)ruid, (void*)(usize)euid);
}
long sys_setuid(uid_t uid) {
    return (long)syscall1(SYS_setuid, (void*)(usize)uid);
}
long sys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
    return (long)syscall3(SYS_setresuid, (void*)(usize)ruid, (void*)(usize)euid, (void*)(usize)suid);
}
long sys_getresuid(uid_t* ruid, uid_t* euid, uid_t* suid) {
    return (long)syscall3(SYS_getresuid, (void*)ruid, (void*)euid, (void*)suid);
}
long sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
    return (long)syscall3(SYS_setresgid, (void*)(usize)rgid, (void*)(usize)egid, (void*)(usize)sgid);
}
long sys_getresgid(gid_t* rgid, gid_t* egid, gid_t* sgid) {
    return (long)syscall3(SYS_getresgid, (void*)rgid, (void*)egid, (void*)sgid);
}
long sys_setfsuid(uid_t uid) {
    return (long)syscall1(SYS_setfsuid, (void*)(usize)uid);
}
long sys_setfsgid(gid_t gid) {
    return (long)syscall1(SYS_setfsgid, (void*)(usize)gid);
}
long sys_times(struct tms* tbuf) {
    return (long)syscall1(SYS_times, (void*)tbuf);
}
long sys_setpgid(pid_t pid, pid_t pgid) {
    return (long)syscall2(SYS_setpgid, (void*)(usize)pid, (void*)(usize)pgid);
}
long sys_getpgid(pid_t pid) {
    return (long)syscall1(SYS_getpgid, (void*)(usize)pid);
}
long sys_getsid(pid_t pid) {
    return (long)syscall1(SYS_getsid, (void*)(usize)pid);
}
long sys_setsid(void) {
    return (long)syscall0(SYS_setsid);
}
long sys_getgroups(i32 gidsetsize, gid_t* grouplist) {
    return (long)syscall2(SYS_getgroups, (void*)(usize)gidsetsize, (void*)grouplist);
}
long sys_setgroups(i32 gidsetsize, gid_t* grouplist) {
    return (long)syscall2(SYS_setgroups, (void*)(usize)gidsetsize, (void*)grouplist);
}
i32 sys_sethostname(char* name, i32 len) {
    return (i32)(usize)syscall2(SYS_sethostname, (void*)name, (void*)(usize)len);
}
long sys_setdomainname(char* name, i32 len) {
    return (long)syscall2(SYS_setdomainname, (void*)name, (void*)(usize)len);
}
long sys_getrlimit(u32 resource, struct rlimit* rlim) {
    return (long)syscall2(SYS_getrlimit, (void*)(usize)resource, (void*)rlim);
}
long sys_setrlimit(u32 resource, struct rlimit* rlim) {
    return (long)syscall2(SYS_setrlimit, (void*)(usize)resource, (void*)rlim);
}
long sys_getrusage(i32 who, struct rusage* ru) {
    return (long)syscall2(SYS_getrusage, (void*)(usize)who, (void*)ru);
}
long sys_umask(i32 mask) {
    return (long)syscall1(SYS_umask, (void*)(usize)mask);
}
long sys_prctl(i32 option, u64 arg2, u64 arg3, u64 arg4, u64 arg5) {
    return (long)syscall5(SYS_prctl, (void*)(usize)option, (void*)arg2, (void*)arg3, (void*)arg4, (void*)arg5);
}
long sys_getcpu(u32* cpu, u32* node, struct getcpu_cache* cache) {
    return (long)syscall3(SYS_getcpu, (void*)cpu, (void*)node, (void*)cache);
}
long sys_gettimeofday(struct __kernel_old_timeval* tv, struct timezone* tz) {
    return (long)syscall2(SYS_gettimeofday, (void*)tv, (void*)tz);
}
long sys_settimeofday(struct __kernel_old_timeval* tv, struct timezone* tz) {
    return (long)syscall2(SYS_settimeofday, (void*)tv, (void*)tz);
}
long sys_adjtimex(struct __kernel_timex* txc_p) {
    return (long)syscall1(SYS_adjtimex, (void*)txc_p);
}
long sys_getpid(void) {
    return (long)syscall0(SYS_getpid);
}
long sys_getppid(void) {
    return (long)syscall0(SYS_getppid);
}
long sys_getuid(void) {
    return (long)syscall0(SYS_getuid);
}
long sys_geteuid(void) {
    return (long)syscall0(SYS_geteuid);
}
long sys_getgid(void) {
    return (long)syscall0(SYS_getgid);
}
long sys_getegid(void) {
    return (long)syscall0(SYS_getegid);
}
long sys_gettid(void) {
    return (long)syscall0(SYS_gettid);
}
long sys_sysinfo(struct sysinfo* info) {
    return (long)syscall1(SYS_sysinfo, (void*)info);
}
long sys_mq_open(const char* name, i32 oflag, umode_t mode, struct mq_attr* attr) {
    return (long)syscall4(SYS_mq_open, (void*)name, (void*)(usize)oflag, (void*)(usize)mode, (void*)attr);
}
long sys_mq_unlink(const char* name) {
    return (long)syscall1(SYS_mq_unlink, (void*)name);
}
long sys_mq_timedsend(
    mqd_t mqdes, const char* msg_ptr, usize msg_len, u32 msg_prio, const struct __kernel_timespec* abs_timeout) {
    return (long)syscall5(SYS_mq_timedsend,
                          (void*)(usize)mqdes,
                          (void*)msg_ptr,
                          (void*)msg_len,
                          (void*)(usize)msg_prio,
                          (void*)abs_timeout);
}
long sys_mq_timedreceive(
    mqd_t mqdes, char* msg_ptr, usize msg_len, u32* msg_prio, const struct __kernel_timespec* abs_timeout) {
    return (long)syscall5(
        SYS_mq_timedreceive, (void*)(usize)mqdes, (void*)msg_ptr, (void*)msg_len, (void*)msg_prio, (void*)abs_timeout);
}
long sys_mq_notify(mqd_t mqdes, const struct sigevent* notification) {
    return (long)syscall2(SYS_mq_notify, (void*)(usize)mqdes, (void*)notification);
}
long sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr* mqstat, struct mq_attr* omqstat) {
    return (long)syscall3(SYS_mq_getsetattr, (void*)(usize)mqdes, (void*)mqstat, (void*)omqstat);
}
long sys_msgget(key_t key, i32 msgflg) {
    return (long)syscall2(SYS_msgget, (void*)(usize)key, (void*)(usize)msgflg);
}
long sys_msgctl(i32 msqid, i32 cmd, struct msqid_ds* buf) {
    return (long)syscall3(SYS_msgctl, (void*)(usize)msqid, (void*)(usize)cmd, (void*)buf);
}
long sys_msgrcv(i32 msqid, struct msgbuf* msgp, usize msgsz, i64 msgtyp, i32 msgflg) {
    return (long)syscall5(
        SYS_msgrcv, (void*)(usize)msqid, (void*)msgp, (void*)msgsz, (void*)msgtyp, (void*)(usize)msgflg);
}
long sys_msgsnd(i32 msqid, struct msgbuf* msgp, usize msgsz, i32 msgflg) {
    return (long)syscall4(SYS_msgsnd, (void*)(usize)msqid, (void*)msgp, (void*)msgsz, (void*)(usize)msgflg);
}
long sys_semget(key_t key, i32 nsems, i32 semflg) {
    return (long)syscall3(SYS_semget, (void*)(usize)key, (void*)(usize)nsems, (void*)(usize)semflg);
}
long sys_semctl(i32 semid, i32 semnum, i32 cmd, u64 arg) {
    return (long)syscall4(SYS_semctl, (void*)(usize)semid, (void*)(usize)semnum, (void*)(usize)cmd, (void*)arg);
}
long sys_semtimedop(i32 semid, struct sembuf* sops, u32 nsops, const struct __kernel_timespec* timeout) {
    return (long)syscall4(SYS_semtimedop, (void*)(usize)semid, (void*)sops, (void*)(usize)nsops, (void*)timeout);
}
long sys_semop(i32 semid, struct sembuf* sops, u32 nsops) {
    return (long)syscall3(SYS_semop, (void*)(usize)semid, (void*)sops, (void*)(usize)nsops);
}
long sys_shmget(key_t key, usize size, i32 flag) {
    return (long)syscall3(SYS_shmget, (void*)(usize)key, (void*)size, (void*)(usize)flag);
}
long sys_shmctl(i32 shmid, i32 cmd, struct shmid_ds* buf) {
    return (long)syscall3(SYS_shmctl, (void*)(usize)shmid, (void*)(usize)cmd, (void*)buf);
}
long sys_shmat(i32 shmid, char* shmaddr, i32 shmflg) {
    return (long)syscall3(SYS_shmat, (void*)(usize)shmid, (void*)shmaddr, (void*)(usize)shmflg);
}
long sys_shmdt(char* shmaddr) {
    return (long)syscall1(SYS_shmdt, (void*)shmaddr);
}
long sys_socket(i32 domain, i32 type, i32 protocol) {
    return (long)syscall3(SYS_socket, (void*)(usize)domain, (void*)(usize)type, (void*)(usize)protocol);
}
long sys_socketpair(i32 domain, i32 type, i32 protocol, i32 sv[2]) {
    return (long)syscall4(SYS_socketpair, (void*)(usize)domain, (void*)(usize)type, (void*)(usize)protocol, (void*)sv);
}
long sys_bind(i32 sockfd, struct sockaddr* addr, i32 addrlen) {
    return (long)syscall3(SYS_bind, (void*)(usize)sockfd, (void*)addr, (void*)(usize)addrlen);
}
long sys_listen(i32 sockfd, i32 backlog) {
    return (long)syscall2(SYS_listen, (void*)(usize)sockfd, (void*)(usize)backlog);
}
long sys_accept(i32 sockfd, struct sockaddr* addr, i32* addrlen) {
    return (long)syscall3(SYS_accept, (void*)(usize)sockfd, (void*)addr, (void*)addrlen);
}
long sys_connect(i32 sockfd, struct sockaddr* addr, i32 addrlen) {
    return (long)syscall3(SYS_connect, (void*)(usize)sockfd, (void*)addr, (void*)(usize)addrlen);
}
long sys_getsockname(i32 sockfd, struct sockaddr* addr, i32* addrlen) {
    return (long)syscall3(SYS_getsockname, (void*)(usize)sockfd, (void*)addr, (void*)addrlen);
}
long sys_getpeername(i32 sockfd, struct sockaddr* addr, i32* addrlen) {
    return (long)syscall3(SYS_getpeername, (void*)(usize)sockfd, (void*)addr, (void*)addrlen);
}
long sys_sendto(i32 sockfd, void* buf, usize len, u32 flags, struct sockaddr* dest_addr, i32 addrlen) {
    return (long)syscall6(SYS_sendto,
                          (void*)(usize)sockfd,
                          (void*)buf,
                          (void*)len,
                          (void*)(usize)flags,
                          (void*)dest_addr,
                          (void*)(usize)addrlen);
}
long sys_recvfrom(i32 sockfd, void* buf, usize len, u32 flags, struct sockaddr* src_addr, i32* addrlen) {
    return (long)syscall6(SYS_recvfrom,
                          (void*)(usize)sockfd,
                          (void*)buf,
                          (void*)len,
                          (void*)(usize)flags,
                          (void*)src_addr,
                          (void*)addrlen);
}
long sys_setsockopt(i32 fd, i32 level, i32 optname, char* optval, i32 optlen) {
    return (long)syscall5(SYS_setsockopt,
                          (void*)(usize)fd,
                          (void*)(usize)level,
                          (void*)(usize)optname,
                          (void*)optval,
                          (void*)(usize)optlen);
}
long sys_getsockopt(i32 fd, i32 level, i32 optname, char* optval, i32* optlen) {
    return (long)syscall5(
        SYS_getsockopt, (void*)(usize)fd, (void*)(usize)level, (void*)(usize)optname, (void*)optval, (void*)optlen);
}
long sys_shutdown(i32 sockfd, i32 how) {
    return (long)syscall2(SYS_shutdown, (void*)(usize)sockfd, (void*)(usize)how);
}
long sys_sendmsg(i32 fd, struct user_msghdr* msg, u32 flags) {
    return (long)syscall3(SYS_sendmsg, (void*)(usize)fd, (void*)msg, (void*)(usize)flags);
}
long sys_recvmsg(i32 fd, struct user_msghdr* msg, u32 flags) {
    return (long)syscall3(SYS_recvmsg, (void*)(usize)fd, (void*)msg, (void*)(usize)flags);
}
long sys_readahead(i32 fd, loff_t offset, usize count) {
    return (long)syscall3(SYS_readahead, (void*)(usize)fd, (void*)offset, (void*)count);
}
long sys_brk(u64 brk) {
    return (long)syscall1(SYS_brk, (void*)brk);
}
long sys_munmap(u64 addr, usize len) {
    return (long)syscall2(SYS_munmap, (void*)addr, (void*)len);
}
long sys_mremap(u64 addr, u64 old_len, u64 new_len, u64 flags, u64 new_addr) {
    return (long)syscall5(SYS_mremap, (void*)addr, (void*)old_len, (void*)new_len, (void*)flags, (void*)new_addr);
}
long sys_add_key(
    const char* _type, const char* _description, const void* _payload, usize plen, key_serial_t destringid) {
    return (long)syscall5(
        SYS_add_key, (void*)_type, (void*)_description, (void*)_payload, (void*)plen, (void*)(usize)destringid);
}
long sys_request_key(const char* _type, const char* _description, const char* _callout_info, key_serial_t destringid) {
    return (long)syscall4(
        SYS_request_key, (void*)_type, (void*)_description, (void*)_callout_info, (void*)(usize)destringid);
}
long sys_keyctl(i32 cmd, u64 arg2, u64 arg3, u64 arg4, u64 arg5) {
    return (long)syscall5(SYS_keyctl, (void*)(usize)cmd, (void*)arg2, (void*)arg3, (void*)arg4, (void*)arg5);
}
long sys_clone(u64 flags, void* stack, i32* parent_tid, i32* child_tid, u64 tls) {
    return (long)syscall5(SYS_clone, (void*)flags, (void*)stack, (void*)parent_tid, (void*)child_tid, (void*)tls);
}
long sys_clone3(struct clone_args* uargs, usize size) {
    return (long)syscall2(SYS_clone3, (void*)uargs, (void*)size);
}
long sys_execve(const char* filename, const char* const* argv, const char* const* envp) {
    return (long)syscall3(SYS_execve, (void*)filename, (void*)argv, (void*)envp);
}
long sys_swapon(const char* specialfile, i32 swap_flags) {
    return (long)syscall2(SYS_swapon, (void*)specialfile, (void*)(usize)swap_flags);
}
long sys_swapoff(const char* specialfile) {
    return (long)syscall1(SYS_swapoff, (void*)specialfile);
}
long sys_mprotect(u64 start, usize len, u64 prot) {
    return (long)syscall3(SYS_mprotect, (void*)start, (void*)len, (void*)prot);
}
long sys_msync(u64 start, usize len, i32 flags) {
    return (long)syscall3(SYS_msync, (void*)start, (void*)len, (void*)(usize)flags);
}
long sys_mlock(u64 start, usize len) {
    return (long)syscall2(SYS_mlock, (void*)start, (void*)len);
}
long sys_munlock(u64 start, usize len) {
    return (long)syscall2(SYS_munlock, (void*)start, (void*)len);
}
long sys_mlockall(i32 flags) {
    return (long)syscall1(SYS_mlockall, (void*)(usize)flags);
}
long sys_munlockall(void) {
    return (long)syscall0(SYS_munlockall);
}
long sys_mincore(u64 start, usize len, u8* vec) {
    return (long)syscall3(SYS_mincore, (void*)start, (void*)len, (void*)vec);
}
long sys_madvise(u64 start, usize len, i32 behavior) {
    return (long)syscall3(SYS_madvise, (void*)start, (void*)len, (void*)(usize)behavior);
}
long sys_process_madvise(i32 pidfd, const struct iovec* vec, usize vlen, i32 behavior, u32 flags) {
    return (long)syscall5(
        SYS_process_madvise, (void*)(usize)pidfd, (void*)vec, (void*)vlen, (void*)(usize)behavior, (void*)(usize)flags);
}
long sys_process_mrelease(i32 pidfd, u32 flags) {
    return (long)syscall2(SYS_process_mrelease, (void*)(usize)pidfd, (void*)(usize)flags);
}
long sys_remap_file_pages(u64 start, u64 size, u64 prot, u64 pgoff, u64 flags) {
    return (long)syscall5(SYS_remap_file_pages, (void*)start, (void*)size, (void*)prot, (void*)pgoff, (void*)flags);
}
long sys_mbind(u64 start, u64 len, u64 mode, const u64* nmask, u64 maxnode, u32 flags) {
    return (long)syscall6(
        SYS_mbind, (void*)start, (void*)len, (void*)mode, (void*)nmask, (void*)maxnode, (void*)(usize)flags);
}
long sys_get_mempolicy(i32* policy, u64* nmask, u64 maxnode, u64 addr, u64 flags) {
    return (long)syscall5(SYS_get_mempolicy, (void*)policy, (void*)nmask, (void*)maxnode, (void*)addr, (void*)flags);
}
long sys_set_mempolicy(i32 mode, const u64* nmask, u64 maxnode) {
    return (long)syscall3(SYS_set_mempolicy, (void*)(usize)mode, (void*)nmask, (void*)maxnode);
}
long sys_migrate_pages(pid_t pid, u64 maxnode, const u64* from, const u64* to) {
    return (long)syscall4(SYS_migrate_pages, (void*)(usize)pid, (void*)maxnode, (void*)from, (void*)to);
}
long sys_move_pages(pid_t pid, u64 nr_pages, const void** pages, const i32* nodes, i32* status, i32 flags) {
    return (long)syscall6(SYS_move_pages,
                          (void*)(usize)pid,
                          (void*)nr_pages,
                          (void*)pages,
                          (void*)nodes,
                          (void*)status,
                          (void*)(usize)flags);
}
long sys_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, i32 sig, siginfo_t* uinfo) {
    return (long)syscall4(
        SYS_rt_tgsigqueueinfo, (void*)(usize)tgid, (void*)(usize)pid, (void*)(usize)sig, (void*)uinfo);
}
long sys_perf_event_open(struct perf_event_attr* attr_uptr, pid_t pid, i32 cpu, i32 group_fd, u64 flags) {
    return (long)syscall5(SYS_perf_event_open,
                          (void*)attr_uptr,
                          (void*)(usize)pid,
                          (void*)(usize)cpu,
                          (void*)(usize)group_fd,
                          (void*)flags);
}
long sys_accept4(i32, struct sockaddr*, i32*, i32) {
    return (long)syscall0(SYS_accept4);
}
long sys_recvmmsg(i32 fd, struct mmsghdr* msg, u32 vlen, u32 flags, struct __kernel_timespec* timeout) {
    return (long)syscall5(
        SYS_recvmmsg, (void*)(usize)fd, (void*)msg, (void*)(usize)vlen, (void*)(usize)flags, (void*)timeout);
}
long sys_wait4(pid_t pid, i32* stat_addr, i32 options, struct rusage* ru) {
    return (long)syscall4(SYS_wait4, (void*)(usize)pid, (void*)stat_addr, (void*)(usize)options, (void*)ru);
}
long sys_prlimit64(pid_t pid, u32 resource, const struct rlimit64* new_rlim, struct rlimit64* old_rlim) {
    return (long)syscall4(SYS_prlimit64, (void*)(usize)pid, (void*)(usize)resource, (void*)new_rlim, (void*)old_rlim);
}
long sys_fanotify_init(u32 flags, u32 event_f_flags) {
    return (long)syscall2(SYS_fanotify_init, (void*)(usize)flags, (void*)(usize)event_f_flags);
}
long sys_fanotify_mark(i32 fanotify_fd, u32 flags, u64 mask, i32 fd, const char* pathname) {
    return (long)syscall5(SYS_fanotify_mark,
                          (void*)(usize)fanotify_fd,
                          (void*)(usize)flags,
                          (void*)mask,
                          (void*)(usize)fd,
                          (void*)pathname);
}
long sys_name_to_handle_at(i32 dfd, const char* name, struct file_handle* handle, i32* mnt_id, i32 flag) {
    return (long)syscall5(
        SYS_name_to_handle_at, (void*)(usize)dfd, (void*)name, (void*)handle, (void*)mnt_id, (void*)(usize)flag);
}
long sys_open_by_handle_at(i32 mountdirfd, struct file_handle* handle, i32 flags) {
    return (long)syscall3(SYS_open_by_handle_at, (void*)(usize)mountdirfd, (void*)handle, (void*)(usize)flags);
}
long sys_clock_adjtime(clockid_t which_clock, struct __kernel_timex* tx) {
    return (long)syscall2(SYS_clock_adjtime, (void*)(usize)which_clock, (void*)tx);
}
long sys_syncfs(i32 fd) {
    return (long)syscall1(SYS_syncfs, (void*)(usize)fd);
}
long sys_setns(i32 fd, i32 nstype) {
    return (long)syscall2(SYS_setns, (void*)(usize)fd, (void*)(usize)nstype);
}
long sys_pidfd_open(pid_t pid, u32 flags) {
    return (long)syscall2(SYS_pidfd_open, (void*)(usize)pid, (void*)(usize)flags);
}
long sys_sendmmsg(i32 fd, struct mmsghdr* msg, u32 vlen, u32 flags) {
    return (long)syscall4(SYS_sendmmsg, (void*)(usize)fd, (void*)msg, (void*)(usize)vlen, (void*)(usize)flags);
}
long sys_process_vm_readv(
    pid_t pid, const struct iovec* lvec, u64 liovcnt, const struct iovec* rvec, u64 riovcnt, u64 flags) {
    return (long)syscall6(SYS_process_vm_readv,
                          (void*)(usize)pid,
                          (void*)lvec,
                          (void*)liovcnt,
                          (void*)rvec,
                          (void*)riovcnt,
                          (void*)flags);
}
long sys_process_vm_writev(
    pid_t pid, const struct iovec* lvec, u64 liovcnt, const struct iovec* rvec, u64 riovcnt, u64 flags) {
    return (long)syscall6(SYS_process_vm_writev,
                          (void*)(usize)pid,
                          (void*)lvec,
                          (void*)liovcnt,
                          (void*)rvec,
                          (void*)riovcnt,
                          (void*)flags);
}
long sys_kcmp(pid_t pid1, pid_t pid2, i32 type, u64 idx1, u64 idx2) {
    return (long)syscall5(
        SYS_kcmp, (void*)(usize)pid1, (void*)(usize)pid2, (void*)(usize)type, (void*)idx1, (void*)idx2);
}
long sys_finit_module(i32 fd, const char* uargs, i32 flags) {
    return (long)syscall3(SYS_finit_module, (void*)(usize)fd, (void*)uargs, (void*)(usize)flags);
}
long sys_sched_setattr(pid_t pid, struct sched_attr* attr, u32 flags) {
    return (long)syscall3(SYS_sched_setattr, (void*)(usize)pid, (void*)attr, (void*)(usize)flags);
}
long sys_sched_getattr(pid_t pid, struct sched_attr* attr, u32 size, u32 flags) {
    return (long)syscall4(SYS_sched_getattr, (void*)(usize)pid, (void*)attr, (void*)(usize)size, (void*)(usize)flags);
}
long sys_renameat2(i32 olddfd, const char* oldname, i32 newdfd, const char* newname, u32 flags) {
    return (long)syscall5(
        SYS_renameat2, (void*)(usize)olddfd, (void*)oldname, (void*)(usize)newdfd, (void*)newname, (void*)(usize)flags);
}
long sys_seccomp(u32 op, u32 flags, void* uargs) {
    return (long)syscall3(SYS_seccomp, (void*)(usize)op, (void*)(usize)flags, (void*)uargs);
}
long sys_getrandom(char* buf, usize count, u32 flags) {
    return (long)syscall3(SYS_getrandom, (void*)buf, (void*)count, (void*)(usize)flags);
}
long sys_memfd_create(const char* uname_ptr, u32 flags) {
    return (long)syscall2(SYS_memfd_create, (void*)uname_ptr, (void*)(usize)flags);
}
long sys_bpf(i32 cmd, union bpf_attr* attr, u32 size) {
    return (long)syscall3(SYS_bpf, (void*)(usize)cmd, (void*)attr, (void*)(usize)size);
}
long sys_execveat(i32 dfd, const char* filename, const char* const* argv, const char* const* envp, i32 flags) {
    return (long)syscall5(
        SYS_execveat, (void*)(usize)dfd, (void*)filename, (void*)argv, (void*)envp, (void*)(usize)flags);
}
long sys_userfaultfd(i32 flags) {
    return (long)syscall1(SYS_userfaultfd, (void*)(usize)flags);
}
long sys_membarrier(i32 cmd, u32 flags, i32 cpu_id) {
    return (long)syscall3(SYS_membarrier, (void*)(usize)cmd, (void*)(usize)flags, (void*)(usize)cpu_id);
}
long sys_mlock2(u64 start, usize len, i32 flags) {
    return (long)syscall3(SYS_mlock2, (void*)start, (void*)len, (void*)(usize)flags);
}
long sys_copy_file_range(i32 fd_in, loff_t* off_in, i32 fd_out, loff_t* off_out, usize len, u32 flags) {
    return (long)syscall6(SYS_copy_file_range,
                          (void*)(usize)fd_in,
                          (void*)off_in,
                          (void*)(usize)fd_out,
                          (void*)off_out,
                          (void*)len,
                          (void*)(usize)flags);
}
long sys_preadv2(u64 fd, const struct iovec* vec, u64 vlen, u64 pos_l, u64 pos_h, rwf_t flags) {
    return (long)syscall6(
        SYS_preadv2, (void*)fd, (void*)vec, (void*)vlen, (void*)pos_l, (void*)pos_h, (void*)(usize)flags);
}
long sys_pwritev2(u64 fd, const struct iovec* vec, u64 vlen, u64 pos_l, u64 pos_h, rwf_t flags) {
    return (long)syscall6(
        SYS_pwritev2, (void*)fd, (void*)vec, (void*)vlen, (void*)pos_l, (void*)pos_h, (void*)(usize)flags);
}
long sys_pkey_mprotect(u64 start, usize len, u64 prot, i32 pkey) {
    return (long)syscall4(SYS_pkey_mprotect, (void*)start, (void*)len, (void*)prot, (void*)(usize)pkey);
}
long sys_pkey_alloc(u64 flags, u64 init_val) {
    return (long)syscall2(SYS_pkey_alloc, (void*)flags, (void*)init_val);
}
long sys_pkey_free(i32 pkey) {
    return (long)syscall1(SYS_pkey_free, (void*)(usize)pkey);
}
long sys_statx(i32 dfd, const char* path, u32 flags, u32 mask, struct statx* buffer) {
    return (long)syscall5(
        SYS_statx, (void*)(usize)dfd, (void*)path, (void*)(usize)flags, (void*)(usize)mask, (void*)buffer);
}
long sys_rseq(struct rseq* rseq, u32 rseq_len, i32 flags, u32 sig) {
    return (long)syscall4(SYS_rseq, (void*)rseq, (void*)(usize)rseq_len, (void*)(usize)flags, (void*)(usize)sig);
}
long sys_open_tree(i32 dfd, const char* path, u32 flags) {
    return (long)syscall3(SYS_open_tree, (void*)(usize)dfd, (void*)path, (void*)(usize)flags);
}
long sys_move_mount(i32 from_dfd, const char* from_path, i32 to_dfd, const char* to_path, u32 ms_flags) {
    return (long)syscall5(SYS_move_mount,
                          (void*)(usize)from_dfd,
                          (void*)from_path,
                          (void*)(usize)to_dfd,
                          (void*)to_path,
                          (void*)(usize)ms_flags);
}
long sys_mount_setattr(i32 dfd, const char* path, u32 flags, struct mount_attr* uattr, usize size) {
    return (long)syscall5(
        SYS_mount_setattr, (void*)(usize)dfd, (void*)path, (void*)(usize)flags, (void*)uattr, (void*)size);
}
long sys_fsopen(const char* fs_name, u32 flags) {
    return (long)syscall2(SYS_fsopen, (void*)fs_name, (void*)(usize)flags);
}
long sys_fsconfig(i32 fs_fd, u32 cmd, const char* key, const void* value, i32 aux) {
    return (long)syscall5(
        SYS_fsconfig, (void*)(usize)fs_fd, (void*)(usize)cmd, (void*)key, (void*)value, (void*)(usize)aux);
}
long sys_fsmount(i32 fs_fd, u32 flags, u32 ms_flags) {
    return (long)syscall3(SYS_fsmount, (void*)(usize)fs_fd, (void*)(usize)flags, (void*)(usize)ms_flags);
}
long sys_fspick(i32 dfd, const char* path, u32 flags) {
    return (long)syscall3(SYS_fspick, (void*)(usize)dfd, (void*)path, (void*)(usize)flags);
}
long sys_pidfd_send_signal(i32 pidfd, i32 sig, siginfo_t* info, u32 flags) {
    return (long)syscall4(
        SYS_pidfd_send_signal, (void*)(usize)pidfd, (void*)(usize)sig, (void*)info, (void*)(usize)flags);
}
long sys_pidfd_getfd(i32 pidfd, i32 fd, u32 flags) {
    return (long)syscall3(SYS_pidfd_getfd, (void*)(usize)pidfd, (void*)(usize)fd, (void*)(usize)flags);
}
long sys_landlock_create_ruleset(const struct landlock_ruleset_attr* attr, usize size, u32 flags) {
    return (long)syscall3(SYS_landlock_create_ruleset, (void*)attr, (void*)size, (void*)(usize)flags);
}
long sys_landlock_add_rule(i32 ruleset_fd, enum landlock_rule_type rule_type, const void* rule_attr, u32 flags) {
    return (long)syscall4(
        SYS_landlock_add_rule, (void*)(usize)ruleset_fd, (void*)rule_type, (void*)rule_attr, (void*)(usize)flags);
}
long sys_landlock_restrict_self(i32 ruleset_fd, u32 flags) {
    return (long)syscall2(SYS_landlock_restrict_self, (void*)(usize)ruleset_fd, (void*)(usize)flags);
}
long sys_memfd_secret(u32 flags) {
    return (long)syscall1(SYS_memfd_secret, (void*)(usize)flags);
}
long sys_set_mempolicy_home_node(u64 start, u64 len, u64 home_node, u64 flags) {
    return (long)syscall4(SYS_set_mempolicy_home_node, (void*)start, (void*)len, (void*)home_node, (void*)flags);
}
long sys_cachestat(u32 fd, struct cachestat_range* cstat_range, struct cachestat* cstat, u32 flags) {
    return (long)syscall4(SYS_cachestat, (void*)(usize)fd, (void*)cstat_range, (void*)cstat, (void*)(usize)flags);
}
long sys_map_shadow_stack(u64 addr, u64 size, u32 flags) {
    return (long)syscall3(SYS_map_shadow_stack, (void*)addr, (void*)size, (void*)(usize)flags);
}
long sys_lsm_get_self_attr(u32 attr, struct lsm_ctx* ctx, u32* size, u32 flags) {
    return (long)syscall4(SYS_lsm_get_self_attr, (void*)(usize)attr, (void*)ctx, (void*)size, (void*)(usize)flags);
}
long sys_lsm_set_self_attr(u32 attr, struct lsm_ctx* ctx, u32 size, u32 flags) {
    return (long)syscall4(
        SYS_lsm_set_self_attr, (void*)(usize)attr, (void*)ctx, (void*)(usize)size, (void*)(usize)flags);
}
long sys_lsm_list_modules(u64* ids, u32* size, u32 flags) {
    return (long)syscall3(SYS_lsm_list_modules, (void*)ids, (void*)size, (void*)(usize)flags);
}
long sys_ioperm(u64 from, u64 num, i32 on) {
    return (long)syscall3(SYS_ioperm, (void*)from, (void*)num, (void*)(usize)on);
}
i32 sys_open(const char* filename, i32 flags, umode_t mode) {
    return (i32)(usize)syscall3(SYS_open, (void*)filename, (void*)(usize)flags, (void*)(usize)mode);
}
long sys_link(const char* oldname, const char* newname) {
    return (long)syscall2(SYS_link, (void*)oldname, (void*)newname);
}
long sys_unlink(const char* pathname) {
    return (long)syscall1(SYS_unlink, (void*)pathname);
}
long sys_mknod(const char* filename, umode_t mode, u32 dev) {
    return (long)syscall3(SYS_mknod, (void*)filename, (void*)(usize)mode, (void*)(usize)dev);
}
long sys_chmod(const char* filename, umode_t mode) {
    return (long)syscall2(SYS_chmod, (void*)filename, (void*)(usize)mode);
}
long sys_chown(const char* filename, uid_t user, gid_t group) {
    return (long)syscall3(SYS_chown, (void*)filename, (void*)(usize)user, (void*)(usize)group);
}
long sys_mkdir(const char* pathname, umode_t mode) {
    return (long)syscall2(SYS_mkdir, (void*)pathname, (void*)(usize)mode);
}
long sys_rmdir(const char* pathname) {
    return (long)syscall1(SYS_rmdir, (void*)pathname);
}
long sys_lchown(const char* filename, uid_t user, gid_t group) {
    return (long)syscall3(SYS_lchown, (void*)filename, (void*)(usize)user, (void*)(usize)group);
}
long sys_access(const char* filename, i32 mode) {
    return (long)syscall2(SYS_access, (void*)filename, (void*)(usize)mode);
}
long sys_rename(const char* oldname, const char* newname) {
    return (long)syscall2(SYS_rename, (void*)oldname, (void*)newname);
}
long sys_symlink(const char* old, const char* new) {
    return (long)syscall2(SYS_symlink, (void*)old, (void*)new);
}
long sys_pipe(i32* fildes) {
    return (long)syscall1(SYS_pipe, (void*)fildes);
}
long sys_dup2(u32 oldfd, u32 newfd) {
    return (long)syscall2(SYS_dup2, (void*)(usize)oldfd, (void*)(usize)newfd);
}
long sys_epoll_create(i32 size) {
    return (long)syscall1(SYS_epoll_create, (void*)(usize)size);
}
long sys_inotify_init(void) {
    return (long)syscall0(SYS_inotify_init);
}
long sys_eventfd(u32 count) {
    return (long)syscall1(SYS_eventfd, (void*)(usize)count);
}
long sys_signalfd(i32 ufd, sigset_t* user_mask, usize sizemask) {
    return (long)syscall3(SYS_signalfd, (void*)(usize)ufd, (void*)user_mask, (void*)sizemask);
}
long sys_fadvise64(i32 fd, loff_t offset, usize len, i32 advice) {
    return (long)syscall4(SYS_fadvise64, (void*)(usize)fd, (void*)offset, (void*)len, (void*)(usize)advice);
}
long sys_alarm(u32 seconds) {
    return (long)syscall1(SYS_alarm, (void*)(usize)seconds);
}
long sys_getpgrp(void) {
    return (long)syscall0(SYS_getpgrp);
}
long sys_pause(void) {
    return (long)syscall0(SYS_pause);
}
long sys_time(__kernel_old_time_t* tloc) {
    return (long)syscall1(SYS_time, (void*)tloc);
}
long sys_utime(char* filename, struct utimbuf* times) {
    return (long)syscall2(SYS_utime, (void*)filename, (void*)times);
}
long sys_utimes(char* filename, struct __kernel_old_timeval* utimes) {
    return (long)syscall2(SYS_utimes, (void*)filename, (void*)utimes);
}
long sys_futimesat(i32 dfd, const char* filename, struct __kernel_old_timeval* utimes) {
    return (long)syscall3(SYS_futimesat, (void*)(usize)dfd, (void*)filename, (void*)utimes);
}
i32 sys_creat(const char* pathname, umode_t mode) {
    return (i32)(usize)syscall2(SYS_creat, (void*)pathname, (void*)(usize)mode);
}
long sys_getdents(u32 fd, struct linux_dirent* dirent, u32 count) {
    return (long)syscall3(SYS_getdents, (void*)(usize)fd, (void*)dirent, (void*)(usize)count);
}
long sys_select(i32 n, fd_set* inp, fd_set* outp, fd_set* exp, struct __kernel_old_timeval* tvp) {
    return (long)syscall5(SYS_select, (void*)(usize)n, (void*)inp, (void*)outp, (void*)exp, (void*)tvp);
}
long sys_poll(struct pollfd* ufds, u32 nfds, i32 timeout) {
    return (long)syscall3(SYS_poll, (void*)ufds, (void*)(usize)nfds, (void*)(usize)timeout);
}
long sys_epoll_wait(i32 epfd, struct epoll_event* events, i32 maxevents, i32 timeout) {
    return (long)syscall4(
        SYS_epoll_wait, (void*)(usize)epfd, (void*)events, (void*)(usize)maxevents, (void*)(usize)timeout);
}
long sys_ustat(u32 dev, struct ustat* ubuf) {
    return (long)syscall2(SYS_ustat, (void*)(usize)dev, (void*)ubuf);
}
long sys_vfork(void) {
    return (long)syscall0(SYS_vfork);
}
long sys_uselib(const char* library) {
    return (long)syscall1(SYS_uselib, (void*)library);
}
long sys_sysfs(i32 option, u64 arg1, u64 arg2) {
    return (long)syscall3(SYS_sysfs, (void*)(usize)option, (void*)arg1, (void*)arg2);
}
long sys_fork(void) {
    return (long)syscall0(SYS_fork);
}
long sys_kexec_file_load(i32 kernel_fd, i32 initrd_fd, u64 cmdline_len, const char* cmdline_ptr, u64 flags) {
    return (long)syscall5(SYS_kexec_file_load,
                          (void*)(usize)kernel_fd,
                          (void*)(usize)initrd_fd,
                          (void*)cmdline_len,
                          (void*)cmdline_ptr,
                          (void*)flags);
}
i32 sys_stat(const char* filename, struct stat* statbuf) {
    return (i32)(usize)syscall2(SYS_stat, (void*)filename, (void*)statbuf);
}
i32 sys_lstat(const char* filename, struct stat* statbuf) {
    return (i32)(usize)syscall2(SYS_lstat, (void*)filename, (void*)statbuf);
}
i32 sys_fstat(u32 fd, struct stat* statbuf) {
    return (i32)(usize)syscall2(SYS_fstat, (void*)(usize)fd, (void*)statbuf);
}
isize sys_readlink(const char* path, char* buf, i32 bufsiz) {
    return (isize)syscall3(SYS_readlink, (void*)path, (void*)buf, (void*)(usize)bufsiz);
}
i32 sys_uname(struct new_utsname* name) {
    return (i32)(usize)syscall1(SYS_uname, (void*)name);
}
#pragma GCC diagnostic pop
