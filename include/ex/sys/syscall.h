/// Provides raw Linux system calls of various argument widths
///
/// Provides typed wrappers around specific system calls that have types matching
/// the kernel types. These types can be found in `kernel_types.h` and `user_types.h`
#pragma once

#include <ex/sys/kernel_types.h>
#include <exalt.h>

extern void* syscall0(usize syscall_number);
extern void* syscall1(usize syscall_number, void* arg1);
extern void* syscall2(usize syscall_number, void* arg1, void* arg2);
extern void* syscall3(usize syscall_number, void* arg1, void* arg2, void* arg3);
extern void* syscall4(usize syscall_number, void* arg1, void* arg2, void* arg3, void* arg4);
extern void* syscall5(usize syscall_number, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5);
extern void* syscall6(usize syscall_number, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6);

struct dummy {
    int _f[0];
};

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_stat 4
#define SYS_fstat 5
#define SYS_lstat 6
#define SYS_poll 7
#define SYS_lseek 8
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_brk 12
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigreturn 15
#define SYS_ioctl 16
#define SYS_pread64 17
#define SYS_pwrite64 18
#define SYS_readv 19
#define SYS_writev 20
#define SYS_access 21
#define SYS_pipe 22
#define SYS_select 23
#define SYS_sched_yield 24
#define SYS_mremap 25
#define SYS_msync 26
#define SYS_mincore 27
#define SYS_madvise 28
#define SYS_shmget 29
#define SYS_shmat 30
#define SYS_shmctl 31
#define SYS_dup 32
#define SYS_dup2 33
#define SYS_pause 34
#define SYS_nanosleep 35
#define SYS_getitimer 36
#define SYS_alarm 37
#define SYS_setitimer 38
#define SYS_getpid 39
#define SYS_sendfile 40
#define SYS_socket 41
#define SYS_connect 42
#define SYS_accept 43
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_sendmsg 46
#define SYS_recvmsg 47
#define SYS_shutdown 48
#define SYS_bind 49
#define SYS_listen 50
#define SYS_getsockname 51
#define SYS_getpeername 52
#define SYS_socketpair 53
#define SYS_setsockopt 54
#define SYS_getsockopt 55
#define SYS_clone 56
#define SYS_fork 57
#define SYS_vfork 58
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_uname 63
#define SYS_semget 64
#define SYS_semop 65
#define SYS_semctl 66
#define SYS_shmdt 67
#define SYS_msgget 68
#define SYS_msgsnd 69
#define SYS_msgrcv 70
#define SYS_msgctl 71
#define SYS_fcntl 72
#define SYS_flock 73
#define SYS_fsync 74
#define SYS_fdatasync 75
#define SYS_truncate 76
#define SYS_ftruncate 77
#define SYS_getdents 78
#define SYS_getcwd 79
#define SYS_chdir 80
#define SYS_fchdir 81
#define SYS_rename 82
#define SYS_mkdir 83
#define SYS_rmdir 84
#define SYS_creat 85
#define SYS_link 86
#define SYS_unlink 87
#define SYS_symlink 88
#define SYS_readlink 89
#define SYS_chmod 90
#define SYS_fchmod 91
#define SYS_chown 92
#define SYS_fchown 93
#define SYS_lchown 94
#define SYS_umask 95
#define SYS_gettimeofday 96
#define SYS_getrlimit 97
#define SYS_getrusage 98
#define SYS_sysinfo 99
#define SYS_times 100
#define SYS_ptrace 101
#define SYS_getuid 102
#define SYS_syslog 103
#define SYS_getgid 104
#define SYS_setuid 105
#define SYS_setgid 106
#define SYS_geteuid 107
#define SYS_getegid 108
#define SYS_setpgid 109
#define SYS_getppid 110
#define SYS_getpgrp 111
#define SYS_setsid 112
#define SYS_setreuid 113
#define SYS_setregid 114
#define SYS_getgroups 115
#define SYS_setgroups 116
#define SYS_setresuid 117
#define SYS_getresuid 118
#define SYS_setresgid 119
#define SYS_getresgid 120
#define SYS_getpgid 121
#define SYS_setfsuid 122
#define SYS_setfsgid 123
#define SYS_getsid 124
#define SYS_capget 125
#define SYS_capset 126
#define SYS_rt_sigpending 127
#define SYS_rt_sigtimedwait 128
#define SYS_rt_sigqueueinfo 129
#define SYS_rt_sigsuspend 130
#define SYS_sigaltstack 131
#define SYS_utime 132
#define SYS_mknod 133
#define SYS_uselib 134
#define SYS_personality 135
#define SYS_ustat 136
#define SYS_statfs 137
#define SYS_fstatfs 138
#define SYS_sysfs 139
#define SYS_getpriority 140
#define SYS_setpriority 141
#define SYS_sched_setparam 142
#define SYS_sched_getparam 143
#define SYS_sched_setscheduler 144
#define SYS_sched_getscheduler 145
#define SYS_sched_get_priority_max 146
#define SYS_sched_get_priority_min 147
#define SYS_sched_rr_get_interval 148
#define SYS_mlock 149
#define SYS_munlock 150
#define SYS_mlockall 151
#define SYS_munlockall 152
#define SYS_vhangup 153
#define SYS_modify_ldt 154
#define SYS_pivot_root 155
#define SYS__sysctl 156
#define SYS_prctl 157
#define SYS_arch_prctl 158
#define SYS_adjtimex 159
#define SYS_setrlimit 160
#define SYS_chroot 161
#define SYS_sync 162
#define SYS_acct 163
#define SYS_settimeofday 164
#define SYS_mount 165
#define SYS_umount2 166
#define SYS_swapon 167
#define SYS_swapoff 168
#define SYS_reboot 169
#define SYS_sethostname 170
#define SYS_setdomainname 171
#define SYS_iopl 172
#define SYS_ioperm 173
#define SYS_create_module 174
#define SYS_init_module 175
#define SYS_delete_module 176
#define SYS_get_kernel_syms 177
#define SYS_query_module 178
#define SYS_quotactl 179
#define SYS_nfsservctl 180
#define SYS_getpmsg 181
#define SYS_putpmsg 182
#define SYS_afs_syscall 183
#define SYS_tuxcall 184
#define SYS_security 185
#define SYS_gettid 186
#define SYS_readahead 187
#define SYS_setxattr 188
#define SYS_lsetxattr 189
#define SYS_fsetxattr 190
#define SYS_getxattr 191
#define SYS_lgetxattr 192
#define SYS_fgetxattr 193
#define SYS_listxattr 194
#define SYS_llistxattr 195
#define SYS_flistxattr 196
#define SYS_removexattr 197
#define SYS_lremovexattr 198
#define SYS_fremovexattr 199
#define SYS_tkill 200
#define SYS_time 201
#define SYS_futex 202
#define SYS_sched_setaffinity 203
#define SYS_sched_getaffinity 204
#define SYS_set_thread_area 205
#define SYS_io_setup 206
#define SYS_io_destroy 207
#define SYS_io_getevents 208
#define SYS_io_submit 209
#define SYS_io_cancel 210
#define SYS_get_thread_area 211
#define SYS_lookup_dcookie 212
#define SYS_epoll_create 213
#define SYS_epoll_ctl_old 214
#define SYS_epoll_wait_old 215
#define SYS_remap_file_pages 216
#define SYS_getdents64 217
#define SYS_set_tid_address 218
#define SYS_restart_syscall 219
#define SYS_semtimedop 220
#define SYS_fadvise64 221
#define SYS_timer_create 222
#define SYS_timer_settime 223
#define SYS_timer_gettime 224
#define SYS_timer_getoverrun 225
#define SYS_timer_delete 226
#define SYS_clock_settime 227
#define SYS_clock_gettime 228
#define SYS_clock_getres 229
#define SYS_clock_nanosleep 230
#define SYS_exit_group 231
#define SYS_epoll_wait 232
#define SYS_epoll_ctl 233
#define SYS_tgkill 234
#define SYS_utimes 235
#define SYS_vserver 236
#define SYS_mbind 237
#define SYS_set_mempolicy 238
#define SYS_get_mempolicy 239
#define SYS_mq_open 240
#define SYS_mq_unlink 241
#define SYS_mq_timedsend 242
#define SYS_mq_timedreceive 243
#define SYS_mq_notify 244
#define SYS_mq_getsetattr 245
#define SYS_kexec_load 246
#define SYS_waitid 247
#define SYS_add_key 248
#define SYS_request_key 249
#define SYS_keyctl 250
#define SYS_ioprio_set 251
#define SYS_ioprio_get 252
#define SYS_inotify_init 253
#define SYS_inotify_add_watch 254
#define SYS_inotify_rm_watch 255
#define SYS_migrate_pages 256
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_mknodat 259
#define SYS_fchownat 260
#define SYS_futimesat 261
#define SYS_newfstatat 262
#define SYS_unlinkat 263
#define SYS_renameat 264
#define SYS_linkat 265
#define SYS_symlinkat 266
#define SYS_readlinkat 267
#define SYS_fchmodat 268
#define SYS_faccessat 269
#define SYS_pselect6 270
#define SYS_ppoll 271
#define SYS_unshare 272
#define SYS_set_robust_list 273
#define SYS_get_robust_list 274
#define SYS_splice 275
#define SYS_tee 276
#define SYS_sync_file_range 277
#define SYS_vmsplice 278
#define SYS_move_pages 279
#define SYS_utimensat 280
#define SYS_epoll_pwait 281
#define SYS_signalfd 282
#define SYS_timerfd_create 283
#define SYS_eventfd 284
#define SYS_fallocate 285
#define SYS_timerfd_settime 286
#define SYS_timerfd_gettime 287
#define SYS_accept4 288
#define SYS_signalfd4 289
#define SYS_eventfd2 290
#define SYS_epoll_create1 291
#define SYS_dup3 292
#define SYS_pipe2 293
#define SYS_inotify_init1 294
#define SYS_preadv 295
#define SYS_pwritev 296
#define SYS_rt_tgsigqueueinfo 297
#define SYS_perf_event_open 298
#define SYS_recvmmsg 299
#define SYS_fanotify_init 300
#define SYS_fanotify_mark 301
#define SYS_prlimit64 302
#define SYS_name_to_handle_at 303
#define SYS_open_by_handle_at 304
#define SYS_clock_adjtime 305
#define SYS_syncfs 306
#define SYS_sendmmsg 307
#define SYS_setns 308
#define SYS_getcpu 309
#define SYS_process_vm_readv 310
#define SYS_process_vm_writev 311
#define SYS_kcmp 312
#define SYS_finit_module 313
#define SYS_sched_setattr 314
#define SYS_sched_getattr 315
#define SYS_renameat2 316
#define SYS_seccomp 317
#define SYS_getrandom 318
#define SYS_memfd_create 319
#define SYS_kexec_file_load 320
#define SYS_bpf 321
#define SYS_execveat 322
#define SYS_userfaultfd 323
#define SYS_membarrier 324
#define SYS_mlock2 325
#define SYS_copy_file_range 326
#define SYS_preadv2 327
#define SYS_pwritev2 328
#define SYS_pkey_mprotect 329
#define SYS_pkey_alloc 330
#define SYS_pkey_free 331
#define SYS_statx 332
#define SYS_io_pgetevents 333
#define SYS_rseq 334
#define SYS_pidfd_send_signal 424
#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#define SYS_open_tree 428
#define SYS_move_mount 429
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#define SYS_fspick 433
#define SYS_pidfd_open 434
#define SYS_clone3 435
#define SYS_close_range 436
#define SYS_openat2 437
#define SYS_pidfd_getfd 438
#define SYS_faccessat2 439
#define SYS_process_madvise 440
#define SYS_epoll_pwait2 441
#define SYS_mount_setattr 442
#define SYS_quotactl_fd 443
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#define SYS_memfd_secret 447
#define SYS_process_mrelease 448
#define SYS_futex_waitv 449
#define SYS_set_mempolicy_home_node 450
#define SYS_cachestat 451
#define SYS_fchmodat2 452
#define SYS_map_shadow_stack 453
#define SYS_futex_wake 454
#define SYS_futex_wait 455
#define SYS_futex_requeue 456
#define SYS_statmount 457
#define SYS_listmount 458
#define SYS_lsm_get_self_attr 459
#define SYS_lsm_set_self_attr 460
#define SYS_lsm_list_modules 461

long sys_io_setup(u32 nr_reqs, aio_context_t* ctx);
long sys_io_destroy(aio_context_t ctx);
long sys_io_submit(aio_context_t ctx_id, i64 nr, struct iocb** iocbpp);
long sys_io_cancel(aio_context_t ctx_id, struct iocb* iocb, struct io_event* result);
long sys_io_getevents(
    aio_context_t ctx_id, i64 min_nr, i64 nr, struct io_event* events, struct __kernel_timespec* timeout);
long sys_io_pgetevents(aio_context_t ctx_id,
                       i64 min_nr,
                       i64 nr,
                       struct io_event* events,
                       struct __kernel_timespec* timeout,
                       const struct __aio_sigset* sig);
long sys_io_uring_setup(u32 entries, struct io_uring_params* p);
long sys_io_uring_enter(u32 fd, u32 to_submit, u32 min_complete, u32 flags, const void* argp, usize argsz);
long sys_io_uring_register(u32 fd, u32 op, void* arg, u32 nr_args);
long sys_setxattr(const char* path, const char* name, const void* value, usize size, i32 flags);
long sys_lsetxattr(const char* path, const char* name, const void* value, usize size, i32 flags);
long sys_fsetxattr(i32 fd, const char* name, const void* value, usize size, i32 flags);
long sys_getxattr(const char* path, const char* name, void* value, usize size);
long sys_lgetxattr(const char* path, const char* name, void* value, usize size);
long sys_fgetxattr(i32 fd, const char* name, void* value, usize size);
long sys_listxattr(const char* path, char* list, usize size);
long sys_llistxattr(const char* path, char* list, usize size);
long sys_flistxattr(i32 fd, char* list, usize size);
long sys_removexattr(const char* path, const char* name);
long sys_lremovexattr(const char* path, const char* name);
long sys_fremovexattr(i32 fd, const char* name);
long sys_getcwd(char* buf, u64 size);
long sys_eventfd2(u32 count, i32 flags);
long sys_epoll_create1(i32 flags);
long sys_epoll_ctl(i32 epfd, i32 op, i32 fd, struct epoll_event* event);
long sys_epoll_pwait(
    i32 epfd, struct epoll_event* events, i32 maxevents, i32 timeout, const sigset_t* sigmask, usize sigsetsize);
long sys_epoll_pwait2(i32 epfd,
                      struct epoll_event* events,
                      i32 maxevents,
                      const struct __kernel_timespec* timeout,
                      const sigset_t* sigmask,
                      usize sigsetsize);
long sys_dup(u32 fildes);
long sys_dup3(u32 oldfd, u32 newfd, i32 flags);
long sys_fcntl(u32 fd, u32 cmd, u64 arg);
long sys_inotify_init1(i32 flags);
long sys_inotify_add_watch(i32 fd, const char* path, u32 mask);
long sys_inotify_rm_watch(i32 fd, i32 wd);
long sys_ioctl(u32 fd, u32 cmd, u64 arg);
long sys_ioprio_set(i32 which, i32 who, i32 ioprio);
long sys_ioprio_get(i32 which, i32 who);
long sys_flock(u32 fd, u32 cmd);
long sys_mknodat(i32 dfd, const char* filename, umode_t mode, u32 dev);
long sys_mkdirat(i32 dfd, const char* pathname, umode_t mode);
long sys_unlinkat(i32 dfd, const char* pathname, i32 flag);
long sys_symlinkat(const char* oldname, i32 newdfd, const char* newname);
long sys_linkat(i32 olddfd, const char* oldname, i32 newdfd, const char* newname, i32 flags);
long sys_renameat(i32 olddfd, const char* oldname, i32 newdfd, const char* newname);
long sys_umount2(char* name, i32 flags);
long sys_mount(char* dev_name, char* dir_name, char* type, u64 flags, void* data);
long sys_pivot_root(const char* new_root, const char* put_old);
long sys_statfs(const char* path, struct statfs* buf);
long sys_fstatfs(u32 fd, struct statfs* buf);
long sys_statmount(const struct mnt_id_req* req, struct statmount* buf, usize bufsize, u32 flags);
long sys_listmount(const struct mnt_id_req* req, u64* mnt_ids, usize nr_mnt_ids, u32 flags);
long sys_truncate(const char* path, loff_t length);
long sys_ftruncate(u32 fd, loff_t length);
long sys_fallocate(i32 fd, i32 mode, loff_t offset, loff_t len);
long sys_faccessat(i32 dfd, const char* filename, i32 mode);
long sys_faccessat2(i32 dfd, const char* filename, i32 mode, i32 flags);
long sys_chdir(const char* filename);
long sys_fchdir(u32 fd);
long sys_chroot(const char* filename);
long sys_fchmod(u32 fd, umode_t mode);
long sys_fchmodat(i32 dfd, const char* filename, umode_t mode);
long sys_fchmodat2(i32 dfd, const char* filename, umode_t mode, u32 flags);
long sys_fchownat(i32 dfd, const char* filename, uid_t user, gid_t group, i32 flag);
long sys_fchown(u32 fd, uid_t user, gid_t group);
/// On success returns the new file descriptor. On error returns -errno.
i32 sys_openat(i32 dfd, const char* filename, i32 flags, umode_t mode);
/// On success returns the new file descriptor. On error returns -errno.
long sys_openat2(i32 dfd, const char* filename, struct open_how* how, usize size);
long sys_close(u32 fd);
long sys_close_range(u32 fd, u32 max_fd, u32 flags);
long sys_vhangup(void);
long sys_pipe2(i32* fildes, i32 flags);
long sys_quotactl(u32 cmd, const char* special, qid_t id, void* addr);
long sys_quotactl_fd(u32 fd, u32 cmd, qid_t id, void* addr);
long sys_getdents64(u32 fd, struct linux_dirent64* dirent, u32 count);
long sys_lseek(u32 fd, off_t offset, u32 whence);
/// On success, the number of bytes read is returned (0 indicated EOF) and the file position is advanced by the same
/// number. On error, -errno is returned.
isize sys_read(u32 fd, char* buf, usize count);
/// On success, the number of bytes written is returned. On error, -errno is returned.
long sys_write(u32 fd, const char* buf, usize count);
long sys_readv(u64 fd, const struct iovec* vec, u64 vlen);
long sys_writev(u64 fd, const struct iovec* vec, u64 vlen);
long sys_pread64(u32 fd, char* buf, usize count, loff_t pos);
long sys_pwrite64(u32 fd, const char* buf, usize count, loff_t pos);
long sys_preadv(u64 fd, const struct iovec* vec, u64 vlen, u64 pos_l, u64 pos_h);
long sys_pwritev(u64 fd, const struct iovec* vec, u64 vlen, u64 pos_l, u64 pos_h);
long sys_sendfile(i32 out_fd, i32 in_fd, loff_t* offset, usize count);
/// On succes, the number of file descriptors containted in the 3 passed descriptor sets is returned.
/// On error, -errno is returned.
int sys_pselect6(
    i32 nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct __kernel_timespec* timeout, void* sigmask);
long sys_ppoll(
    struct pollfd* fds, u32 nfds, struct __kernel_timespec* tmo_p, const sigset_t* sigmask, usize sigsetsize);
long sys_signalfd4(i32 ufd, sigset_t* user_mask, usize sizemask, i32 flags);
long sys_vmsplice(i32 fd, const struct iovec* iov, u64 nr_segs, u32 flags);
long sys_splice(i32 fd_in, loff_t* off_in, i32 fd_out, loff_t* off_out, usize len, u32 flags);
long sys_tee(i32 fdin, i32 fdout, usize len, u32 flags);
/// On success, returns the number of bytes placed in `buf`. If the returned value equals `bufsiz` truncation may have
/// occurred. On error, -errno is returned.
isize sys_readlinkat(i32 dfd, const char* path, char* buf, i32 bufsiz);
/// On success, zero is returned.  On error, -errno is returned.
i32 sys_newfstatat(i32 dfd, const char* filename, struct stat* statbuf, i32 flag);
long sys_sync(void);
long sys_fsync(u32 fd);
long sys_fdatasync(u32 fd);
long sys_sync_file_range(i32 fd, loff_t offset, loff_t nbytes, u32 flags);
long sys_timerfd_create(i32 clockid, i32 flags);
long sys_timerfd_settime(i32 ufd, i32 flags, const struct __kernel_itimerspec* utmr, struct __kernel_itimerspec* otmr);
long sys_timerfd_gettime(i32 ufd, struct __kernel_itimerspec* otmr);
long sys_utimensat(i32 dfd, const char* filename, struct __kernel_timespec* utimes, i32 flags);
long sys_acct(const char* name);
long sys_capget(cap_user_header_t header, cap_user_data_t dataptr);
long sys_capset(cap_user_header_t header, const cap_user_data_t data);
long sys_personality(u32 personality);
/// Terminates the calling process immediately. This function never returns.
__attribute__((noreturn)) void sys_exit(i32 error_code);
/// Terminates all thread in the calling process's thread group immediately. This function never returns.
__attribute__((noreturn)) void sys_exit_group(i32 error_code);
long sys_waitid(i32 which, pid_t pid, struct siginfo* infop, i32 options, struct rusage* ru);
long sys_set_tid_address(i32* tidptr);
long sys_unshare(u64 unshare_flags);
long sys_futex(u32* uaddr, i32 op, u32 val, const struct __kernel_timespec* utime, u32* uaddr2, u32 val3);
long sys_get_robust_list(i32 pid, struct robust_list_head** head_ptr, usize* len_ptr);
long sys_set_robust_list(struct robust_list_head* head, usize len);
long sys_futex_waitv(
    struct futex_waitv* waiters, u32 nr_futexes, u32 flags, struct __kernel_timespec* timeout, clockid_t clockid);
long sys_futex_wake(void* uaddr, u64 mask, i32 nr, u32 flags);
long sys_futex_wait(void* uaddr, u64 val, u64 mask, u32 flags, struct __kernel_timespec* timespec, clockid_t clockid);
long sys_futex_requeue(struct futex_waitv* waiters, u32 flags, i32 nr_wake, i32 nr_requeue);
long sys_nanosleep(struct __kernel_timespec* rqtp, struct __kernel_timespec* rmtp);
long sys_getitimer(i32 which, struct __kernel_old_itimerval* value);
long sys_setitimer(i32 which, struct __kernel_old_itimerval* value, struct __kernel_old_itimerval* ovalue);
long sys_kexec_load(u64 entry, u64 nr_segments, struct kexec_segment* segments, u64 flags);
long sys_init_module(void* umod, u64 len, const char* uargs);
long sys_delete_module(const char* name_user, u32 flags);
long sys_timer_create(clockid_t which_clock, struct sigevent* timer_event_spec, timer_t* created_timer_id);
long sys_timer_gettime(timer_t timer_id, struct __kernel_itimerspec* setting);
long sys_timer_getoverrun(timer_t timer_id);
long sys_timer_settime(timer_t timer_id,
                       i32 flags,
                       const struct __kernel_itimerspec* new_setting,
                       struct __kernel_itimerspec* old_setting);
long sys_timer_delete(timer_t timer_id);
long sys_clock_settime(clockid_t which_clock, const struct __kernel_timespec* tp);
long sys_clock_gettime(clockid_t which_clock, struct __kernel_timespec* tp);
long sys_clock_getres(clockid_t which_clock, struct __kernel_timespec* tp);
long sys_clock_nanosleep(clockid_t which_clock,
                         i32 flags,
                         const struct __kernel_timespec* rqtp,
                         struct __kernel_timespec* rmtp);
long sys_syslog(i32 type, char* buf, i32 len);
long sys_ptrace(i64 request, i64 pid, u64 addr, u64 data);
long sys_sched_setparam(pid_t pid, struct sched_param* param);
long sys_sched_setscheduler(pid_t pid, i32 policy, struct sched_param* param);
long sys_sched_getscheduler(pid_t pid);
long sys_sched_getparam(pid_t pid, struct sched_param* param);
long sys_sched_setaffinity(pid_t pid, u32 len, u64* user_mask_ptr);
long sys_sched_getaffinity(pid_t pid, u32 len, u64* user_mask_ptr);
long sys_sched_yield(void);
long sys_sched_get_priority_max(i32 policy);
long sys_sched_get_priority_min(i32 policy);
long sys_sched_rr_get_interval(pid_t pid, struct __kernel_timespec* interval);
long sys_restart_syscall(void);
long sys_kill(pid_t pid, i32 sig);
long sys_tkill(pid_t pid, i32 sig);
long sys_tgkill(pid_t tgid, pid_t pid, i32 sig);
long sys_sigaltstack(const struct sigaltstack* uss, struct sigaltstack* uoss);
long sys_rt_sigsuspend(sigset_t* unewset, usize sigsetsize);
/// On success, returns 0.
/// On error, -errno is returned.
/// The `sigsetsize` arugument must be set to `sizeof(sigset_t)`.
int sys_rt_sigaction(i32 signum, const struct sigaction* act, struct sigaction* oldact, usize sigsetsize);
long sys_rt_sigprocmask(i32 how, sigset_t* set, sigset_t* oset, usize sigsetsize);
long sys_rt_sigpending(sigset_t* set, usize sigsetsize);
long sys_rt_sigtimedwait(const sigset_t* uthese,
                         siginfo_t* uinfo,
                         const struct __kernel_timespec* uts,
                         usize sigsetsize);
long sys_rt_sigqueueinfo(pid_t pid, i32 sig, siginfo_t* uinfo);
long sys_setpriority(i32 which, i32 who, i32 niceval);
long sys_getpriority(i32 which, i32 who);
long sys_reboot(i32 magic1, i32 magic2, u32 cmd, void* arg);
long sys_setregid(gid_t rgid, gid_t egid);
long sys_setgid(gid_t gid);
long sys_setreuid(uid_t ruid, uid_t euid);
long sys_setuid(uid_t uid);
long sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);
long sys_getresuid(uid_t* ruid, uid_t* euid, uid_t* suid);
long sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
long sys_getresgid(gid_t* rgid, gid_t* egid, gid_t* sgid);
long sys_setfsuid(uid_t uid);
long sys_setfsgid(gid_t gid);
long sys_times(struct tms* tbuf);
long sys_setpgid(pid_t pid, pid_t pgid);
long sys_getpgid(pid_t pid);
long sys_getsid(pid_t pid);
long sys_setsid(void);
long sys_getgroups(i32 gidsetsize, gid_t* grouplist);
long sys_setgroups(i32 gidsetsize, gid_t* grouplist);
i32 sys_sethostname(char* name, i32 len);
long sys_setdomainname(char* name, i32 len);
long sys_getrlimit(u32 resource, struct rlimit* rlim);
long sys_setrlimit(u32 resource, struct rlimit* rlim);
long sys_getrusage(i32 who, struct rusage* ru);
long sys_umask(i32 mask);
long sys_prctl(i32 option, u64 arg2, u64 arg3, u64 arg4, u64 arg5);
long sys_getcpu(u32* cpu, u32* node, struct getcpu_cache* cache);
long sys_gettimeofday(struct __kernel_old_timeval* tv, struct timezone* tz);
long sys_settimeofday(struct __kernel_old_timeval* tv, struct timezone* tz);
long sys_adjtimex(struct __kernel_timex* txc_p);
long sys_getpid(void);
long sys_getppid(void);
long sys_getuid(void);
long sys_geteuid(void);
long sys_getgid(void);
long sys_getegid(void);
long sys_gettid(void);
long sys_sysinfo(struct sysinfo* info);
long sys_mq_open(const char* name, i32 oflag, umode_t mode, struct mq_attr* attr);
long sys_mq_unlink(const char* name);
long sys_mq_timedsend(
    mqd_t mqdes, const char* msg_ptr, usize msg_len, u32 msg_prio, const struct __kernel_timespec* abs_timeout);
long sys_mq_timedreceive(
    mqd_t mqdes, char* msg_ptr, usize msg_len, u32* msg_prio, const struct __kernel_timespec* abs_timeout);
long sys_mq_notify(mqd_t mqdes, const struct sigevent* notification);
long sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr* mqstat, struct mq_attr* omqstat);
long sys_msgget(key_t key, i32 msgflg);
long sys_msgctl(i32 msqid, i32 cmd, struct msqid_ds* buf);
long sys_msgrcv(i32 msqid, struct msgbuf* msgp, usize msgsz, i64 msgtyp, i32 msgflg);
long sys_msgsnd(i32 msqid, struct msgbuf* msgp, usize msgsz, i32 msgflg);
long sys_semget(key_t key, i32 nsems, i32 semflg);
long sys_semctl(i32 semid, i32 semnum, i32 cmd, u64 arg);
long sys_semtimedop(i32 semid, struct sembuf* sops, u32 nsops, const struct __kernel_timespec* timeout);
long sys_semop(i32 semid, struct sembuf* sops, u32 nsops);
long sys_shmget(key_t key, usize size, i32 flag);
long sys_shmctl(i32 shmid, i32 cmd, struct shmid_ds* buf);
long sys_shmat(i32 shmid, char* shmaddr, i32 shmflg);
long sys_shmdt(char* shmaddr);
long sys_socket(i32 domain, i32 type, i32 protocol);
long sys_socketpair(i32 domain, i32 type, i32 protocol, i32 sv[2]);
long sys_bind(i32 sockfd, struct sockaddr* addr, i32 addrlen);
long sys_listen(i32 sockfd, i32 backlog);
long sys_accept(i32 sockfd, struct sockaddr* addr, i32* addrlen);
long sys_connect(i32 sockfd, struct sockaddr* addr, i32 addrlen);
long sys_getsockname(i32 sockfd, struct sockaddr* addr, i32* addrlen);
long sys_getpeername(i32 sockfd, struct sockaddr* addr, i32* addrlen);
long sys_sendto(i32 sockfd, void* buf, usize len, u32 flags, struct sockaddr* dest_addr, i32 addrlen);
long sys_recvfrom(i32 sockfd, void* buf, usize len, u32 flags, struct sockaddr* src_addr, i32* addrlen);
long sys_setsockopt(i32 fd, i32 level, i32 optname, char* optval, i32 optlen);
long sys_getsockopt(i32 fd, i32 level, i32 optname, char* optval, i32* optlen);
long sys_shutdown(i32 sockfd, i32 how);
long sys_sendmsg(i32 fd, struct user_msghdr* msg, u32 flags);
long sys_recvmsg(i32 fd, struct user_msghdr* msg, u32 flags);
long sys_readahead(i32 fd, loff_t offset, usize count);
long sys_brk(u64 brk);
long sys_munmap(u64 addr, usize len);
long sys_mremap(u64 addr, u64 old_len, u64 new_len, u64 flags, u64 new_addr);
long sys_add_key(
    const char* _type, const char* _description, const void* _payload, usize plen, key_serial_t destringid);
long sys_request_key(const char* _type, const char* _description, const char* _callout_info, key_serial_t destringid);
long sys_keyctl(i32 cmd, u64 arg2, u64 arg3, u64 arg4, u64 arg5);
long sys_clone(u64 flags, void* stack, i32* parent_tid, i32* child_tid, u64 tls);
long sys_clone3(struct clone_args* uargs, usize size);
long sys_execve(const char* filename, const char* const* argv, const char* const* envp);
long sys_swapon(const char* specialfile, i32 swap_flags);
long sys_swapoff(const char* specialfile);
long sys_mprotect(u64 start, usize len, u64 prot);
long sys_msync(u64 start, usize len, i32 flags);
long sys_mlock(u64 start, usize len);
long sys_munlock(u64 start, usize len);
long sys_mlockall(i32 flags);
long sys_munlockall(void);
long sys_mincore(u64 start, usize len, u8* vec);
long sys_madvise(u64 start, usize len, i32 behavior);
long sys_process_madvise(i32 pidfd, const struct iovec* vec, usize vlen, i32 behavior, u32 flags);
long sys_process_mrelease(i32 pidfd, u32 flags);
long sys_remap_file_pages(u64 start, u64 size, u64 prot, u64 pgoff, u64 flags);
long sys_mbind(u64 start, u64 len, u64 mode, const u64* nmask, u64 maxnode, u32 flags);
long sys_get_mempolicy(i32* policy, u64* nmask, u64 maxnode, u64 addr, u64 flags);
long sys_set_mempolicy(i32 mode, const u64* nmask, u64 maxnode);
long sys_migrate_pages(pid_t pid, u64 maxnode, const u64* from, const u64* to);
long sys_move_pages(pid_t pid, u64 nr_pages, const void** pages, const i32* nodes, i32* status, i32 flags);
long sys_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, i32 sig, siginfo_t* uinfo);
long sys_perf_event_open(struct perf_event_attr* attr_uptr, pid_t pid, i32 cpu, i32 group_fd, u64 flags);
/// On success, returns a file descriptor for the accepted socket.
/// On error, -errno is returned.
int sys_accept4(i32 sockfd, struct sockaddr* addr, i32* addrlen, i32 flags);
long sys_recvmmsg(i32 fd, struct mmsghdr* msg, u32 vlen, u32 flags, struct __kernel_timespec* timeout);
long sys_wait4(pid_t pid, i32* stat_addr, i32 options, struct rusage* ru);
long sys_prlimit64(pid_t pid, u32 resource, const struct rlimit64* new_rlim, struct rlimit64* old_rlim);
long sys_fanotify_init(u32 flags, u32 event_f_flags);
long sys_fanotify_mark(i32 fanotify_fd, u32 flags, u64 mask, i32 fd, const char* pathname);
long sys_name_to_handle_at(i32 dfd, const char* name, struct file_handle* handle, i32* mnt_id, i32 flag);
long sys_open_by_handle_at(i32 mountdirfd, struct file_handle* handle, i32 flags);
long sys_clock_adjtime(clockid_t which_clock, struct __kernel_timex* tx);
long sys_syncfs(i32 fd);
long sys_setns(i32 fd, i32 nstype);
long sys_pidfd_open(pid_t pid, u32 flags);
long sys_sendmmsg(i32 fd, struct mmsghdr* msg, u32 vlen, u32 flags);
long sys_process_vm_readv(
    pid_t pid, const struct iovec* lvec, u64 liovcnt, const struct iovec* rvec, u64 riovcnt, u64 flags);
long sys_process_vm_writev(
    pid_t pid, const struct iovec* lvec, u64 liovcnt, const struct iovec* rvec, u64 riovcnt, u64 flags);
long sys_kcmp(pid_t pid1, pid_t pid2, i32 type, u64 idx1, u64 idx2);
long sys_finit_module(i32 fd, const char* uargs, i32 flags);
long sys_sched_setattr(pid_t pid, struct sched_attr* attr, u32 flags);
long sys_sched_getattr(pid_t pid, struct sched_attr* attr, u32 size, u32 flags);
long sys_renameat2(i32 olddfd, const char* oldname, i32 newdfd, const char* newname, u32 flags);
long sys_seccomp(u32 op, u32 flags, void* uargs);
long sys_getrandom(char* buf, usize count, u32 flags);
long sys_memfd_create(const char* uname_ptr, u32 flags);
long sys_bpf(i32 cmd, union bpf_attr* attr, u32 size);
long sys_execveat(i32 dfd, const char* filename, const char* const* argv, const char* const* envp, i32 flags);
long sys_userfaultfd(i32 flags);
long sys_membarrier(i32 cmd, u32 flags, i32 cpu_id);
long sys_mlock2(u64 start, usize len, i32 flags);
long sys_copy_file_range(i32 fd_in, loff_t* off_in, i32 fd_out, loff_t* off_out, usize len, u32 flags);
long sys_preadv2(u64 fd, const struct iovec* vec, u64 vlen, u64 pos_l, u64 pos_h, rwf_t flags);
long sys_pwritev2(u64 fd, const struct iovec* vec, u64 vlen, u64 pos_l, u64 pos_h, rwf_t flags);
long sys_pkey_mprotect(u64 start, usize len, u64 prot, i32 pkey);
long sys_pkey_alloc(u64 flags, u64 init_val);
long sys_pkey_free(i32 pkey);
long sys_statx(i32 dfd, const char* path, u32 flags, u32 mask, struct statx* buffer);
long sys_rseq(struct rseq* rseq, u32 rseq_len, i32 flags, u32 sig);
long sys_open_tree(i32 dfd, const char* path, u32 flags);
long sys_move_mount(i32 from_dfd, const char* from_path, i32 to_dfd, const char* to_path, u32 ms_flags);
long sys_mount_setattr(i32 dfd, const char* path, u32 flags, struct mount_attr* uattr, usize size);
long sys_fsopen(const char* fs_name, u32 flags);
long sys_fsconfig(i32 fs_fd, u32 cmd, const char* key, const void* value, i32 aux);
long sys_fsmount(i32 fs_fd, u32 flags, u32 ms_flags);
long sys_fspick(i32 dfd, const char* path, u32 flags);
long sys_pidfd_send_signal(i32 pidfd, i32 sig, siginfo_t* info, u32 flags);
long sys_pidfd_getfd(i32 pidfd, i32 fd, u32 flags);
long sys_landlock_create_ruleset(const struct landlock_ruleset_attr* attr, usize size, u32 flags);
long sys_landlock_add_rule(i32 ruleset_fd, enum landlock_rule_type rule_type, const void* rule_attr, u32 flags);
long sys_landlock_restrict_self(i32 ruleset_fd, u32 flags);
long sys_memfd_secret(u32 flags);
long sys_set_mempolicy_home_node(u64 start, u64 len, u64 home_node, u64 flags);
long sys_cachestat(u32 fd, struct cachestat_range* cstat_range, struct cachestat* cstat, u32 flags);
long sys_map_shadow_stack(u64 addr, u64 size, u32 flags);
long sys_lsm_get_self_attr(u32 attr, struct lsm_ctx* ctx, u32* size, u32 flags);
long sys_lsm_set_self_attr(u32 attr, struct lsm_ctx* ctx, u32 size, u32 flags);
long sys_lsm_list_modules(u64* ids, u32* size, u32 flags);
long sys_ioperm(u64 from, u64 num, i32 on);
/// On success returns the new file descriptor. On error returns -errno.
i32 sys_open(const char* filename, i32 flags, umode_t mode);
long sys_link(const char* oldname, const char* newname);
long sys_unlink(const char* pathname);
long sys_mknod(const char* filename, umode_t mode, u32 dev);
long sys_chmod(const char* filename, umode_t mode);
long sys_chown(const char* filename, uid_t user, gid_t group);
long sys_mkdir(const char* pathname, umode_t mode);
long sys_rmdir(const char* pathname);
long sys_lchown(const char* filename, uid_t user, gid_t group);
long sys_access(const char* filename, i32 mode);
long sys_rename(const char* oldname, const char* newname);
long sys_symlink(const char* old, const char* new);
long sys_pipe(i32* fildes);
long sys_dup2(u32 oldfd, u32 newfd);
long sys_epoll_create(i32 size);
long sys_inotify_init(void);
long sys_eventfd(u32 count);
long sys_signalfd(i32 ufd, sigset_t* user_mask, usize sizemask);
long sys_fadvise64(i32 fd, loff_t offset, usize len, i32 advice);
long sys_alarm(u32 seconds);
long sys_getpgrp(void);
long sys_pause(void);
long sys_time(__kernel_old_time_t* tloc);
long sys_utime(char* filename, struct utimbuf* times);
long sys_utimes(char* filename, struct __kernel_old_timeval* utimes);
long sys_futimesat(i32 dfd, const char* filename, struct __kernel_old_timeval* utimes);
/// On success returns the new file descriptor. On error returns -errno.
i32 sys_creat(const char* pathname, umode_t mode);
long sys_getdents(u32 fd, struct linux_dirent* dirent, u32 count);
long sys_select(i32 n, fd_set* inp, fd_set* outp, fd_set* exp, struct __kernel_old_timeval* tvp);
long sys_poll(struct pollfd* ufds, u32 nfds, i32 timeout);
long sys_epoll_wait(i32 epfd, struct epoll_event* events, i32 maxevents, i32 timeout);
long sys_ustat(u32 dev, struct ustat* ubuf);
long sys_vfork(void);
long sys_uselib(const char* library);
long sys_sysfs(i32 option, u64 arg1, u64 arg2);
long sys_fork(void);
long sys_kexec_file_load(i32 kernel_fd, i32 initrd_fd, u64 cmdline_len, const char* cmdline_ptr, u64 flags);
/// On success, zero is returned.  On error, -errno is returned.
i32 sys_stat(const char* filename, struct stat* statbuf);
/// On success, zero is returned.  On error, -errno is returned.
i32 sys_lstat(const char* filename, struct stat* statbuf);
/// On success, zero is returned.  On error, -errno is returned.
i32 sys_fstat(u32 fd, struct stat* statbuf);
/// On success, returns the number of bytes placed in `buf`. If the returned value equals `bufsiz` truncation may have
/// occurred. On error, -errno is returned.
isize sys_readlink(const char* path, char* buf, i32 bufsiz);
/// On success, zero is returned.  On error, -errno is returned.
i32 sys_uname(struct new_utsname* name);
