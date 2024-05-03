#ifndef EXALT_EXSYSCALL_H
#define EXALT_EXSYSCALL_H

#include <ex/sys/types.h>
#include <exalt.h>

#define UNIMPLEMENTED void*
#define TODO(impl) impl

extern void* syscall0(usize syscall_number);
extern void* syscall1(usize syscall_number, void* arg1);
extern void* syscall2(usize syscall_number, void* arg1, void* arg2);
extern void* syscall3(usize syscall_number, void* arg1, void* arg2, void* arg3);
extern void* syscall4(usize syscall_number, void* arg1, void* arg2, void* arg3, void* arg4);
extern void* syscall5(usize syscall_number, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5);

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_STAT 4
#define SYS_FSTAT 5
#define SYS_LSTAT 6
#define SYS_POLL 7
#define SYS_LSEEK 8
#define SYS_MMAP 9
#define SYS_MPROTECT 10
#define SYS_MUNMAP 11
#define SYS_BRK 12
#define SYS_RT_SIGACTION 13
#define SYS_RT_SIGPROCMASK 14
#define SYS_RT_SIGRETURN 15
#define SYS_IOCTL 16
#define SYS_PREAD64 17
#define SYS_PWRITE64 18
#define SYS_READV 19
#define SYS_WRITEV 20
#define SYS_ACCESS 21
#define SYS_PIPE 22
#define SYS_SELECT 23
#define SYS_SCHED_YIELD 24
#define SYS_MREMAP 25
#define SYS_MSYNC 26
#define SYS_MINCORE 27
#define SYS_MADVISE 28
#define SYS_SHMGET 29
#define SYS_SHMAT 30
#define SYS_SHMCTL 31
#define SYS_DUP 32
#define SYS_DUP2 33
#define SYS_PAUSE 34
#define SYS_NANOSLEEP 35
#define SYS_GETITIMER 36
#define SYS_ALARM 37
#define SYS_SETITIMER 38
#define SYS_GETPID 39
#define SYS_SENDFILE 40
#define SYS_SOCKET 41
#define SYS_CONNECT 42
#define SYS_ACCEPT 43
#define SYS_SENDTO 44
#define SYS_RECVFROM 45
#define SYS_SENDMSG 46
#define SYS_RECVMSG 47
#define SYS_SHUTDOWN 48
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_GETSOCKNAME 51
#define SYS_GETPEERNAME 52
#define SYS_SOCKETPAIR 53
#define SYS_SETSOCKOPT 54
#define SYS_GETSOCKOPT 55
#define SYS_CLONE 56
#define SYS_FORK 57
#define SYS_VFORK 58
#define SYS_EXECVE 59
#define SYS_EXIT 60
#define SYS_WAIT4 61
#define SYS_KILL 62
#define SYS_UNAME 63
#define SYS_SEMGET 64
#define SYS_SEMOP 65
#define SYS_SEMCTL 66
#define SYS_SHMDT 67
#define SYS_MSGGET 68
#define SYS_MSGSND 69
#define SYS_MSGRCV 70
#define SYS_MSGCTL 71
#define SYS_FCNTL 72
#define SYS_FLOCK 73
#define SYS_FSYNC 74
#define SYS_FDATASYNC 75
#define SYS_TRUNCATE 76
#define SYS_FTRUNCATE 77
#define SYS_GETDENTS 78
#define SYS_GETCWD 79
#define SYS_CHDIR 80
#define SYS_FCHDIR 81
#define SYS_RENAME 82
#define SYS_MKDIR 83
#define SYS_RMDIR 84
#define SYS_CREAT 85
#define SYS_LINK 86
#define SYS_UNLINK 87
#define SYS_SYMLINK 88
#define SYS_READLINK 89
#define SYS_CHMOD 90
#define SYS_FCHMOD 91
#define SYS_CHOWN 92
#define SYS_FCHOWN 93
#define SYS_LCHOWN 94
#define SYS_UMASK 95
#define SYS_GETTIMEOFDAY 96
#define SYS_GETRLIMIT 97
#define SYS_GETRUSAGE 98
#define SYS_SYSINFO 99
#define SYS_TIMES 100
#define SYS_PTRACE 101
#define SYS_GETUID 102
#define SYS_SYSLOG 103
#define SYS_GETGID 104
#define SYS_SETUID 105
#define SYS_SETGID 106
#define SYS_GETEUID 107
#define SYS_GETEGID 108
#define SYS_SETPGID 109
#define SYS_GETPPID 110
#define SYS_GETPGRP 111
#define SYS_SETSID 112
#define SYS_SETREUID 113
#define SYS_SETREGID 114
#define SYS_GETGROUPS 115
#define SYS_SETGROUPS 116
#define SYS_SETRESUID 117
#define SYS_GETRESUID 118
#define SYS_SETRESGID 119
#define SYS_GETRESGID 120
#define SYS_GETPGID 121
#define SYS_SETFSUID 122
#define SYS_SETFSGID 123
#define SYS_GETSID 124
#define SYS_CAPGET 125
#define SYS_CAPSET 126
#define SYS_RT_SIGPENDING 127
#define SYS_RT_SIGTIMEDWAIT 128
#define SYS_RT_SIGQUEUEINFO 129
#define SYS_RT_SIGSUSPEND 130
#define SYS_SIGALTSTACK 131
#define SYS_UTIME 132
#define SYS_MKNOD 133
#define SYS_USELIB 134
#define SYS_PERSONALITY 135
#define SYS_USTAT 136
#define SYS_STATFS 137
#define SYS_FSTATFS 138
#define SYS_SYSFS 139
#define SYS_GETPRIORITY 140
#define SYS_SETPRIORITY 141
#define SYS_SCHED_SETPARAM 142
#define SYS_SCHED_GETPARAM 143
#define SYS_SCHED_SETSCHEDULER 144
#define SYS_SCHED_GETSCHEDULER 145
#define SYS_SCHED_GET_PRIORITY_MAX 146
#define SYS_SCHED_GET_PRIORITY_MIN 147
#define SYS_SCHED_RR_GET_INTERVAL 148
#define SYS_MLOCK 149
#define SYS_MUNLOCK 150
#define SYS_MLOCKALL 151
#define SYS_MUNLOCKALL 152
#define SYS_VHANGUP 153
#define SYS_MODIFY_LDT 154
#define SYS_PIVOT_ROOT 155
#define SYS__SYSCTL 156
#define SYS_PRCTL 157
#define SYS_ARCH_PRCTL 158
#define SYS_ADJTIMEX 159
#define SYS_SETRLIMIT 160
#define SYS_CHROOT 161
#define SYS_SYNC 162
#define SYS_ACCT 163
#define SYS_SETTIMEOFDAY 164
#define SYS_MOUNT 165
#define SYS_UMOUNT2 166
#define SYS_SWAPON 167
#define SYS_SWAPOFF 168
#define SYS_REBOOT 169
#define SYS_SETHOSTNAME 170
#define SYS_SETDOMAINNAME 171
#define SYS_IOPL 172
#define SYS_IOPERM 173
#define SYS_CREATE_MODULE 174 // Unimplemented
#define SYS_INIT_MODULE 175
#define SYS_DELETE_MODULE 176
#define SYS_GET_KERNEL_SYMS 177 // Unimplemented
#define SYS_QUERY_MODULE 178    // Unimplemented
#define SYS_QUOTACTL 179
#define SYS_NFSSERVCTL 180  // Unimplemented
#define SYS_GETPMSG 181     // Unimplemented
#define SYS_PUTPMSG 182     // Unimplemented
#define SYS_AFS_SYSCALL 183 // Unimplemented
#define SYS_TUXCALL 184     // Unimplemented
#define SYS_SECURITY 185    // Unimplemented
#define SYS_GETTID 186
#define SYS_READAHEAD 187
#define SYS_SETXATTR 188
#define SYS_LSETXATTR 189
#define SYS_FSETXATTR 190
#define SYS_GETXATTR 191
#define SYS_LGETXATTR 192
#define SYS_FGETXATTR 193
#define SYS_LISTXATTR 194
#define SYS_LLISTXATTR 195
#define SYS_FLISTXATTR 196
#define SYS_REMOVEXATTR 197
#define SYS_LREMOVEXATTR 198
#define SYS_FREMOVEXATTR 199
#define SYS_TKILL 200
#define SYS_TIME 201
#define SYS_FUTEX 202
#define SYS_SCHED_SETAFFINITY 203
#define SYS_SCHED_GETAFFINITY 204
#define SYS_SET_THREAD_AREA 205
#define SYS_IO_SETUP 206
#define SYS_IO_DESTROY 207
#define SYS_IO_GETEVENTS 208
#define SYS_IO_SUBMIT 209
#define SYS_IO_CANCEL 210
#define SYS_GET_THREAD_AREA 211
#define SYS_LOOKUP_DCOOKIE 212
#define SYS_EPOLL_CREATE 213
#define SYS_EPOLL_CTL_OLD 214  // Unimplemented
#define SYS_EPOLL_WAIT_OLD 215 // Unimplemented
#define SYS_REMAP_FILE_PAGES 216
#define SYS_GETDENTS64 217
#define SYS_SET_TID_ADDRESS 218
#define SYS_RESTART_SYSCALL 219
#define SYS_SEMTIMEDOP 220
#define SYS_FADVISE64 221
#define SYS_TIMER_CREATE 222
#define SYS_TIMER_SETTIME 223
#define SYS_TIMER_GETTIME 224
#define SYS_TIMER_GETOVERRUN 225
#define SYS_TIMER_DELETE 226
#define SYS_CLOCK_SETTIME 227
#define SYS_CLOCK_GETTIME 228
#define SYS_CLOCK_GETRES 229
#define SYS_CLOCK_NANOSLEEP 230
#define SYS_EXIT_GROUP 231
#define SYS_EPOLL_WAIT 232
#define SYS_EPOLL_CTL 233
#define SYS_TGKILL 234
#define SYS_UTIMES 235
#define SYS_VSERVER 236 // Unimplemented
#define SYS_MBIND 237
#define SYS_SET_MEMPOLICY 238
#define SYS_GET_MEMPOLICY 239
#define SYS_MQ_OPEN 240
#define SYS_MQ_UNLINK 241
#define SYS_MQ_TIMEDSEND 242
#define SYS_MQ_TIMEDRECEIVE 243
#define SYS_MQ_NOTIFY 244
#define SYS_MQ_GETSETATTR 245
#define SYS_KEXEC_LOAD 246
#define SYS_WAITID 247
#define SYS_ADD_KEY 248
#define SYS_REQUEST_KEY 249
#define SYS_KEYCTL 250
#define SYS_IOPRIO_SET 251
#define SYS_IOPRIO_GET 252
#define SYS_INOTIFY_INIT 253
#define SYS_INOTIFY_ADD_WATCH 254
#define SYS_INOTIFY_RM_WATCH 255
#define SYS_MIGRATE_PAGES 256
#define SYS_OPENAT 257
#define SYS_MKDIRAT 258
#define SYS_MKNODAT 259
#define SYS_FCHOWNAT 260
#define SYS_FUTIMESAT 261
#define SYS_NEWFSTATAT 262
#define SYS_UNLINKAT 263
#define SYS_RENAMEAT 264
#define SYS_LINKAT 265
#define SYS_SYMLINKAT 266
#define SYS_READLINKAT 267
#define SYS_FCHMODAT 268
#define SYS_FACCESSAT 269
#define SYS_PSELECT6 270
#define SYS_PPOLL 271
#define SYS_UNSHARE 272
#define SYS_SET_ROBUST_LIST 273
#define SYS_GET_ROBUST_LIST 274
#define SYS_SPLICE 275
#define SYS_TEE 276
#define SYS_SYNC_FILE_RANGE 277
#define SYS_VMSPLICE 278
#define SYS_MOVE_PAGES 279
#define SYS_UTIMENSAT 280
#define SYS_EPOLL_PWAIT 281
#define SYS_SIGNALFD 282
#define SYS_TIMERFD_CREATE 283
#define SYS_EVENTFD 284
#define SYS_FALLOCATE 285
#define SYS_TIMERFD_SETTIME 286
#define SYS_TIMERFD_GETTIME 287
#define SYS_ACCEPT4 288
#define SYS_SIGNALFD4 289
#define SYS_EVENTFD2 290
#define SYS_EPOLL_CREATE1 291
#define SYS_DUP3 292
#define SYS_PIPE2 293
#define SYS_INOTIFY_INIT1 294
#define SYS_PREADV 295
#define SYS_PWRITEV 296
#define SYS_RT_TGSIGQUEUEINFO 297
#define SYS_PERF_EVENT_OPEN 298
#define SYS_RECVMMSG 299
#define SYS_FANOTIFY_INIT 300
#define SYS_FANOTIFY_MARK 301
#define SYS_PRLIMIT64 302
#define SYS_NAME_TO_HANDLE_AT 303
#define SYS_OPEN_BY_HANDLE_AT 304
#define SYS_CLOCK_ADJTIME 305
#define SYS_SYNCFS 306
#define SYS_SENDMMSG 307
#define SYS_SETNS 308
#define SYS_GETCPU 309
#define SYS_PROCESS_VM_READV 310
#define SYS_PROCESS_VM_WRITEV 311
#define SYS_KCMP 312
#define SYS_FINIT_MODULE 313

isize sys_read(u32 fd, void* buf, usize count);
isize sys_write(u32 fd, const char* buf, usize count);
i32 sys_open(const char* filename, i32 flags, u32 mode);
i32 sys_close(u32 fd);
UNIMPLEMENTED sys_stat(const char* filename, struct Stat* statbuf);
UNIMPLEMENTED sys_fstat(u32 fd, struct Stat* statbuf);
UNIMPLEMENTED sys_lstat(const char* filename, struct Stat* statbuf);
UNIMPLEMENTED sys_poll(struct PollFd* ufds, u32 nfds, i32 timeout_msecs);
Offset sys_lseek(u32 fd, Offset offset, u32 whence);
UNIMPLEMENTED sys_mmap(u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off);
UNIMPLEMENTED sys_mprotect(u64 start, usize len, u64 prot);
UNIMPLEMENTED sys_munmap(u64 addr, usize len);
UNIMPLEMENTED sys_brk(u64 brk);
UNIMPLEMENTED sys_rt_sigaction(i32 sig, const struct SigAction* act, struct SigAction* oact, usize sigsetsize);
UNIMPLEMENTED sys_rt_sigprocmask(i32 how, SigSet* nset, SigSet* oset, usize sigsetsize);
UNIMPLEMENTED sys_rt_sigreturn(void);
UNIMPLEMENTED sys_ioctl(u32 fd, u32 cmd, u64 arg);
UNIMPLEMENTED sys_pread64(u32 fd, char* buf, usize count, Offset pos);
UNIMPLEMENTED sys_pwrite64(u32 fd, const char* buf, usize count, Offset pos);
UNIMPLEMENTED sys_readv(u64 fd, const struct IoVec* vec, u64 vlen);
UNIMPLEMENTED sys_writev(u64 fd, const struct IoVec* vec, u64 vlen);
UNIMPLEMENTED sys_access(const char* filename, i32 mode);
UNIMPLEMENTED sys_pipe(i32* fildes);
UNIMPLEMENTED sys_select(i32 n, FdSet* inp, FdSet* outp, FdSet* exp, struct TimeVal* tvp);
UNIMPLEMENTED sys_sched_yield(void);
UNIMPLEMENTED sys_mremap(u64 brk);
UNIMPLEMENTED sys_msync(u64 start, usize len, i32 flags);
UNIMPLEMENTED sys_mincore(u64 start, usize len, unsigned char* vec);
UNIMPLEMENTED sys_madvise(u64 start, usize len_in, i32 behavior);
UNIMPLEMENTED sys_shmget(IpcKey key, usize size, i32 shmflg);
UNIMPLEMENTED sys_shmat(i32 shmid, char* shmaddr, i32 shmflg);
UNIMPLEMENTED sys_shmctl(i32 shmid, i32 cmd, struct SharedMemId* buf);
UNIMPLEMENTED sys_dup(u32 fildes);
UNIMPLEMENTED sys_dup2(u32 oldfd, u32 newfd);
UNIMPLEMENTED sys_pause(void);
UNIMPLEMENTED sys_nanosleep(struct TimeSpec* rqtp, struct TimeSpec* rmtp);
UNIMPLEMENTED sys_getitimer(i32 which, struct ITimerVal* value);
UNIMPLEMENTED sys_alarm(u32 seconds);
UNIMPLEMENTED sys_setitimer(i32 which, struct ITimerVal* value, struct ITimerVal* ovalue);
UNIMPLEMENTED sys_getpid(void);
UNIMPLEMENTED sys_sendfile(i32 out_fd, i32 in_fd, Offset* offset, usize count);
UNIMPLEMENTED sys_socket(i32 family, i32 type, i32 protocol);
UNIMPLEMENTED sys_connect(i32 fd, struct SockAddr* uservaddr, i32 addrlen);
UNIMPLEMENTED sys_accept(i32 fd, struct SockAddr* upeer_sockaddr, i32* upeer_addrlen);
UNIMPLEMENTED sys_sendto(i32 fd, void* buff, usize len, u32 flags, struct SockAddr* addr, i32 addr_len);
UNIMPLEMENTED sys_recvfrom(i32 fd, void* ubuf, usize size, u32 flags, struct SockAddr* addr, i32* addr_len);
UNIMPLEMENTED sys_sendmsg(i32 fd, struct MsgHdr* msg, u32 flags);
UNIMPLEMENTED sys_recvmsg(i32 fd, struct MsgHdr* msg, u32 flags);
UNIMPLEMENTED sys_shutdown(i32 fd, i32 how);
UNIMPLEMENTED sys_bind(i32 fd, struct SockAddr* umyaddr, i32 addrlen);
UNIMPLEMENTED sys_listen(i32 fd, i32 backlog);
UNIMPLEMENTED sys_getsockname(i32 fd, struct SockAddr* usockaddr, i32* usockaddr_len);
UNIMPLEMENTED sys_getpeername(i32 fd, struct SockAddr* usockaddr, i32* usockaddr_len);
UNIMPLEMENTED sys_socketpair(i32 family, i32 type, i32 protocol, i32* usockvec);
UNIMPLEMENTED sys_setsockopt(i32 fd, i32 level, i32 optname, char* optval, i32 optlen);
UNIMPLEMENTED sys_getsockopt(i32 fd, i32 level, i32 optname, char* optval, i32* optlen);
UNIMPLEMENTED sys_clone(u64 clone_flags, u64 newsp, i32* parent_tidptr, i32* child_tidptr, i32 tls_val);
UNIMPLEMENTED sys_fork(void);
UNIMPLEMENTED sys_vfork(void);
UNIMPLEMENTED sys_execve(const char* filename, const char* const* argv, const char* const* envp);
void sys_exit(i32 error_code) __attribute__((__noreturn__));
UNIMPLEMENTED sys_wait4(Pid upid, i32* stat_addr, i32 options, struct ResourceUsage* ru);
UNIMPLEMENTED sys_kill(Pid pid, i32 sig);
UNIMPLEMENTED sys_uname(struct UtsName* name);
UNIMPLEMENTED sys_semget(IpcKey key, i32 nsems, i32 semflg);
UNIMPLEMENTED sys_semop(i32 semid, struct SemBuf* tsops, unsigned nsops);
UNIMPLEMENTED sys_semctl(i32 semid, i32 semnum, i32 cmd, u64 arg);
UNIMPLEMENTED sys_shmdt(char* shmaddr);
UNIMPLEMENTED sys_msgget(IpcKey key, i32 msgflg);
/// `msgp` should be a pointer to a MsgBuf struct the caller defines.
UNIMPLEMENTED sys_msgsnd(i32 msqid, void* msgp, usize msgsz, i32 msgflg);
/// `msgp` should be a pointer to a MsgBuf struct the caller defines.
UNIMPLEMENTED sys_msgrcv(i32 msqid, void* msgp, usize msgsz, long msgtyp, i32 msgflg);
UNIMPLEMENTED sys_msgctl(i32 msqid, i32 cmd, struct MsqidDs* buf);
UNIMPLEMENTED sys_fcntl(u32 fd, u32 cmd, u64 arg);
UNIMPLEMENTED sys_flock(u32 fd, u32 cmd);
UNIMPLEMENTED sys_fsync(u32 fd);
UNIMPLEMENTED sys_fdatasync(u32 fd);
UNIMPLEMENTED sys_truncate(const char* path, long length);
UNIMPLEMENTED sys_ftruncate(u32 fd, u64 length);
UNIMPLEMENTED sys_getdents(u32 fd, struct LinuxDirent* dirent, u32 count);
UNIMPLEMENTED sys_getcwd(char* buf, u64 size);
UNIMPLEMENTED sys_chdir(const char* filename);
UNIMPLEMENTED sys_fchdir(u32 fd);
UNIMPLEMENTED sys_rename(const char* oldname, const char* newname);
UNIMPLEMENTED sys_mkdir(const char* pathname, u32 mode);
UNIMPLEMENTED sys_rmdir(const char* pathname);
UNIMPLEMENTED sys_creat(const char* pathname, u32 mode);
UNIMPLEMENTED sys_link(const char* oldname, const char* newname);
UNIMPLEMENTED sys_unlink(const char* pathname);
UNIMPLEMENTED sys_symlink(const char* oldname, const char* newname);
UNIMPLEMENTED sys_readlink(const char* path, char* buf, i32 bufsiz);
UNIMPLEMENTED sys_chmod(const char* filename, u32 mode);
UNIMPLEMENTED sys_fchmod(u32 fd, u32 mode);
UNIMPLEMENTED sys_chown(const char* filename, Uid user, Gid group);
UNIMPLEMENTED sys_fchown(u32 fd, Uid user, Gid group);
UNIMPLEMENTED sys_lchown(const char* filename, Uid user, Gid group);
UNIMPLEMENTED sys_umask(i32 mask);
UNIMPLEMENTED sys_gettimeofday(struct TimeVal* tv, struct Timezone* tz);
UNIMPLEMENTED sys_getrlimit(u32 resource, struct ResourceLimit* rlim);
UNIMPLEMENTED sys_getrusage(i32 who, struct ResourceUsage* ru);
UNIMPLEMENTED sys_sysinfo(struct SysInfo* info);
UNIMPLEMENTED sys_times(struct Times* tbuf);
UNIMPLEMENTED sys_ptrace(long request, long pid, u64 addr, u64 data);
UNIMPLEMENTED sys_getuid(void);
UNIMPLEMENTED sys_syslog(i32 type, char* buf, i32 len);
UNIMPLEMENTED sys_getgid(void);
UNIMPLEMENTED sys_setuid(Uid uid);
UNIMPLEMENTED sys_setgid(Gid gid);
UNIMPLEMENTED sys_geteuid(void);
UNIMPLEMENTED sys_getegid(void);
UNIMPLEMENTED sys_setpgid(Pid pid, Pid pgid);
UNIMPLEMENTED sys_getppid(void);
UNIMPLEMENTED sys_getpgrp(void);
UNIMPLEMENTED sys_setsid(void);
UNIMPLEMENTED sys_setreuid(Uid ruid, Uid euid);
UNIMPLEMENTED sys_setregid(Gid rgid, Gid egid);
UNIMPLEMENTED sys_getgroups(i32 gidsetsize, Gid* grouplist);
UNIMPLEMENTED sys_setgroups(i32 gidsetsize, Gid* grouplist);
UNIMPLEMENTED sys_setresuid(Uid ruid, Uid euid, Uid suid);
UNIMPLEMENTED sys_getresuid(Uid* ruidp, Uid* euidp, Uid* suidp);
UNIMPLEMENTED sys_setresgid(Gid rgid, Gid egid, Gid sgid);
UNIMPLEMENTED sys_getresgid(Gid* rgidp, Gid* egidp, Gid* sgidp);
UNIMPLEMENTED sys_getpgid(Pid pid);
UNIMPLEMENTED sys_setfsuid(Uid uid);
UNIMPLEMENTED sys_setfsgid(Gid gid);
UNIMPLEMENTED sys_getsid(Pid pid);
UNIMPLEMENTED sys_capget(CapUserHeader header, CapUserData dataptr);
UNIMPLEMENTED sys_capset(CapUserHeader header, const CapUserData data);
UNIMPLEMENTED sys_rt_sigpending(SigSet* uset, usize sigsetsize);
UNIMPLEMENTED sys_rt_sigtimedwait(const SigSet* uthese, TODO(SigInfo) * uinfo, const struct TimeSpec* uts, usize sigsetsize);
UNIMPLEMENTED sys_rt_sigqueueinfo(Pid pid, i32 sig, TODO(SigInfo) * uinfo);
UNIMPLEMENTED sys_rt_sigsuspend(SigSet* unewset, usize sigsetsize);
UNIMPLEMENTED sys_sigaltstack(const Stack* uss, Stack* uoss);
UNIMPLEMENTED sys_utime(char* filename, struct UtimeBuf* times);
UNIMPLEMENTED sys_mknod(const char* filename, u32 mode, unsigned dev);
UNIMPLEMENTED sys_uselib(const char* library);
UNIMPLEMENTED sys_personality(u32 personality);
/// ** Deprecated ** use `statfs` instead
UNIMPLEMENTED sys_ustat(u32 dev, struct Ustat* ubuf);
UNIMPLEMENTED sys_statfs(const char* pathname, struct StatFs* buf);
UNIMPLEMENTED sys_fstatfs(u32 fd, struct StatFs* buf);
UNIMPLEMENTED sys_sysfs(i32 option, u64 arg1, u64 arg2);
UNIMPLEMENTED sys_getpriority(i32 which, i32 who);
UNIMPLEMENTED sys_setpriority(i32 which, i32 who, i32 niceval);
UNIMPLEMENTED sys_sched_setparam(Pid pid, struct SchedParam* param);
UNIMPLEMENTED sys_sched_getparam(Pid pid, struct SchedParam* param);
UNIMPLEMENTED sys_sched_setscheduler(Pid pid, i32 policy, struct SchedParam* param);
UNIMPLEMENTED sys_sched_getscheduler(Pid pid);
UNIMPLEMENTED sys_sched_get_priority_max(i32 policy);
UNIMPLEMENTED sys_sched_get_priority_min(i32 policy);
UNIMPLEMENTED sys_sched_rr_get_i32erval(Pid pid, struct TimeSpec* i32erval);
UNIMPLEMENTED sys_mlock(u64 start, usize len);
UNIMPLEMENTED sys_munlock(u64 start, usize len);
UNIMPLEMENTED sys_mlockall(i32 flags);
UNIMPLEMENTED sys_munlockall(void);
UNIMPLEMENTED sys_vhangup(void);
UNIMPLEMENTED sys_modify_ldt(i32 func, void* ptr, u64 bytecount);
UNIMPLEMENTED sys_pivot_root(const char* new_root, const char* put_old);
// ** Deprecated ** This system call no longer exists!
// UNIMPLEMENTED sys__sysctl(struct __sysctl_args* args);
UNIMPLEMENTED sys_prctl(i32 option, u64 arg2, u64 arg3, u64 arg4, u64 arg5);
UNIMPLEMENTED sys_arch_prctl(i32 code, u64* addr);
UNIMPLEMENTED sys_adjtimex(struct TimeX* txc_p);
UNIMPLEMENTED sys_setrlimit(u32 resource, struct ResourceLimit* rlim);
UNIMPLEMENTED sys_chroot(const char* filename);
UNIMPLEMENTED sys_sync(void);
UNIMPLEMENTED sys_acct(const char* name);
UNIMPLEMENTED sys_settimeofday(struct TimeVal* tv, struct Timezone* tz);
UNIMPLEMENTED sys_mount(char* dev_name, char* dir_name, char* type, u64 flags, void* data);
UNIMPLEMENTED sys_umount2(char* name, i32 flags);
UNIMPLEMENTED sys_swapon(const char* specialfile, i32 swap_flags);
UNIMPLEMENTED sys_swapoff(const char* specialfile);
UNIMPLEMENTED sys_reboot(i32 magic1, i32 magic2, u32 cmd, void* arg);
UNIMPLEMENTED sys_sethostname(char* name, i32 len);
UNIMPLEMENTED sys_setdomainname(char* name, i32 len);
UNIMPLEMENTED sys_iopl(u32 level);
UNIMPLEMENTED sys_ioperm(u64 from, u64 num, i32 turn_on);
UNIMPLEMENTED sys_create_module(void); // Unimplemented
UNIMPLEMENTED sys_init_module(void* umod, u64 len, const char* uargs);
UNIMPLEMENTED sys_delete_module(const char* name_user, u32 flags);
UNIMPLEMENTED sys_get_kernel_syms(void); // Unimplemented
UNIMPLEMENTED sys_query_module(void);    // Unimplemented
UNIMPLEMENTED sys_quotactl(u32 cmd, const char* special, Gid id, void* addr);
UNIMPLEMENTED sys_nfsservctl(void);  // Unimplemented
UNIMPLEMENTED sys_getpmsg(void);     // Unimplemented
UNIMPLEMENTED sys_putpmsg(void);     // Unimplemented
UNIMPLEMENTED sys_afs_syscall(void); // Unimplemented
UNIMPLEMENTED sys_tuxcall(void);     // Unimplemented
UNIMPLEMENTED sys_security(void);    // Unimplemented
UNIMPLEMENTED sys_gettid(void);
UNIMPLEMENTED sys_readahead(i32 fd, Offset offset, usize count);
UNIMPLEMENTED sys_setxattr(const char* pathname, const char* name, const void* value, usize size, i32 flags);
UNIMPLEMENTED sys_lsetxattr(const char* pathname, const char* name, const void* value, usize size, i32 flags);
UNIMPLEMENTED sys_fsetxattr(i32 fd, const char* name, const void* value, usize size, i32 flags);
UNIMPLEMENTED sys_getxattr(const char* pathname, const char* name, void* value, usize size);
UNIMPLEMENTED sys_lgetxattr(const char* pathname, const char* name, void* value, usize size);
UNIMPLEMENTED sys_fgetxattr(i32 fd, const char* name, void* value, usize size);
UNIMPLEMENTED sys_listxattr(const char* pathname, char* list, usize size);
UNIMPLEMENTED sys_llistxattr(const char* pathname, char* list, usize size);
UNIMPLEMENTED sys_flistxattr(i32 fd, char* list, usize size);
UNIMPLEMENTED sys_removexattr(const char* pathname, const char* name);
UNIMPLEMENTED sys_lremovexattr(const char* pathname, const char* name);
UNIMPLEMENTED sys_fremovexattr(i32 fd, const char* name);
UNIMPLEMENTED sys_tkill(Pid pid, i32 sig);
UNIMPLEMENTED sys_time(Time* tloc);
UNIMPLEMENTED sys_futex(u32* uaddr, i32 op, u32 val, struct TimeSpec* utime, u32* uaddr2, u32 val3);
UNIMPLEMENTED sys_sched_setaffinity(Pid pid, u32 len, u64* user_mask_ptr);
UNIMPLEMENTED sys_sched_getaffinity(Pid pid, u32 len, u64* user_mask_ptr);
UNIMPLEMENTED sys_set_thread_area(struct UserDesc* u_info);
UNIMPLEMENTED sys_io_setup(unsigned nr_events, AioContext* ctxp);
UNIMPLEMENTED sys_io_destroy(AioContext ctx);
UNIMPLEMENTED sys_io_getevents(AioContext ctx_id, long min_nr, long nr, struct IoEvent* events, struct TimeSpec* timeout);
UNIMPLEMENTED sys_io_submit(AioContext ctx_id, long nr, struct IoCb** iocbpp);
UNIMPLEMENTED sys_io_cancel(AioContext ctx_id, struct IoCb* iocb, struct IoEvent* result);
UNIMPLEMENTED sys_get_thread_area(struct UserDesc* u_info);
UNIMPLEMENTED sys_lookup_dcookie(u64 cookie64, char* buf, usize len);
UNIMPLEMENTED sys_epoll_create(i32 size);
UNIMPLEMENTED sys_epoll_ctl_old(void);  // Unimplemented
UNIMPLEMENTED sys_epoll_wait_old(void); // Unimplemented
UNIMPLEMENTED sys_remap_file_pages(u64 start, u64 size, u64 prot, u64 pgoff, u64 flags);
UNIMPLEMENTED sys_getdents64(u32 fd, struct LinuxDirent64* dirent, u32 count);
UNIMPLEMENTED sys_set_tid_address(i32* tidptr);
UNIMPLEMENTED sys_restart_syscall(void);
UNIMPLEMENTED sys_semtimedop(i32 semid, struct SemBuf* tsops, unsigned nsops, const struct TimeSpec* timeout);
UNIMPLEMENTED sys_fadvise64(i32 fd, Offset offset, usize len, i32 advice);
UNIMPLEMENTED sys_timer_create(const ClockId which_clock, struct SigEvent* timer_event_spec, Timer* created_timer_id);
UNIMPLEMENTED sys_timer_settime(Timer timer_id, i32 flags, const struct ITimerSpec* new_setting, struct ITimerSpec* old_setting);
UNIMPLEMENTED sys_timer_gettime(Timer timer_id, struct ITimerSpec* setting);
UNIMPLEMENTED sys_timer_getoverrun(Timer timer_id);
UNIMPLEMENTED sys_timer_delete(Timer timer_id);
UNIMPLEMENTED sys_clock_settime(const ClockId which_clock, const struct TimeSpec* tp);
UNIMPLEMENTED sys_clock_gettime(const ClockId which_clock, struct TimeSpec* tp);
UNIMPLEMENTED sys_clock_getres(const ClockId which_clock, struct TimeSpec* tp);
UNIMPLEMENTED sys_clock_nanosleep(const ClockId which_clock, i32 flags, const struct TimeSpec* rqtp, struct TimeSpec* rmtp);
UNIMPLEMENTED sys_exit_group(i32 error_code);
UNIMPLEMENTED sys_epoll_wait(i32 epfd, struct EpollEvent* events, i32 maxevents, i32 timeout);
UNIMPLEMENTED sys_epoll_ctl(i32 epfd, i32 op, i32 fd, struct EpollEvent* event);
UNIMPLEMENTED sys_tgkill(Pid tgid, Pid pid, i32 sig);
UNIMPLEMENTED sys_utimes(char* filename, struct TimeVal* utimes);
UNIMPLEMENTED sys_vserver(void); // Unimplemented
UNIMPLEMENTED sys_mbind(u64 start, u64 len, u64 mode, u64* nmask, u64 maxnode, unsigned flags);
UNIMPLEMENTED sys_set_mempolicy(i32 mode, u64* nmask, u64 maxnode);
UNIMPLEMENTED sys_get_mempolicy(i32* policy, u64* nmask, u64 maxnode, u64 addr, u64 flags);
UNIMPLEMENTED sys_mq_open(const char* u_name, i32 oflag, u32 mode, struct MqAttr* u_attr);
UNIMPLEMENTED sys_mq_unlink(const char* u_name);
UNIMPLEMENTED sys_mq_timedsend(MsgQueueDescriptor mqdes, const char* u_msg_ptr, usize msg_len, u32 msg_prio, const struct TimeSpec* u_abs_timeout);
UNIMPLEMENTED sys_mq_timedreceive(MsgQueueDescriptor mqdes, char* u_msg_ptr, usize msg_len, u32* u_msg_prio, const struct TimeSpec* u_abs_timeout);
UNIMPLEMENTED sys_mq_notify(MsgQueueDescriptor mqdes, const struct SigEvent* u_notification);
UNIMPLEMENTED sys_mq_getsetattr(MsgQueueDescriptor mqdes, const struct MqAttr* u_mqstat, struct MqAttr* u_omqstat);
UNIMPLEMENTED sys_kexec_load(u64 entry, u64 nr_segments, struct KExecSegment* segments, u64 flags);
UNIMPLEMENTED sys_waitid(i32 which, Pid upid, struct SigInfo* infop, i32 options, struct ResourceUsage* ru);
UNIMPLEMENTED sys_add_key(const char* _type, const char* _description, const void* _payload, usize plen, KeySerial ringid);
UNIMPLEMENTED sys_request_key(const char* _type, const char* _description, const char* _callout_info, KeySerial destringid);
UNIMPLEMENTED sys_keyctl(i32 option, u64 arg2, u64 arg3, u64 arg4, u64 arg5);
UNIMPLEMENTED sys_ioprio_set(i32 which, i32 who, i32 ioprio);
UNIMPLEMENTED sys_ioprio_get(i32 which, i32 who);
UNIMPLEMENTED sys_inotify_init(void);
UNIMPLEMENTED sys_inotify_add_watch(i32 fd, const char* pathname, u32 mask);
UNIMPLEMENTED sys_inotify_rm_watch(i32 fd, i32 wd);
UNIMPLEMENTED sys_migrate_pages(Pid pid, u64 maxnode, const u64* old_nodes, const u64* new_nodes);
UNIMPLEMENTED sys_openat(i32 dfd, const char* filename, i32 flags, u32 mode);
UNIMPLEMENTED sys_mkdirat(i32 dfd, const char* pathname, u32 mode);
UNIMPLEMENTED sys_mknodat(i32 dfd, const char* filename, u32 mode, unsigned dev);
UNIMPLEMENTED sys_fchownat(i32 dfd, const char* filename, Uid user, Gid group, i32 flag);
UNIMPLEMENTED sys_futimesat(i32 dfd, const char* filename, struct TimeVal* utimes);
UNIMPLEMENTED sys_newfstatat(i32 dfd, const char* filename, struct Stat* statbuf, i32 flag);
UNIMPLEMENTED sys_unlinkat(i32 dfd, const char* pathname, i32 flag);
UNIMPLEMENTED sys_renameat(i32 olddfd, const char* oldname, i32 newdfd, const char* newname);
UNIMPLEMENTED sys_linkat(i32 olddfd, const char* oldname, i32 newdfd, const char* newname, i32 flags);
UNIMPLEMENTED sys_symlinkat(const char* oldname, i32 newdfd, const char* newname);
UNIMPLEMENTED sys_readlinkat(i32 dfd, const char* pathname, char* buf, i32 bufsiz);
UNIMPLEMENTED sys_fchmodat(i32 dfd, const char* filename, u32 mode);
UNIMPLEMENTED sys_faccessat(i32 dfd, const char* filename, i32 mode);
UNIMPLEMENTED sys_pselect6(i32 n, FdSet* inp, FdSet* outp, FdSet* exp, struct TimeSpec* tsp, void* sig);
UNIMPLEMENTED sys_ppoll(struct PollFd* ufds, u32 nfds, struct TimeSpec* tsp, const SigSet* sigmask, usize sigsetsize);
UNIMPLEMENTED sys_unshare(u64 unshare_flags);
UNIMPLEMENTED sys_set_robust_list(struct RobustListHead* head, usize len);
UNIMPLEMENTED sys_get_robust_list(i32 pid, struct RobustListHead** head_ptr, usize* len_ptr);
UNIMPLEMENTED sys_splice(i32 fd_in, Offset* off_in, i32 fd_out, Offset* off_out, usize len, u32 flags);
UNIMPLEMENTED sys_tee(i32 fdin, i32 fdout, usize len, u32 flags);
UNIMPLEMENTED sys_sync_file_range(i32 fd, Offset offset, Offset nbytes, u32 flags);
UNIMPLEMENTED sys_vmsplice(i32 fd, const struct IoVec* iov, u64 nr_segs, u32 flags);
UNIMPLEMENTED sys_move_pages(Pid pid, u64 nr_pages, const void** pages, const i32* nodes, i32* status, i32 flags);
UNIMPLEMENTED sys_utimensat(i32 dfd, const char* filename, struct TimeSpec* utimes, i32 flags);
UNIMPLEMENTED sys_epoll_pwait(i32 epfd, struct EpollEvent* events, i32 maxevents, i32 timeout, const SigSet* sigmask, usize sigsetsize);
UNIMPLEMENTED sys_signalfd(i32 ufd, SigSet* user_mask, usize sizemask);
UNIMPLEMENTED sys_timerfd_create(i32 clockid, i32 flags);
UNIMPLEMENTED sys_eventfd(u32 count);
UNIMPLEMENTED sys_fallocate(i32 fd, i32 mode, Offset offset, Offset len);
UNIMPLEMENTED sys_timerfd_settime(i32 ufd, i32 flags, const struct ITimerSpec* utmr, struct ITimerSpec* otmr);
UNIMPLEMENTED sys_timerfd_gettime(i32 ufd, struct ITimerSpec* otmr);
UNIMPLEMENTED sys_accept4(i32 fd, struct SockAddr* upeer_sockaddr, i32* upeer_addrlen, i32 flags);
UNIMPLEMENTED sys_signalfd4(i32 ufd, SigSet* user_mask, usize sizemask, i32 flags);
UNIMPLEMENTED sys_eventfd2(u32 count, i32 flags);
UNIMPLEMENTED sys_epoll_create1(i32 flags);
UNIMPLEMENTED sys_dup3(u32 oldfd, u32 newfd, i32 flags);
UNIMPLEMENTED sys_pipe2(i32* fildes, i32 flags);
UNIMPLEMENTED sys_inotify_init1(i32 flags);
UNIMPLEMENTED sys_preadv(u64 fd, const struct IoVec* vec, u64 vlen, u64 pos_l, u64 pos_h);
UNIMPLEMENTED sys_pwritev(u64 fd, const struct IoVec* vec, u64 vlen, u64 pos_l, u64 pos_h);
UNIMPLEMENTED sys_rt_tgsigqueueinfo(Pid tgid, Pid pid, i32 sig, TODO(SigInfo) * uinfo);
UNIMPLEMENTED sys_perf_event_open(struct perf_event_attr* attr_uptr, Pid pid, i32 cpu, i32 group_fd, u64 flags);
UNIMPLEMENTED sys_recvmmsg(i32 fd, struct mmsghdr* mmsg, u32 vlen, u32 flags, struct TimeSpec* timeout);
UNIMPLEMENTED sys_fanotify_init(u32 flags, u32 event_f_flags);
UNIMPLEMENTED sys_fanotify_mark(i32 fanotify_fd, u32 flags, u64 mask, i32 dfd, const char* pathname);
UNIMPLEMENTED sys_prlimit64(Pid pid, u32 resource, const struct ResourceLimit64* new_rlim, struct ResourceLimit64* old_rlim);
UNIMPLEMENTED sys_name_to_handle_at(i32 dfd, const char* name, struct file_handle* handle, i32* mnt_id, i32 flag);
UNIMPLEMENTED sys_open_by_handle_at(i32 mountdirfd, struct file_handle* handle, i32 flags);
UNIMPLEMENTED sys_clock_adjtime(const ClockId which_clock, struct TimeX* utx);
UNIMPLEMENTED sys_syncfs(i32 fd);
UNIMPLEMENTED sys_sendmmsg(i32 fd, struct mmsghdr* mmsg, u32 vlen, u32 flags);
UNIMPLEMENTED sys_setns(i32 fd, i32 nstype);
UNIMPLEMENTED sys_getcpu(unsigned* cpup, unsigned* nodep, struct getcpu_cache* unused);
UNIMPLEMENTED sys_process_vm_readv(Pid pid, const struct IoVec* lvec, u64 liovcnt, const struct IoVec* rvec, u64 riovcnt, u64 flags);
UNIMPLEMENTED sys_process_vm_writev(Pid pid, const struct IoVec* lvec, u64 liovcnt, const struct IoVec* rvec, u64 riovcnt, u64 flags);
UNIMPLEMENTED sys_kcmp(Pid pid1, Pid pid2, i32 type, u64 idx1, u64 idx2);
UNIMPLEMENTED sys_finit_module(i32 fd, const char* uargs, i32 flags);

#endif // ifndef EXALT_EXSYSCALL_H
