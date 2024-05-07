/// Types that are used in the Linux kernel system call interface explicitly.
/// These definitions come from the `vmlinux.h` header that is generated
/// when Linux is built.
///
/// For user space types (such as flags) see the `user_types.h` file in this
/// same directory.
#pragma once

#include <exalt.h>

typedef u64 aio_context_t;

struct io_event {
    u64 data;
    u64 obj;
    i64 res;
    i64 res2;
};

typedef i32 kernel_rwf_t;

struct iocb {
    u64 aio_data;
    u32 aio_key;
    kernel_rwf_t aio_rw_flags;
    u16 aio_lio_opcode;
    i16 aio_reqprio;
    u32 aio_fildes;
    u64 aio_buf;
    u64 aio_nbytes;
    i64 aio_offset;
    u64 aio_reserved2;
    u32 aio_flags;
    u32 aio_resfd;
};

struct io_sqring_offsets {
    u32 head;
    u32 tail;
    u32 ring_mask;
    u32 ring_entries;
    u32 flags;
    u32 dropped;
    u32 array;
    u32 resv1;
    u64 user_addr;
};

struct io_cqring_offsets {
    u32 head;
    u32 tail;
    u32 ring_mask;
    u32 ring_entries;
    u32 overflow;
    u32 cqes;
    u32 flags;
    u32 resv1;
    u64 user_addr;
};

struct io_uring_params {
    u32 sq_entries;
    u32 cq_entries;
    u32 flags;
    u32 sq_thread_cpu;
    u32 sq_thread_idle;
    u32 features;
    u32 wq_fd;
    u32 resv[3];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
};

typedef i64 __kernel_time64_t;
typedef i64 __kernel_old_time_t;

struct __kernel_timespec {
    __kernel_time64_t tv_sec;
    i64 tv_nsec;
};

struct utimbuf {
    __kernel_old_time_t actime;
    __kernel_old_time_t modtime;
};

typedef struct {
    u64 sig[1];
} sigset_t;

struct __aio_sigset {
    const sigset_t* sigmask;
    usize sigsetsize;
};

typedef u32 __poll_t;

struct epoll_event {
    __poll_t events;
    u64 data;
} __attribute__((packed));

typedef u16 umode_t;

typedef struct {
    i32 val[2];
} fsid_t;

struct stat {
    u64 st_dev;
    u64 st_ino;
    u64 st_nlink;
    u32 st_mode;
    u32 st_uid;
    u32 st_gid;
    u32 __pad0;
    u64 st_rdev;
    i64 st_size;
    i64 st_blksize;
    i64 st_blocks;
    u64 st_atime;
    u64 st_atime_nsec;
    u64 st_mtime;
    u64 st_mtime_nsec;
    u64 st_ctime;
    u64 st_ctime_nsec;
    i64 __unused[3];
};

struct statfs {
    i64 f_type;
    i64 f_bsize;
    i64 f_blocks;
    i64 f_bfree;
    i64 f_bavail;
    i64 f_files;
    i64 f_ffree;
    fsid_t f_fsid;
    i64 f_namelen;
    i64 f_frsize;
    i64 f_flags;
    i64 f_spare[4];
};

struct statx_timestamp {
    i64 tv_sec;
    u32 tv_nsec;
    i32 __reserved;
};

struct statx {
    u32 stx_mask;
    u32 stx_blksize;
    u64 stx_attributes;
    u32 stx_nlink;
    u32 stx_uid;
    u32 stx_gid;
    u16 stx_mode;
    u16 __spare0[1];
    u64 stx_ino;
    u64 stx_size;
    u64 stx_blocks;
    u64 stx_attributes_mask;
    struct statx_timestamp stx_atime;
    struct statx_timestamp stx_btime;
    struct statx_timestamp stx_ctime;
    struct statx_timestamp stx_mtime;
    u32 stx_rdev_major;
    u32 stx_rdev_minor;
    u32 stx_dev_major;
    u32 stx_dev_minor;
    u64 stx_mnt_id;
    u32 stx_dio_mem_align;
    u32 stx_dio_offset_align;
    u64 __spare3[12];
};

struct mount_attr {
    u64 attr_set;
    u64 attr_clr;
    u64 propagation;
    u64 userns_fd;
};

struct statmount {
    u32 size;
    u32 __spare1;
    u64 mask;
    u32 sb_dev_major;
    u32 sb_dev_minor;
    u64 sb_magic;
    u32 sb_flags;
    u32 fs_type;
    u64 mnt_id;
    u64 mnt_parent_id;
    u32 mnt_id_old;
    u32 mnt_parent_id_old;
    u64 mnt_attr;
    u64 mnt_propagation;
    u64 mnt_peer_group;
    u64 mnt_master;
    u64 propagate_from;
    u32 mnt_root;
    u32 mnt_point;
    u64 __spare2[50];
    char str[0];
};

struct mnt_id_req {
    u32 size;
    u32 spare;
    u64 mnt_id;
    u64 param;
};

typedef i64 loff_t;
typedef i64 off_t;

typedef u32 uid_t;
typedef u32 gid_t;
typedef i32 pid_t;
typedef u32 qid_t;

struct open_how {
    u64 flags;
    u64 mode;
    u64 resolve;
};

struct linux_dirent64 {
    u64 d_ino;
    i64 d_off;
    u16 d_reclen;
    u8 d_type;
    char d_name[0];
};

struct iovec {
    void* iov_base;
    usize iov_len;
};

typedef struct {
    u64 fds_bits[16];
} fd_set;

struct pollfd {
    i32 fd;
    i16 events;
    i16 revents;
};

struct __kernel_itimerspec {
    struct __kernel_timespec it_interval;
    struct __kernel_timespec it_value;
};

typedef i32 __kernel_timer_t;
typedef __kernel_timer_t timer_t;

typedef i64 __kernel_clock_t;
typedef __kernel_clock_t clock_t;

typedef i32 clockid_t;

struct tms {
    __kernel_clock_t tms_utime;
    __kernel_clock_t tms_stime;
    __kernel_clock_t tms_cutime;
    __kernel_clock_t tms_cstime;
};

struct __kernel_old_timeval {
    i64 tv_sec;
    i64 tv_usec;
};

struct __kernel_old_itimerval {
    struct __kernel_old_timeval it_interval;
    struct __kernel_old_timeval it_value;
};

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

struct __kernel_timex_timeval {
    __kernel_time64_t tv_sec;
    i64 tv_usec;
};

struct __kernel_timex {
    u32 modes;
    i64 offset;
    i64 freq;
    i64 maxerror;
    i64 esterror;
    i32 status;
    i64 constant;
    i64 precision;
    i64 tolerance;
    struct __kernel_timex_timeval time;
    i64 tick;
    i64 ppsfreq;
    i64 jitter;
    i32 shift;
    i64 stabil;
    i64 jitcnt;
    i64 calcnt;
    i64 errcnt;
    i64 stbcnt;
    i32 tai;
    i64 : 64;
    i64 : 64;
    i64 : 64;
    i64 : 64;
    i64 : 64;
};

typedef i64 __kernel_old_time_t;

struct __cap_user_header {
    u32 version;
    i32 pid;
};

typedef struct __cap_user_header* cap_user_header_t;

struct __cap_user_data {
    u32 effective;
    u32 permitted;
    u32 inheritable;
};

typedef struct __cap_user_data* cap_user_data_t;

typedef union {
    i32 sival_int;
    void* sival_ptr;
} sigval_t;

union __sifields {
    struct {
        pid_t _pid;
        uid_t _uid;
    } _kill;
    struct {
        __kernel_timer_t _tid;
        i32 _overrun;
        sigval_t _sigval;
        int _sys_private;
    } _timer;
    struct {
        pid_t _pid;
        uid_t _uid;
        sigval_t _sigval;
    } _rt;
    struct {
        pid_t _pid;
        uid_t _uid;
        i32 _status;
        __kernel_clock_t _utime;
        __kernel_clock_t _stime;
    } _sigchld;
    struct {
        void* _addr;
        union {
            i32 _trapno;
            short int _addr_lsb;
            struct {
                char _dummy_bnd[8];
                void* _lower;
                void* _upper;
            } _addr_bnd;
            struct {
                char _dummy_pkey[8];
                u32 _pkey;
            } _addr_pkey;
            struct {
                u64 _data;
                u32 _type;
                u32 _flags;
            } _perf;
        };
    } _sigfault;
    struct {
        i64 _band;
        i32 _fd;
    } _sigpoll;
    struct {
        void* _call_addr;
        i32 _syscall;
        u32 _arch;
    } _sigsys;
};

struct siginfo {
    union {
        struct {
            i32 si_signo;
            i32 si_errno;
            i32 si_code;
            union __sifields _sifields;
        };
        i32 _si_pad[32];
    };
};

typedef struct siginfo siginfo_t;

struct sigevent {
    sigval_t sigev_value;
    i32 sigev_signo;
    i32 sigev_notify;
    union {
        i32 _pad[12];
        i32 _tid;
        struct {
            void (*_function)(sigval_t);
            void* _attribute;
        } _sigev_thread;
    } _sigev_un;
};

typedef void __signalfn_t(int);
typedef __signalfn_t* __sighandler_t;
typedef void __restorefn_t();
typedef __restorefn_t* __sigrestore_t;

struct sigaction {
    __sighandler_t sa_handler;
    long unsigned int sa_flags;
    __sigrestore_t sa_restorer;
    sigset_t sa_mask;
};

struct sigaltstack {
    void* ss_sp;
    i32 ss_flags;
    usize ss_size;
};

struct rusage {
    struct __kernel_old_timeval ru_utime;
    struct __kernel_old_timeval ru_stime;
    i64 ru_maxrss;
    i64 ru_ixrss;
    i64 ru_idrss;
    i64 ru_isrss;
    i64 ru_minflt;
    i64 ru_majflt;
    i64 ru_nswap;
    i64 ru_inblock;
    i64 ru_oublock;
    i64 ru_msgsnd;
    i64 ru_msgrcv;
    i64 ru_nsignals;
    i64 ru_nvcsw;
    i64 ru_nivcsw;
};

struct robust_list {
    struct robust_list* next;
};

struct robust_list_head {
    struct robust_list list;
    i64 futex_offset;
    struct robust_list* list_op_pending;
};

struct futex_waitv {
    u64 val;
    u64 uaddr;
    u32 flags;
    u32 __reserved;
};

struct kexec_segment {
    union {
        void* buf;
        void* kbuf;
    };
    usize bufsz;
    u64 mem;
    usize memsz;
};

struct sched_param {
    int sched_priority;
};

struct sched_attr {
    u32 size;
    u32 sched_policy;
    u64 sched_flags;
    i32 sched_nice;
    u32 sched_priority;
    u64 sched_runtime;
    u64 sched_deadline;
    u64 sched_period;
    u32 sched_util_min;
    u32 sched_util_max;
};

struct old_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};

struct new_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct rlimit {
    u64 rlim_cur;
    u64 rlim_max;
};

struct rlimit64 {
    u64 rlim_cur;
    u64 rlim_max;
};

struct getcpu_cache {
    u64 blob[16];
};

struct sysinfo {
    i64 uptime;
    u64 loads[3];
    u64 totalram;
    u64 freeram;
    u64 sharedram;
    u64 bufferram;
    u64 totalswap;
    u64 freeswap;
    u16 procs;
    u16 pad;
    u64 totalhigh;
    u64 freehigh;
    u32 mem_unit;
    char _f[0];
};

typedef i32 key_t;

typedef i32 key_serial_t;

typedef u32 __kernel_mode_t;

struct mq_attr {
    i64 mq_flags;
    i64 mq_maxmsg;
    i64 mq_msgsize;
    i64 mq_curmsgs;
    i64 __reserved[4];
};

struct ipc_perm {
    key_t key;
    uid_t uid;
    gid_t gid;
    uid_t cuid;
    gid_t cgid;
    __kernel_mode_t mode;
    u16 seq;
};

typedef i32 __kernel_ipc_pid_t;

/// A msgbuf is meant to be used in the `msgrcv` and `msgsnd` syscalls.
/// It has the general form:
/// ```
/// struct msgbuf {
///     i64 msg_type; /* must be greater than 0 */
///     char msg_text[msg_size]; /* data */
/// };
/// ```
/// Where `msg_size` is a caller defined usize that gets passed to `msgrcv`
/// of `msgsnd`.
///
/// This macro makes it easier to define these structs with a desired `msg_size`
/// when using these system calls.
#define define_struct_msgbuf(msg_size, suffix) \
    struct msgbuf {                            \
        i64 mtype;                             \
        char mtext[msg_size];                  \
    };

/// Not to be used directly
struct msgbuf {
    i64 mtype;
    char mtext[1];
};

struct msg;

struct msqid_ds {
    struct ipc_perm msg_perm;
    struct msg* msg_first;
    struct msg* msg_last;
    __kernel_old_time_t msg_stime;
    __kernel_old_time_t msg_rtime;
    __kernel_old_time_t msg_ctime;
    long unsigned int msg_lcbytes;
    long unsigned int msg_lqbytes;
    short unsigned int msg_cbytes;
    short unsigned int msg_qnum;
    short unsigned int msg_qbytes;
    __kernel_ipc_pid_t msg_lspid;
    __kernel_ipc_pid_t msg_lrpid;
};

struct user_msghdr {
    void* msg_name;
    i32 msg_namelen;
    struct iovec* msg_iov;
    usize msg_iovlen;
    void* msg_control;
    usize msg_controllen;
    u32 msg_flags;
};

struct mmsghdr {
    struct user_msghdr msg_hdr;
    unsigned int msg_len;
};

typedef i32 mqd_t;

struct sembuf {
    u16 sem_num;
    i16 sem_op;
    i16 sem_flg;
};

struct shmid_ds {
    struct ipc_perm shm_perm;
    i32 shm_segsz;
    __kernel_old_time_t shm_atime;
    __kernel_old_time_t shm_dtime;
    __kernel_old_time_t shm_ctime;
    __kernel_ipc_pid_t shm_cpid;
    __kernel_ipc_pid_t shm_lpid;
    u16 shm_nattch;
    u16 shm_unused;
    void* shm_unused2;
    void* shm_unused3;
};

typedef u16 sa_family_t;
struct sockaddr {
    sa_family_t sa_family;
    union {
        char sa_data_min[14];
        struct {
            struct {
            } __empty_sa_data;
            char sa_data[0];
        };
    };
};

struct clone_args {
    u64 flags;
    u64 pidfd;
    u64 child_tid;
    u64 parent_tid;
    u64 exit_signal;
    u64 stack;
    u64 stack_size;
    u64 tls;
    u64 set_tid;
    u64 set_tid_size;
    u64 cgroup;
};

struct perf_event_attr {
    u32 type;
    u32 size;
    u64 config;
    union {
        u64 sample_period;
        u64 sample_freq;
    };
    u64 sample_type;
    u64 read_format;
    u64 disabled : 1;
    u64 inherit : 1;
    u64 pinned : 1;
    u64 exclusive : 1;
    u64 exclude_user : 1;
    u64 exclude_kernel : 1;
    u64 exclude_hv : 1;
    u64 exclude_idle : 1;
    u64 mmap : 1;
    u64 comm : 1;
    u64 freq : 1;
    u64 inherit_stat : 1;
    u64 enable_on_exec : 1;
    u64 task : 1;
    u64 watermark : 1;
    u64 precise_ip : 2;
    u64 mmap_data : 1;
    u64 sample_id_all : 1;
    u64 exclude_host : 1;
    u64 exclude_guest : 1;
    u64 exclude_callchain_kernel : 1;
    u64 exclude_callchain_user : 1;
    u64 mmap2 : 1;
    u64 comm_exec : 1;
    u64 use_clockid : 1;
    u64 context_switch : 1;
    u64 write_backward : 1;
    u64 namespaces : 1;
    u64 ksymbol : 1;
    u64 bpf_event : 1;
    u64 aux_output : 1;
    u64 cgroup : 1;
    u64 text_poke : 1;
    u64 build_id : 1;
    u64 inherit_thread : 1;
    u64 remove_on_exec : 1;
    u64 sigtrap : 1;
    u64 __reserved_1 : 26;
    union {
        u32 wakeup_events;
        u32 wakeup_watermark;
    };
    u32 bp_type;
    union {
        u64 bp_addr;
        u64 kprobe_func;
        u64 uprobe_path;
        u64 config1;
    };
    union {
        u64 bp_len;
        u64 kprobe_addr;
        u64 probe_offset;
        u64 config2;
    };
    u64 branch_sample_type;
    u64 sample_regs_user;
    u32 sample_stack_user;
    i32 clockid;
    u64 sample_regs_intr;
    u32 aux_watermark;
    u16 sample_max_stack;
    u16 __reserved_2;
    u32 aux_sample_size;
    u32 __reserved_3;
    u64 sig_data;
    u64 config3;
};

struct file_handle {
    u32 handle_bytes;
    i32 handle_type;
    u8 f_handle[0];
};

union bpf_attr {
    struct {
        u32 map_type;
        u32 key_size;
        u32 value_size;
        u32 max_entries;
        u32 map_flags;
        u32 inner_map_fd;
        u32 numa_node;
        char map_name[16];
        u32 map_ifindex;
        u32 btf_fd;
        u32 btf_key_type_id;
        u32 btf_value_type_id;
        u32 btf_vmlinux_value_type_id;
        u64 map_extra;
    };
    struct {
        u32 map_fd;
        u64 key;
        union {
            u64 value;
            u64 next_key;
        };
        u64 flags;
    };
    struct {
        u64 in_batch;
        u64 out_batch;
        u64 keys;
        u64 values;
        u32 count;
        u32 map_fd;
        u64 elem_flags;
        u64 flags;
    } batch;
    struct {
        u32 prog_type;
        u32 insn_cnt;
        u64 insns;
        u64 license;
        u32 log_level;
        u32 log_size;
        u64 log_buf;
        u32 kern_version;
        u32 prog_flags;
        char prog_name[16];
        u32 prog_ifindex;
        u32 expected_attach_type;
        u32 prog_btf_fd;
        u32 func_info_rec_size;
        u64 func_info;
        u32 func_info_cnt;
        u32 line_info_rec_size;
        u64 line_info;
        u32 line_info_cnt;
        u32 attach_btf_id;
        union {
            u32 attach_prog_fd;
            u32 attach_btf_obj_fd;
        };
        u32 core_relo_cnt;
        u64 fd_array;
        u64 core_relos;
        u32 core_relo_rec_size;
        u32 log_true_size;
    };
    struct {
        u64 pathname;
        u32 bpf_fd;
        u32 file_flags;
        i32 path_fd;
    };
    struct {
        union {
            u32 target_fd;
            u32 target_ifindex;
        };
        u32 attach_bpf_fd;
        u32 attach_type;
        u32 attach_flags;
        u32 replace_bpf_fd;
        union {
            u32 relative_fd;
            u32 relative_id;
        };
        u64 expected_revision;
    };
    struct {
        u32 prog_fd;
        u32 retval;
        u32 data_size_in;
        u32 data_size_out;
        u64 data_in;
        u64 data_out;
        u32 repeat;
        u32 duration;
        u32 ctx_size_in;
        u32 ctx_size_out;
        u64 ctx_in;
        u64 ctx_out;
        u32 flags;
        u32 cpu;
        u32 batch_size;
    } test;
    struct {
        union {
            u32 start_id;
            u32 prog_id;
            u32 map_id;
            u32 btf_id;
            u32 link_id;
        };
        u32 next_id;
        u32 open_flags;
    };
    struct {
        u32 bpf_fd;
        u32 info_len;
        u64 info;
    } info;
    struct {
        union {
            u32 target_fd;
            u32 target_ifindex;
        };
        u32 attach_type;
        u32 query_flags;
        u32 attach_flags;
        u64 prog_ids;
        union {
            u32 prog_cnt;
            u32 count;
        };
        u64 prog_attach_flags;
        u64 link_ids;
        u64 link_attach_flags;
        u64 revision;
    } query;
    struct {
        u64 name;
        u32 prog_fd;
    } raw_tracepoint;
    struct {
        u64 btf;
        u64 btf_log_buf;
        u32 btf_size;
        u32 btf_log_size;
        u32 btf_log_level;
        u32 btf_log_true_size;
    };
    struct {
        u32 pid;
        u32 fd;
        u32 flags;
        u32 buf_len;
        u64 buf;
        u32 prog_id;
        u32 fd_type;
        u64 probe_offset;
        u64 probe_addr;
    } task_fd_query;
    struct {
        union {
            u32 prog_fd;
            u32 map_fd;
        };
        union {
            u32 target_fd;
            u32 target_ifindex;
        };
        u32 attach_type;
        u32 flags;
        union {
            u32 target_btf_id;
            struct {
                u64 iter_info;
                u32 iter_info_len;
            };
            struct {
                u64 bpf_cookie;
            } perf_event;
            struct {
                u32 flags;
                u32 cnt;
                u64 syms;
                u64 addrs;
                u64 cookies;
            } kprobe_multi;
            struct {
                u32 target_btf_id;
                u64 cookie;
            } tracing;
            struct {
                u32 pf;
                u32 hooknum;
                i32 priority;
                u32 flags;
            } netfilter;
            struct {
                union {
                    u32 relative_fd;
                    u32 relative_id;
                };
                u64 expected_revision;
            } tcx;
            struct {
                u64 path;
                u64 offsets;
                u64 ref_ctr_offsets;
                u64 cookies;
                u32 cnt;
                u32 flags;
                u32 pid;
            } uprobe_multi;
            struct {
                union {
                    u32 relative_fd;
                    u32 relative_id;
                };
                u64 expected_revision;
            } netkit;
        };
    } link_create;
    struct {
        u32 link_fd;
        union {
            u32 new_prog_fd;
            u32 new_map_fd;
        };
        u32 flags;
        union {
            u32 old_prog_fd;
            u32 old_map_fd;
        };
    } link_update;
    struct {
        u32 link_fd;
    } link_detach;
    struct {
        u32 type;
    } enable_stats;
    struct {
        u32 link_fd;
        u32 flags;
    } iter_create;
    struct {
        u32 prog_fd;
        u32 map_fd;
        u32 flags;
    } prog_bind_map;
};

struct rseq {
    u32 cpu_id_start;
    u32 cpu_id;
    u64 rseq_cs;
    u32 flags;
    u32 node_id;
    u32 mm_cid;
    char end[0];
};

typedef i32 rwf_t;

struct landlock_ruleset_attr {
    u64 handled_access_fs;
    u64 handled_access_net;
};

enum landlock_rule_type {
    LANDLOCK_RULE_PATH_BENEATH = 1,
    LANDLOCK_RULE_NET_PORT = 2,
};

struct cachestat_range {
    u64 off;
    u64 len;
};

struct cachestat {
    u64 nr_cache;
    u64 nr_dirty;
    u64 nr_writeback;
    u64 nr_evicted;
    u64 nr_recently_evicted;
};

struct lsm_ctx {
    u64 id;
    u64 flags;
    u64 len;
    u64 ctx_len;
    u8 ctx[0];
};

struct linux_dirent {
    u64 d_ino;
    u64 d_off;
    u16 d_reclen;
    char d_name[0];
};

typedef i32 __kernel_daddr_t;

struct ustat {
    __kernel_daddr_t f_tfree;
    u64 f_tinode;
    char f_fname[6];
    char f_fpack[6];
};
