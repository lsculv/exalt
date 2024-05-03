// Types expected by the Linux system call interface.
#ifndef EXALT_EXSYSTYPES_H
#define EXALT_EXSYSTYPES_H

#include <exalt.h>

// Integer type redefinitions
// These are used by certain system calls instead of the actual integer type
// partially for clarity, but also because different systems can have different
// underlying values for these types. These are the ones for modern x86_64 Linux
typedef i64 Time;
typedef i64 SignedMicros;
typedef i64 SignedNanos;
typedef i64 Clock;
typedef i32 ClockId;

typedef u64 DeviceId;
typedef u64 InodeId;
typedef u64 NLinks;
typedef u32 Mode;
typedef i32 DAddr;
typedef i64 FsWord;
typedef u64 FsBlockCount;
typedef u64 FsFileCount;

typedef i32 Pid;
typedef u32 Uid;
typedef u32 Gid;

typedef isize Offset;
typedef isize BlockSize;
typedef isize BlockCount;

typedef u16 SAFamily;
typedef u32 SockLen;

typedef i32 MsgQueueDescriptor;
typedef i32 IpcKey;
typedef i32 KeySerial;

/// Represents the amount of messages in a message queue.
typedef u64 MsgQueueCount;
/// Represents the amount of bytes allowed on the queue.
typedef u64 MsgLen;

typedef u64 AioContext;
typedef i32 KernelRwf;

typedef usize SharedMemAttaches;

typedef usize RLimit;
typedef usize RLimit64;

enum OpenFlags {
    O_APPEND = 02000,
    O_ASYNC = 020000,
    O_RDONLY = 00,
    O_WRONLY = 01,
    O_RDWR = 02,
    O_CLOEXEC = 02000000,
    O_CREAT = 0100,
    O_EXCL = 0200,
    O_NONBLOCK = 04000,
    O_DIRECTORY = 0200000,
    O_DSYNC = 010000,
    O_NOCTTY = 0400,
    O_NOFOLLOW = 0400000,
    O_NDELAY = 04000,
    O_SYNC = 04010000,
    O_TRUNC = 01000,
    O_TMPFILE = 020200000,

};

typedef struct {
    void* ss_sp;
    i32 ss_flags;
    usize ss_size;
} Stack;

#define __SIGSET_NWORDS (1024 / (8 * sizeof(u64)))
typedef struct {
    u64 __val[__SIGSET_NWORDS];
} SigSet;

typedef i64 __FdMask;
#define __FD_SETSIZE 1024
#define __NFDBITS (8 * (int)sizeof(__FdMask))
typedef struct {
    __FdMask __fds_bits[__FD_SETSIZE / __NFDBITS];
} FdSet;

struct LinuxDirent {
    u64 d_ino;     // inode number
    Offset d_off;  // offset to next structure
    u16 d_reclen;  // size of this dirent
    char d_name[]; // null-terminated filename
};

struct LinuxDirent64 {
    u64 d_ino;     // inode number
    Offset d_off;  // offset to next structure
    u16 d_reclen;  // size of this dirent
    u8 d_type;     // file type
    char d_name[]; // null-terminated filename
};

typedef struct {
    i32 val[2];
} FsId;

struct PollFd {};

union SigVal {
    i32 sival_int;
    void* sival_ptr;
};

enum {
    SIGEV_SIGNAL = 0,    // Notify via signal.
    SIGEV_NONE,          // Other notification: meaningless.
    SIGEV_THREAD,        // Deliver via thread creation.
    SIGEV_THREAD_ID = 4, // Send signal to specific thread. This is a Linux extension.
};

struct SigEvent {
    // Notification method
    int sigev_notify;
    // Notification signal
    int sigev_signo;
    // Data passed with notification
    union SigVal sigev_value;
    // Function used for thread notification (SIGEV_THREAD)
    void (*sigev_notify_function)(union SigVal);
    // Attributes for notification thread (SIGEV_THREAD)
    void* sigev_notify_attributes;
    // ID of thread to signal (SIGEV_THREAD_ID); Linux-specific
    Pid sigev_notify_thread_id;
};

struct SigAction {};

struct IoVec {
    void* iov_base; // data
    usize iov_len;  // length of data
};

struct TimeVal {
    Time tv_sec;          // seconds
    SignedMicros tv_usec; // microseconds
};

struct TimeSpec {
    Time tv_sec;         // seconds
    SignedNanos tv_nsec; // nanoseconds
};

struct ITimerVal {
    // Value to put into `it_value` when the timer expires.
    struct TimeVal it_interval;
    // Time to the next timer expiration.
    struct TimeVal it_value;
};

struct ITimerSpec {
    struct TimeSpec it_interval;
    struct TimeSpec it_value;
};

/// It is generally a bad idea to use this.
struct Timezone {
    i32 tz_minuteswest; // Minutes west of GMT
    i32 tz_dsttime;     // Daylight savings time correction
};

/// Structure for RFC 5905 clock adjustment algorithm
struct TimeX {
    unsigned int modes;  // mode selector
    i64 offset;          // time offset (usec)
    i64 freq;            // frequency offset (scaled ppm)
    i64 maxerror;        // maximum error (usec)
    i64 esterror;        // estimated error (usec)
    int status;          // clock command/status
    i64 constant;        // pll time constant
    i64 precision;       // clock precision (usec) (ro)
    i64 tolerance;       // clock frequency tolerance (ppm) (ro)
    struct TimeVal time; // (read only, except for ADJ_SETOFFSET)
    i64 tick;            // (modified) usecs between clock ticks
    i64 ppsfreq;         // pps frequency (scaled ppm) (ro)
    i64 jitter;          // pps jitter (us) (ro)
    int shift;           // interval duration (s) (shift) (ro)
    i64 stabil;          // pps stability (scaled ppm) (ro)
    i64 jitcnt;          // jitter limit exceeded (ro)
    i64 calcnt;          // calibration intervals (ro)
    i64 errcnt;          // calibration errors (ro)
    i64 stbcnt;          // stability limit exceeded (ro)
    int tai;             // TAI offset (ro)
    // Padding
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
};

struct Stat {
    DeviceId device;
    InodeId inode;
    NLinks nlink;
    Mode mode;
    Uid uid;
    Gid gid;
    i32 __pad0;
    DeviceId special_device;
    Offset size;
    BlockSize blocksize;
    BlockCount blocks;
    struct TimeSpec access_time;
    struct TimeSpec modify_time;
    struct TimeSpec change_time;
    isize __libc_reserved[3];
};

struct SockAddr {
    SAFamily sa_family;
    char sa_data[14];
};

/// For use in messages sent by `sendmsg` and received by `recvmsg`.
struct MsgHdr {
    void* msg_name;      // Address to send to/receive from
    SockLen msg_namelen; // Length of address

    struct IoVec* msg_iov; // Data vector that will be sent to/recieved from
    usize msg_iovlen;      // Length of the vector

    void* msg_control;    // Extra data
    usize msg_controllen; // Ancillary data buffer length

    i32 msg_flags; // Flags on received message
};

/// A MsgBuf is meant to be used in the `msgrcv` and `msgsnd` syscalls.
/// It has the general form:
/// ```
/// struct MsgBuf {
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
    struct MsgBuf##suffix {                    \
        i64 msg_type;                          \
        char msg_text[msg_size];               \
    };

enum IpcMode {
    // Mode bits for `msgget', `semget', and `shmget'.
    IPC_CREAT = 01000,  // Create key if key does not exist.
    IPC_EXCL = 02000,   // Fail if key exists.
    IPC_NOWAIT = 04000, // Return error on wait.

    // Control commands for `msgctl', `semctl', and `shmctl'.
    IPC_RMID = 0, // Remove identifier.
    IPC_SET = 1,  // Set `ipc_perm' options.
    IPC_STAT = 2, // Get `ipc_perm' options.
    IPC_INFO = 3, // See ipcs.

    // Special key values.
    IPC_PRIVATE = ((IpcKey)0), // Private key.

};
struct IpcPerm {
    IpcKey key; // Key given to msgget
    Uid uid;    // Effective UID of the owner
    Gid gid;    // Effective GID of the owner
    Uid cuid;   // Effective UID of the creator
    Gid cgid;   // Effective GID of the creator
    u16 mode;   // Permissions
    u16 seq;    // Sequence number
};

struct MsqidDs {
    struct IpcPerm msg_perm; // structure describing operation permission
    Time msg_stime;          // time of last msgsnd command
    Time msg_rtime;          // time of last msgsnd command
    Time msg_ctime;          // time of last change
    u64 msg_cbytes;          // current number of bytes on queue
    MsgQueueCount msg_qnum;  // number of messages currently on queue
    MsgLen msg_qbytes;       // max number of bytes allowed on queue
    Pid msg_lspid;           // pid of last msgsnd()
    Pid msg_lrpid;           // pid of last msgrcv()
};

struct MqAttr {
    i64 mq_flags;   // Flags (ignored for mq_open())
    i64 mq_maxmsg;  // Max. # of messages on queue
    i64 mq_msgsize; // Max. message size (bytes)
    i64 mq_curmsgs; // # of messages currently in queue (ignored for mq_open())
    i64 _pad[4];
};

enum ResourceUsageWho {
    RUSAGE_SELF = 0,
    RUSAGE_CHILDREN = -1,
    RUSAGE_THREAD = 1,
};
/// Structure describing resource usage
struct ResourceUsage {
    // Total amount of user time used.
    struct TimeVal ru_utime;
    // Total amount of system time used.
    struct TimeVal ru_stime;
    // Maximum resident set size (in kilobytes).
    i64 ru_maxrss;
    // Amount of sharing of text segment memory
    // with other processes (kilobyte-seconds).
    i64 ru_ixrss;
    // Amount of data segment memory used (kilobyte-seconds).
    i64 ru_idrss;
    // Amount of stack memory used (kilobyte-seconds).
    i64 ru_isrss;
    // Number of soft page faults (i.e. those serviced by reclaiming
    // a page from the list of pages awaiting reallocation.
    i64 ru_minflt;
    // Number of hard page faults (i.e. those that required I/O).
    i64 ru_majflt;
    // Number of times a process was swapped out of physical memory.
    i64 ru_nswap;
    // Number of input operations via the file system.  Note: This
    // and `ru_oublock' do not include operations with the cache.
    i64 ru_inblock;
    // Number of output operations via the file system.
    i64 ru_oublock;
    // Number of IPC messages sent.
    i64 ru_msgsnd;
    // Number of IPC messages received.
    i64 ru_msgrcv;
    // Number of signals delivered.
    i64 ru_nsignals;
    // Number of voluntary context switches, i.e. because the process
    // gave up the process before it had to (usually to wait for some
    // resource to be available).
    i64 ru_nvcsw;
    // Number of involuntary context switches, i.e. a higher priority process
    // became runnable or the current process used up its time slice.
    i64 ru_nivcsw;
};

#define _UTSNAME_LENGTH 65
/// Unix Time-Sharing System Name. Used to contain information about the
/// current Unix system you are running.
struct UtsName {
    // Name of the implementation of the operating system.
    char sysname[_UTSNAME_LENGTH];
    // Name of this node on the network.
    char nodename[_UTSNAME_LENGTH];
    // Current release level of this implementation.
    char release[_UTSNAME_LENGTH];
    // Current version level of this release.
    char version[_UTSNAME_LENGTH];
    // Name of the hardware type the system is running on.
    char machine[_UTSNAME_LENGTH];
    // Name of the domain of this node on the network.
    // This is typically unused.
    char domainname[_UTSNAME_LENGTH];
};

enum SemFlag {
    SEM_UNDO = 0x1000,
};
/// Used for argument to `semop` to describe operations.
struct SemBuf {
    u16 sem_num; // semaphore number
    i16 sem_op;  // semaphore operation
    i16 sem_flg; // operation flag
};

struct UserDesc {
    u32 entry_number;
    u32 base_addr;
    u32 limit;
    u32 seg_32bit : 1;
    u32 contents : 2;
    u32 read_exec_only : 1;
    u32 limit_in_pages : 1;
    u32 seg_not_present : 1;
    u32 useable : 1;
    u32 lm : 1;
};

struct IoCb {
    // these are internal to the kernel/libc.
    u64 aio_data; // data to be returned in event's data

    u32 aio_key;            // the kernel sets aio_key to the req #
    KernelRwf aio_rw_flags; // RWF_* flags

    // common fields
    u16 aio_lio_opcode;
    i16 aio_reqprio;
    u32 aio_fildes;

    u64 aio_buf;
    u64 aio_nbytes;
    i64 aio_offset;

    // extra parameters
    u64 aio_reserved2; // TODO: use this for a (struct sigevent *)

    // flags for the "struct iocb"
    u32 aio_flags;

    // if the IOCB_FLAG_RESFD flag of "aio_flags" is set, this is an
    // eventfd to signal AIO readiness to
    u32 aio_resfd;
};

// read() from /dev/aio returns these structures.
struct IoEvent {
    u64 data; // the data field from the iocb
    u64 obj;  // what iocb this event came from
    i64 res;  // result code for this event
    i64 res2; // secondary result
};

typedef union {
    void* ptr;
    int fd;
    u32 uint32;
    u64 uint64;
} EpollData;

struct EpollEvent {
    u32 events;     // Epoll events
    EpollData data; // User data variable
} __attribute__((__packed__));

typedef void* Timer;

typedef union {
    i32 integer;
    void* ptr;
} SigVal;
// TODO: Implement this struct. The glibc source is below. Good luck.
// Might want to look at the Rust libc crate source or the musl source as well
typedef struct SigInfo {
    i32 signal_number;
    i32 error_number;
    i32 code;
    i32 __pad0;
    union {
        i32 _pad[28];
        struct {
            Pid pid;
            Uid uid;
        } kill;
        struct {
            i32 tid;
            i32 overrun;
        } timer;
        struct {
            Pid pid;
            Uid uid;
            SigVal signal_value;
        } rt;
        struct {
            Pid pid;
            Uid uid;
            i32 status;
            Clock utime; // TODO: Look into meaning of these field names
            Clock stime; //
        } sigchld;
        struct {
            void* address;
            i16 address_lsb;

        } sigfault;
        struct {
            i64 band; // Band event for SIGPOLL
            i32 fd;
        } sigpoll;
        struct {
            void* call_addr; // Calling user insn
            i32 syscall;     // Triggering system call
            u32 arch;        // AUDIT_ARCH_* of syscall
        } sigsys;
    } feilds;

} SigInfo;

// typedef struct
//   {
//     int si_signo;		/* Signal number.  */
// #if __SI_ERRNO_THEN_CODE
//     int si_errno;		/* If non-zero, an errno value associated with
//				   this signal, as defined in <errno.h>.  */
//     int si_code;		/* Signal code.  */
// #else
//     int si_code;
//     int si_errno;
// #endif
// #if __WORDSIZE == 64
//     int __pad0;			/* Explicit padding.  */
// #endif
//
//     union
//       {
//	int _pad[__SI_PAD_SIZE];
//
//	 /* kill().  */
//	struct
//	  {
//	    __pid_t si_pid;	/* Sending process ID.  */
//	    __uid_t si_uid;	/* Real user ID of sending process.  */
//	  } _kill;
//
//	/* POSIX.1b timers.  */
//	struct
//	  {
//	    int si_tid;		/* Timer ID.  */
//	    int si_overrun;	/* Overrun count.  */
//	    __sigval_t si_sigval;	/* Signal value.  */
//	  } _timer;
//
//	/* POSIX.1b signals.  */
//	struct
//	  {
//	    __pid_t si_pid;	/* Sending process ID.  */
//	    __uid_t si_uid;	/* Real user ID of sending process.  */
//	    __sigval_t si_sigval;	/* Signal value.  */
//	  } _rt;
//
//	/* SIGCHLD.  */
//	struct
//	  {
//	    __pid_t si_pid;	/* Which child.	 */
//	    __uid_t si_uid;	/* Real user ID of sending process.  */
//	    int si_status;	/* Exit value or signal.  */
//	    __SI_CLOCK_T si_utime;
//	    __SI_CLOCK_T si_stime;
//	  } _sigchld;
//
//	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
//	struct
//	  {
//	    void *si_addr;	    /* Faulting insn/memory ref.  */
//	    __SI_SIGFAULT_ADDL
//	    short int si_addr_lsb;  /* Valid LSB of the reported address.  */
//	    union
//	      {
//		/* used when si_code=SEGV_BNDERR */
//		struct
//		  {
//		    void *_lower;
//		    void *_upper;
//		  } _addr_bnd;
//		/* used when si_code=SEGV_PKUERR */
//		__uint32_t _pkey;
//	      } _bounds;
//	  } _sigfault;
//
//	/* SIGPOLL.  */
//	struct
//	  {
//	    __SI_BAND_TYPE si_band;	/* Band event for SIGPOLL.  */
//	    int si_fd;
//	  } _sigpoll;
//
//	/* SIGSYS.  */
// #if __SI_HAVE_SIGSYS
//	struct
//	  {
//	    void *_call_addr;	/* Calling user insn.  */
//	    int _syscall;	/* Triggering system call number.  */
//	    unsigned int _arch; /* AUDIT_ARCH_* of syscall.  */
//	  } _sigsys;
// #endif
//       } _sifields;
//   } siginfo_t __SI_ALIGNMENT;
//

typedef struct {
    u32 version;
    Pid pid;
}* CapUserHeader;

typedef struct {
    u32 effective;
    u32 permitted;
    u32 inheritable;
}* CapUserData;

struct SharedMemId {
    struct IpcPerm permissions;
    usize segment_size;
    Time attach_time;
    Time detach_time;
    Time creation_time;
    Pid creator_pid;
    Pid modifier_pid;
    SharedMemAttaches attaches;
    usize __libc_reserved5;
    usize __libc_reserved6;
};

struct ResourceLimit {
    RLimit current;
    RLimit max;
};

struct ResourceLimit64 {
    RLimit64 curr;
};

/// Sizes of the memory and swap fields are given as multiples of mem_unit bytes.
struct SysInfo {
    i64 uptime;    // Seconds since boot
    u64 loads[3];  // 1, 5, and 15 minute load averages
    u64 totalram;  // Total usable main memory size
    u64 freeram;   // Available memory size
    u64 sharedram; // Amount of shared memory
    u64 bufferram; // Memory used by buffers
    u64 totalswap; // Total swap space size
    u64 freeswap;  // Swap space still available
    u16 procs;     // Number of current processes
    u64 totalhigh; // Total high memory size
    u64 freehigh;  // Available high memory size
    u32 mem_unit;  // Memory unit size in bytes
    // Padding
    byte _f[20 - 2 * sizeof(i64) - sizeof(i32)];
};

struct Times {
    Clock tms_utime;  // user time
    Clock tms_stime;  // system time
    Clock tms_cutime; // user time of children
    Clock tms_cstime; // system time of children
};

struct UtimeBuf {
    Time actime;  // access time
    Time modtime; // modification time
};

enum ClockKind {
    CLOCK_REALTIME = 0,
    // Monotonic system-wide clock.
    CLOCK_MONOTONIC = 1,
    // High-resolution timer from the CPU.
    CLOCK_PROCESS_CPUTIME_ID = 2,
    // Thread-specific CPU-time clock.
    CLOCK_THREAD_CPUTIME_ID = 3,
    // Monotonic system-wide clock, not adjusted for frequency scaling.
    CLOCK_MONOTONIC_RAW = 4,
    // Identifier for system-wide realtime clock, updated only on ticks.
    CLOCK_REALTIME_COARSE = 5,
    // Monotonic system-wide clock, updated only on ticks.
    CLOCK_MONOTONIC_COARSE = 6,
    // Monotonic system-wide clock that includes time spent in suspension.
    CLOCK_BOOTTIME = 7,
    // Like CLOCK_REALTIME but also wakes suspended system.
    CLOCK_REALTIME_ALARM = 8,
    // Like CLOCK_BOOTTIME but also wakes suspended system.
    CLOCK_BOOTTIME_ALARM = 9,
    // Like CLOCK_REALTIME but in International Atomic Time.
    CLOCK_TAI = 11,
};

/// ** Deprecated **
struct Ustat {
    DAddr f_tfree;    // Total free blocks
    InodeId f_tinode; // Number of free inodes
    char f_fname[6];  // Filsys name, unimplemented, always full of null bytes
    char f_fpack[6];  // Filsys pack name unimplemented, always full of null bytes
};

/// Magic numbers that may appear as `f_type` in `StatFs`
enum FsTypeMagic {
    ADFS_SUPER_MAGIC = 0xadf5,
    AFFS_SUPER_MAGIC = 0xadff,
    AFS_SUPER_MAGIC = 0x5346414f,
    // Anonymous inode FS (for pseudofiles that have no name; e.g., epoll, signalfd, bpf)
    ANON_INODE_FS_MAGIC = 0x09041934,
    AUTOFS_SUPER_MAGIC = 0x0187,
    BDEVFS_MAGIC = 0x62646576,
    BEFS_SUPER_MAGIC = 0x42465331,
    BFS_MAGIC = 0x1badface,
    BINFMTFS_MAGIC = 0x42494e4d,
    BPF_FS_MAGIC = 0xcafe4a11,
    BTRFS_SUPER_MAGIC = 0x9123683e,
    BTRFS_TEST_MAGIC = 0x73727279,
    CGROUP_SUPER_MAGIC = 0x27e0eb,    // Cgroup pseudo FS
    CGROUP2_SUPER_MAGIC = 0x63677270, // Cgroup v2 pseudo FS
    CIFS_MAGIC_NUMBER = 0xff534d42,
    CODA_SUPER_MAGIC = 0x73757245,
    COH_SUPER_MAGIC = 0x012ff7b7,
    CRAMFS_MAGIC = 0x28cd3d45,
    DEBUGFS_MAGIC = 0x64626720,
    DEVFS_SUPER_MAGIC = 0x1373, // Linux 2.6.17 and earlier
    DEVPTS_SUPER_MAGIC = 0x1cd1,
    ECRYPTFS_SUPER_MAGIC = 0xf15f,
    EFIVARFS_MAGIC = 0xde5e81e4,
    EFS_SUPER_MAGIC = 0x00414a53,
    EXT_SUPER_MAGIC = 0x137d, // Linux 2.0 and earlier
    EXT2_OLD_SUPER_MAGIC = 0xef51,
    EXT2_SUPER_MAGIC = 0xef53,
    EXT3_SUPER_MAGIC = 0xef53,
    EXT4_SUPER_MAGIC = 0xef53,
    F2FS_SUPER_MAGIC = 0xf2f52010,
    FUSE_SUPER_MAGIC = 0x65735546,
    FUTEXFS_SUPER_MAGIC = 0xbad1dea, // Unused
    HFS_SUPER_MAGIC = 0x4244,
    HOSTFS_SUPER_MAGIC = 0x00c0ffee,
    HPFS_SUPER_MAGIC = 0xf995e849,
    HUGETLBFS_MAGIC = 0x958458f6,
    ISOFS_SUPER_MAGIC = 0x9660,
    JFFS2_SUPER_MAGIC = 0x72b6,
    JFS_SUPER_MAGIC = 0x3153464a,
    MINIX_SUPER_MAGIC = 0x137f,   // original minix FS
    MINIX_SUPER_MAGIC2 = 0x138f,  // 30 char minix FS
    MINIX2_SUPER_MAGIC = 0x2468,  // minix V2 FS
    MINIX2_SUPER_MAGIC2 = 0x2478, // minix V2 FS, 30 char names
    MINIX3_SUPER_MAGIC = 0x4d5a,  // minix V3 FS, 60 char names
    MQUEUE_MAGIC = 0x19800202,    // POSIX message queue FS
    MSDOS_SUPER_MAGIC = 0x4d44,
    MTD_INODE_FS_MAGIC = 0x11307854,
    NCP_SUPER_MAGIC = 0x564c,
    NFS_SUPER_MAGIC = 0x6969,
    NILFS_SUPER_MAGIC = 0x3434,
    NSFS_MAGIC = 0x6e736673,
    NTFS_SB_MAGIC = 0x5346544e,
    OCFS2_SUPER_MAGIC = 0x7461636f,
    OPENPROM_SUPER_MAGIC = 0x9fa1,
    OVERLAYFS_SUPER_MAGIC = 0x794c7630,
    PIPEFS_MAGIC = 0x50495045,
    PROC_SUPER_MAGIC = 0x9fa0, // /proc FS
    PSTOREFS_MAGIC = 0x6165676c,
    QNX4_SUPER_MAGIC = 0x002f,
    QNX6_SUPER_MAGIC = 0x68191122,
    RAMFS_MAGIC = 0x858458f6,
    REISERFS_SUPER_MAGIC = 0x52654973,
    ROMFS_MAGIC = 0x7275,
    SECURITYFS_MAGIC = 0x73636673,
    SELINUX_MAGIC = 0xf97cff8c,
    SMACK_MAGIC = 0x43415d53,
    SMB_SUPER_MAGIC = 0x517b,
    SMB2_MAGIC_NUMBER = 0xfe534d42,
    SOCKFS_MAGIC = 0x534f434b,
    SQUASHFS_MAGIC = 0x73717368,
    SYSFS_MAGIC = 0x62656572,
    SYSV2_SUPER_MAGIC = 0x012ff7b6,
    SYSV4_SUPER_MAGIC = 0x012ff7b5,
    TMPFS_MAGIC = 0x01021994,
    TRACEFS_MAGIC = 0x74726163,
    UDF_SUPER_MAGIC = 0x15013346,
    UFS_MAGIC = 0x00011954,
    USBDEVICE_SUPER_MAGIC = 0x9fa2,
    V9FS_MAGIC = 0x01021997,
    VXFS_SUPER_MAGIC = 0xa501fcf5,
    XENFS_SUPER_MAGIC = 0xabba1974,
    XENIX_SUPER_MAGIC = 0x012ff7b4,
    XFS_SUPER_MAGIC = 0x58465342,
    _XIAFS_SUPER_MAGIC = 0x012fd16d, // Linux 2.0 and earlier
};

enum StatFsMountFlags {
    ST_RDONLY = 1,        // Mount read-only.
    ST_NOSUID = 2,        // Ignore suid and sgid bits.
    ST_NODEV = 4,         // Disallow access to device special files.
    ST_NOEXEC = 8,        // Disallow program execution.
    ST_SYNCHRONOUS = 16,  // Writes are synced at once.
    ST_MANDLOCK = 64,     // Allow mandatory locks on an FS.
    ST_WRITE = 128,       // Write on file/directory/symlink.
    ST_APPEND = 256,      // Append-only file.
    ST_IMMUTABLE = 512,   // Immutable file.
    ST_NOATIME = 1024,    // Do not update access times.
    ST_NODIRATIME = 2048, // Do not update directory access times.
    ST_RELATIME = 4096    // Update atime relative to mtime/ctime.
};

/// Information about a mounted filesystem
struct StatFs {
    FsWord f_type;         // Type of filesystem
    FsWord f_bsize;        // Optimal transfer block size
    FsBlockCount f_blocks; // Total data blocks in filesystem
    FsBlockCount f_bfree;  // Free blocks in filesystem
    FsBlockCount f_bavail; // Free blocks available to unprivileged user
    FsFileCount f_files;   // Total inodes in filesystem
    FsFileCount f_ffree;   // Free inodes in filesystem
    //  man 2 statfs: "Nobody knows what f_fsid is supposed to contain"
    FsId f_fsid;       // Filesystem ID
    FsWord f_namelen;  // Maximum filename length
    FsWord f_frsize;   // Fragment size
    FsWord f_flags;    // Filesystem mount flags
    FsWord f_spare[4]; // Reserved padding bytes
};

// Data structure to describe a process' schedulability.
struct SchedParam {
    i32 sched_priority;
};

/// kexec flags for different usage scenarios
enum KExecFlags {
    KEXEC_ON_CRASH = 0x00000001,
    KEXEC_PRESERVE_CONTEXT = 0x00000002,
    KEXEC_UPDATE_ELFCOREHDR = 0x00000004,
    KEXEC_ARCH_MASK = 0xffff0000,

    // Kexec file load interface flags.
    // KEXEC_FILE_UNLOAD : Unload already loaded kexec/kdump image.
    // KEXEC_FILE_ON_CRASH : Load/unload operation belongs to kdump image.
    // KEXEC_FILE_NO_INITRAMFS : No initramfs is being loaded. Ignore the initrd fd field.
    KEXEC_FILE_UNLOAD = 0x00000001,
    KEXEC_FILE_ON_CRASH = 0x00000002,
    KEXEC_FILE_NO_INITRAMFS = 0x00000004,
    KEXEC_FILE_DEBUG = 0x00000008,

    // These values match the ELF architecture values.
    // Unless there is a good reason that should continue to be the case.
    KEXEC_ARCH_DEFAULT = (0 << 16),
    KEXEC_ARCH_386 = (3 << 16),
    KEXEC_ARCH_68K = (4 << 16),
    KEXEC_ARCH_PARISC = (15 << 16),
    KEXEC_ARCH_X86_64 = (62 << 16),
    KEXEC_ARCH_PPC = (20 << 16),
    KEXEC_ARCH_PPC64 = (21 << 16),
    KEXEC_ARCH_IA_64 = (50 << 16),
    KEXEC_ARCH_ARM = (40 << 16),
    KEXEC_ARCH_S390 = (22 << 16),
    KEXEC_ARCH_SH = (42 << 16),
    KEXEC_ARCH_MIPS_LE = (10 << 16),
    KEXEC_ARCH_MIPS = (8 << 16),
    KEXEC_ARCH_AARCH64 = (183 << 16),
    KEXEC_ARCH_RISCV = (243 << 16),
    KEXEC_ARCH_LOONGARCH = (258 << 16),

    // The artificial cap on the number of segments passed to kexec_load.
    KEXEC_SEGMENT_MAX = 16,
};

struct KExecSegment {
    void* buf;
    usize bufsz;
    void* mem;
    usize memsz;
};

/// Per-lock list entry - embedded in user-space locks, somewhere close
/// to the futex field. (Note: user-space uses a double-linked list to
/// achieve O(1) list add and remove, but the kernel only needs to know
/// about the forward link)
struct RobustList {
    struct RobustList* next;
};

/// Per-thread list head:
struct RobustListHead {
    // The head of the list. Points back to itself if empty:
    struct RobustList list;

    // This relative offset is set by user-space, it gives the kernel
    // the relative position of the futex field to examine. This way
    // we keep userspace flexible, to freely shape its data-structure,
    // without hardcoding any particular offset into the kernel:
    long futex_offset;

    // The death of the thread may race with userspace setting
    // up a lock's links. So to handle this race, userspace first
    // sets this field to the address of the to-be-taken lock,
    // then does the lock acquire, and then adds itself to the
    // list, and then clears this field. Hence the kernel will
    // always have full knowledge of all locks that the thread
    // _might_ have taken. We check the owner TID in any case,
    // so only truly owned locks will be handled.
    struct RobustList* list_op_pending;
};

#endif // ifndef EXALT_EXSYSTYPES_H
