// Types expected by the Linux system call interface.
#ifndef EXALT_EXSYSTYPES_H
#define EXALT_EXSYSTYPES_H

#include "../int.h"

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

struct Stat {};

typedef isize Offset;

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

struct PollFd {};

struct SigAction {};

struct IoVec {
    void* iov_base; // data
    usize iov_len;  // length of data
};

typedef i64 Time;
typedef i64 SignedMicros;
typedef i64 SignedNanos;

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

typedef void* Timer;
typedef i32 ClockId;

typedef u16 SAFamily;
typedef u32 SockLen;
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

typedef i32 MsgQueueDescriptor;

typedef i32 Pid;
typedef u32 Uid;
typedef u32 Gid;

typedef i32 IpcKey;

struct IpcPerm {
    IpcKey key; // Key given to msgget
    Uid uid;    // Effective UID of the owner
    Gid gid;    // Effective GID of the owner
    Uid cuid;   // Effective UID of the creator
    Gid cgid;   // Effective GID of the creator
    u16 mode;   // Permissions
    u16 seq;    // Sequence number
};

/// Represents the amount of messages in a message queue.
typedef u64 MsgQueueCount;
/// Represents the amount of bytes allowed on the queue.
typedef u64 MsgLen;

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

struct RUsage {
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

// Unix Time-Sharing System Name. Used to contain information about the
// current Unix system you are running.
#define _UTSNAME_LENGTH 65
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

// Used for argument to `semop` to describe operations.
struct SemBuf {
    u16 sem_num; // semaphore number
    i16 sem_op;  // semaphore operation
    i16 sem_flg; // operation flag
};

struct UserDesc {
    unsigned int entry_number;
    unsigned int base_addr;
    unsigned int limit;
    unsigned int seg_32bit : 1;
    unsigned int contents : 2;
    unsigned int read_exec_only : 1;
    unsigned int limit_in_pages : 1;
    unsigned int seg_not_present : 1;
    unsigned int useable : 1;
    unsigned int lm : 1;
};

typedef u64 AioContext;
typedef i32 KernelRwf;

struct IoCb {
    /* these are internal to the kernel/libc. */
    u64 aio_data; /* data to be returned in event's data */

    u32 aio_key;            /* the kernel sets aio_key to the req # */
    KernelRwf aio_rw_flags; /* RWF_* flags */

    /* common fields */
    u16 aio_lio_opcode; /* see IOCB_CMD_ above */
    i16 aio_reqprio;
    u32 aio_fildes;

    u64 aio_buf;
    u64 aio_nbytes;
    i64 aio_offset;

    /* extra parameters */
    u64 aio_reserved2; /* TODO: use this for a (struct sigevent *) */

    /* flags for the "struct iocb" */
    u32 aio_flags;

    /*
     * if the IOCB_FLAG_RESFD flag of "aio_flags" is set, this is an
     * eventfd to signal AIO readiness to
     */
    u32 aio_resfd;
};

/* read() from /dev/aio returns these structures. */
struct IoEvent {
    u64 data; /* the data field from the iocb */
    u64 obj;  /* what iocb this event came from */
    i64 res;  /* result code for this event */
    i64 res2; /* secondary result */
};

typedef union {
    void* ptr;
    int fd;
    u32 uint32;
    u64 uint64;
} EpollData;

struct EpollEvent {
    u32 events;     /* Epoll events */
    EpollData data; /* User data variable */
} __attribute__((__packed__));

// TODO: Implement this struct. The glibc source is below. Good luck.
// Might want to look at the Rust libc crate source or the musl source as well
typedef struct {
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

#endif // ifndef EXALT_EXSYSTYPES_H
