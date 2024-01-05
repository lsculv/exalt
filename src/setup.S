// These are the definitions for the entry-point and syscalls.
//
// This requires some knowledge of calling conventions, the AMD64 ABI, and
// the Linux system call interface. This code is heavily commented and citied
// to make it easier to understand and more educational.
// 
// Much of the code and research was sourced from https://gist.github.com/tcoppex/443d1dd45f873d96260195d6431b0989
.intel_syntax noprefix
.text
    .globl _start, syscall, syscall1, syscall2, syscall3, syscall4, syscall5

    _start:
        // [1] p.30 | Section 3.4.1
        xor rbp, rbp // We have to zero the rbp register (frame pointer) as it
                     // can contain arbitary data when a processs is initialized.
        // [1] p.29 | Figure 3.9
        pop rdi // The rdi register contains the first function argument. In the
                // case of `main` this needs to be `argc`, which is at the top 
                // of the stack on AMD64.
        // [1] p.29 | Figure 3.9
        mov rsi, rsp // The second argument goes in rsi. This needs to be the
                     // `argv` argument pointer, which is in the next stack slot
                     // after `argc`.
        // [1] p.30 | Section 3.4.1
        and rsp, -16 // The stack needs to be 16-byte aligned.
        call main // Call the `main` function that the user implements.
        mov rdi, rax // `rax` now contains the return value of main, which we
                     // want to be the exit status of our program (see syscall section).
        mov rax, 60 // see syscall section.
        syscall // Making the exit syscall.
        ret // The program should have already exited by now, if this is reached 
            // it will SEGFAULT the program.

    // Linux syscalls all follow a standard interface of where to place the
    // arguments and where the value they return goes. See https://filippo.io/linux-syscall-table/
    // for a handy table, and the syscall(2) and syscalls(2) manpages for more.
    //
    // Multiple syscall functions are defined as different syscalls have different
    // numbers of arguments.
    syscall0:
        mov rax, rdi
        syscall
        ret

    syscall1:
        mov rax, rdi
        mov rdi, rsi
        syscall
        ret

    syscall2:
        mov rax, rdi
        mov rdi, rsi
        mov rsi, rdx
        syscall
        ret

    syscall3:
        mov rax, rdi
        mov rdi, rsi
        mov rsi, rdx
        mov rdx, rcx
        syscall
        ret

    syscall4:
        mov rax, rdi
        mov rdi, rsi
        mov rsi, rdx
        mov rdx, rcx
        mov r10, r8
        syscall
        ret

    syscall5:
        mov rax, rdi
        mov rdi, rsi
        mov rsi, rdx
        mov rdx, rcx
        mov r10, r8
        mov r8,  r9
        syscall
        ret

    syscall6:
        mov rax, rdi
        mov rdi, rsi
        mov rsi, rdx
        mov rdx, rcx
        mov r10, r8
        mov r8,  r9
        mov r9,  qword ptr [rsp+8]
        syscall
        ret
        

// Resources:
// [1] AMD64 ABI Draft 0.99.6 – July 2, 2012
//     https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
//
// [2] Searchable Linux Syscall Table for x86 and x86_64
//     https://filippo.io/linux-syscall-table/
//
// [3] Writing C software without the standard library [Linux Edition]
//     https://gist.github.com/tcoppex/443d1dd45f873d96260195d6431b0989
