/*
 * SentinalOS System Call Interface
 * Pentagon-Level Security System Calls
 */

#include <stdarg.h>
#include <errno.h>

/* Global errno variable */
int errno = 0;

/* System call numbers */
#define SYS_READ        0
#define SYS_WRITE       1
#define SYS_OPEN        2
#define SYS_CLOSE       3
#define SYS_STAT        4
#define SYS_FSTAT       5
#define SYS_LSTAT       6
#define SYS_POLL        7
#define SYS_LSEEK       8
#define SYS_MMAP        9
#define SYS_MPROTECT    10
#define SYS_MUNMAP      11
#define SYS_BRK         12
#define SYS_GETPID      39
#define SYS_GETPPID     110
#define SYS_GETUID      102
#define SYS_GETGID      104
#define SYS_GETEUID     107
#define SYS_GETEGID     108
#define SYS_EXIT        60
#define SYS_KILL        62
#define SYS_FORK        57
#define SYS_EXECVE      59
#define SYS_WAIT4       61

/* Security-enhanced system calls */
#define SYS_SENTINAL_SECURE_READ   1000
#define SYS_SENTINAL_SECURE_WRITE  1001
#define SYS_SENTINAL_ENCRYPT       1002
#define SYS_SENTINAL_DECRYPT       1003
#define SYS_SENTINAL_AUDIT_LOG     1004

/* Low-level system call interface */
static inline long _syscall0(long number) {
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a" (ret)
        : "a" (number)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _syscall1(long number, long arg1) {
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a" (ret)
        : "a" (number), "D" (arg1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _syscall2(long number, long arg1, long arg2) {
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a" (ret)
        : "a" (number), "D" (arg1), "S" (arg2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _syscall3(long number, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a" (ret)
        : "a" (number), "D" (arg1), "S" (arg2), "d" (arg3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _syscall4(long number, long arg1, long arg2, long arg3, long arg4) {
    long ret;
    register long r10 __asm__("r10") = arg4;
    __asm__ __volatile__(
        "syscall"
        : "=a" (ret)
        : "a" (number), "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _syscall5(long number, long arg1, long arg2, long arg3, long arg4, long arg5) {
    long ret;
    register long r10 __asm__("r10") = arg4;
    register long r8 __asm__("r8") = arg5;
    __asm__ __volatile__(
        "syscall"
        : "=a" (ret)
        : "a" (number), "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10), "r" (r8)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _syscall6(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    long ret;
    register long r10 __asm__("r10") = arg4;
    register long r8 __asm__("r8") = arg5;
    register long r9 __asm__("r9") = arg6;
    __asm__ __volatile__(
        "syscall"
        : "=a" (ret)
        : "a" (number), "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10), "r" (r8), "r" (r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/* Generic system call interface */
long syscall(long number, ...) {
    va_list args;
    va_start(args, number);
    
    long ret;
    
    /* Count arguments */
    switch (number) {
        /* 0-argument syscalls */
        case SYS_GETPID:
        case SYS_GETPPID:
        case SYS_GETUID:
        case SYS_GETGID:
        case SYS_GETEUID:
        case SYS_GETEGID:
        case SYS_FORK:
            ret = _syscall0(number);
            break;
            
        /* 1-argument syscalls */
        case SYS_CLOSE:
        case SYS_BRK:
        case SYS_EXIT:
            ret = _syscall1(number, va_arg(args, long));
            break;
            
        /* 2-argument syscalls */
        case SYS_KILL:
            ret = _syscall2(number, va_arg(args, long), va_arg(args, long));
            break;
            
        /* 3-argument syscalls */
        case SYS_READ:
        case SYS_WRITE:
        case SYS_OPEN:
        case SYS_LSEEK:
        case SYS_EXECVE:
            ret = _syscall3(number, va_arg(args, long), va_arg(args, long), va_arg(args, long));
            break;
            
        /* 4-argument syscalls */
        case SYS_WAIT4:
            ret = _syscall4(number, va_arg(args, long), va_arg(args, long), 
                           va_arg(args, long), va_arg(args, long));
            break;
            
        /* 6-argument syscalls */
        case SYS_MMAP:
            ret = _syscall6(number, va_arg(args, long), va_arg(args, long),
                           va_arg(args, long), va_arg(args, long),
                           va_arg(args, long), va_arg(args, long));
            break;
            
        default:
            /* Generic handling - assume up to 6 arguments */
            ret = _syscall6(number, 
                           va_arg(args, long), va_arg(args, long), va_arg(args, long),
                           va_arg(args, long), va_arg(args, long), va_arg(args, long));
            break;
    }
    
    va_end(args);
    
    /* Handle error returns */
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    
    return ret;
}

/* Standard POSIX system call wrappers */

#include <sys/types.h>
#include <unistd.h>

ssize_t read(int fd, void *buf, size_t count) {
    return syscall(SYS_READ, fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count) {
    return syscall(SYS_WRITE, fd, buf, count);
}

int close(int fd) {
    return syscall(SYS_CLOSE, fd);
}

pid_t getpid(void) {
    return syscall(SYS_GETPID);
}

pid_t getppid(void) {
    return syscall(SYS_GETPPID);
}

uid_t getuid(void) {
    return syscall(SYS_GETUID);
}

gid_t getgid(void) {
    return syscall(SYS_GETGID);
}

uid_t geteuid(void) {
    return syscall(SYS_GETEUID);
}

gid_t getegid(void) {
    return syscall(SYS_GETEGID);
}

void _exit(int status) {
    syscall(SYS_EXIT, status);
    while (1); /* Should never reach here */
}

int kill(pid_t pid, int sig) {
    return syscall(SYS_KILL, pid, sig);
}

pid_t fork(void) {
    return syscall(SYS_FORK);
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    return syscall(SYS_EXECVE, pathname, argv, envp);
}

void *sbrk(intptr_t increment) {
    static void *current_brk = NULL;
    
    if (current_brk == NULL) {
        current_brk = (void*)syscall(SYS_BRK, 0);
        if (current_brk == (void*)-1) {
            errno = ENOMEM;
            return (void*)-1;
        }
    }
    
    if (increment == 0) {
        return current_brk;
    }
    
    void *new_brk = (void*)syscall(SYS_BRK, (char*)current_brk + increment);
    if (new_brk == (void*)-1) {
        errno = ENOMEM;
        return (void*)-1;
    }
    
    void *old_brk = current_brk;
    current_brk = new_brk;
    return old_brk;
}

/* SentinalOS-specific secure system calls */

ssize_t sentinal_secure_read(int fd, void *buf, size_t count, const char *security_context) {
    return syscall(SYS_SENTINAL_SECURE_READ, fd, buf, count, security_context);
}

ssize_t sentinal_secure_write(int fd, const void *buf, size_t count, const char *security_context) {
    return syscall(SYS_SENTINAL_SECURE_WRITE, fd, buf, count, security_context);
}

int sentinal_encrypt_data(const void *plaintext, size_t plain_len, void *ciphertext, size_t *cipher_len, const char *key) {
    return syscall(SYS_SENTINAL_ENCRYPT, plaintext, plain_len, ciphertext, cipher_len, key);
}

int sentinal_decrypt_data(const void *ciphertext, size_t cipher_len, void *plaintext, size_t *plain_len, const char *key) {
    return syscall(SYS_SENTINAL_DECRYPT, ciphertext, cipher_len, plaintext, plain_len, key);
}

int sentinal_audit_log(const char *event, const char *details, int severity) {
    return syscall(SYS_SENTINAL_AUDIT_LOG, event, details, severity);
}