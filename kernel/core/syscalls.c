/*
 * SentinalOS System Call Implementation
 * POSIX-Compatible System Call Interface
 */

#include "../include/system.h"
#include <stdarg.h>

/* Global system state */
static struct process *current_process = NULL;
static struct process *process_list = NULL;
static uint32_t next_pid = 1;
static struct file_descriptor file_table[MAX_OPEN_FILES];

/* System call jump table */
static long (*syscall_table[SYS_MAX])(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* Forward declarations */
static long sys_exit(uint64_t status, uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4);
static long sys_fork(uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4, uint64_t unused5);
static long sys_read(uint64_t fd, uint64_t buf, uint64_t count, uint64_t unused1, uint64_t unused2);
static long sys_write(uint64_t fd, uint64_t buf, uint64_t count, uint64_t unused1, uint64_t unused2);
static long sys_open(uint64_t filename, uint64_t flags, uint64_t mode, uint64_t unused1, uint64_t unused2);
static long sys_close(uint64_t fd, uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4);
static long sys_getpid(uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4, uint64_t unused5);
static long sys_execve(uint64_t filename, uint64_t argv, uint64_t envp, uint64_t unused1, uint64_t unused2);
static long sys_waitpid(uint64_t pid, uint64_t status, uint64_t options, uint64_t unused1, uint64_t unused2);
static long sys_kill(uint64_t pid, uint64_t sig, uint64_t unused1, uint64_t unused2, uint64_t unused3);
static long sys_brk(uint64_t addr, uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4);
static long sys_mmap(uint64_t addr, uint64_t length, uint64_t prot, uint64_t flags, uint64_t fd);

/* Initialize system call table */
void syscall_init(void) {
    /* Clear file table */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        file_table[i].inode = NULL;
        file_table[i].ref_count = 0;
    }
    
    /* Initialize system call table */
    syscall_table[SYS_EXIT] = sys_exit;
    syscall_table[SYS_FORK] = sys_fork;
    syscall_table[SYS_READ] = sys_read;
    syscall_table[SYS_WRITE] = sys_write;
    syscall_table[SYS_OPEN] = sys_open;
    syscall_table[SYS_CLOSE] = sys_close;
    syscall_table[SYS_GETPID] = sys_getpid;
    syscall_table[SYS_EXECVE] = sys_execve;
    syscall_table[SYS_WAITPID] = sys_waitpid;
    syscall_table[SYS_KILL] = sys_kill;
    syscall_table[SYS_BRK] = sys_brk;
    syscall_table[SYS_MMAP] = sys_mmap;
    
    debug_print("System call interface initialized\n");
}

/* Main system call handler */
long syscall_handler(uint64_t syscall_num, uint64_t arg1, uint64_t arg2, 
                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    
    /* Security validation */
    if (current_process && 
        security_validate_syscall(syscall_num, current_process) != 0) {
        security_audit_log("SYSCALL_DENIED", current_process->pid, "Insufficient privileges");
        return -1; /* EPERM */
    }
    
    /* Bounds check */
    if (syscall_num >= SYS_MAX || syscall_table[syscall_num] == NULL) {
        return -38; /* ENOSYS */
    }
    
    /* Log system call for audit */
    if (current_process && current_process->security_level >= 2) {
        char audit_msg[256];
        snprintf(audit_msg, sizeof(audit_msg), "syscall_%lu", syscall_num);
        security_audit_log("SYSCALL", current_process->pid, audit_msg);
    }
    
    /* Call the appropriate system call handler */
    return syscall_table[syscall_num](arg1, arg2, arg3, arg4, arg5);
}

/* Process exit system call */
static long sys_exit(uint64_t status, uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4) {
    if (!current_process) {
        return -1;
    }
    
    debug_print("Process %d exiting with status %lu\n", current_process->pid, status);
    
    /* Close all open files */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (current_process->open_files[i] != 0) {
            sys_close(i, 0, 0, 0, 0);
        }
    }
    
    /* Set process state to zombie */
    current_process->state = PROCESS_ZOMBIE;
    
    /* Schedule next process */
    process_schedule();
    
    /* This should never return */
    return 0;
}

/* Fork system call */
static long sys_fork(uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4, uint64_t unused5) {
    if (!current_process) {
        return -1;
    }
    
    /* Allocate new process structure */
    struct process *child = (struct process *)kmalloc(sizeof(struct process));
    if (!child) {
        return -12; /* ENOMEM */
    }
    
    /* Copy parent process */
    *child = *current_process;
    child->pid = next_pid++;
    child->ppid = current_process->pid;
    child->state = PROCESS_READY;
    
    /* Allocate new page directory */
    child->page_directory = (uint64_t *)kmalloc(PAGE_SIZE);
    if (!child->page_directory) {
        kfree(child);
        return -12; /* ENOMEM */
    }
    
    /* Copy memory space (simplified) */
    for (int i = 0; i < 512; i++) {
        child->page_directory[i] = current_process->page_directory[i];
    }
    
    /* Add to process list */
    child->next = process_list;
    if (process_list) {
        process_list->prev = child;
    }
    child->prev = NULL;
    process_list = child;
    
    debug_print("Forked process %d from %d\n", child->pid, current_process->pid);
    
    /* Return child PID to parent, 0 to child */
    return child->pid;
}

/* Read system call */
static long sys_read(uint64_t fd, uint64_t buf, uint64_t count, uint64_t unused1, uint64_t unused2) {
    if (fd >= MAX_OPEN_FILES || file_table[fd].inode == NULL) {
        return -9; /* EBADF */
    }
    
    if (!buf || count == 0) {
        return -14; /* EFAULT */
    }
    
    struct file_descriptor *file = &file_table[fd];
    
    /* Read from file */
    long bytes_read = fs_read_inode(file->inode, file->offset, (void *)buf, count);
    if (bytes_read > 0) {
        file->offset += bytes_read;
    }
    
    return bytes_read;
}

/* Write system call */
static long sys_write(uint64_t fd, uint64_t buf, uint64_t count, uint64_t unused1, uint64_t unused2) {
    if (fd >= MAX_OPEN_FILES) {
        return -9; /* EBADF */
    }
    
    if (!buf || count == 0) {
        return -14; /* EFAULT */
    }
    
    /* Special handling for stdout/stderr */
    if (fd == 1 || fd == 2) {
        /* Write to console */
        const char *str = (const char *)buf;
        for (size_t i = 0; i < count; i++) {
            debug_print("%c", str[i]);
        }
        return count;
    }
    
    if (file_table[fd].inode == NULL) {
        return -9; /* EBADF */
    }
    
    struct file_descriptor *file = &file_table[fd];
    
    /* Write to file */
    long bytes_written = fs_write_inode(file->inode, file->offset, (void *)buf, count);
    if (bytes_written > 0) {
        file->offset += bytes_written;
    }
    
    return bytes_written;
}

/* Open system call */
static long sys_open(uint64_t filename, uint64_t flags, uint64_t mode, uint64_t unused1, uint64_t unused2) {
    if (!filename) {
        return -14; /* EFAULT */
    }
    
    const char *path = (const char *)filename;
    
    /* Find free file descriptor */
    int fd = -1;
    for (int i = 3; i < MAX_OPEN_FILES; i++) { /* Reserve 0,1,2 for stdin,stdout,stderr */
        if (file_table[i].inode == NULL) {
            fd = i;
            break;
        }
    }
    
    if (fd == -1) {
        return -24; /* EMFILE */
    }
    
    /* Get inode for file */
    struct inode *inode = fs_get_inode(0); /* Simplified - should resolve path */
    if (!inode) {
        /* Try to create file if O_CREAT flag is set */
        if (flags & 0x40) { /* O_CREAT */
            if (fs_create_file(path, mode) != 0) {
                return -2; /* ENOENT */
            }
            inode = fs_get_inode(0);
        }
        
        if (!inode) {
            return -2; /* ENOENT */
        }
    }
    
    /* Initialize file descriptor */
    file_table[fd].inode = inode;
    file_table[fd].offset = 0;
    file_table[fd].flags = flags;
    file_table[fd].mode = mode;
    file_table[fd].ref_count = 1;
    
    /* Update process open files */
    if (current_process) {
        current_process->open_files[fd] = 1;
    }
    
    debug_print("Opened file '%s' with fd %d\n", path, fd);
    
    return fd;
}

/* Close system call */
static long sys_close(uint64_t fd, uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4) {
    if (fd >= MAX_OPEN_FILES || file_table[fd].inode == NULL) {
        return -9; /* EBADF */
    }
    
    /* Decrement reference count */
    file_table[fd].ref_count--;
    
    if (file_table[fd].ref_count == 0) {
        /* Close file */
        file_table[fd].inode = NULL;
        file_table[fd].offset = 0;
        file_table[fd].flags = 0;
        file_table[fd].mode = 0;
    }
    
    /* Update process open files */
    if (current_process) {
        current_process->open_files[fd] = 0;
    }
    
    debug_print("Closed fd %lu\n", fd);
    
    return 0;
}

/* Get process ID system call */
static long sys_getpid(uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4, uint64_t unused5) {
    return current_process ? current_process->pid : 1;
}

/* Execute program system call */
static long sys_execve(uint64_t filename, uint64_t argv, uint64_t envp, uint64_t unused1, uint64_t unused2) {
    if (!filename) {
        return -14; /* EFAULT */
    }
    
    const char *path = (const char *)filename;
    debug_print("Executing program: %s\n", path);
    
    /* For now, just change the process name */
    if (current_process) {
        strncpy(current_process->name, path, sizeof(current_process->name) - 1);
        current_process->name[sizeof(current_process->name) - 1] = '\0';
    }
    
    /* In a full implementation, this would load and execute the program */
    return 0;
}

/* Wait for process system call */
static long sys_waitpid(uint64_t pid, uint64_t status, uint64_t options, uint64_t unused1, uint64_t unused2) {
    if (!current_process) {
        return -1;
    }
    
    /* Find child process */
    struct process *child = process_find_by_pid(pid);
    if (!child || child->ppid != current_process->pid) {
        return -10; /* ECHILD */
    }
    
    /* Wait for child to become zombie */
    while (child->state != PROCESS_ZOMBIE) {
        current_process->state = PROCESS_BLOCKED;
        process_schedule();
    }
    
    /* Clean up child process */
    if (child->prev) {
        child->prev->next = child->next;
    } else {
        process_list = child->next;
    }
    
    if (child->next) {
        child->next->prev = child->prev;
    }
    
    uint32_t child_pid = child->pid;
    kfree(child->page_directory);
    kfree(child);
    
    debug_print("Reaped child process %d\n", child_pid);
    
    return child_pid;
}

/* Kill process system call */
static long sys_kill(uint64_t pid, uint64_t sig, uint64_t unused1, uint64_t unused2, uint64_t unused3) {
    struct process *target = process_find_by_pid(pid);
    if (!target) {
        return -3; /* ESRCH */
    }
    
    /* Security check - can only kill own processes or with proper privileges */
    if (current_process && 
        target->uid != current_process->uid && 
        current_process->uid != 0) {
        return -1; /* EPERM */
    }
    
    debug_print("Killing process %lu with signal %lu\n", pid, sig);
    
    /* Terminate process */
    target->state = PROCESS_TERMINATED;
    
    return 0;
}

/* Memory allocation system call */
static long sys_brk(uint64_t addr, uint64_t unused1, uint64_t unused2, uint64_t unused3, uint64_t unused4) {
    if (!current_process) {
        return -1;
    }
    
    /* For now, just return current break */
    static uint64_t current_brk = 0x400000; /* 4MB */
    
    if (addr == 0) {
        return current_brk;
    }
    
    /* Expand heap */
    if (addr > current_brk) {
        uint64_t pages_needed = (addr - current_brk + PAGE_SIZE - 1) / PAGE_SIZE;
        for (uint64_t i = 0; i < pages_needed; i++) {
            uint64_t virtual_addr = current_brk + (i * PAGE_SIZE);
            uint64_t physical_addr = (uint64_t)kmalloc(PAGE_SIZE);
            if (physical_addr) {
                map_page(virtual_addr, physical_addr, 0x07); /* Present, RW, User */
            }
        }
    }
    
    current_brk = addr;
    return current_brk;
}

/* Memory mapping system call */
static long sys_mmap(uint64_t addr, uint64_t length, uint64_t prot, uint64_t flags, uint64_t fd) {
    if (length == 0) {
        return -22; /* EINVAL */
    }
    
    /* Simplified mmap implementation */
    uint64_t pages_needed = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    uint64_t virtual_base = addr ? addr : 0x10000000; /* 256MB */
    
    for (uint64_t i = 0; i < pages_needed; i++) {
        uint64_t virtual_addr = virtual_base + (i * PAGE_SIZE);
        uint64_t physical_addr = (uint64_t)kmalloc(PAGE_SIZE);
        
        if (!physical_addr) {
            return -12; /* ENOMEM */
        }
        
        uint32_t page_flags = 0x01; /* Present */
        if (prot & 0x02) page_flags |= 0x02; /* Writable */
        if (prot & 0x04) page_flags |= 0x04; /* User */
        
        map_page(virtual_addr, physical_addr, page_flags);
    }
    
    debug_print("Mapped %lu bytes at 0x%lx\n", length, virtual_base);
    
    return virtual_base;
}

/* Utility function for string operations in kernel */
int snprintf(char *str, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    /* Simplified snprintf implementation */
    size_t pos = 0;
    const char *p = format;
    
    while (*p && pos < size - 1) {
        if (*p == '%' && *(p + 1)) {
            p++;
            switch (*p) {
                case 'd': {
                    int val = va_arg(args, int);
                    /* Convert integer to string */
                    char temp[32];
                    int len = 0;
                    if (val == 0) {
                        temp[len++] = '0';
                    } else {
                        int tmp = val;
                        while (tmp && len < 31) {
                            temp[len++] = '0' + (tmp % 10);
                            tmp /= 10;
                        }
                        /* Reverse string */
                        for (int i = 0; i < len / 2; i++) {
                            char c = temp[i];
                            temp[i] = temp[len - 1 - i];
                            temp[len - 1 - i] = c;
                        }
                    }
                    for (int i = 0; i < len && pos < size - 1; i++) {
                        str[pos++] = temp[i];
                    }
                    break;
                }
                case 'l': {
                    if (*(p + 1) == 'u' || *(p + 1) == 'd') {
                        p++;
                        unsigned long val = va_arg(args, unsigned long);
                        /* Convert to string */
                        char temp[32];
                        int len = 0;
                        if (val == 0) {
                            temp[len++] = '0';
                        } else {
                            while (val && len < 31) {
                                temp[len++] = '0' + (val % 10);
                                val /= 10;
                            }
                            /* Reverse */
                            for (int i = 0; i < len / 2; i++) {
                                char c = temp[i];
                                temp[i] = temp[len - 1 - i];
                                temp[len - 1 - i] = c;
                            }
                        }
                        for (int i = 0; i < len && pos < size - 1; i++) {
                            str[pos++] = temp[i];
                        }
                    }
                    break;
                }
                case 's': {
                    const char *s = va_arg(args, const char *);
                    while (*s && pos < size - 1) {
                        str[pos++] = *s++;
                    }
                    break;
                }
                case 'c': {
                    char c = va_arg(args, int);
                    str[pos++] = c;
                    break;
                }
                default:
                    str[pos++] = *p;
                    break;
            }
        } else {
            str[pos++] = *p;
        }
        p++;
    }
    
    str[pos] = '\0';
    va_end(args);
    return pos;
}

/* String copy function */
char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}