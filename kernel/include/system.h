#ifndef _SYSTEM_H
#define _SYSTEM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* System constants */
#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000UL
#define PAGE_SIZE 4096
#define MAX_PROCESSES 1024
#define MAX_OPEN_FILES 256
#define KERNEL_STACK_SIZE 16384

/* Process states */
typedef enum {
    PROCESS_READY = 0,
    PROCESS_RUNNING,
    PROCESS_BLOCKED,
    PROCESS_ZOMBIE,
    PROCESS_TERMINATED
} process_state_t;

/* System call numbers */
typedef enum {
    SYS_EXIT = 0,
    SYS_FORK,
    SYS_READ,
    SYS_WRITE,
    SYS_OPEN,
    SYS_CLOSE,
    SYS_WAITPID,
    SYS_CREAT,
    SYS_LINK,
    SYS_UNLINK,
    SYS_EXECVE,
    SYS_CHDIR,
    SYS_TIME,
    SYS_MKNOD,
    SYS_CHMOD,
    SYS_GETPID,
    SYS_MOUNT,
    SYS_UMOUNT,
    SYS_GETUID,
    SYS_GETGID,
    SYS_STIME,
    SYS_ALARM,
    SYS_FSTAT,
    SYS_PAUSE,
    SYS_UTIME,
    SYS_ACCESS,
    SYS_SYNC,
    SYS_KILL,
    SYS_RENAME,
    SYS_MKDIR,
    SYS_RMDIR,
    SYS_DUP,
    SYS_PIPE,
    SYS_TIMES,
    SYS_BRK,
    SYS_SETGID,
    SYS_GETEGID,
    SYS_SETSID,
    SYS_SIGACTION,
    SYS_SGETMASK,
    SYS_SSETMASK,
    SYS_SETREUID,
    SYS_SETREGID,
    SYS_SIGSUSPEND,
    SYS_SIGPENDING,
    SYS_SETHOSTNAME,
    SYS_SETRLIMIT,
    SYS_GETRLIMIT,
    SYS_GETRUSAGE,
    SYS_GETTIMEOFDAY,
    SYS_SETTIMEOFDAY,
    SYS_GETGROUPS,
    SYS_SETGROUPS,
    SYS_SYMLINK,
    SYS_READLINK,
    SYS_USELIB,
    SYS_SWAPON,
    SYS_REBOOT,
    SYS_READDIR,
    SYS_MMAP,
    SYS_MUNMAP,
    SYS_TRUNCATE,
    SYS_FTRUNCATE,
    SYS_FCHMOD,
    SYS_FCHOWN,
    SYS_GETPRIORITY,
    SYS_SETPRIORITY,
    SYS_STATFS,
    SYS_FSTATFS,
    SYS_SOCKETCALL,
    SYS_MAX
} syscall_t;

/* Process Control Block */
struct process {
    uint32_t pid;
    uint32_t ppid;
    process_state_t state;
    uint32_t priority;
    uint64_t *page_directory;
    uint64_t kernel_stack;
    uint64_t user_stack;
    struct cpu_context *context;
    uint32_t uid, gid;
    uint32_t euid, egid;
    char name[64];
    uint64_t memory_usage;
    uint64_t cpu_time;
    uint32_t open_files[MAX_OPEN_FILES];
    struct process *next;
    struct process *prev;
    
    /* Security context */
    uint8_t security_level;
    uint32_t security_flags;
    char security_context[128];
};

/* CPU context for process switching */
struct cpu_context {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip, rflags;
    uint64_t cs, ds, es, fs, gs, ss;
    uint64_t cr3;
};

/* Memory management structures */
struct page_frame {
    uint64_t physical_addr;
    uint32_t ref_count;
    uint32_t flags;
    struct page_frame *next;
};

struct memory_region {
    uint64_t start_addr;
    uint64_t end_addr;
    uint32_t flags;
    struct memory_region *next;
};

/* File system structures */
struct inode {
    uint32_t inode_num;
    uint32_t mode;
    uint32_t uid, gid;
    uint64_t size;
    uint64_t blocks;
    uint64_t atime, mtime, ctime;
    uint32_t links_count;
    uint32_t flags;
    uint64_t block_ptrs[15];
    uint32_t security_level;
};

struct file_descriptor {
    struct inode *inode;
    uint64_t offset;
    uint32_t flags;
    uint32_t mode;
    uint32_t ref_count;
};

struct directory_entry {
    uint32_t inode_num;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    char name[256];
};

/* Network structures */
struct network_packet {
    uint8_t *data;
    uint32_t length;
    uint32_t protocol;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    struct network_packet *next;
};

struct socket {
    uint32_t type;
    uint32_t protocol;
    uint32_t state;
    uint32_t local_addr;
    uint32_t remote_addr;
    uint16_t local_port;
    uint16_t remote_port;
    struct network_packet *recv_queue;
    struct network_packet *send_queue;
};

/* Function prototypes */

/* Process management */
int process_create(const char *name, void (*entry_point)(void));
int process_destroy(uint32_t pid);
void process_schedule(void);
struct process *process_get_current(void);
struct process *process_find_by_pid(uint32_t pid);

/* Memory management */
void *kmalloc(size_t size);
void kfree(void *ptr);
uint64_t *get_page_directory(void);
int map_page(uint64_t virtual_addr, uint64_t physical_addr, uint32_t flags);
int unmap_page(uint64_t virtual_addr);

/* System calls */
long syscall_handler(uint64_t syscall_num, uint64_t arg1, uint64_t arg2, 
                    uint64_t arg3, uint64_t arg4, uint64_t arg5);

/* File system */
int fs_init(void);
struct inode *fs_get_inode(uint32_t inode_num);
int fs_read_inode(struct inode *inode, uint64_t offset, void *buffer, size_t count);
int fs_write_inode(struct inode *inode, uint64_t offset, const void *buffer, size_t count);
int fs_create_file(const char *path, uint32_t mode);
int fs_delete_file(const char *path);

/* Device drivers */
int device_init(void);
int device_read(uint32_t device, uint64_t offset, void *buffer, size_t count);
int device_write(uint32_t device, uint64_t offset, const void *buffer, size_t count);

/* Network stack */
int network_init(void);
int network_send_packet(struct network_packet *packet);
struct network_packet *network_receive_packet(void);
int socket_create(uint32_t type, uint32_t protocol);
int socket_bind(int socket_fd, uint32_t addr, uint16_t port);
int socket_connect(int socket_fd, uint32_t addr, uint16_t port);

/* Interrupt handling */
void interrupt_init(void);
void interrupt_register_handler(uint8_t interrupt, void (*handler)(void));
void interrupt_enable(void);
void interrupt_disable(void);

/* Security functions */
int security_check_access(struct process *proc, uint32_t resource, uint32_t operation);
int security_validate_syscall(uint32_t syscall_num, struct process *proc);
void security_audit_log(const char *event, uint32_t pid, const char *details);

/* Utility functions */
void kernel_panic(const char *message);
void debug_print(const char *format, ...);
uint64_t get_timestamp(void);
void delay_ms(uint32_t milliseconds);

#endif /* _SYSTEM_H */