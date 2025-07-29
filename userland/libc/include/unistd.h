#ifndef _UNISTD_H
#define _UNISTD_H

#include <stddef.h>
#include <sys/types.h>

/* Standard file descriptors */
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* Access modes for access() */
#define F_OK 0  /* Test for existence */
#define X_OK 1  /* Test for execute permission */
#define W_OK 2  /* Test for write permission */
#define R_OK 4  /* Test for read permission */

/* Whence values for lseek() */
#define SEEK_SET 0  /* Set file offset to offset */
#define SEEK_CUR 1  /* Set file offset to current plus offset */
#define SEEK_END 2  /* Set file offset to EOF plus offset */

/* File I/O functions */
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int close(int fd);
off_t lseek(int fd, off_t offset, int whence);

/* Process functions */
pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
gid_t getgid(void);
uid_t geteuid(void);
gid_t getegid(void);
int setuid(uid_t uid);
int setgid(gid_t gid);
int seteuid(uid_t euid);
int setegid(gid_t egid);

/* Process control */
pid_t fork(void);
int execve(const char *pathname, char *const argv[], char *const envp[]);
int execv(const char *pathname, char *const argv[]);
int execvp(const char *file, char *const argv[]);
void _exit(int status) __attribute__((noreturn));

/* Memory management */
void *sbrk(intptr_t increment);
int brk(void *addr);

/* File system operations */
int access(const char *pathname, int mode);
int chdir(const char *path);
char *getcwd(char *buf, size_t size);
int rmdir(const char *pathname);
int unlink(const char *pathname);
int link(const char *oldpath, const char *newpath);
int symlink(const char *target, const char *linkpath);
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);

/* File permissions */
int chown(const char *pathname, uid_t owner, gid_t group);
int fchown(int fd, uid_t owner, gid_t group);
int lchown(const char *pathname, uid_t owner, gid_t group);

/* Process groups and sessions */
pid_t getpgrp(void);
pid_t getpgid(pid_t pid);
int setpgid(pid_t pid, pid_t pgid);
pid_t setsid(void);
pid_t getsid(pid_t pid);

/* Signals */
int kill(pid_t pid, int sig);

/* Sleep functions */
unsigned int sleep(unsigned int seconds);
int usleep(useconds_t usec);

/* Host identification */
int gethostname(char *name, size_t len);
int sethostname(const char *name, size_t len);

/* Standard paths */
#define _PATH_DEFPATH "/usr/bin:/bin"
#define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"

/* SentinalOS-specific secure functions */
ssize_t sentinal_secure_read(int fd, void *buf, size_t count, const char *security_context);
ssize_t sentinal_secure_write(int fd, const void *buf, size_t count, const char *security_context);
int sentinal_encrypt_data(const void *plaintext, size_t plain_len, void *ciphertext, size_t *cipher_len, const char *key);
int sentinal_decrypt_data(const void *ciphertext, size_t cipher_len, void *plaintext, size_t *plain_len, const char *key);
int sentinal_audit_log(const char *event, const char *details, int severity);

/* Constants */
#define _POSIX_VERSION 200809L
#define _POSIX2_VERSION 200809L

/* System configuration */
long sysconf(int name);
long fpathconf(int fd, int name);
long pathconf(const char *path, int name);

/* sysconf() names */
#define _SC_PAGE_SIZE        1
#define _SC_PAGESIZE         _SC_PAGE_SIZE
#define _SC_OPEN_MAX         2
#define _SC_CLK_TCK          3
#define _SC_NPROCESSORS_CONF 4
#define _SC_NPROCESSORS_ONLN 5

#endif /* _UNISTD_H */