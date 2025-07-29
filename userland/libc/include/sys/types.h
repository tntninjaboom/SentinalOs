#ifndef _SYS_TYPES_H
#define _SYS_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* Process and user IDs */
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;

/* File system types */
typedef long off_t;
typedef unsigned long ino_t;
typedef unsigned int mode_t;
typedef unsigned int nlink_t;
typedef long blksize_t;
typedef long blkcnt_t;
typedef unsigned long dev_t;

/* Time types */
typedef long time_t;
typedef long suseconds_t;
typedef unsigned long useconds_t;

/* Size types */
typedef long ssize_t;

/* Signal types */
typedef int sig_atomic_t;

/* Thread types */
typedef unsigned long pthread_t;

/* Socket types */
typedef unsigned int socklen_t;
typedef uint16_t sa_family_t;

/* File descriptor sets */
#define FD_SETSIZE 1024

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / (8 * sizeof(unsigned long))];
} fd_set;

#define FD_ZERO(set) \
    do { \
        unsigned int __i; \
        for (__i = 0; __i < sizeof(fd_set) / sizeof(unsigned long); __i++) \
            ((fd_set *)(set))->fds_bits[__i] = 0; \
    } while (0)

#define FD_SET(fd, set) \
    ((void) (((fd_set *)(set))->fds_bits[(fd) / (8 * sizeof(unsigned long))] |= \
             (1UL << ((fd) % (8 * sizeof(unsigned long))))))

#define FD_CLR(fd, set) \
    ((void) (((fd_set *)(set))->fds_bits[(fd) / (8 * sizeof(unsigned long))] &= \
             ~(1UL << ((fd) % (8 * sizeof(unsigned long))))))

#define FD_ISSET(fd, set) \
    (((fd_set *)(set))->fds_bits[(fd) / (8 * sizeof(unsigned long))] & \
     (1UL << ((fd) % (8 * sizeof(unsigned long)))))

#endif /* _SYS_TYPES_H */