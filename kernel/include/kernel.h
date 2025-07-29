#ifndef _KERNEL_H
#define _KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* SentinalOS Kernel Headers */
#define SENTINALOS_VERSION_MAJOR 1
#define SENTINALOS_VERSION_MINOR 0
#define SENTINALOS_VERSION_PATCH 0
#define SENTINALOS_CODENAME "Pentagon"

/* Architecture definitions */
#define ARCH_X86_64
#define PAGE_SIZE 4096
#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000UL
#define KERNEL_PHYSICAL_BASE 0x100000UL

/* Security configuration */
#define SECURITY_LEVEL_PENTAGON
#define ENABLE_KASLR
#define ENABLE_SMAP
#define ENABLE_SMEP
#define ENABLE_STACK_CANARIES

/* Memory layout */
#define KERNEL_HEAP_START 0xFFFFFFFF90000000UL
#define KERNEL_HEAP_SIZE  0x10000000UL  /* 256MB */
#define KERNEL_STACK_SIZE 0x4000        /* 16KB */

/* Basic types */
typedef uint64_t vaddr_t;
typedef uint64_t paddr_t;
typedef uint64_t size_t;
typedef int64_t ssize_t;

/* Kernel panic and assertions */
#define PANIC(fmt, ...) kernel_panic(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define ASSERT(cond) do { if (!(cond)) PANIC("Assertion failed: %s", #cond); } while(0)

/* Function prototypes */
void kernel_main(void);
void kernel_panic(const char *file, int line, const char *fmt, ...);
void early_console_init(void);
void console_putc(char c);
void console_puts(const char *s);
int console_printf(const char *fmt, ...);

/* Memory management */
void mm_init(void);
void *kmalloc(size_t size);
void kfree(void *ptr);
void *kmalloc_aligned(size_t size, size_t alignment);

/* Security functions */
void security_init(void);
void enable_smep(void);
void enable_smap(void);
void init_stack_canary(void);
uint64_t get_stack_canary(void);
void check_stack_canary(uint64_t canary);

/* CPU features */
void cpu_init(void);
bool cpu_has_feature(uint32_t feature);
void enable_cpu_security_features(void);

/* Interrupt handling */
void idt_init(void);
void irq_init(void);
void enable_interrupts(void);
void disable_interrupts(void);

/* Time and scheduling */
void timer_init(void);
uint64_t get_ticks(void);
void scheduler_init(void);

/* Debug and logging */
void debug_init(void);
void klog(const char *level, const char *fmt, ...);

#define KLOG_EMERG(fmt, ...)   klog("EMERG", fmt, ##__VA_ARGS__)
#define KLOG_ALERT(fmt, ...)   klog("ALERT", fmt, ##__VA_ARGS__)
#define KLOG_CRIT(fmt, ...)    klog("CRIT", fmt, ##__VA_ARGS__)
#define KLOG_ERR(fmt, ...)     klog("ERR", fmt, ##__VA_ARGS__)
#define KLOG_WARN(fmt, ...)    klog("WARN", fmt, ##__VA_ARGS__)
#define KLOG_NOTICE(fmt, ...)  klog("NOTICE", fmt, ##__VA_ARGS__)
#define KLOG_INFO(fmt, ...)    klog("INFO", fmt, ##__VA_ARGS__)
#define KLOG_DEBUG(fmt, ...)   klog("DEBUG", fmt, ##__VA_ARGS__)

/* Compiler attributes */
#define __packed       __attribute__((packed))
#define __aligned(x)   __attribute__((aligned(x)))
#define __noreturn     __attribute__((noreturn))
#define __unused       __attribute__((unused))
#define __init         __attribute__((section(".init.text")))
#define __initdata     __attribute__((section(".init.data")))

/* Likely/unlikely for branch prediction */
#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

/* Barrier macros */
#define barrier()      __asm__ __volatile__("" ::: "memory")
#define rmb()          __asm__ __volatile__("lfence" ::: "memory")
#define wmb()          __asm__ __volatile__("sfence" ::: "memory")
#define mb()           __asm__ __volatile__("mfence" ::: "memory")

#endif /* _KERNEL_H */