/*
 * SentinalOS Kernel Main
 * Pentagon-Level Security Operating System
 * AMD64 Architecture
 */

#include "kernel.h"
#include "string.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/* External string functions */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
int snprintf(char *buf, size_t size, const char *fmt, ...);

/* Stack canary for security */
static uint64_t __stack_chk_guard = 0xDEADBEEFCAFEBABE;

/* Boot information from multiboot */
struct multiboot_info {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    uint64_t syms;
    uint32_t mmap_length;
    uint32_t mmap_addr;
} __packed;

/* Global kernel state */
static struct {
    bool initialized;
    uint64_t boot_time;
    uint32_t security_level;
    const char *version;
} kernel_state = {
    .initialized = false,
    .boot_time = 0,
    .security_level = 5, /* Pentagon level */
    .version = SENTINALOS_VERSION
};

/* Early console for debugging */
static volatile uint16_t *vga_buffer = (uint16_t*)0xFFFFFFFF800B8000UL;
static size_t vga_row = 0;
static size_t vga_column = 0;
static uint8_t vga_color = 0x0F; /* White on black */

void early_console_init(void) {
    /* Clear screen */
    for (size_t i = 0; i < 80 * 25; i++) {
        vga_buffer[i] = 0x0720; /* Space with default color */
    }
    vga_row = 0;
    vga_column = 0;
    vga_color = 0x0F;
}

void console_putc(char c) {
    if (c == '\n') {
        vga_column = 0;
        vga_row++;
    } else if (c == '\r') {
        vga_column = 0;
    } else if (c == '\t') {
        vga_column = (vga_column + 8) & ~7;
    } else if (c >= 32) {
        const size_t index = vga_row * 80 + vga_column;
        vga_buffer[index] = (uint16_t)c | ((uint16_t)vga_color << 8);
        vga_column++;
    }
    
    if (vga_column >= 80) {
        vga_column = 0;
        vga_row++;
    }
    
    if (vga_row >= 25) {
        /* Scroll up */
        for (size_t i = 0; i < 24 * 80; i++) {
            vga_buffer[i] = vga_buffer[i + 80];
        }
        for (size_t i = 24 * 80; i < 25 * 80; i++) {
            vga_buffer[i] = 0x0720;
        }
        vga_row = 24;
    }
}

void console_puts(const char *s) {
    while (*s) {
        console_putc(*s++);
    }
}

int console_printf(const char *fmt, ...) {
    /* Simple printf implementation for early boot */
    va_list args;
    va_start(args, fmt);
    
    char buffer[1024];
    int ret = vsnprintf(buffer, sizeof(buffer), fmt, args);
    console_puts(buffer);
    
    va_end(args);
    return ret;
}

void kernel_panic(const char *file, int line, const char *fmt, ...) {
    disable_interrupts();
    
    vga_color = 0x4F; /* White on red */
    console_puts("\n\n*** KERNEL PANIC ***\n");
    
    console_printf("File: %s, Line: %d\n", file, line);
    
    va_list args;
    va_start(args, fmt);
    char buffer[512];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    console_puts(buffer);
    va_end(args);
    
    console_puts("\nSystem halted.\n");
    
    /* Halt the system */
    while (1) {
        __asm__ __volatile__("cli; hlt");
    }
}

void security_init(void) {
    /* Call comprehensive security initialization */
    security_init_comprehensive();
}

void init_stack_canary(void) {
    /* Generate random canary using RDRAND if available */
    uint64_t canary;
    
    /* Try RDRAND first */
    int rdrand_success = 0;
    __asm__ __volatile__("rdrand %0; setc %b1" : "=r" (canary), "=q" (rdrand_success));
    
    if (rdrand_success) {
        __stack_chk_guard = canary;
    } else {
        /* Fallback to time-based seed */
        __stack_chk_guard ^= get_ticks();
    }
    
    console_printf("[SECURITY] Stack canary initialized\n");
}

uint64_t get_stack_canary(void) {
    return __stack_chk_guard;
}

void check_stack_canary(uint64_t canary) {
    if (canary != __stack_chk_guard) {
        PANIC("Stack buffer overflow detected!");
    }
}

void __stack_chk_fail(void) {
    PANIC("Stack smashing detected!");
}

void enable_cpu_security_features(void) {
    console_puts("[SECURITY] Enabling CPU security features...\n");
    
    /* SMEP and SMAP are already enabled in boot.s */
    
    /* Enable additional features if available */
    uint32_t eax, ebx, ecx, edx;
    
    /* Check for FSGSBASE */
    __asm__ __volatile__("cpuid" 
                        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
                        : "a" (7), "c" (0));
    
    if (ebx & (1 << 0)) {
        console_puts("[SECURITY] FSGSBASE supported\n");
    }
    
    /* Check for Intel CET */
    if (ecx & (1 << 7)) {
        console_puts("[SECURITY] Intel CET supported\n");
    }
    
    console_puts("[SECURITY] CPU security features enabled\n");
}

void cpu_init(void) {
    console_puts("[CPU] Initializing CPU...\n");
    
    /* Get CPU information */
    uint32_t eax, ebx, ecx, edx;
    char vendor[13] = {0};
    
    __asm__ __volatile__("cpuid"
                        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
                        : "a" (0));
    
    *(uint32_t*)vendor = ebx;
    *(uint32_t*)(vendor + 4) = edx;
    *(uint32_t*)(vendor + 8) = ecx;
    
    console_printf("[CPU] Vendor: %s\n", vendor);
    
    /* Get CPU features */
    __asm__ __volatile__("cpuid"
                        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
                        : "a" (1));
    
    console_printf("[CPU] Family: %d, Model: %d, Stepping: %d\n",
                  (eax >> 8) & 0xF, (eax >> 4) & 0xF, eax & 0xF);
    
    console_puts("[CPU] CPU initialization complete\n");
}

/* Declaration - actual implementation in various files */
void mm_init(void);
void scheduler_init(void);
void drivers_init(void);
void security_init_comprehensive(void);
void security_status_report(void);

uint64_t get_ticks(void) {
    /* Simple tick counter using TSC */
    uint32_t low, high;
    __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));
    return ((uint64_t)high << 32) | low;
}

void disable_interrupts(void) {
    __asm__ __volatile__("cli");
}

void enable_interrupts(void) {
    __asm__ __volatile__("sti");
}

void klog(const char *level, const char *fmt, ...) {
    console_printf("[%s] ", level);
    
    va_list args;
    va_start(args, fmt);
    char buffer[512];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    console_puts(buffer);
    va_end(args);
    
    console_putc('\n');
}

void print_banner(void) {
    vga_color = 0x0A; /* Green */
    console_puts("\n");
    console_puts("   _____            _   _             _  ____   _____ \n");
    console_puts("  / ____|          | | (_)           | |/ __ \\ / ____|\n");
    console_puts(" | (___   ___ _ __ | |_ _ _ __   __ _| | |  | | (___  \n");
    console_puts("  \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _` | | |  | |\\___ \\ \n");
    console_puts("  ____) |  __/ | | | |_| | | | | (_| | | |__| |____) |\n");
    console_puts(" |_____/ \\___|_| |_|\\__|_|_| |_|\\__,_|_|\\____/|_____/ \n");
    console_puts("\n");
    
    vga_color = 0x0F; /* White */
    console_printf("  SentinalOS %s (\"%s\") - Pentagon-Level Security OS\n", 
                   SENTINALOS_VERSION, SENTINALOS_CODENAME);
    console_puts("  AMD64 Architecture - Built for Maximum Security\n");
    console_puts("\n");
}

void kernel_main(uint32_t multiboot_magic, struct multiboot_info *multiboot_info) {
    /* Initialize early console */
    early_console_init();
    
    /* Print banner */
    print_banner();
    
    /* Verify multiboot */
    if (multiboot_magic != 0x36d76289) {
        PANIC("Invalid multiboot magic: 0x%x", multiboot_magic);
    }
    
    KLOG_INFO("Booting SentinalOS %s...", SENTINALOS_VERSION);
    KLOG_INFO("Multiboot magic: 0x%x", multiboot_magic);
    
    /* Initialize subsystems */
    cpu_init();
    security_init();
    mm_init();
    scheduler_init();
    drivers_init();
    
    /* Mark kernel as initialized */
    kernel_state.initialized = true;
    kernel_state.boot_time = get_ticks();
    
    KLOG_INFO("Kernel initialization complete");
    KLOG_INFO("Security level: Pentagon (%d)", kernel_state.security_level);
    
    /* Display security status */
    security_status_report();
    
    /* Main kernel loop */
    console_puts("\n[KERNEL] Entering main loop...\n");
    
    while (1) {
        /* Halt until interrupt */
        __asm__ __volatile__("hlt");
    }
}