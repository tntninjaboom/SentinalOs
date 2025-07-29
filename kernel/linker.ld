/*
 * SentinalOS Kernel Linker Script
 * Pentagon-Level Security Operating System
 * AMD64 Architecture
 */

ENTRY(_start)

SECTIONS
{
    /* Kernel is loaded at 1MB physical, but linked at higher half */
    . = 0x100000;
    
    kernel_physical_start = .;
    
    /* Multiboot header must be early */
    .multiboot ALIGN(4K) : {
        *(.multiboot)
    }
    
    /* Bootstrap code (32-bit) */
    .text.boot ALIGN(4K) : {
        *(.text.boot)
    }
    
    /* Map to higher half */
    . += 0xFFFFFFFF80000000;
    
    kernel_virtual_start = .;
    
    /* Main kernel code */
    .text ALIGN(4K) : AT(ADDR(.text) - 0xFFFFFFFF80000000) {
        *(.text)
        *(.text.*)
    }
    
    /* Read-only data */
    .rodata ALIGN(4K) : AT(ADDR(.rodata) - 0xFFFFFFFF80000000) {
        *(.rodata)
        *(.rodata.*)
        
        /* String tables */
        . = ALIGN(8);
        __start_string_table = .;
        *(.string_table)
        __end_string_table = .;
    }
    
    /* Initialization code and data */
    .init ALIGN(4K) : AT(ADDR(.init) - 0xFFFFFFFF80000000) {
        __init_start = .;
        *(.init.text)
        *(.init.data)
        __init_end = .;
    }
    
    /* Security sections */
    .security ALIGN(4K) : AT(ADDR(.security) - 0xFFFFFFFF80000000) {
        __security_start = .;
        *(.security.text)
        *(.security.data)
        *(.security.rodata)
        __security_end = .;
    }
    
    /* Driver sections */
    .drivers ALIGN(4K) : AT(ADDR(.drivers) - 0xFFFFFFFF80000000) {
        __drivers_start = .;
        *(.drivers.text)
        *(.drivers.data)
        *(.drivers.rodata)
        __drivers_end = .;
    }
    
    /* Exception handling */
    .eh_frame ALIGN(8) : AT(ADDR(.eh_frame) - 0xFFFFFFFF80000000) {
        __eh_frame_start = .;
        *(.eh_frame)
        __eh_frame_end = .;
    }
    
    /* Global constructors */
    .ctors ALIGN(8) : AT(ADDR(.ctors) - 0xFFFFFFFF80000000) {
        __ctors_start = .;
        *(.ctors)
        __ctors_end = .;
    }
    
    /* Global destructors */
    .dtors ALIGN(8) : AT(ADDR(.dtors) - 0xFFFFFFFF80000000) {
        __dtors_start = .;
        *(.dtors)
        __dtors_end = .;
    }
    
    /* Initialized data */
    .data ALIGN(4K) : AT(ADDR(.data) - 0xFFFFFFFF80000000) {
        *(.data)
        *(.data.*)
    }
    
    /* Uninitialized data */
    .bss ALIGN(4K) : AT(ADDR(.bss) - 0xFFFFFFFF80000000) {
        __bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        . = ALIGN(4K);
        __bss_end = .;
    }
    
    /* Bootstrap stack and page tables */
    .bootstrap_stack (NOLOAD) : AT(ADDR(.bootstrap_stack) - 0xFFFFFFFF80000000) {
        *(.bootstrap_stack)
    }
    
    /* Kernel heap (placeholder) */
    .heap ALIGN(4K) : AT(ADDR(.heap) - 0xFFFFFFFF80000000) {
        __heap_start = .;
        . += 0x100000; /* 1MB initial heap */
        __heap_end = .;
    }
    
    kernel_virtual_end = .;
    kernel_physical_end = . - 0xFFFFFFFF80000000;
    
    kernel_size = kernel_physical_end - kernel_physical_start;
    
    /* Debug information (not loaded) */
    .debug_info 0 : { *(.debug_info) }
    .debug_abbrev 0 : { *(.debug_abbrev) }
    .debug_line 0 : { *(.debug_line) }
    .debug_str 0 : { *(.debug_str) }
    .debug_ranges 0 : { *(.debug_ranges) }
    .debug_frame 0 : { *(.debug_frame) }
    
    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame_hdr)
    }
}

/* Provide symbols for kernel boundaries */
KERNEL_PHYSICAL_START = kernel_physical_start;
KERNEL_PHYSICAL_END = kernel_physical_end;
KERNEL_VIRTUAL_START = kernel_virtual_start;
KERNEL_VIRTUAL_END = kernel_virtual_end;
KERNEL_SIZE = kernel_size;

/* Security markers */
SECURITY_SECTION_START = __security_start;
SECURITY_SECTION_END = __security_end;
DRIVERS_SECTION_START = __drivers_start;
DRIVERS_SECTION_END = __drivers_end;

/* Initialization markers */
INIT_SECTION_START = __init_start;
INIT_SECTION_END = __init_end;

/* BSS markers */
BSS_START = __bss_start;
BSS_END = __bss_end;

/* Heap markers */
HEAP_START = __heap_start;
HEAP_END = __heap_end;