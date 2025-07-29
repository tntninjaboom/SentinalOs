# SentinalOS Boot Assembly
# Pentagon-Level Security Operating System
# AMD64 Architecture Bootstrap

.section .multiboot
.align 4

# Multiboot2 Header
.long 0xe85250d6                # Magic number
.long 0                         # Architecture (0 = i386)
.long multiboot_header_end - multiboot_header_start
.long -(0xe85250d6 + 0 + (multiboot_header_end - multiboot_header_start))

multiboot_header_start:

# Information request tag
.align 8
.word 1                         # Type: information request
.word 0                         # Flags
.long info_request_tag_end - info_request_tag_start
info_request_tag_start:
.long 4                         # Memory map
.long 6                         # Memory info
.long 8                         # Framebuffer info
.long 9                         # ELF symbols
.long 14                        # ACPI old
.long 15                        # ACPI new
info_request_tag_end:

# Address tag (not needed for ELF)

# Entry address tag (not needed for ELF)

# Console flags tag
.align 8
.word 4                         # Type: console flags
.word 0                         # Flags
.long 12                        # Size
.long 0                         # Console flags (EGA text supported)

# Framebuffer tag
.align 8
.word 5                         # Type: framebuffer
.word 0                         # Flags
.long 20                        # Size
.long 1024                      # Width
.long 768                       # Height
.long 32                        # Depth

# Module alignment tag
.align 8
.word 6                         # Type: module alignment
.word 0                         # Flags
.long 8                         # Size

# End tag
.align 8
.word 0                         # Type: end
.word 0                         # Flags
.long 8                         # Size

multiboot_header_end:

# Boot stack
.section .bootstrap_stack, "aw", @nobits
stack_bottom:
.skip 16384                     # 16KB stack
stack_top:

# Early page tables for long mode
.section .bss
.align 4096
early_pml4:
    .skip 4096
early_pdpt:
    .skip 4096
early_pd:
    .skip 4096

# GDT for long mode
.section .rodata
.align 16
gdt64:
    .quad 0                     # Null descriptor
gdt64_code:
    .quad 0x00af9a000000ffff    # Kernel code segment
gdt64_data:
    .quad 0x00af92000000ffff    # Kernel data segment
gdt64_user_code:
    .quad 0x00affa000000ffff    # User code segment  
gdt64_user_data:
    .quad 0x00aff2000000ffff    # User data segment
gdt64_end:

gdt64_pointer:
    .word gdt64_end - gdt64 - 1
    .quad gdt64

.section .text
.global _start
.type _start, @function

_start:
    # Disable interrupts
    cli
    
    # Set up stack
    mov $stack_top, %esp
    
    # Save multiboot info
    push %ebx                   # Multiboot info structure
    push %eax                   # Multiboot magic
    
    # Check if CPUID is supported
    call check_cpuid
    test %eax, %eax
    jz no_cpuid
    
    # Check if long mode is available
    call check_long_mode
    test %eax, %eax
    jz no_long_mode
    
    # Set up paging for long mode
    call setup_page_tables
    
    # Enable PAE
    mov %cr4, %eax
    or $0x20, %eax              # Set PAE bit
    mov %eax, %cr4
    
    # Load page table
    mov $early_pml4, %eax
    mov %eax, %cr3
    
    # Enable long mode
    mov $0xC0000080, %ecx       # EFER MSR
    rdmsr
    or $0x100, %eax             # Set LME bit
    wrmsr
    
    # Enable paging and protection
    mov %cr0, %eax
    or $0x80000001, %eax        # Set PG and PE bits
    mov %eax, %cr0
    
    # Load GDT
    lgdt gdt64_pointer
    
    # Jump to long mode
    ljmp $0x08, $long_mode_start

check_cpuid:
    # Check if CPUID is supported by attempting to flip ID bit in EFLAGS
    pushfd
    pop %eax
    mov %eax, %ecx
    xor $0x200000, %eax
    push %eax
    popfd
    pushfd
    pop %eax
    xor %ecx, %eax
    shr $21, %eax
    and $1, %eax
    ret

check_long_mode:
    # Check if extended function CPUID is available
    mov $0x80000000, %eax
    cpuid
    cmp $0x80000001, %eax
    jb .no_long_mode
    
    # Check if long mode is available
    mov $0x80000001, %eax
    cpuid
    test $0x20000000, %edx      # Test LM bit
    jz .no_long_mode
    
    mov $1, %eax
    ret
    
.no_long_mode:
    mov $0, %eax
    ret

setup_page_tables:
    # Clear page tables
    mov $early_pml4, %edi
    mov $0, %eax
    mov $4096, %ecx
    rep stosl
    
    mov $early_pdpt, %edi
    mov $0, %eax
    mov $4096, %ecx
    rep stosl
    
    mov $early_pd, %edi
    mov $0, %eax
    mov $4096, %ecx
    rep stosl
    
    # Set up identity mapping for first 2MB
    # PML4[0] -> PDPT
    mov $early_pml4, %eax
    mov $early_pdpt, %ebx
    or $0x03, %ebx              # Present + Writable
    mov %ebx, (%eax)
    
    # PDPT[0] -> PD
    mov $early_pdpt, %eax
    mov $early_pd, %ebx
    or $0x03, %ebx              # Present + Writable
    mov %ebx, (%eax)
    
    # PD[0] = 2MB page at 0x00000000
    mov $early_pd, %eax
    mov $0x83, %ebx             # Present + Writable + Page Size
    mov %ebx, (%eax)
    
    # Map kernel at higher half (0xFFFFFFFF80000000)
    # PML4[511] -> PDPT
    mov $early_pml4, %eax
    add $4088, %eax             # 511 * 8
    mov $early_pdpt, %ebx
    or $0x03, %ebx
    mov %ebx, (%eax)
    
    ret

.code64
long_mode_start:
    # Set up segment registers
    mov $0x10, %ax              # Data segment
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    
    # Set up 64-bit stack
    mov $stack_top, %rsp
    
    # Enable security features
    call enable_security_features
    
    # Call kernel main
    # Multiboot info is still on stack
    pop %rsi                    # Multiboot magic
    pop %rdi                    # Multiboot info
    call kernel_main
    
    # If kernel returns, halt
    cli
    hlt
    jmp .-1

enable_security_features:
    # Enable SMEP (Supervisor Mode Execution Prevention)
    mov %cr4, %rax
    or $0x100000, %rax          # Set SMEP bit (bit 20)
    mov %rax, %cr4
    
    # Enable SMAP (Supervisor Mode Access Prevention)
    mov %cr4, %rax
    or $0x200000, %rax          # Set SMAP bit (bit 21)
    mov %rax, %cr4
    
    # Enable Write Protect
    mov %cr0, %rax
    or $0x10000, %rax           # Set WP bit
    mov %rax, %cr0
    
    ret

# Error handlers
no_cpuid:
    mov $no_cpuid_msg, %esi
    call print_error
    jmp halt_system

no_long_mode:
    mov $no_long_mode_msg, %esi
    call print_error
    jmp halt_system

print_error:
    mov $0xb8000, %edi          # VGA text buffer
    mov $0x4f, %ah              # White on red
.print_loop:
    lodsb
    test %al, %al
    jz .print_done
    stosw
    jmp .print_loop
.print_done:
    ret

halt_system:
    cli
    hlt
    jmp halt_system

.section .rodata
no_cpuid_msg:
    .asciz "FATAL: CPUID not supported"
no_long_mode_msg:
    .asciz "FATAL: Long mode not supported"

.size _start, . - _start