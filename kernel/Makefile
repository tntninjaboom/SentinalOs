# SentinalOS Kernel Makefile
# Pentagon-Level Security Operating System

# Load configuration
include ../config/version

# Target configuration
TARGET := x86_64-sentinalos
ARCH := x86_64

# Directories
KERNEL_DIR := $(CURDIR)
TOOLS_DIR := $(KERNEL_DIR)/../tools
BUILD_DIR := $(KERNEL_DIR)/../build/kernel
INCLUDE_DIR := $(KERNEL_DIR)/include

# Cross-compilation tools
CC := $(TOOLS_DIR)/bin/$(TARGET)-gcc
AS := $(TOOLS_DIR)/bin/$(TARGET)-as
LD := $(TOOLS_DIR)/bin/$(TARGET)-ld
AR := $(TOOLS_DIR)/bin/$(TARGET)-ar
OBJCOPY := $(TOOLS_DIR)/bin/$(TARGET)-objcopy
OBJDUMP := $(TOOLS_DIR)/bin/$(TARGET)-objdump
NM := $(TOOLS_DIR)/bin/$(TARGET)-nm
STRIP := $(TOOLS_DIR)/bin/$(TARGET)-strip

# Compiler flags
CFLAGS := -std=c17 -ffreestanding -fno-stack-protector -fno-pic -mno-sse -mno-sse2
CFLAGS += -mno-mmx -mno-80387 -mno-red-zone -mcmodel=kernel
CFLAGS += -Wall -Wextra -Werror -O2 -g
CFLAGS += -I$(INCLUDE_DIR)
CFLAGS += -D__KERNEL__ -D__SENTINALOS__
CFLAGS += -DSENTINALOS_VERSION=\"$(SENTINALOS_VERSION)\"
CFLAGS += -DSENTINALOS_ARCH=\"$(SENTINALOS_ARCH)\"
CFLAGS += -DSECURITY_LEVEL_PENTAGON

# Security hardening flags
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS += -fPIE -Wformat -Wformat-security
CFLAGS += -fno-common -ffunction-sections -fdata-sections
CFLAGS += -mstack-alignment=16

# Kernel-specific flags
CFLAGS += -mno-red-zone -fno-omit-frame-pointer
CFLAGS += -fno-builtin -nostdlib -nostartfiles -nodefaultlibs

# Assembler flags
ASFLAGS := --64

# Linker flags
LDFLAGS := -T $(KERNEL_DIR)/linker.ld -nostdlib -z max-page-size=0x1000
LDFLAGS += -z relro -z now -z noexecstack
LDFLAGS += --gc-sections --build-id=none

# Source files
C_SOURCES := $(shell find $(KERNEL_DIR) -name '*.c' -not -path '*/.*')
ASM_SOURCES := $(shell find $(KERNEL_DIR) -name '*.s' -not -path '*/.*')

# Object files
C_OBJECTS := $(C_SOURCES:$(KERNEL_DIR)/%.c=$(BUILD_DIR)/%.o)
ASM_OBJECTS := $(ASM_SOURCES:$(KERNEL_DIR)/%.s=$(BUILD_DIR)/%.o)
OBJECTS := $(C_OBJECTS) $(ASM_OBJECTS)

# Dependency files
DEPS := $(C_OBJECTS:.o=.d)

# Target kernel
KERNEL := $(BUILD_DIR)/sentinalos.elf
KERNEL_BIN := $(BUILD_DIR)/sentinalos.bin
KERNEL_SYM := $(BUILD_DIR)/sentinalos.sym
KERNEL_MAP := $(BUILD_DIR)/sentinalos.map

# Default target
.PHONY: all
all: $(KERNEL) $(KERNEL_BIN) $(KERNEL_SYM)

# Create build directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/boot
	mkdir -p $(BUILD_DIR)/mm
	mkdir -p $(BUILD_DIR)/security
	mkdir -p $(BUILD_DIR)/drivers
	mkdir -p $(BUILD_DIR)/fs
	mkdir -p $(BUILD_DIR)/net

# Compile C source files
$(BUILD_DIR)/%.o: $(KERNEL_DIR)/%.c | $(BUILD_DIR)
	@echo "CC $<"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Compile assembly source files
$(BUILD_DIR)/%.o: $(KERNEL_DIR)/%.s | $(BUILD_DIR)
	@echo "AS $<"
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

# Link kernel
$(KERNEL): $(OBJECTS) $(KERNEL_DIR)/linker.ld
	@echo "LD $@"
	$(LD) $(LDFLAGS) -Map=$(KERNEL_MAP) $(OBJECTS) -o $@
	@echo "Kernel size: $$(stat -c%s $@) bytes"

# Create binary image
$(KERNEL_BIN): $(KERNEL)
	@echo "OBJCOPY $@"
	$(OBJCOPY) -O binary $< $@

# Generate symbol table
$(KERNEL_SYM): $(KERNEL)
	@echo "NM $@"
	$(NM) $< | sort > $@

# Generate disassembly
$(BUILD_DIR)/sentinalos.dis: $(KERNEL)
	@echo "OBJDUMP $@"
	$(OBJDUMP) -d $< > $@

# Security analysis
.PHONY: security-check
security-check: $(KERNEL)
	@echo "=== Kernel Security Analysis ==="
	@echo "Checking for stack canaries..."
	@$(OBJDUMP) -d $< | grep -q "__stack_chk" && echo "✓ Stack canaries found" || echo "✗ No stack canaries"
	@echo "Checking for PIE..."
	@$(OBJDUMP) -h $< | grep -q "\.rela\." && echo "✓ PIE enabled" || echo "✗ PIE not enabled"
	@echo "Checking for NX bit..."
	@$(OBJDUMP) -h $< | grep -q "CODE" && echo "✓ Code sections found" || echo "✗ No code sections"
	@echo "Kernel security check complete"

# Generate kernel information
.PHONY: info
info: $(KERNEL)
	@echo "=== SentinalOS Kernel Information ==="
	@echo "Version: $(SENTINALOS_VERSION)"
	@echo "Codename: $(SENTINALOS_CODENAME)"
	@echo "Architecture: $(SENTINALOS_ARCH)"
	@echo "Security Level: $(SENTINALOS_SECURITY_LEVEL)"
	@echo "Target: $(TARGET)"
	@echo "Kernel: $<"
	@echo "Size: $$(stat -c%s $<) bytes"
	@echo "Build Date: $$(date)"
	@echo "Sections:"
	@$(OBJDUMP) -h $< | grep -E "\.(text|rodata|data|bss)"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning kernel build artifacts..."
	rm -rf $(BUILD_DIR)

# Install kernel to sysroot
.PHONY: install
install: $(KERNEL) $(KERNEL_BIN)
	@echo "Installing kernel to sysroot..."
	mkdir -p $(KERNEL_DIR)/../sysroot/boot
	cp $(KERNEL) $(KERNEL_DIR)/../sysroot/boot/
	cp $(KERNEL_BIN) $(KERNEL_DIR)/../sysroot/boot/
	cp $(KERNEL_SYM) $(KERNEL_DIR)/../sysroot/boot/

# Test kernel with QEMU
.PHONY: test
test: $(KERNEL)
	@echo "Testing kernel in QEMU..."
	qemu-system-x86_64 -kernel $(KERNEL) -serial stdio -display none

# Debug kernel with QEMU + GDB
.PHONY: debug
debug: $(KERNEL)
	@echo "Starting kernel debug session..."
	@echo "Connect GDB with: target remote :1234"
	qemu-system-x86_64 -kernel $(KERNEL) -s -S -serial stdio -display none

# Verbose build
.PHONY: verbose
verbose:
	$(MAKE) V=1

ifeq ($(V),1)
	Q :=
else
	Q := @
endif

# Include dependency files
-include $(DEPS)

# Help target
.PHONY: help
help:
	@echo "SentinalOS Kernel Build System"
	@echo "Available targets:"
	@echo "  all           - Build kernel (default)"
	@echo "  clean         - Clean build artifacts"
	@echo "  install       - Install kernel to sysroot"
	@echo "  test          - Test kernel in QEMU"
	@echo "  debug         - Debug kernel with QEMU+GDB"
	@echo "  security-check- Analyze kernel security"
	@echo "  info          - Show kernel information"
	@echo "  verbose       - Build with verbose output"
	@echo "  help          - Show this help"

# Phony targets
.PHONY: all clean install test debug security-check info verbose help