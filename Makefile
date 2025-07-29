# SentinalOS Main Makefile
# Pentagon-Level Security Operating System

# Load version information from shell script
SENTINALOS_VERSION := $(shell . config/version && echo $$SENTINALOS_VERSION)
SENTINALOS_CODENAME := $(shell . config/version && echo $$SENTINALOS_CODENAME)
SENTINALOS_BUILD_DATE := $(shell . config/version && echo $$SENTINALOS_BUILD_DATE)
SENTINALOS_ARCH := $(shell . config/version && echo $$SENTINALOS_ARCH)
SENTINALOS_SECURITY_LEVEL := $(shell . config/version && echo $$SENTINALOS_SECURITY_LEVEL)

# Build configuration
TARGET := x86_64-sentinalos
TOOLS_DIR := $(CURDIR)/tools
BUILD_DIR := $(CURDIR)/build
SOURCES_DIR := $(CURDIR)/sources
SYSROOT_DIR := $(CURDIR)/sysroot
ISO_DIR := $(CURDIR)/iso

# Cross-compilation tools
CC := $(TOOLS_DIR)/bin/$(TARGET)-gcc
CXX := $(TOOLS_DIR)/bin/$(TARGET)-g++
AS := $(TOOLS_DIR)/bin/$(TARGET)-as
LD := $(TOOLS_DIR)/bin/$(TARGET)-ld
AR := $(TOOLS_DIR)/bin/$(TARGET)-ar
OBJCOPY := $(TOOLS_DIR)/bin/$(TARGET)-objcopy
OBJDUMP := $(TOOLS_DIR)/bin/$(TARGET)-objdump
STRIP := $(TOOLS_DIR)/bin/$(TARGET)-strip

# Build flags
CFLAGS := -std=c17 -ffreestanding -fno-stack-protector -fno-pic -mno-sse -mno-sse2
CFLAGS += -mno-mmx -mno-80387 -mno-red-zone -mcmodel=kernel
CFLAGS += -Wall -Wextra -Werror -O2
CFLAGS += -DSENTINALOS_VERSION=\"$(SENTINALOS_VERSION)\"
CFLAGS += -DSENTINALOS_ARCH=\"$(SENTINALOS_ARCH)\"
CFLAGS += -DSECURITY_LEVEL_PENTAGON

# Security hardening flags
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS += -fPIE -Wformat -Wformat-security
LDFLAGS += -z relro -z now -z noexecstack

# Kernel-specific flags
KERNEL_CFLAGS := $(CFLAGS) -D__KERNEL__ -mno-red-zone -fno-omit-frame-pointer
KERNEL_LDFLAGS := -T kernel/linker.ld -nostdlib -z max-page-size=0x1000

# Default target
.PHONY: all
all: validate toolchain kernel userland iso

# Validate host system
.PHONY: validate
validate:
	@echo "=== Validating Host System ==="
	@./scripts/validate-host.sh

# Build cross-compilation toolchain
.PHONY: toolchain
toolchain:
	@echo "=== Building Cross-Compilation Toolchain ==="
	@./scripts/build-toolchain.sh

# Build kernel
.PHONY: kernel
kernel: toolchain
	@echo "=== Building SentinalOS Kernel ==="
	@$(MAKE) -C kernel CC="$(CC)" CFLAGS="$(KERNEL_CFLAGS)" LDFLAGS="$(KERNEL_LDFLAGS)"

# Build userland applications
.PHONY: userland
userland: toolchain
	@echo "=== Building Userland Applications ==="
	@$(MAKE) -C userland CC="$(CC)" CFLAGS="$(CFLAGS)"

# Create bootable ISO
.PHONY: iso
iso: kernel userland
	@echo "=== Creating Bootable ISO ==="
	@./scripts/create-iso.sh

# Test in QEMU
.PHONY: test
test: iso
	@echo "=== Testing in QEMU ==="
	@./scripts/test-qemu.sh

# Test with KVM acceleration
.PHONY: test-kvm
test-kvm: iso
	@echo "=== Testing in QEMU with KVM ==="
	@./scripts/test-qemu.sh --kvm

# Debug in QEMU with GDB
.PHONY: debug
debug: kernel
	@echo "=== Debugging Kernel in QEMU ==="
	@./scripts/debug-qemu.sh

# Clean build artifacts
.PHONY: clean
clean:
	@echo "=== Cleaning Build Artifacts ==="
	@rm -rf $(BUILD_DIR)
	@$(MAKE) -C kernel clean
	@$(MAKE) -C userland clean
	@rm -f $(ISO_DIR)/*.iso

# Clean everything including toolchain
.PHONY: distclean
distclean: clean
	@echo "=== Deep Cleaning (Including Toolchain) ==="
	@rm -rf $(TOOLS_DIR)
	@rm -rf $(SOURCES_DIR)/*.tar.*
	@rm -rf $(SOURCES_DIR)/*.tgz
	@rm -rf $(SYSROOT_DIR)

# Show build information
.PHONY: info
info:
	@echo "SentinalOS Build Information:"
	@echo "  Version: $(SENTINALOS_VERSION)"
	@echo "  Codename: $(SENTINALOS_CODENAME)"
	@echo "  Architecture: $(SENTINALOS_ARCH)"
	@echo "  Security Level: $(SENTINALOS_SECURITY_LEVEL)"
	@echo "  Target: $(TARGET)"
	@echo "  Tools Directory: $(TOOLS_DIR)"
	@echo "  Build Directory: $(BUILD_DIR)"
	@echo "  Cross-Compiler: $(CC)"

# Help target
.PHONY: help
help:
	@echo "SentinalOS Build System"
	@echo "Available targets:"
	@echo "  all        - Build everything (default)"
	@echo "  validate   - Validate host system requirements"
	@echo "  toolchain  - Build cross-compilation toolchain"
	@echo "  kernel     - Build SentinalOS kernel"
	@echo "  userland   - Build userland applications"
	@echo "  iso        - Create bootable ISO image"
	@echo "  test       - Test in QEMU emulator"
	@echo "  test-kvm   - Test in QEMU with KVM acceleration"
	@echo "  debug      - Debug kernel in QEMU with GDB"
	@echo "  clean      - Clean build artifacts"
	@echo "  distclean  - Clean everything including toolchain"
	@echo "  info       - Show build information"
	@echo "  help       - Show this help message"

# Create necessary directories
$(BUILD_DIR) $(TOOLS_DIR) $(SYSROOT_DIR) $(ISO_DIR):
	mkdir -p $@

# Ensure directories exist for builds
toolchain: | $(TOOLS_DIR) $(SOURCES_DIR) $(SYSROOT_DIR)
kernel: | $(BUILD_DIR)
userland: | $(BUILD_DIR)
iso: | $(ISO_DIR)