# SentinalOS sentinal_send Makefile
# Pentagon-Level Secure File Transfer Application

# Configuration
TARGET := sentinal_send
SOURCE_DIR := src
INCLUDE_DIR := include
BUILD_DIR := ../../build/userland/sentinal_send

# Cross-compilation tools (if available)
CROSS_PREFIX := ../../tools/bin/x86_64-sentinalos-
CC := $(if $(wildcard $(CROSS_PREFIX)gcc),$(CROSS_PREFIX)gcc,gcc)
AR := $(if $(wildcard $(CROSS_PREFIX)ar),$(CROSS_PREFIX)ar,ar)
OBJCOPY := $(if $(wildcard $(CROSS_PREFIX)objcopy),$(CROSS_PREFIX)objcopy,objcopy)

# Compiler flags
CFLAGS := -std=c17 -Wall -Wextra -Werror -O2
CFLAGS += -I$(INCLUDE_DIR)
CFLAGS += -D_GNU_SOURCE
CFLAGS += -DSECURITY_LEVEL_PENTAGON

# Security hardening flags
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS += -fPIE -Wformat -Wformat-security
CFLAGS += -fno-common -ffunction-sections -fdata-sections

# Linker flags
LDFLAGS := -pie -z relro -z now -z noexecstack
LDFLAGS += -Wl,--gc-sections

# Source files
SOURCES := $(wildcard $(SOURCE_DIR)/*.c)
OBJECTS := $(SOURCES:$(SOURCE_DIR)/%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJECTS:.o=.d)

# Target binary
BINARY := $(BUILD_DIR)/$(TARGET)

# Default target
.PHONY: all
all: $(BINARY)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile source files
$(BUILD_DIR)/%.o: $(SOURCE_DIR)/%.c | $(BUILD_DIR)
	@echo "CC $<"
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Link binary
$(BINARY): $(OBJECTS)
	@echo "LD $@"
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@
	@echo "Built sentinal_send: Pentagon-level secure file transfer"

# Install to sysroot
.PHONY: install
install: $(BINARY)
	@echo "Installing sentinal_send..."
	mkdir -p ../../sysroot/usr/bin
	cp $(BINARY) ../../sysroot/usr/bin/
	chmod 755 ../../sysroot/usr/bin/$(TARGET)
	@echo "sentinal_send installed to sysroot"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning sentinal_send..."
	rm -rf $(BUILD_DIR)

# Show information
.PHONY: info
info:
	@echo "SentinalOS sentinal_send Build Information:"
	@echo "  Target: $(TARGET)"
	@echo "  Compiler: $(CC)"
	@echo "  Build Directory: $(BUILD_DIR)"
	@echo "  Security Level: Pentagon"
	@echo "  Features: AES-256-CBC, PBKDF2, Secure Memory"

# Help
.PHONY: help
help:
	@echo "SentinalOS sentinal_send Build System"
	@echo "Available targets:"
	@echo "  all     - Build sentinal_send (default)"
	@echo "  install - Install to sysroot"
	@echo "  clean   - Clean build artifacts"
	@echo "  info    - Show build information"
	@echo "  help    - Show this help"

# Include dependency files
-include $(DEPS)

# Phony targets
.PHONY: all install clean info help