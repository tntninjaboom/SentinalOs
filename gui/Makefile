# SentinalOS GUI Environment Makefile
# Pentagon-Level Secure Desktop Interface

# Configuration
GUI_SOURCES := window_manager compositor security_ui
BUILD_DIR := ../build/gui
SYSROOT_DIR := ../sysroot
INCLUDE_DIR := include

# Cross-compilation tools
CROSS_PREFIX := ../tools/bin/x86_64-sentinalos-
CC := $(if $(wildcard $(CROSS_PREFIX)gcc),$(CROSS_PREFIX)gcc,gcc)
AR := $(if $(wildcard $(CROSS_PREFIX)ar),$(CROSS_PREFIX)ar,ar)

# Compiler flags with security hardening
CFLAGS := -std=c17 -Wall -Wextra -Werror -O2
CFLAGS += -I$(INCLUDE_DIR) -I../kernel/include
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS += -fPIE -Wformat -Wformat-security
CFLAGS += -DSECURITY_LEVEL_PENTAGON
CFLAGS += -DGUI_FRAMEBUFFER_MODE

# Linker flags
LDFLAGS := -pie -z relro -z now -z noexecstack

# Build targets
GUI_OBJECTS := $(GUI_SOURCES:%=$(BUILD_DIR)/%.o)
GUI_LIB := $(BUILD_DIR)/libsentinal_gui.a

# Default target
.PHONY: all
all: $(GUI_LIB) install_gui_apps

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile GUI sources
$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	@echo "CC $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Create GUI library
$(GUI_LIB): $(GUI_OBJECTS)
	@echo "AR $@"
	$(AR) rcs $@ $(GUI_OBJECTS)
	@echo "Built SentinalOS GUI Library"

# Install GUI applications
.PHONY: install_gui_apps
install_gui_apps: $(GUI_LIB)
	@echo "Installing GUI applications..."
	mkdir -p $(SYSROOT_DIR)/usr/bin
	mkdir -p $(SYSROOT_DIR)/usr/lib
	mkdir -p $(SYSROOT_DIR)/etc/sentinal/gui
	cp $(GUI_LIB) $(SYSROOT_DIR)/usr/lib/
	cp config/gui_config.conf $(SYSROOT_DIR)/etc/sentinal/gui/
	@echo "GUI system installed"

# Clean
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: help
help:
	@echo "SentinalOS GUI Build System"
	@echo "Available targets:"
	@echo "  all     - Build GUI system"
	@echo "  clean   - Clean build artifacts"
	@echo "  help    - Show this help"