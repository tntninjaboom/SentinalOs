#!/bin/bash

# SentinalOS Host System Validation Script
# Validates that the host system has all required tools and dependencies

set -e

echo "=== SentinalOS Host System Validation ==="
echo "Checking host system requirements..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0

check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 is installed"
        if [ "$2" ]; then
            version=$($1 $2 2>&1 | head -n1)
            echo "  Version: $version"
        fi
    else
        echo -e "${RED}✗${NC} $1 is not installed"
        ERRORS=$((ERRORS + 1))
    fi
}

check_package() {
    if dpkg -l | grep -q "^ii  $1 "; then
        echo -e "${GREEN}✓${NC} Package $1 is installed"
    else
        echo -e "${RED}✗${NC} Package $1 is not installed"
        ERRORS=$((ERRORS + 1))
    fi
}

echo ""
echo "=== Required Tools ==="

# Essential build tools
check_command "gcc" "--version"
check_command "g++" "--version"
check_command "make" "--version"
check_command "ld" "--version"
check_command "as" "--version"
check_command "ar" "--version"
check_command "nasm" "-version"
check_command "bison" "--version"
check_command "flex" "--version"
check_command "makeinfo" "--version"
check_command "gawk" "--version"
check_command "m4" "--version"
check_command "patch" "--version"
check_command "tar" "--version"
check_command "gzip" "--version"
check_command "xz" "--version"
check_command "wget" "--version"
check_command "curl" "--version"
check_command "git" "--version"

# QEMU for testing
check_command "qemu-system-x86_64" "--version"

# Disk space check
echo ""
echo "=== Disk Space Check ==="
available_space=$(df . | tail -1 | awk '{print $4}')
available_gb=$((available_space / 1024 / 1024))

if [ $available_gb -ge 50 ]; then
    echo -e "${GREEN}✓${NC} Available disk space: ${available_gb}GB (≥50GB required)"
else
    echo -e "${RED}✗${NC} Available disk space: ${available_gb}GB (<50GB required)"
    ERRORS=$((ERRORS + 1))
fi

# Memory check
echo ""
echo "=== Memory Check ==="
total_mem=$(grep MemTotal /proc/meminfo | awk '{print $2}')
total_mem_gb=$((total_mem / 1024 / 1024))

if [ $total_mem_gb -ge 8 ]; then
    echo -e "${GREEN}✓${NC} Total memory: ${total_mem_gb}GB (≥8GB recommended)"
else
    echo -e "${YELLOW}!${NC} Total memory: ${total_mem_gb}GB (<8GB, may be slow)"
fi

# Architecture check
echo ""
echo "=== Architecture Check ==="
arch=$(uname -m)
if [ "$arch" = "x86_64" ]; then
    echo -e "${GREEN}✓${NC} Architecture: $arch (AMD64/x86_64)"
else
    echo -e "${RED}✗${NC} Architecture: $arch (AMD64/x86_64 required)"
    ERRORS=$((ERRORS + 1))
fi

# Kernel version check
echo ""
echo "=== Kernel Version Check ==="
kernel_version=$(uname -r)
echo "Kernel version: $kernel_version"

# Check for virtualization support
echo ""
echo "=== Virtualization Support ==="
if grep -q -E "(vmx|svm)" /proc/cpuinfo; then
    echo -e "${GREEN}✓${NC} Hardware virtualization supported"
else
    echo -e "${YELLOW}!${NC} Hardware virtualization not detected"
fi

# Summary
echo ""
echo "=== Validation Summary ==="
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ Host system validation passed!${NC}"
    echo "Your system is ready for SentinalOS development."
    exit 0
else
    echo -e "${RED}✗ Host system validation failed with $ERRORS errors.${NC}"
    echo ""
    echo "Please install missing dependencies:"
    echo "sudo apt update"
    echo "sudo apt install -y build-essential gcc g++ make binutils nasm bison flex"
    echo "sudo apt install -y texinfo gawk m4 patch tar gzip xz-utils wget curl git"
    echo "sudo apt install -y qemu-system-x86 qemu-utils"
    echo "sudo apt install -y libelf-dev libssl-dev bc python3 python3-pip"
    exit 1
fi