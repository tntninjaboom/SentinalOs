#!/bin/bash

# SentinalOS Cross-Compilation Toolchain Build Script
# Builds GCC cross-compiler for x86_64-sentinalos target

set -e

# Load configuration
source "$(dirname "$0")/../config/version"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOURCES_DIR="$ROOT_DIR/sources"
TOOLS_DIR="$ROOT_DIR/tools"
BUILD_DIR="$ROOT_DIR/build/toolchain"
SYSROOT_DIR="$ROOT_DIR/sysroot"

# Target configuration  
TARGET="x86_64-elf"
ARCH="x86_64"

# Package versions (LFS/security-hardened versions)
BINUTILS_VERSION="2.41"
GCC_VERSION="13.2.0"
GMP_VERSION="6.3.0"
MPFR_VERSION="4.2.1"
MPC_VERSION="1.3.1"
ISL_VERSION="0.26"

# Build configuration
MAKE_JOBS=$(nproc)
PATH="$TOOLS_DIR/bin:$PATH"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

download_package() {
    local package="$1"
    local version="$2"
    local url="$3"
    local filename="$4"
    
    log_info "Downloading $package $version..."
    
    # Ensure sources directory exists
    mkdir -p "$SOURCES_DIR"
    
    if [ ! -f "$SOURCES_DIR/$filename" ]; then
        wget -c "$url" -O "$SOURCES_DIR/$filename" || {
            log_error "Failed to download $package"
            exit 1
        }
        log_success "Downloaded $filename"
    else
        log_info "$filename already exists, skipping download"
    fi
}

extract_package() {
    local filename="$1"
    local extract_dir="$2"
    
    log_info "Extracting $filename..."
    
    # Ensure build directory exists
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    if [ ! -d "$extract_dir" ]; then
        tar -xf "$SOURCES_DIR/$filename" || {
            log_error "Failed to extract $filename"
            exit 1
        }
        log_success "Extracted $extract_dir"
    else
        log_info "$extract_dir already exists, skipping extraction"
    fi
}

setup_directories() {
    log_info "Setting up directories..."
    
    mkdir -p "$SOURCES_DIR" "$TOOLS_DIR" "$BUILD_DIR" "$SYSROOT_DIR"
    mkdir -p "$SYSROOT_DIR/{bin,sbin,lib,lib64,usr,etc,dev,proc,sys,tmp,var}"
    mkdir -p "$SYSROOT_DIR/usr/{bin,sbin,lib,lib64,include,share}"
    
    # Create target-specific directories
    mkdir -p "$TOOLS_DIR/$TARGET"
    
    log_success "Directories created"
}

download_sources() {
    log_info "Downloading toolchain sources..."
    
    # GNU Mirror URLs
    local gnu_mirror="https://ftp.gnu.org/gnu"
    
    download_package "Binutils" "$BINUTILS_VERSION" \
        "$gnu_mirror/binutils/binutils-$BINUTILS_VERSION.tar.xz" \
        "binutils-$BINUTILS_VERSION.tar.xz"
    
    download_package "GCC" "$GCC_VERSION" \
        "$gnu_mirror/gcc/gcc-$GCC_VERSION/gcc-$GCC_VERSION.tar.xz" \
        "gcc-$GCC_VERSION.tar.xz"
    
    download_package "GMP" "$GMP_VERSION" \
        "$gnu_mirror/gmp/gmp-$GMP_VERSION.tar.xz" \
        "gmp-$GMP_VERSION.tar.xz"
    
    download_package "MPFR" "$MPFR_VERSION" \
        "$gnu_mirror/mpfr/mpfr-$MPFR_VERSION.tar.xz" \
        "mpfr-$MPFR_VERSION.tar.xz"
    
    download_package "MPC" "$MPC_VERSION" \
        "$gnu_mirror/mpc/mpc-$MPC_VERSION.tar.gz" \
        "mpc-$MPC_VERSION.tar.gz"
    
    download_package "ISL" "$ISL_VERSION" \
        "https://libisl.sourceforge.io/isl-$ISL_VERSION.tar.bz2" \
        "isl-$ISL_VERSION.tar.bz2"
    
    log_success "All sources downloaded"
}

build_binutils() {
    log_info "Building Binutils for $TARGET..."
    
    extract_package "binutils-$BINUTILS_VERSION.tar.xz" "binutils-$BINUTILS_VERSION"
    
    cd "$BUILD_DIR"
    mkdir -p binutils-build
    cd binutils-build
    
    # Configure binutils with security hardening
    ../binutils-$BINUTILS_VERSION/configure \
        --target="$TARGET" \
        --prefix="$TOOLS_DIR" \
        --with-sysroot="$SYSROOT_DIR" \
        --disable-nls \
        --disable-werror \
        --enable-64-bit-bfd \
        --enable-gold \
        --enable-plugins \
        --enable-threads \
        --enable-deterministic-archives \
        --enable-relro \
        --enable-default-pie || {
        log_error "Binutils configure failed"
        exit 1
    }
    
    # Build and install
    make -j"$MAKE_JOBS" || {
        log_error "Binutils build failed"
        exit 1
    }
    
    make install || {
        log_error "Binutils install failed"
        exit 1
    }
    
    log_success "Binutils built and installed"
}

build_gcc_bootstrap() {
    log_info "Building GCC bootstrap compiler..."
    
    extract_package "gcc-$GCC_VERSION.tar.xz" "gcc-$GCC_VERSION"
    
    # Extract GCC dependencies into GCC source tree
    cd "$BUILD_DIR/gcc-$GCC_VERSION"
    
    extract_package "gmp-$GMP_VERSION.tar.xz" "gmp-$GMP_VERSION"
    extract_package "mpfr-$MPFR_VERSION.tar.xz" "mpfr-$MPFR_VERSION"
    extract_package "mpc-$MPC_VERSION.tar.gz" "mpc-$MPC_VERSION"
    extract_package "isl-$ISL_VERSION.tar.bz2" "isl-$ISL_VERSION"
    
    # Move dependencies to expected locations
    mv "../gmp-$GMP_VERSION" gmp
    mv "../mpfr-$MPFR_VERSION" mpfr
    mv "../mpc-$MPC_VERSION" mpc
    mv "../isl-$ISL_VERSION" isl
    
    cd "$BUILD_DIR"
    mkdir -p gcc-build
    cd gcc-build
    
    # Configure GCC with security features
    ../gcc-$GCC_VERSION/configure \
        --target="$TARGET" \
        --prefix="$TOOLS_DIR" \
        --with-glibc-version=2.38 \
        --with-sysroot="$SYSROOT_DIR" \
        --with-newlib \
        --without-headers \
        --enable-default-pie \
        --enable-default-ssp \
        --enable-initfini-array \
        --disable-nls \
        --disable-shared \
        --disable-multilib \
        --disable-threads \
        --disable-libatomic \
        --disable-libgomp \
        --disable-libquadmath \
        --disable-libssp \
        --disable-libvtv \
        --disable-libstdcxx \
        --enable-languages=c,c++ || {
        log_error "GCC configure failed"
        exit 1
    }
    
    # Build bootstrap compiler
    make -j"$MAKE_JOBS" all-gcc || {
        log_error "GCC bootstrap build failed"
        exit 1
    }
    
    make install-gcc || {
        log_error "GCC bootstrap install failed"
        exit 1
    }
    
    log_success "GCC bootstrap compiler built and installed"
}

create_target_specs() {
    log_info "Creating target specifications..."
    
    # Create basic target headers
    mkdir -p "$SYSROOT_DIR/usr/include"
    
    # Create minimal libc headers for freestanding environment
    cat > "$SYSROOT_DIR/usr/include/limits.h" << 'EOF'
#ifndef _LIMITS_H
#define _LIMITS_H

#define CHAR_BIT 8
#define SCHAR_MIN (-128)
#define SCHAR_MAX 127
#define UCHAR_MAX 255
#define CHAR_MIN SCHAR_MIN
#define CHAR_MAX SCHAR_MAX
#define SHRT_MIN (-32768)
#define SHRT_MAX 32767
#define USHRT_MAX 65535
#define INT_MIN (-2147483648)
#define INT_MAX 2147483647
#define UINT_MAX 4294967295U
#define LONG_MIN (-9223372036854775808L)
#define LONG_MAX 9223372036854775807L
#define ULONG_MAX 18446744073709551615UL
#define LLONG_MIN (-9223372036854775808LL)
#define LLONG_MAX 9223372036854775807LL
#define ULLONG_MAX 18446744073709551615ULL

#endif
EOF
    
    log_success "Target specifications created"
}

validate_toolchain() {
    log_info "Validating cross-compilation toolchain..."
    
    # Check if tools exist
    local tools=("$TARGET-gcc" "$TARGET-g++" "$TARGET-as" "$TARGET-ld" "$TARGET-ar" "$TARGET-objcopy" "$TARGET-objdump" "$TARGET-nm" "$TARGET-strip")
    
    for tool in "${tools[@]}"; do
        if [ -x "$TOOLS_DIR/bin/$tool" ]; then
            log_success "$tool: OK"
        else
            log_error "$tool: MISSING"
            exit 1
        fi
    done
    
    # Test compilation
    log_info "Testing cross-compiler..."
    
    cat > /tmp/test.c << 'EOF'
int main(void) {
    return 42;
}
EOF
    
    if "$TOOLS_DIR/bin/$TARGET-gcc" -c /tmp/test.c -o /tmp/test.o; then
        log_success "Cross-compiler test: OK"
        rm -f /tmp/test.c /tmp/test.o
    else
        log_error "Cross-compiler test: FAILED"
        exit 1
    fi
    
    log_success "Toolchain validation complete"
}

main() {
    echo "=== SentinalOS Cross-Compilation Toolchain Build ==="
    echo "Target: $TARGET"
    echo "Architecture: $ARCH"
    echo "Build Jobs: $MAKE_JOBS"
    echo ""
    
    setup_directories
    download_sources
    build_binutils
    build_gcc_bootstrap
    create_target_specs
    validate_toolchain
    
    echo ""
    log_success "Cross-compilation toolchain build complete!"
    echo "Toolchain installed to: $TOOLS_DIR"
    echo "Target sysroot: $SYSROOT_DIR"
    echo ""
    echo "Add to PATH: export PATH=\"$TOOLS_DIR/bin:\$PATH\""
}

# Run main function
main "$@"