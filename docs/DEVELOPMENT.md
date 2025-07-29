# SentinalOS Development Guide

This document provides comprehensive development guidelines for SentinalOS, a Pentagon-level security operating system built from scratch.

## Development Environment Setup

### Required Tools

- **Host OS**: Linux (Ubuntu 20.04+ recommended)
- **Architecture**: x86_64 (AMD64)
- **Memory**: 8GB+ RAM recommended
- **Storage**: 50GB+ free space
- **Development Tools**: GCC, Make, Binutils, NASM, QEMU

### VS Code Configuration

The project includes a comprehensive VS Code workspace configuration:

1. **Open Workspace**: Load `SentinalOS.code-workspace`
2. **Install Extensions**: VS Code will prompt to install recommended extensions
3. **Build Tasks**: Use Ctrl+Shift+P → "Tasks: Run Task" to access build commands
4. **Debugging**: F5 to start kernel debugging in QEMU

### Key VS Code Features

- **IntelliSense**: Full C/C++ code completion for kernel development
- **Build Integration**: One-click builds with error highlighting
- **Debugging Support**: GDB integration for kernel debugging
- **Assembly Syntax**: x86-64 assembly highlighting
- **Problem Matching**: Automatic error detection and navigation

## Build System

### Main Makefile Targets

```bash
make help          # Show available targets
make validate      # Validate host system
make toolchain     # Build cross-compilation tools
make kernel        # Build SentinalOS kernel
make userland      # Build user applications
make iso           # Create bootable ISO
make test          # Test in QEMU
make debug         # Debug with GDB
make clean         # Clean build artifacts
make distclean     # Clean everything
```

### Build Process Flow

1. **Host Validation**: Check system requirements
2. **Toolchain Build**: Create cross-compilation environment
3. **Kernel Build**: Compile hardened kernel with security features
4. **Userland Build**: Build system utilities and applications
5. **ISO Creation**: Generate bootable image with GRUB
6. **Testing**: Validate in QEMU environment

## Security Architecture

### Kernel Hardening

- **SME (Secure Memory Encryption)**: Hardware memory encryption
- **SMAP (Supervisor Mode Access Prevention)**: Kernel/user separation
- **KASLR (Kernel Address Space Layout Randomization)**: Memory layout randomization
- **Stack Protection**: Buffer overflow prevention
- **Control Flow Integrity**: ROP/JOP attack mitigation

### Boot Security

- **UEFI Secure Boot**: Cryptographically signed kernel
- **TPM Integration**: Measured boot with attestation
- **LUKS Encryption**: Full disk encryption support

### Application Security

- **SELinux/AppArmor**: Mandatory access control
- **Sandboxing**: Process isolation
- **Capability System**: Fine-grained permissions

## Directory Structure

```
SentinalOS/
├── .vscode/           # VS Code configuration
├── bootloader/        # GRUB configuration
├── build/             # Build artifacts
├── config/            # System configuration
├── docs/              # Documentation
├── drivers/           # Device drivers
├── filesystem/        # File system layout
├── iso/               # ISO creation workspace
├── kernel/            # Custom kernel source
├── pentesting/        # Security testing tools
├── scripts/           # Build and utility scripts
├── security/          # Security modules
├── sources/           # Source packages
├── sysroot/           # Target system root
├── tools/             # Cross-compilation toolchain
└── userland/          # User space applications
    └── sentinal_send/ # Custom encrypted file transfer
```

## Coding Standards

### Kernel Code

- **Standard**: C17 with GCC extensions
- **Indentation**: 8-space tabs (Linux kernel style)
- **Line Length**: 80 columns maximum
- **Functions**: Static where possible, clear naming
- **Comments**: Comprehensive documentation

### Security Requirements

- **No hardcoded secrets**: All sensitive data externalized
- **Input validation**: All user input sanitized
- **Buffer bounds**: Strict array bounds checking
- **Memory safety**: No unsafe pointer operations
- **Privilege separation**: Minimal required permissions

### Code Review Process

1. **Security Review**: All code reviewed for security implications
2. **Functionality Test**: Comprehensive testing in QEMU
3. **Performance Analysis**: No unnecessary overhead
4. **Documentation**: All public APIs documented

## Testing Strategy

### Unit Testing

- Kernel modules tested in isolation
- User applications tested independently
- Security features validated separately

### Integration Testing

- Full system boot testing
- Hardware driver validation
- Network stack testing
- Security policy enforcement

### Performance Testing

- Boot time optimization
- Memory usage profiling
- Network throughput testing
- Security overhead analysis

## Debugging

### QEMU + GDB Setup

```bash
# Terminal 1: Start QEMU with GDB server
make debug

# Terminal 2: Connect GDB
gdb build/kernel/sentinalos.elf
(gdb) target remote :1234
(gdb) continue
```

### VS Code Debugging

1. Set breakpoints in kernel code
2. Press F5 to start debugging
3. VS Code connects to QEMU automatically
4. Use standard debugging controls

### Common Debug Scenarios

- **Boot Issues**: Check bootloader configuration
- **Kernel Panics**: Analyze stack traces
- **Memory Issues**: Use QEMU monitor commands
- **Driver Problems**: Enable verbose logging

## Contributing Guidelines

### Security-First Development

- All code changes reviewed for security implications
- No features that compromise system integrity
- Defensive programming practices mandatory
- Security documentation required for all changes

### Code Submission

1. **Branch Naming**: `feature/description` or `security/description`
2. **Commit Messages**: Clear, descriptive commit messages
3. **Testing**: All changes tested in QEMU
4. **Documentation**: Update relevant documentation

### Review Criteria

- **Security**: No introduction of vulnerabilities
- **Performance**: No significant performance degradation
- **Compatibility**: Maintains x86_64 compatibility
- **Standards**: Follows coding standards

## Advanced Topics

### Custom Applications

- **sentinal_send**: AES-256 encrypted file transfer
- **Security Tools**: Integrated pentesting capabilities
- **System Utilities**: Custom UNIX-compatible tools

### Driver Development

- **Network Drivers**: Intel, Realtek, Atheros support
- **Storage Drivers**: SATA, NVMe, SCSI support
- **Input Drivers**: Keyboard, mouse, touchpad support

### Security Modules

- **Access Control**: SELinux policy development
- **Encryption**: LUKS integration
- **Audit System**: Security event logging

## Troubleshooting

### Common Issues

1. **Toolchain Build Fails**: Check host dependencies
2. **Kernel Won't Boot**: Verify GRUB configuration
3. **QEMU Issues**: Check virtualization support
4. **Build Errors**: Clean build and retry

### Getting Help

- Check logs in `build/` directory
- Review VS Code problem panel
- Consult security documentation
- Test in minimal QEMU environment

This development guide ensures consistent, secure development practices for SentinalOS.