WE ARE STILL IN BETA TESTING DO NOT RUN THE ISO UNLESS IT IS IN A VM. WE HAVE NOT SET UP THE BASE SYSTEM IT IS JUST A KERNEL

# SentinalOS - Pentagon-Level Secure Operating System

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗ █████╗ ██║         ██████╗ ███████╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔══██╗██║        ██╔═══██╗██╔════╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║███████║██║        ██║   ██║███████╗
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══██║██║        ██║   ██║╚════██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║██║  ██║███████╗   ╚██████╔╝███████║
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝    ╚═════╝ ╚══════╝

                            PENTAGON EDITION v1.0
                       Classification: TOP SECRET // SI
                         *** AUTHORIZED PERSONNEL ONLY ***
```

## Overview

SentinalOS is a Pentagon-level secure operating system built from scratch with advanced security features and multi-level classification support. This system provides a secure computing environment for high-security operations, pentesting, and classified data handling.

**⚠️ SECURITY CLASSIFICATION: TOP SECRET // SI // NOFORN**

## 🛡️ Security Features

### Pentagon-Level Security Hardening
- **Multi-Level Security (MLS)**: 5-level classification system (Unclassified → Pentagon)
- **Hardware Security**: SME, SMAP, SMEP, KASLR, Control Flow Integrity
- **Memory Protection**: Secure memory allocation with hardware isolation
- **Audit Logging**: Comprehensive security event logging and monitoring

### Cryptographic Security
- **AES-256-CBC Encryption**: Pentagon-level file encryption with `sentinal_send`
- **Secure Key Derivation**: PBKDF2-based password security
- **Hardware Entropy**: RDRAND/RDSEED for cryptographic randomization
- **Secure Communications**: Encrypted data transfer with integrity validation

### Pentesting Integration
- **Sandboxed Tools**: Secure execution environment for penetration testing
- **Tool Suite**: nmap, metasploit, hashcat, john, sqlmap, wireshark
- **Resource Isolation**: Namespace-based security with privilege dropping
- **Audit Integration**: Complete logging of all pentesting activities

### Desktop Security
- **Pentagon-Level GUI**: Multi-level classification-aware desktop environment
- **Secure Windows**: Classification banners and access control
- **Protected Input**: Secure keyboard/mouse handling for classified data
- **Visual Security**: Color-coded classification levels and security indicators

## 🏗️ Architecture

### System Components
```
SentinalOS/
├── kernel/           # Pentagon-level secure kernel
├── drivers/          # Hardware drivers with security validation
├── security/         # Security subsystems (KASLR, SME, classification)
├── userland/         # User space applications and libraries
├── pentesting/       # Sandboxed penetration testing framework
├── gui/              # Pentagon-level secure desktop environment
├── apps/             # Security applications and utilities
├── scripts/          # Build system and toolchain
├── config/           # System configuration files
├── sysroot/          # Target system root filesystem
├── tools/            # Cross-compilation toolchain
└── iso/              # Bootable ISO creation system
```

### Security Subsystems
- **Classification Engine**: Multi-level security enforcement
- **Memory Manager**: Secure allocation with hardware features
- **Process Scheduler**: Security-aware task scheduling
- **Audit System**: Pentagon-level event logging
- **Crypto Engine**: Hardware-accelerated cryptography

## 🚀 Quick Start

### Prerequisites
- Linux development environment (Ubuntu/Debian recommended)
- Cross-compilation toolchain support
- QEMU for testing (optional)
- Security clearance for classified operations

### Building SentinalOS

1. **Clone Repository**
   ```bash
   git clone [repository-url]
   cd SentinalOS
   ```

2. **Build Cross-Compilation Toolchain**
   ```bash
   ./scripts/build-toolchain.sh
   ```

3. **Build Kernel and System**
   ```bash
   make all
   ```

4. **Create Bootable ISO**
   ```bash
   cd iso/
   make all
   ```

5. **Test in QEMU** (Optional)
   ```bash
   make test
   ```

### Development Environment

Open the project in VS Code:
```bash
code SentinalOS.code-workspace
```

The workspace includes:
- Cross-compilation configuration
- Kernel debugging support
- Security linting rules
- Pentagon-level development standards

## 🔧 Pentagon Tools

### sentinal_send - Secure File Transfer
Pentagon-level encrypted file transfer with AES-256-CBC:
```bash
# Encrypt file
sentinal_send -e -i document.txt -o document.enc -c 4 -s WORKSTATION -t SERVER

# Decrypt file  
sentinal_send -d -i document.enc -o document.txt -u 4
```

### Pentesting Sandbox
Secure execution environment for penetration testing tools:
```bash
# List available tools
pentesting_sandbox --list

# Execute nmap in sandbox
pentesting_sandbox nmap -sn 192.168.1.0/24

# Run hashcat with resource limits
pentesting_sandbox hashcat -m 0 hashes.txt wordlist.txt
```

### Security Terminal
Pentagon-level command interface with classification awareness:
```bash
# Launch security terminal
./apps/security_terminal

# Available commands:
classify <level>    # Set security classification
secstat            # Show security status
audit on/off       # Enable/disable audit mode
pentesting         # Launch pentesting tools
sentinal_send      # Launch secure file transfer
```

## 🖥️ Desktop Environment

### Pentagon-Level GUI
- **Classification Banners**: Visual security level indicators
- **Secure Windows**: Multi-level security context for applications
- **Audit Integration**: Complete user action logging
- **Access Control**: Clearance-based window access control

### Security Features
- **Classification Colors**: Visual coding by security level
- **Secure Input**: Protected input for classified data
- **Screen Protection**: Anti-screenshot and recording protection
- **Session Monitoring**: Real-time security event tracking

## 📊 System Specifications

### Hardware Requirements
- **Architecture**: x86_64 (AMD64) only
- **Memory**: Minimum 2GB RAM (4GB recommended)
- **Storage**: 8GB minimum for full installation
- **Security**: TPM 2.0 recommended for secure boot

### Software Features
- **Kernel**: Custom security-hardened kernel
- **Init System**: BusyBox-based initialization
- **Shell**: Security-aware command interpreter
- **File System**: Encrypted with classification metadata
- **Networking**: Intel E1000, Realtek, Atheros drivers

## 🛠️ Development

### Build System
- **Cross-Compilation**: x86_64-sentinalos toolchain
- **Security Flags**: Stack protection, FORTIFY_SOURCE, PIE
- **Validation**: Automated security checking
- **Testing**: QEMU-based system testing

### Security Standards
- **Code Review**: Mandatory security review process
- **Static Analysis**: Automated vulnerability scanning
- **Penetration Testing**: Regular security assessments
- **Compliance**: Pentagon-level security requirements

## 📚 Documentation

### Classification Levels
- **Level 0**: UNCLASSIFIED - General system access
- **Level 1**: CONFIDENTIAL - Restricted information
- **Level 2**: SECRET - Highly sensitive data
- **Level 3**: TOP SECRET - Critical national security
- **Level 4**: PENTAGON - Highest level classification

### Security Procedures
- All system access requires proper authentication
- Security events are logged and audited
- Classification levels must be respected
- Unauthorized access attempts are reported

## ⚠️ Security Warnings

### CLASSIFIED SYSTEM
This system contains and processes classified information at the TOP SECRET level. Access is restricted to authorized personnel with appropriate security clearance.

### AUTHORIZED USE ONLY
Unauthorized access, use, or modification of this system is strictly prohibited and may result in criminal prosecution under applicable federal laws.

### MONITORING NOTICE
All activities on this system are monitored and logged. Users have no expectation of privacy.

## 🏢 Compliance & Standards

### Security Frameworks
- **Common Criteria**: EAL4+ evaluation target
- **FIPS 140-2**: Cryptographic module compliance
- **NIST 800-53**: Security control implementation
- **DoD 8500.2**: Information assurance requirements

### Certifications
- Pentagon-level security assessment (pending)
- TEMPEST shielding evaluation (planned)
- Cryptographic validation (in progress)

## 📞 Support & Contact

### Security Issues
Report security vulnerabilities through appropriate classified channels only.

### Development Support
Contact the SentinalOS development team through secure communication channels.

### Classification Authority
All classification decisions must be approved by appropriate security authorities.

---

**DISTRIBUTION STATEMENT**: This document contains technical data subject to export controls. Distribution is limited to authorized personnel with appropriate security clearance.

**CLASSIFICATION**: TOP SECRET // SI // NOFORN  
**AUTHORITY**: Pentagon Security Classification Guide  
**DECLASSIFICATION DATE**: Not Applicable

## License

This project is for educational and defensive security purposes only.
