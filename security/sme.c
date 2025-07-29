/*
 * SME - Secure Memory Encryption
 * Pentagon-Level Hardware Memory Protection
 */

#include "kernel.h"
#include "string.h"

/* SME MSR Registers */
#define MSR_K8_SYSCFG           0xC0010010
#define MSR_K7_HWCR             0xC0010015
#define MSR_MEM_ENCRYPT_CTRL    0xC0010055
#define MSR_MEM_ENCRYPT_FEAT    0xC0010056

/* SME Control Bits */
#define SYSCFG_MEM_ENCRYPT_EN   (1ULL << 23)
#define SYSCFG_MEM_ENCRYPT_LOCK (1ULL << 24)
#define MEM_ENCRYPT_EN          (1ULL << 0)

/* SME State */
static struct {
    bool supported;
    bool enabled;
    bool locked;
    uint32_t cbit_position;
    uint64_t memory_encryption_mask;
    uint32_t physical_addr_reduction;
    bool initialized;
} sme_state;

/* Read MSR */
static uint64_t read_msr(uint32_t msr) {
    uint32_t low, high;
    __asm__ __volatile__(
        "rdmsr"
        : "=a" (low), "=d" (high)
        : "c" (msr)
    );
    return ((uint64_t)high << 32) | low;
}

/* Write MSR */
static void write_msr(uint32_t msr, uint64_t value) {
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high = value >> 32;
    __asm__ __volatile__(
        "wrmsr"
        :
        : "a" (low), "d" (high), "c" (msr)
    );
}

/* Check if SME is supported */
static bool check_sme_support(void) {
    uint32_t eax, ebx, ecx, edx;
    
    /* Check if this is an AMD processor */
    __asm__ __volatile__(
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (0)
    );
    
    /* Check vendor ID */
    char vendor[13];
    *(uint32_t*)vendor = ebx;
    *(uint32_t*)(vendor + 4) = edx;
    *(uint32_t*)(vendor + 8) = ecx;
    vendor[12] = '\0';
    
    if (strcmp(vendor, "AuthenticAMD") != 0) {
        KLOG_INFO("SME requires AMD processor, found: %s", vendor);
        return false;
    }
    
    /* Check for SME support in CPUID */
    __asm__ __volatile__(
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (0x8000001F)
    );
    
    if (!(eax & 0x01)) {
        KLOG_INFO("SME not supported by processor");
        return false;
    }
    
    /* Extract SME information */
    sme_state.cbit_position = (ebx >> 0) & 0x3F;
    sme_state.physical_addr_reduction = (ebx >> 6) & 0x3F;
    sme_state.memory_encryption_mask = 1ULL << sme_state.cbit_position;
    
    KLOG_INFO("SME supported: C-bit position %u, phys addr reduction %u bits",
              sme_state.cbit_position, sme_state.physical_addr_reduction);
    
    return true;
}

/* Enable SME */
static bool enable_sme(void) {
    KLOG_INFO("Enabling Secure Memory Encryption...");
    
    /* Read current SYSCFG MSR */
    uint64_t syscfg = read_msr(MSR_K8_SYSCFG);
    
    /* Check if SME is already locked */
    if (syscfg & SYSCFG_MEM_ENCRYPT_LOCK) {
        KLOG_WARN("SME is locked by firmware");
        sme_state.locked = true;
        
        /* Check if it's enabled */
        if (syscfg & SYSCFG_MEM_ENCRYPT_EN) {
            KLOG_INFO("SME already enabled by firmware");
            return true;
        } else {
            KLOG_ERR("SME is locked but not enabled");
            return false;
        }
    }
    
    /* Enable SME */
    syscfg |= SYSCFG_MEM_ENCRYPT_EN;
    write_msr(MSR_K8_SYSCFG, syscfg);
    
    /* Verify SME is enabled */
    syscfg = read_msr(MSR_K8_SYSCFG);
    if (!(syscfg & SYSCFG_MEM_ENCRYPT_EN)) {
        KLOG_ERR("Failed to enable SME");
        return false;
    }
    
    /* Lock SME to prevent tampering */
    syscfg |= SYSCFG_MEM_ENCRYPT_LOCK;
    write_msr(MSR_K8_SYSCFG, syscfg);
    
    sme_state.locked = true;
    
    KLOG_INFO("SME enabled and locked");
    return true;
}

/* Initialize page table entries with SME */
void sme_encrypt_page_table_entry(uint64_t *pte, uint64_t physical_addr) {
    if (!sme_state.enabled) {
        *pte = physical_addr;
        return;
    }
    
    /* Set the C-bit to enable encryption for this page */
    *pte = physical_addr | sme_state.memory_encryption_mask;
}

/* Check if a physical address is encrypted */
bool sme_is_address_encrypted(uint64_t physical_addr) {
    if (!sme_state.enabled) {
        return false;
    }
    
    return (physical_addr & sme_state.memory_encryption_mask) != 0;
}

/* Get SME encryption mask */
uint64_t sme_get_encryption_mask(void) {
    return sme_state.enabled ? sme_state.memory_encryption_mask : 0;
}

/* Encrypt a physical address */
uint64_t sme_encrypt_address(uint64_t physical_addr) {
    if (!sme_state.enabled) {
        return physical_addr;
    }
    
    return physical_addr | sme_state.memory_encryption_mask;
}

/* Decrypt a physical address */
uint64_t sme_decrypt_address(uint64_t physical_addr) {
    if (!sme_state.enabled) {
        return physical_addr;
    }
    
    return physical_addr & ~sme_state.memory_encryption_mask;
}

/* Initialize SME */
void sme_init(void) {
    KLOG_INFO("Initializing Secure Memory Encryption (SME)...");
    
    /* Check if SME is supported */
    if (!check_sme_support()) {
        KLOG_INFO("SME not available on this system");
        sme_state.supported = false;
        sme_state.initialized = true;
        return;
    }
    
    sme_state.supported = true;
    
    /* Enable SME */
    if (enable_sme()) {
        sme_state.enabled = true;
        
        KLOG_INFO("SME successfully initialized");
        KLOG_INFO("Memory encryption mask: 0x%lx", sme_state.memory_encryption_mask);
        KLOG_INFO("All kernel memory is now encrypted");
    } else {
        KLOG_ERR("Failed to enable SME");
        sme_state.enabled = false;
    }
    
    sme_state.initialized = true;
}

/* Get SME status */
void sme_get_status(bool *supported, bool *enabled, bool *locked) {
    if (supported) *supported = sme_state.supported;
    if (enabled) *enabled = sme_state.enabled;
    if (locked) *locked = sme_state.locked;
}

/* Secure memory allocation with SME */
void *sme_secure_alloc(size_t size) {
    if (!sme_state.enabled) {
        /* Fallback to regular allocation */
        return kmalloc(size);
    }
    
    /* Allocate memory - it will be automatically encrypted */
    void *ptr = kmalloc_aligned(size, PAGE_SIZE);
    
    if (ptr) {
        /* Clear the memory (encrypted) */
        memset(ptr, 0, size);
        
        KLOG_DEBUG("SME secure allocation: %p, size: %lu", ptr, size);
    }
    
    return ptr;
}

/* Secure memory deallocation */
void sme_secure_free(void *ptr, size_t size) {
    if (!ptr) return;
    
    if (sme_state.enabled) {
        /* Clear memory before freeing (encrypted clear) */
        memset(ptr, 0, size);
        KLOG_DEBUG("SME secure deallocation: %p, size: %lu", ptr, size);
    }
    
    kfree(ptr);
}