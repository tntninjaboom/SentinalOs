/*
 * SentinalOS Driver Initialization
 * Pentagon-Level Security Hardware Abstraction
 */

#include "kernel.h"
#include "string.h"

/* Driver function prototypes */
void keyboard_init(void);
void e1000_init(uint64_t mmio_base);
void ahci_init(uint64_t mmio_base);

/* PCI Configuration Space Access */
#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

/* PCI Device IDs */
#define PCI_VENDOR_INTEL   0x8086
#define PCI_DEVICE_E1000   0x100E
#define PCI_DEVICE_AHCI    0x2922

static uint32_t pci_read32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    uint32_t address = 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC);
    
    __asm__ __volatile__("outl %0, %1" : : "a"(address), "Nd"(PCI_CONFIG_ADDRESS));
    
    uint32_t data;
    __asm__ __volatile__("inl %1, %0" : "=a"(data) : "Nd"(PCI_CONFIG_DATA));
    
    return data;
}

static void pci_write32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value) {
    uint32_t address = 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC);
    
    __asm__ __volatile__("outl %0, %1" : : "a"(address), "Nd"(PCI_CONFIG_ADDRESS));
    __asm__ __volatile__("outl %0, %1" : : "a"(value), "Nd"(PCI_CONFIG_DATA));
}

static void scan_pci_devices(void) {
    KLOG_INFO("Scanning PCI devices...");
    
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            for (uint8_t function = 0; function < 8; function++) {
                uint32_t vendor_device = pci_read32(bus, device, function, 0);
                
                if ((vendor_device & 0xFFFF) == 0xFFFF) {
                    continue; /* No device */
                }
                
                uint16_t vendor_id = vendor_device & 0xFFFF;
                uint16_t device_id = (vendor_device >> 16) & 0xFFFF;
                
                uint32_t class_subclass = pci_read32(bus, device, function, 8);
                uint8_t class_code = (class_subclass >> 24) & 0xFF;
                uint8_t subclass = (class_subclass >> 16) & 0xFF;
                
                KLOG_INFO("PCI %02x:%02x.%x - Vendor: 0x%04x, Device: 0x%04x, Class: 0x%02x%02x",
                         bus, device, function, vendor_id, device_id, class_code, subclass);
                
                /* Initialize specific devices */
                if (vendor_id == PCI_VENDOR_INTEL) {
                    if (device_id == PCI_DEVICE_E1000) {
                        KLOG_INFO("Found Intel E1000 network adapter");
                        
                        /* Get BAR0 (MMIO base) */
                        uint32_t bar0 = pci_read32(bus, device, function, 0x10);
                        if (bar0 & 0x01) {
                            KLOG_WARN("E1000 BAR0 is I/O, expected MMIO");
                            continue;
                        }
                        
                        uint64_t mmio_base = bar0 & 0xFFFFFFF0;
                        
                        /* Enable bus mastering and memory space */
                        uint32_t command = pci_read32(bus, device, function, 0x04);
                        command |= 0x06; /* Memory Space Enable | Bus Master Enable */
                        pci_write32(bus, device, function, 0x04, command);
                        
                        e1000_init(mmio_base);
                    }
                    else if (device_id == PCI_DEVICE_AHCI) {
                        KLOG_INFO("Found Intel AHCI SATA controller");
                        
                        /* Get BAR5 (AHCI MMIO base) */
                        uint32_t bar5 = pci_read32(bus, device, function, 0x24);
                        if (bar5 & 0x01) {
                            KLOG_WARN("AHCI BAR5 is I/O, expected MMIO");
                            continue;
                        }
                        
                        uint64_t mmio_base = bar5 & 0xFFFFFFF0;
                        
                        /* Enable bus mastering and memory space */
                        uint32_t command = pci_read32(bus, device, function, 0x04);
                        command |= 0x06; /* Memory Space Enable | Bus Master Enable */
                        pci_write32(bus, device, function, 0x04, command);
                        
                        ahci_init(mmio_base);
                    }
                }
            }
        }
    }
}

void drivers_init(void) {
    KLOG_INFO("Initializing Pentagon-level device drivers...");
    
    /* Initialize PS/2 keyboard first (no PCI scan needed) */
    keyboard_init();
    
    /* Scan PCI bus and initialize PCI devices */
    scan_pci_devices();
    
    KLOG_INFO("Driver initialization complete");
}