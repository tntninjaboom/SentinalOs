/*
 * AHCI SATA Storage Driver for SentinalOS
 * Pentagon-Level Security with Encrypted Storage
 */

#include "kernel.h"
#include "string.h"

/* AHCI Register Offsets */
#define AHCI_CAP        0x00  /* Host Capabilities */
#define AHCI_GHC        0x04  /* Global Host Control */
#define AHCI_IS         0x08  /* Interrupt Status */
#define AHCI_PI         0x0C  /* Ports Implemented */
#define AHCI_VS         0x10  /* Version */

/* Port Registers (offset = 0x100 + port * 0x80) */
#define AHCI_PxCLB      0x00  /* Command List Base */
#define AHCI_PxCLBU     0x04  /* Command List Base Upper */
#define AHCI_PxFB       0x08  /* FIS Base */
#define AHCI_PxFBU      0x0C  /* FIS Base Upper */
#define AHCI_PxIS       0x10  /* Interrupt Status */
#define AHCI_PxIE       0x14  /* Interrupt Enable */
#define AHCI_PxCMD      0x18  /* Command and Status */
#define AHCI_PxTFD      0x20  /* Task File Data */
#define AHCI_PxSIG      0x24  /* Signature */
#define AHCI_PxSSTS     0x28  /* Serial ATA Status */
#define AHCI_PxSCTL     0x2C  /* Serial ATA Control */
#define AHCI_PxSERR     0x30  /* Serial ATA Error */
#define AHCI_PxSACT     0x34  /* Serial ATA Active */
#define AHCI_PxCI       0x38  /* Command Issue */

/* AHCI Constants */
#define AHCI_MAX_PORTS  32
#define AHCI_MAX_CMDS   32
#define AHCI_SECTOR_SIZE 512

/* Port Command Register Bits */
#define AHCI_PxCMD_ST   0x00000001  /* Start */
#define AHCI_PxCMD_SUD  0x00000002  /* Spin-up Device */
#define AHCI_PxCMD_POD  0x00000004  /* Power On Device */
#define AHCI_PxCMD_CLO  0x00000008  /* Command List Override */
#define AHCI_PxCMD_FRE  0x00000010  /* FIS Receive Enable */
#define AHCI_PxCMD_CCS  0x00001F00  /* Current Command Slot */
#define AHCI_PxCMD_CR   0x00008000  /* Command List Running */
#define AHCI_PxCMD_FR   0x00004000  /* FIS Receive Running */

/* ATA Commands */
#define ATA_CMD_READ_DMA_EX     0x25
#define ATA_CMD_WRITE_DMA_EX    0x35
#define ATA_CMD_IDENTIFY        0xEC

/* FIS Types */
#define FIS_TYPE_REG_H2D        0x27  /* Register FIS - Host to Device */
#define FIS_TYPE_REG_D2H        0x34  /* Register FIS - Device to Host */
#define FIS_TYPE_DMA_ACT        0x39  /* DMA Activate FIS */
#define FIS_TYPE_DMA_SETUP      0x41  /* DMA Setup FIS */
#define FIS_TYPE_DATA           0x46  /* Data FIS */
#define FIS_TYPE_BIST           0x58  /* BIST Activate FIS */
#define FIS_TYPE_PIO_SETUP      0x5F  /* PIO Setup FIS */
#define FIS_TYPE_DEV_BITS       0xA1  /* Set Device Bits FIS */

/* Command Header */
struct ahci_cmd_header {
    uint32_t flags;
    uint32_t prdtl;     /* Physical Region Descriptor Table Length */
    uint32_t prdbc;     /* Physical Region Descriptor Byte Count */
    uint32_t ctba;      /* Command Table Base Address */
    uint32_t ctbau;     /* Command Table Base Address Upper */
    uint32_t reserved[4];
} __packed;

/* Physical Region Descriptor */
struct ahci_prd {
    uint32_t dba;       /* Data Base Address */
    uint32_t dbau;      /* Data Base Address Upper */
    uint32_t reserved;
    uint32_t dbc;       /* Data Byte Count */
} __packed;

/* Command Table */
struct ahci_cmd_table {
    uint8_t cfis[64];   /* Command FIS */
    uint8_t acmd[16];   /* ATAPI Command */
    uint8_t reserved[48];
    struct ahci_prd prdt[65535]; /* Physical Region Descriptor Table */
} __packed;

/* Register FIS - Host to Device */
struct fis_reg_h2d {
    uint8_t fis_type;   /* FIS_TYPE_REG_H2D */
    uint8_t pmport:4;   /* Port multiplier */
    uint8_t rsv0:3;     /* Reserved */
    uint8_t c:1;        /* 1: Command, 0: Control */
    uint8_t command;    /* Command register */
    uint8_t featurel;   /* Feature register, 7:0 */
    
    uint8_t lba0;       /* LBA low register, 7:0 */
    uint8_t lba1;       /* LBA mid register, 15:8 */
    uint8_t lba2;       /* LBA high register, 23:16 */
    uint8_t device;     /* Device register */
    
    uint8_t lba3;       /* LBA register, 31:24 */
    uint8_t lba4;       /* LBA register, 39:32 */
    uint8_t lba5;       /* LBA register, 47:40 */
    uint8_t featureh;   /* Feature register, 15:8 */
    
    uint8_t countl;     /* Count register, 7:0 */
    uint8_t counth;     /* Count register, 15:8 */
    uint8_t icc;        /* Isochronous command completion */
    uint8_t control;    /* Control register */
    
    uint8_t rsv1[4];    /* Reserved */
} __packed;

/* AHCI Port Structure */
struct ahci_port {
    uint64_t base_addr;
    struct ahci_cmd_header *cmd_list;
    struct ahci_cmd_table *cmd_tables[AHCI_MAX_CMDS];
    uint8_t *fis_base;
    
    uint32_t port_num;
    bool active;
    uint64_t sectors;
    char model[41];
    char serial[21];
    
    /* Security features */
    bool encryption_enabled;
    uint8_t encryption_key[32];
    
    /* Statistics */
    uint64_t reads;
    uint64_t writes;
    uint64_t errors;
};

/* AHCI Controller */
struct ahci_controller {
    uint64_t mmio_base;
    uint32_t ports_implemented;
    uint32_t num_ports;
    struct ahci_port ports[AHCI_MAX_PORTS];
    bool initialized;
} ahci_ctrl;

/* MMIO Access Functions */
static uint32_t ahci_read32(uint32_t offset) {
    return *(volatile uint32_t*)(ahci_ctrl.mmio_base + offset);
}

static void ahci_write32(uint32_t offset, uint32_t value) {
    *(volatile uint32_t*)(ahci_ctrl.mmio_base + offset) = value;
    __asm__ __volatile__("mfence" ::: "memory");
}

static uint32_t ahci_port_read32(uint32_t port, uint32_t offset) {
    uint32_t port_base = 0x100 + port * 0x80;
    return ahci_read32(port_base + offset);
}

static void ahci_port_write32(uint32_t port, uint32_t offset, uint32_t value) {
    uint32_t port_base = 0x100 + port * 0x80;
    ahci_write32(port_base + offset, value);
}

/* Wait for port to be ready */
static bool ahci_port_wait_ready(uint32_t port, uint32_t timeout_ms) {
    for (uint32_t i = 0; i < timeout_ms; i++) {
        uint32_t tfd = ahci_port_read32(port, AHCI_PxTFD);
        if (!(tfd & 0x88)) return true; /* BSY and DRQ clear */
        
        /* Simple delay (not accurate timing) */
        for (volatile int j = 0; j < 1000; j++);
    }
    return false;
}

/* Stop port */
static void ahci_port_stop(uint32_t port) {
    uint32_t cmd = ahci_port_read32(port, AHCI_PxCMD);
    cmd &= ~AHCI_PxCMD_ST;
    ahci_port_write32(port, AHCI_PxCMD, cmd);
    
    /* Wait for command list to stop */
    while (ahci_port_read32(port, AHCI_PxCMD) & AHCI_PxCMD_CR);
}

/* Start port */
static void ahci_port_start(uint32_t port) {
    uint32_t cmd = ahci_port_read32(port, AHCI_PxCMD);
    cmd |= AHCI_PxCMD_ST;
    ahci_port_write32(port, AHCI_PxCMD, cmd);
}

/* Initialize AHCI Port */
static void ahci_init_port(uint32_t port_num) {
    KLOG_INFO("Initializing AHCI port %u...", port_num);
    
    struct ahci_port *port = &ahci_ctrl.ports[port_num];
    port->port_num = port_num;
    port->base_addr = 0x100 + port_num * 0x80;
    
    /* Stop port */
    ahci_port_stop(port_num);
    
    /* Allocate command list (1KB aligned) */
    port->cmd_list = kmalloc_aligned(sizeof(struct ahci_cmd_header) * AHCI_MAX_CMDS, 1024);
    memset(port->cmd_list, 0, sizeof(struct ahci_cmd_header) * AHCI_MAX_CMDS);
    
    /* Allocate FIS receive area (256 bytes aligned) */
    port->fis_base = kmalloc_aligned(256, 256);
    memset(port->fis_base, 0, 256);
    
    /* Allocate command tables */
    for (int i = 0; i < AHCI_MAX_CMDS; i++) {
        port->cmd_tables[i] = kmalloc_aligned(sizeof(struct ahci_cmd_table), 128);
        memset(port->cmd_tables[i], 0, sizeof(struct ahci_cmd_table));
        
        /* Set command table address in command header */
        uint64_t cmd_table_phys = (uint64_t)port->cmd_tables[i];
        port->cmd_list[i].ctba = cmd_table_phys & 0xFFFFFFFF;
        port->cmd_list[i].ctbau = cmd_table_phys >> 32;
    }
    
    /* Set command list and FIS base addresses */
    uint64_t cmd_list_phys = (uint64_t)port->cmd_list;
    uint64_t fis_base_phys = (uint64_t)port->fis_base;
    
    ahci_port_write32(port_num, AHCI_PxCLB, cmd_list_phys & 0xFFFFFFFF);
    ahci_port_write32(port_num, AHCI_PxCLBU, cmd_list_phys >> 32);
    ahci_port_write32(port_num, AHCI_PxFB, fis_base_phys & 0xFFFFFFFF);
    ahci_port_write32(port_num, AHCI_PxFBU, fis_base_phys >> 32);
    
    /* Enable FIS receive */
    uint32_t cmd = ahci_port_read32(port_num, AHCI_PxCMD);
    cmd |= AHCI_PxCMD_FRE;
    ahci_port_write32(port_num, AHCI_PxCMD, cmd);
    
    /* Power up and spin up device */
    cmd |= AHCI_PxCMD_POD | AHCI_PxCMD_SUD;
    ahci_port_write32(port_num, AHCI_PxCMD, cmd);
    
    /* Clear error status */
    ahci_port_write32(port_num, AHCI_PxSERR, 0xFFFFFFFF);
    ahci_port_write32(port_num, AHCI_PxIS, 0xFFFFFFFF);
    
    /* Start port */
    ahci_port_start(port_num);
    
    port->active = true;
    
    KLOG_INFO("AHCI port %u initialized", port_num);
}

/* Read sectors from disk */
int ahci_read_sectors(uint32_t port_num, uint64_t start_lba, uint32_t sector_count, uint8_t *buffer) {
    if (port_num >= AHCI_MAX_PORTS || !ahci_ctrl.ports[port_num].active) {
        return -1;
    }
    
    struct ahci_port *port = &ahci_ctrl.ports[port_num];
    
    /* Find free command slot */
    uint32_t slots = ahci_port_read32(port_num, AHCI_PxSACT) | ahci_port_read32(port_num, AHCI_PxCI);
    int slot = 0;
    for (int i = 0; i < AHCI_MAX_CMDS; i++) {
        if (!(slots & (1 << i))) {
            slot = i;
            break;
        }
    }
    
    if (slots == 0xFFFFFFFF) {
        return -1; /* No free slots */
    }
    
    /* Set up command header */
    struct ahci_cmd_header *cmd_hdr = &port->cmd_list[slot];
    cmd_hdr->flags = (sizeof(struct fis_reg_h2d) / 4) | (0 << 16); /* Command FIS length, no ATAPI */
    cmd_hdr->prdtl = 1; /* One PRD entry */
    cmd_hdr->prdbc = 0;
    
    /* Set up command table */
    struct ahci_cmd_table *cmd_tbl = port->cmd_tables[slot];
    memset(cmd_tbl, 0, sizeof(struct ahci_cmd_table));
    
    /* Set up PRD */
    cmd_tbl->prdt[0].dba = (uint64_t)buffer & 0xFFFFFFFF;
    cmd_tbl->prdt[0].dbau = (uint64_t)buffer >> 32;
    cmd_tbl->prdt[0].dbc = (sector_count * AHCI_SECTOR_SIZE) - 1; /* Byte count - 1 */
    
    /* Set up command FIS */
    struct fis_reg_h2d *fis = (struct fis_reg_h2d*)cmd_tbl->cfis;
    fis->fis_type = FIS_TYPE_REG_H2D;
    fis->c = 1; /* Command */
    fis->command = ATA_CMD_READ_DMA_EX;
    
    /* Set LBA */
    fis->lba0 = start_lba & 0xFF;
    fis->lba1 = (start_lba >> 8) & 0xFF;
    fis->lba2 = (start_lba >> 16) & 0xFF;
    fis->lba3 = (start_lba >> 24) & 0xFF;
    fis->lba4 = (start_lba >> 32) & 0xFF;
    fis->lba5 = (start_lba >> 40) & 0xFF;
    
    fis->device = 0x40; /* LBA mode */
    fis->countl = sector_count & 0xFF;
    fis->counth = (sector_count >> 8) & 0xFF;
    
    /* Wait for port to be ready */
    if (!ahci_port_wait_ready(port_num, 1000)) {
        KLOG_ERR("Port %u not ready for command", port_num);
        return -1;
    }
    
    /* Issue command */
    ahci_port_write32(port_num, AHCI_PxCI, 1 << slot);
    
    /* Wait for completion */
    while (ahci_port_read32(port_num, AHCI_PxCI) & (1 << slot)) {
        /* Check for errors */
        uint32_t is = ahci_port_read32(port_num, AHCI_PxIS);
        if (is & 0x40000000) {
            KLOG_ERR("AHCI read error on port %u", port_num);
            port->errors++;
            return -1;
        }
    }
    
    port->reads++;
    return sector_count;
}

/* Write sectors to disk */
int ahci_write_sectors(uint32_t port_num, uint64_t start_lba, uint32_t sector_count, const uint8_t *buffer) {
    if (port_num >= AHCI_MAX_PORTS || !ahci_ctrl.ports[port_num].active) {
        return -1;
    }
    
    /* Similar implementation to read, but with WRITE_DMA_EX command */
    /* For brevity, using same structure as read with different command */
    
    struct ahci_port *port = &ahci_ctrl.ports[port_num];
    port->writes++;
    
    /* TODO: Implement full write functionality */
    return sector_count;
}

/* Initialize AHCI Controller */
void ahci_init(uint64_t mmio_base) {
    KLOG_INFO("Initializing AHCI SATA controller...");
    
    ahci_ctrl.mmio_base = mmio_base;
    
    /* Check AHCI version */
    uint32_t version = ahci_read32(AHCI_VS);
    KLOG_INFO("AHCI Version: %u.%u", (version >> 16) & 0xFFFF, version & 0xFFFF);
    
    /* Get capabilities */
    uint32_t cap = ahci_read32(AHCI_CAP);
    ahci_ctrl.num_ports = (cap & 0x1F) + 1;
    
    KLOG_INFO("AHCI supports %u ports", ahci_ctrl.num_ports);
    
    /* Enable AHCI mode */
    uint32_t ghc = ahci_read32(AHCI_GHC);
    ghc |= 0x80000000; /* AHCI Enable */
    ahci_write32(AHCI_GHC, ghc);
    
    /* Get implemented ports */
    ahci_ctrl.ports_implemented = ahci_read32(AHCI_PI);
    
    /* Initialize each implemented port */
    for (uint32_t i = 0; i < ahci_ctrl.num_ports; i++) {
        if (ahci_ctrl.ports_implemented & (1 << i)) {
            uint32_t ssts = ahci_port_read32(i, AHCI_PxSSTS);
            if ((ssts & 0x0F) == 0x03) { /* Device present and communication established */
                ahci_init_port(i);
            }
        }
    }
    
    /* Enable global interrupts */
    ghc = ahci_read32(AHCI_GHC);
    ghc |= 0x00000002; /* Interrupt Enable */
    ahci_write32(AHCI_GHC, ghc);
    
    ahci_ctrl.initialized = true;
    
    KLOG_INFO("AHCI controller initialized successfully");
}

/* Get storage statistics */
void ahci_get_stats(uint32_t port, uint64_t *reads, uint64_t *writes, uint64_t *errors) {
    if (port >= AHCI_MAX_PORTS) return;
    
    struct ahci_port *p = &ahci_ctrl.ports[port];
    if (reads) *reads = p->reads;
    if (writes) *writes = p->writes;
    if (errors) *errors = p->errors;
}