/*
 * Intel E1000 Network Driver for SentinalOS
 * Pentagon-Level Security with Hardware Isolation
 */

#include "kernel.h"
#include "string.h"

/* E1000 Register Offsets */
#define E1000_CTRL     0x00000  /* Device Control */
#define E1000_STATUS   0x00008  /* Device Status */
#define E1000_EECD     0x00010  /* EEPROM Control */
#define E1000_EERD     0x00014  /* EEPROM Read */
#define E1000_ICR      0x000C0  /* Interrupt Cause Read */
#define E1000_IMS      0x000D0  /* Interrupt Mask Set */
#define E1000_IMC      0x000D8  /* Interrupt Mask Clear */
#define E1000_RCTL     0x00100  /* Receive Control */
#define E1000_TCTL     0x00400  /* Transmit Control */
#define E1000_RDBAL    0x02800  /* RX Descriptor Base Low */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base High */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length */
#define E1000_RDH      0x02810  /* RX Descriptor Head */
#define E1000_RDT      0x02818  /* RX Descriptor Tail */
#define E1000_TDBAL    0x03800  /* TX Descriptor Base Low */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base High */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length */
#define E1000_TDH      0x03810  /* TX Descriptor Head */
#define E1000_TDT      0x03818  /* TX Descriptor Tail */

/* Control Register Bits */
#define E1000_CTRL_RST      0x04000000  /* Global Reset */
#define E1000_CTRL_SLU      0x00000040  /* Set Link Up */
#define E1000_CTRL_ASDE     0x00000020  /* Auto Speed Detection */

/* Receive Control Register Bits */
#define E1000_RCTL_EN       0x00000002  /* Receive Enable */
#define E1000_RCTL_SBP      0x00000004  /* Store Bad Packets */
#define E1000_RCTL_UPE      0x00000008  /* Unicast Promiscuous */
#define E1000_RCTL_MPE      0x00000010  /* Multicast Promiscuous */
#define E1000_RCTL_LPE      0x00000020  /* Long Packet Enable */
#define E1000_RCTL_BAM      0x00008000  /* Broadcast Accept Mode */
#define E1000_RCTL_SZ_2048  0x00000000  /* Buffer Size 2048 */
#define E1000_RCTL_SECRC    0x04000000  /* Strip CRC */

/* Transmit Control Register Bits */
#define E1000_TCTL_EN       0x00000002  /* Transmit Enable */
#define E1000_TCTL_PSP      0x00000008  /* Pad Short Packets */
#define E1000_TCTL_CT       0x00000ff0  /* Collision Threshold */
#define E1000_TCTL_COLD     0x003ff000  /* Collision Distance */

/* Descriptor Definitions */
#define E1000_NUM_RX_DESC   32
#define E1000_NUM_TX_DESC   32
#define E1000_RX_BUFFER_SIZE 2048

/* RX Descriptor */
struct e1000_rx_desc {
    uint64_t buffer_addr;
    uint16_t length;
    uint16_t checksum;
    uint8_t status;
    uint8_t errors;
    uint16_t special;
} __packed;

/* TX Descriptor */
struct e1000_tx_desc {
    uint64_t buffer_addr;
    uint16_t length;
    uint8_t cso;
    uint8_t cmd;
    uint8_t status;
    uint8_t css;
    uint16_t special;
} __packed;

/* E1000 Device Structure */
struct e1000_device {
    uint64_t mmio_base;
    uint8_t mac_addr[6];
    
    /* RX Ring */
    struct e1000_rx_desc *rx_descs;
    uint8_t **rx_buffers;
    uint32_t rx_head;
    uint32_t rx_tail;
    
    /* TX Ring */
    struct e1000_tx_desc *tx_descs;
    uint8_t **tx_buffers;
    uint32_t tx_head;
    uint32_t tx_tail;
    
    /* Statistics */
    uint64_t packets_received;
    uint64_t packets_transmitted;
    uint64_t bytes_received;
    uint64_t bytes_transmitted;
    uint64_t rx_errors;
    uint64_t tx_errors;
    
    bool initialized;
} e1000_dev;

/* MMIO Register Access */
static uint32_t e1000_read32(uint32_t reg) {
    return *(volatile uint32_t*)(e1000_dev.mmio_base + reg);
}

static void e1000_write32(uint32_t reg, uint32_t value) {
    *(volatile uint32_t*)(e1000_dev.mmio_base + reg) = value;
    __asm__ __volatile__("mfence" ::: "memory"); /* Memory barrier */
}

/* Read EEPROM */
static uint16_t e1000_read_eeprom(uint8_t addr) {
    uint32_t data = 0;
    
    e1000_write32(E1000_EERD, (addr << 8) | 1);
    
    /* Wait for read completion */
    while (!((data = e1000_read32(E1000_EERD)) & 0x10)) {
        /* Busy wait with security timeout */
        static int timeout = 1000;
        if (--timeout <= 0) {
            KLOG_ERR("EEPROM read timeout");
            return 0;
        }
    }
    
    return (data >> 16) & 0xFFFF;
}

/* Initialize RX Ring */
static void e1000_init_rx(void) {
    KLOG_INFO("Initializing E1000 RX ring...");
    
    /* Allocate RX descriptors */
    e1000_dev.rx_descs = kmalloc_aligned(sizeof(struct e1000_rx_desc) * E1000_NUM_RX_DESC, 16);
    e1000_dev.rx_buffers = kmalloc(sizeof(uint8_t*) * E1000_NUM_RX_DESC);
    
    /* Initialize RX descriptors and buffers */
    for (int i = 0; i < E1000_NUM_RX_DESC; i++) {
        e1000_dev.rx_buffers[i] = kmalloc_aligned(E1000_RX_BUFFER_SIZE, 16);
        e1000_dev.rx_descs[i].buffer_addr = (uint64_t)e1000_dev.rx_buffers[i];
        e1000_dev.rx_descs[i].status = 0;
    }
    
    /* Set RX ring registers */
    uint64_t rx_phys = (uint64_t)e1000_dev.rx_descs;
    e1000_write32(E1000_RDBAL, rx_phys & 0xFFFFFFFF);
    e1000_write32(E1000_RDBAH, rx_phys >> 32);
    e1000_write32(E1000_RDLEN, E1000_NUM_RX_DESC * sizeof(struct e1000_rx_desc));
    e1000_write32(E1000_RDH, 0);
    e1000_write32(E1000_RDT, E1000_NUM_RX_DESC - 1);
    
    e1000_dev.rx_head = 0;
    e1000_dev.rx_tail = 0;
    
    KLOG_INFO("E1000 RX ring initialized");
}

/* Initialize TX Ring */
static void e1000_init_tx(void) {
    KLOG_INFO("Initializing E1000 TX ring...");
    
    /* Allocate TX descriptors */
    e1000_dev.tx_descs = kmalloc_aligned(sizeof(struct e1000_tx_desc) * E1000_NUM_TX_DESC, 16);
    e1000_dev.tx_buffers = kmalloc(sizeof(uint8_t*) * E1000_NUM_TX_DESC);
    
    /* Initialize TX descriptors and buffers */
    for (int i = 0; i < E1000_NUM_TX_DESC; i++) {
        e1000_dev.tx_buffers[i] = kmalloc_aligned(E1000_RX_BUFFER_SIZE, 16);
        e1000_dev.tx_descs[i].buffer_addr = (uint64_t)e1000_dev.tx_buffers[i];
        e1000_dev.tx_descs[i].status = 1; /* Descriptor done */
    }
    
    /* Set TX ring registers */
    uint64_t tx_phys = (uint64_t)e1000_dev.tx_descs;
    e1000_write32(E1000_TDBAL, tx_phys & 0xFFFFFFFF);
    e1000_write32(E1000_TDBAH, tx_phys >> 32);
    e1000_write32(E1000_TDLEN, E1000_NUM_TX_DESC * sizeof(struct e1000_tx_desc));
    e1000_write32(E1000_TDH, 0);
    e1000_write32(E1000_TDT, 0);
    
    e1000_dev.tx_head = 0;
    e1000_dev.tx_tail = 0;
    
    KLOG_INFO("E1000 TX ring initialized");
}

/* Read MAC Address */
static void e1000_read_mac_addr(void) {
    uint16_t mac_low = e1000_read_eeprom(0);
    uint16_t mac_mid = e1000_read_eeprom(1);
    uint16_t mac_high = e1000_read_eeprom(2);
    
    e1000_dev.mac_addr[0] = mac_low & 0xFF;
    e1000_dev.mac_addr[1] = (mac_low >> 8) & 0xFF;
    e1000_dev.mac_addr[2] = mac_mid & 0xFF;
    e1000_dev.mac_addr[3] = (mac_mid >> 8) & 0xFF;
    e1000_dev.mac_addr[4] = mac_high & 0xFF;
    e1000_dev.mac_addr[5] = (mac_high >> 8) & 0xFF;
    
    KLOG_INFO("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
              e1000_dev.mac_addr[0], e1000_dev.mac_addr[1], e1000_dev.mac_addr[2],
              e1000_dev.mac_addr[3], e1000_dev.mac_addr[4], e1000_dev.mac_addr[5]);
}

/* Initialize E1000 Device */
void e1000_init(uint64_t mmio_base) {
    KLOG_INFO("Initializing Intel E1000 network controller...");
    
    e1000_dev.mmio_base = mmio_base;
    
    /* Reset the device */
    e1000_write32(E1000_CTRL, E1000_CTRL_RST);
    
    /* Wait for reset completion */
    for (int i = 0; i < 1000; i++) {
        if (!(e1000_read32(E1000_CTRL) & E1000_CTRL_RST)) break;
    }
    
    /* Read MAC address */
    e1000_read_mac_addr();
    
    /* Initialize descriptor rings */
    e1000_init_rx();
    e1000_init_tx();
    
    /* Configure receive control */
    uint32_t rctl = E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SZ_2048 | E1000_RCTL_SECRC;
    e1000_write32(E1000_RCTL, rctl);
    
    /* Configure transmit control */
    uint32_t tctl = E1000_TCTL_EN | E1000_TCTL_PSP | (15 << 4) | (64 << 12);
    e1000_write32(E1000_TCTL, tctl);
    
    /* Set link up */
    uint32_t ctrl = e1000_read32(E1000_CTRL);
    e1000_write32(E1000_CTRL, ctrl | E1000_CTRL_SLU | E1000_CTRL_ASDE);
    
    /* Enable interrupts */
    e1000_write32(E1000_IMS, 0x1F6DC);
    
    e1000_dev.initialized = true;
    
    KLOG_INFO("Intel E1000 initialized successfully");
}

/* Transmit packet */
int e1000_transmit(const uint8_t *data, uint16_t length) {
    if (!e1000_dev.initialized || length > E1000_RX_BUFFER_SIZE) {
        return -1;
    }
    
    uint32_t tail = e1000_dev.tx_tail;
    
    /* Check if descriptor is available */
    if (!(e1000_dev.tx_descs[tail].status & 1)) {
        return -1; /* TX ring full */
    }
    
    /* Copy data to buffer */
    memcpy(e1000_dev.tx_buffers[tail], data, length);
    
    /* Set up descriptor */
    e1000_dev.tx_descs[tail].length = length;
    e1000_dev.tx_descs[tail].cmd = 0x0B; /* EOP | IFCS | RS */
    e1000_dev.tx_descs[tail].status = 0;
    
    /* Update tail */
    e1000_dev.tx_tail = (tail + 1) % E1000_NUM_TX_DESC;
    e1000_write32(E1000_TDT, e1000_dev.tx_tail);
    
    /* Update statistics */
    e1000_dev.packets_transmitted++;
    e1000_dev.bytes_transmitted += length;
    
    return 0;
}

/* Receive packet */
int e1000_receive(uint8_t *buffer, uint16_t max_length) {
    if (!e1000_dev.initialized) {
        return -1;
    }
    
    uint32_t head = e1000_dev.rx_head;
    
    /* Check if packet is available */
    if (!(e1000_dev.rx_descs[head].status & 1)) {
        return 0; /* No packet available */
    }
    
    uint16_t length = e1000_dev.rx_descs[head].length;
    if (length > max_length) {
        length = max_length;
    }
    
    /* Copy packet data */
    memcpy(buffer, e1000_dev.rx_buffers[head], length);
    
    /* Reset descriptor */
    e1000_dev.rx_descs[head].status = 0;
    
    /* Update head */
    e1000_dev.rx_head = (head + 1) % E1000_NUM_RX_DESC;
    
    /* Update tail */
    uint32_t tail = (e1000_dev.rx_tail + 1) % E1000_NUM_RX_DESC;
    e1000_write32(E1000_RDT, tail);
    e1000_dev.rx_tail = tail;
    
    /* Update statistics */
    e1000_dev.packets_received++;
    e1000_dev.bytes_received += length;
    
    return length;
}

/* Get network statistics */
void e1000_get_stats(uint64_t *rx_packets, uint64_t *tx_packets, uint64_t *rx_bytes, uint64_t *tx_bytes) {
    if (rx_packets) *rx_packets = e1000_dev.packets_received;
    if (tx_packets) *tx_packets = e1000_dev.packets_transmitted;
    if (rx_bytes) *rx_bytes = e1000_dev.bytes_received;
    if (tx_bytes) *tx_bytes = e1000_dev.bytes_transmitted;
}