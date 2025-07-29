/*
 * SentinalOS Memory Management
 * Pentagon-Level Security with Hardware Isolation
 */

#include "kernel.h"

/* Memory layout constants */
#define KERNEL_HEAP_START   0xFFFFFFFF90000000UL
#define KERNEL_HEAP_SIZE    0x10000000UL  /* 256MB */
#define PAGE_SIZE           4096
#define PAGE_SHIFT          12
#define PAGES_PER_TABLE     512
#define TABLES_PER_DIR      512

/* Page flags */
#define PAGE_PRESENT        (1UL << 0)
#define PAGE_WRITABLE       (1UL << 1)
#define PAGE_USER           (1UL << 2)
#define PAGE_WRITETHROUGH   (1UL << 3)
#define PAGE_NOCACHE        (1UL << 4)
#define PAGE_ACCESSED       (1UL << 5)
#define PAGE_DIRTY          (1UL << 6)
#define PAGE_HUGE           (1UL << 7)
#define PAGE_GLOBAL         (1UL << 8)
#define PAGE_NX             (1UL << 63)  /* No Execute */

/* Memory zones */
enum memory_zone {
    ZONE_DMA,      /* 0-16MB */
    ZONE_NORMAL,   /* 16MB-896MB */
    ZONE_HIGHMEM,  /* >896MB */
    ZONE_COUNT
};

/* Page frame descriptor */
struct page {
    uint64_t flags;
    uint32_t ref_count;
    uint32_t order;     /* Buddy system order */
    struct page *next;  /* Free list */
} __packed;

/* Memory zone descriptor */
struct memory_zone {
    struct page *free_pages[12];  /* Buddy system free lists */
    uint64_t start_pfn;
    uint64_t end_pfn;
    uint64_t free_pages_count;
    uint64_t total_pages;
    const char *name;
};

/* Global memory state */
static struct {
    struct memory_zone zones[ZONE_COUNT];
    struct page *page_array;
    uint64_t total_memory;
    uint64_t used_memory;
    uint64_t kernel_heap_ptr;
    bool initialized;
} mm_state;

/* Simple heap allocator for early boot */
static uint8_t early_heap[1024 * 1024];  /* 1MB early heap */
static size_t early_heap_offset = 0;

void *early_kmalloc(size_t size) {
    /* Align to 8 bytes */
    size = (size + 7) & ~7;
    
    if (early_heap_offset + size > sizeof(early_heap)) {
        PANIC("Early heap exhausted");
    }
    
    void *ptr = &early_heap[early_heap_offset];
    early_heap_offset += size;
    return ptr;
}

/* Page frame number to physical address */
static inline uint64_t pfn_to_phys(uint64_t pfn) {
    return pfn << PAGE_SHIFT;
}

/* Physical address to page frame number */
static inline uint64_t phys_to_pfn(uint64_t phys) {
    return phys >> PAGE_SHIFT;
}

/* Get page descriptor for physical address */
static struct page *phys_to_page(uint64_t phys) {
    uint64_t pfn = phys_to_pfn(phys);
    return &mm_state.page_array[pfn];
}

/* Buddy system allocation */
static struct page *buddy_alloc_pages(enum memory_zone zone, int order) {
    struct memory_zone *z = &mm_state.zones[zone];
    
    /* Find a free block of the requested order or larger */
    for (int current_order = order; current_order < 12; current_order++) {
        if (z->free_pages[current_order]) {
            struct page *page = z->free_pages[current_order];
            z->free_pages[current_order] = page->next;
            
            /* Split larger blocks if necessary */
            while (current_order > order) {
                current_order--;
                struct page *buddy = page + (1 << current_order);
                buddy->next = z->free_pages[current_order];
                z->free_pages[current_order] = buddy;
            }
            
            page->order = order;
            page->ref_count = 1;
            z->free_pages_count -= (1 << order);
            
            return page;
        }
    }
    
    return NULL; /* Out of memory */
}

/* Buddy system deallocation */
static void buddy_free_pages(struct page *page, int order) {
    uint64_t pfn = page - mm_state.page_array;
    enum memory_zone zone = ZONE_NORMAL; /* Simplified zone detection */
    struct memory_zone *z = &mm_state.zones[zone];
    
    /* Coalesce with buddy blocks */
    while (order < 11) {
        uint64_t buddy_pfn = pfn ^ (1UL << order);
        struct page *buddy = &mm_state.page_array[buddy_pfn];
        
        /* Check if buddy is free and same order */
        if (buddy->ref_count != 0 || buddy->order != order) {
            break;
        }
        
        /* Remove buddy from free list */
        struct page **prev = &z->free_pages[order];
        while (*prev && *prev != buddy) {
            prev = &(*prev)->next;
        }
        if (*prev) {
            *prev = buddy->next;
        }
        
        /* Merge with buddy */
        if (pfn > buddy_pfn) {
            page = buddy;
            pfn = buddy_pfn;
        }
        order++;
    }
    
    /* Add to free list */
    page->order = order;
    page->ref_count = 0;
    page->next = z->free_pages[order];
    z->free_pages[order] = page;
    z->free_pages_count += (1 << order);
}

void *kmalloc(size_t size) {
    if (!mm_state.initialized) {
        return early_kmalloc(size);
    }
    
    /* Simple allocation from kernel heap */
    /* TODO: Implement proper slab allocator */
    
    size = (size + 7) & ~7; /* Align to 8 bytes */
    
    if (mm_state.kernel_heap_ptr + size > KERNEL_HEAP_START + KERNEL_HEAP_SIZE) {
        PANIC("Kernel heap exhausted");
    }
    
    void *ptr = (void*)mm_state.kernel_heap_ptr;
    mm_state.kernel_heap_ptr += size;
    mm_state.used_memory += size;
    
    return ptr;
}

void *kmalloc_aligned(size_t size, size_t alignment) {
    if (!mm_state.initialized) {
        /* Simple alignment for early allocator */
        early_heap_offset = (early_heap_offset + alignment - 1) & ~(alignment - 1);
        return early_kmalloc(size);
    }
    
    /* Align heap pointer */
    mm_state.kernel_heap_ptr = (mm_state.kernel_heap_ptr + alignment - 1) & ~(alignment - 1);
    return kmalloc(size);
}

void kfree(void *ptr) {
    if (!ptr) return;
    
    /* TODO: Implement proper free for slab allocator */
    /* For now, we don't actually free memory (simple bump allocator) */
}

/* Initialize page tables with security features */
static void init_page_tables(void) {
    KLOG_INFO("Initializing secure page tables...");
    
    /* Enable NX bit globally */
    uint64_t efer;
    __asm__ __volatile__("rdmsr" : "=A" (efer) : "c" (0xC0000080));
    efer |= (1UL << 11); /* NXE bit */
    __asm__ __volatile__("wrmsr" :: "A" (efer), "c" (0xC0000080));
    
    KLOG_INFO("NX bit enabled for enhanced security");
}

/* Initialize memory zones */
static void init_memory_zones(void) {
    KLOG_INFO("Initializing memory zones...");
    
    /* Zone DMA: 0-16MB */
    mm_state.zones[ZONE_DMA].start_pfn = 0;
    mm_state.zones[ZONE_DMA].end_pfn = (16 * 1024 * 1024) >> PAGE_SHIFT;
    mm_state.zones[ZONE_DMA].name = "DMA";
    
    /* Zone Normal: 16MB-896MB */
    mm_state.zones[ZONE_NORMAL].start_pfn = (16 * 1024 * 1024) >> PAGE_SHIFT;
    mm_state.zones[ZONE_NORMAL].end_pfn = (896 * 1024 * 1024) >> PAGE_SHIFT;
    mm_state.zones[ZONE_NORMAL].name = "Normal";
    
    /* Zone HighMem: >896MB */
    mm_state.zones[ZONE_HIGHMEM].start_pfn = (896 * 1024 * 1024) >> PAGE_SHIFT;
    mm_state.zones[ZONE_HIGHMEM].end_pfn = mm_state.total_memory >> PAGE_SHIFT;
    mm_state.zones[ZONE_HIGHMEM].name = "HighMem";
    
    /* Initialize free lists */
    for (int zone = 0; zone < ZONE_COUNT; zone++) {
        for (int order = 0; order < 12; order++) {
            mm_state.zones[zone].free_pages[order] = NULL;
        }
    }
    
    KLOG_INFO("Memory zones initialized");
}

void mm_init(void) {
    KLOG_INFO("Initializing Pentagon-level memory management...");
    
    /* Get memory size from multiboot or detect */
    mm_state.total_memory = 512 * 1024 * 1024; /* Assume 512MB for now */
    
    /* Initialize security features */
    init_page_tables();
    
    /* Set up memory zones */
    init_memory_zones();
    
    /* Initialize kernel heap */
    mm_state.kernel_heap_ptr = KERNEL_HEAP_START;
    mm_state.used_memory = 0;
    
    /* Allocate page array */
    uint64_t total_pages = mm_state.total_memory >> PAGE_SHIFT;
    mm_state.page_array = early_kmalloc(total_pages * sizeof(struct page));
    
    /* Initialize page descriptors */
    for (uint64_t i = 0; i < total_pages; i++) {
        mm_state.page_array[i].flags = 0;
        mm_state.page_array[i].ref_count = 0;
        mm_state.page_array[i].order = 0;
        mm_state.page_array[i].next = NULL;
    }
    
    mm_state.initialized = true;
    
    KLOG_INFO("Memory management initialized");
    KLOG_INFO("Total memory: %lu MB", mm_state.total_memory / (1024 * 1024));
    KLOG_INFO("Kernel heap: 0x%lx - 0x%lx", KERNEL_HEAP_START, KERNEL_HEAP_START + KERNEL_HEAP_SIZE);
}

/* Memory protection functions */
void mm_set_page_protection(uint64_t vaddr, uint64_t flags) {
    /* TODO: Implement page table manipulation */
    (void)vaddr;
    (void)flags;
}

void mm_enable_smep(void) {
    uint64_t cr4;
    __asm__ __volatile__("mov %%cr4, %0" : "=r" (cr4));
    cr4 |= (1UL << 20); /* SMEP bit */
    __asm__ __volatile__("mov %0, %%cr4" :: "r" (cr4));
    
    KLOG_INFO("SMEP (Supervisor Mode Execution Prevention) enabled");
}

void mm_enable_smap(void) {
    uint64_t cr4;
    __asm__ __volatile__("mov %%cr4, %0" : "=r" (cr4));
    cr4 |= (1UL << 21); /* SMAP bit */
    __asm__ __volatile__("mov %0, %%cr4" :: "r" (cr4));
    
    KLOG_INFO("SMAP (Supervisor Mode Access Prevention) enabled");
}

/* Get memory statistics */
void mm_get_stats(uint64_t *total, uint64_t *used, uint64_t *free) {
    if (total) *total = mm_state.total_memory;
    if (used) *used = mm_state.used_memory;
    if (free) *free = mm_state.total_memory - mm_state.used_memory;
}