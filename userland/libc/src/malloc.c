/*
 * SentinalOS Memory Allocator Implementation
 * Pentagon-Level Secure Memory Management
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* Memory block header */
struct mem_block {
    size_t size;
    int free;
    uint32_t magic;
    struct mem_block *next;
    struct mem_block *prev;
    uint32_t checksum;
} __attribute__((packed));

/* Magic numbers for heap corruption detection */
#define BLOCK_MAGIC 0xDEADBEEF
#define FREE_MAGIC  0xFEEDFACE

/* Heap management */
static struct mem_block *heap_start = NULL;
static struct mem_block *heap_end = NULL;
static void *heap_base = NULL;
static size_t heap_size = 0;
static int heap_initialized = 0;

/* Security features */
static uint32_t heap_canary = 0x12345678;
static int security_checks_enabled = 1;

/* Thread safety (simplified) */
static volatile int heap_lock = 0;

/* Forward declarations */
static void heap_init(void);
static struct mem_block *find_free_block(size_t size);
static struct mem_block *create_block(size_t size);
static void split_block(struct mem_block *block, size_t size);
static void merge_free_blocks(void);
static uint32_t calculate_checksum(struct mem_block *block);
static int validate_block(struct mem_block *block);
static void *allocate_pages(size_t size);
static void security_wipe(void *ptr, size_t size);

/* Initialize heap */
static void heap_init(void) {
    if (heap_initialized) {
        return;
    }
    
    /* Initial heap size: 1MB */
    heap_size = 1024 * 1024;
    
    /* Allocate heap using system call */
    heap_base = allocate_pages(heap_size);
    if (!heap_base) {
        /* Fallback to sbrk */
        heap_base = sbrk(heap_size);
        if (heap_base == (void *)-1) {
            return; /* Failed to allocate heap */
        }
    }
    
    /* Initialize first block */
    heap_start = (struct mem_block *)heap_base;
    heap_start->size = heap_size - sizeof(struct mem_block);
    heap_start->free = 1;
    heap_start->magic = BLOCK_MAGIC;
    heap_start->next = NULL;
    heap_start->prev = NULL;
    heap_start->checksum = calculate_checksum(heap_start);
    
    heap_end = heap_start;
    heap_initialized = 1;
}

/* Calculate checksum for heap corruption detection */
static uint32_t calculate_checksum(struct mem_block *block) {
    if (!block) return 0;
    
    uint32_t checksum = 0;
    checksum ^= (uint32_t)block->size;
    checksum ^= (uint32_t)block->free;
    checksum ^= block->magic;
    checksum ^= (uintptr_t)block->next;
    checksum ^= (uintptr_t)block->prev;
    checksum ^= heap_canary;
    
    return checksum;
}

/* Validate block integrity */
static int validate_block(struct mem_block *block) {
    if (!block || !security_checks_enabled) {
        return 1;
    }
    
    /* Check magic number */
    if (block->magic != BLOCK_MAGIC && block->magic != FREE_MAGIC) {
        return 0;
    }
    
    /* Check checksum */
    uint32_t expected = calculate_checksum(block);
    if (block->checksum != expected) {
        return 0;
    }
    
    /* Check size bounds */
    if (block->size == 0 || block->size > heap_size) {
        return 0;
    }
    
    return 1;
}

/* Find free block of sufficient size */
static struct mem_block *find_free_block(size_t size) {
    struct mem_block *current = heap_start;
    
    while (current) {
        if (!validate_block(current)) {
            /* Heap corruption detected */
            abort();
        }
        
        if (current->free && current->size >= size) {
            return current;
        }
        current = current->next;
    }
    
    return NULL;
}

/* Create new block at end of heap */
static struct mem_block *create_block(size_t size) {
    size_t total_size = size + sizeof(struct mem_block);
    
    /* Check if we need to expand heap */
    uintptr_t current_end = (uintptr_t)heap_base + heap_size;
    uintptr_t needed_end = (uintptr_t)heap_end + sizeof(struct mem_block) + heap_end->size + total_size;
    
    if (needed_end > current_end) {
        /* Expand heap */
        size_t expand_size = needed_end - current_end;
        expand_size = (expand_size + 4095) & ~4095; /* Round up to page size */
        
        void *new_space = allocate_pages(expand_size);
        if (!new_space) {
            return NULL;
        }
        
        heap_size += expand_size;
    }
    
    /* Create new block */
    struct mem_block *new_block = (struct mem_block *)((char *)heap_end + sizeof(struct mem_block) + heap_end->size);
    new_block->size = size;
    new_block->free = 0;
    new_block->magic = BLOCK_MAGIC;
    new_block->next = NULL;
    new_block->prev = heap_end;
    new_block->checksum = calculate_checksum(new_block);
    
    /* Update links */
    heap_end->next = new_block;
    heap_end = new_block;
    
    return new_block;
}

/* Split block if it's too large */
static void split_block(struct mem_block *block, size_t size) {
    if (!block || block->size <= size + sizeof(struct mem_block) + 16) {
        return; /* Block too small to split */
    }
    
    size_t original_size = block->size;
    block->size = size;
    block->checksum = calculate_checksum(block);
    
    /* Create new free block */
    struct mem_block *new_block = (struct mem_block *)((char *)block + sizeof(struct mem_block) + size);
    new_block->size = original_size - size - sizeof(struct mem_block);
    new_block->free = 1;
    new_block->magic = FREE_MAGIC;
    new_block->next = block->next;
    new_block->prev = block;
    new_block->checksum = calculate_checksum(new_block);
    
    /* Update links */
    if (block->next) {
        block->next->prev = new_block;
    } else {
        heap_end = new_block;
    }
    
    block->next = new_block;
    block->checksum = calculate_checksum(block);
}

/* Merge adjacent free blocks */
static void merge_free_blocks(void) {
    struct mem_block *current = heap_start;
    
    while (current && current->next) {
        if (!validate_block(current)) {
            abort(); /* Heap corruption */
        }
        
        if (current->free && current->next->free) {
            /* Merge blocks */
            struct mem_block *next = current->next;
            current->size += next->size + sizeof(struct mem_block);
            current->next = next->next;
            
            if (next->next) {
                next->next->prev = current;
            } else {
                heap_end = current;
            }
            
            /* Security wipe merged block header */
            security_wipe(next, sizeof(struct mem_block));
            
            current->checksum = calculate_checksum(current);
        } else {
            current = current->next;
        }
    }
}

/* Allocate pages from system */
static void *allocate_pages(size_t size) {
    /* Try mmap first */
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (ptr != MAP_FAILED) {
        return ptr;
    }
    
    /* Fallback to sbrk */
    return sbrk(size);
}

/* Security wipe memory */
static void security_wipe(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    volatile char *p = (volatile char *)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
}

/* Public malloc implementation */
void *malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    
    /* Acquire lock */
    while (__sync_lock_test_and_set(&heap_lock, 1)) {
        /* Spin wait */
    }
    
    if (!heap_initialized) {
        heap_init();
        if (!heap_initialized) {
            __sync_lock_release(&heap_lock);
            return NULL;
        }
    }
    
    /* Align size to 8-byte boundary */
    size = (size + 7) & ~7;
    
    /* Add padding for security canaries */
    size += 16;
    
    /* Find or create block */
    struct mem_block *block = find_free_block(size);
    if (!block) {
        block = create_block(size);
        if (!block) {
            __sync_lock_release(&heap_lock);
            return NULL;
        }
    }
    
    /* Mark as allocated */
    block->free = 0;
    block->magic = BLOCK_MAGIC;
    
    /* Split block if necessary */
    split_block(block, size);
    
    /* Update checksum */
    block->checksum = calculate_checksum(block);
    
    __sync_lock_release(&heap_lock);
    
    /* Return pointer to data area */
    void *ptr = (char *)block + sizeof(struct mem_block);
    
    /* Add security canaries */
    *(uint32_t *)ptr = heap_canary;
    *(uint32_t *)((char *)ptr + size - 4) = heap_canary;
    
    return (char *)ptr + 8; /* Skip canary */
}

/* Public free implementation */
void free(void *ptr) {
    if (!ptr) {
        return;
    }
    
    /* Acquire lock */
    while (__sync_lock_test_and_set(&heap_lock, 1)) {
        /* Spin wait */
    }
    
    /* Get block header */
    ptr = (char *)ptr - 8; /* Account for canary */
    struct mem_block *block = (struct mem_block *)((char *)ptr - sizeof(struct mem_block));
    
    /* Validate block */
    if (!validate_block(block)) {
        __sync_lock_release(&heap_lock);
        abort(); /* Heap corruption or double free */
    }
    
    /* Check canaries */
    if (security_checks_enabled) {
        uint32_t start_canary = *(uint32_t *)ptr;
        uint32_t end_canary = *(uint32_t *)((char *)ptr + block->size - 4);
        
        if (start_canary != heap_canary || end_canary != heap_canary) {
            __sync_lock_release(&heap_lock);
            abort(); /* Buffer overflow detected */
        }
    }
    
    /* Security wipe data */
    security_wipe(ptr, block->size);
    
    /* Mark as free */
    block->free = 1;
    block->magic = FREE_MAGIC;
    block->checksum = calculate_checksum(block);
    
    /* Merge adjacent free blocks */
    merge_free_blocks();
    
    __sync_lock_release(&heap_lock);
}

/* Public calloc implementation */
void *calloc(size_t nmemb, size_t size) {
    /* Check for overflow */
    if (nmemb != 0 && size > SIZE_MAX / nmemb) {
        return NULL;
    }
    
    size_t total_size = nmemb * size;
    void *ptr = malloc(total_size);
    
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    
    return ptr;
}

/* Public realloc implementation */
void *realloc(void *ptr, size_t size) {
    if (!ptr) {
        return malloc(size);
    }
    
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    /* Get current block */
    void *orig_ptr = (char *)ptr - 8;
    struct mem_block *block = (struct mem_block *)((char *)orig_ptr - sizeof(struct mem_block));
    
    /* Validate block */
    if (!validate_block(block)) {
        abort();
    }
    
    size_t old_size = block->size - 16; /* Account for canaries */
    
    /* If new size fits in current block, just return */
    if (size <= old_size) {
        return ptr;
    }
    
    /* Allocate new block */
    void *new_ptr = malloc(size);
    if (!new_ptr) {
        return NULL;
    }
    
    /* Copy data */
    memcpy(new_ptr, ptr, old_size < size ? old_size : size);
    
    /* Free old block */
    free(ptr);
    
    return new_ptr;
}

/* Heap statistics for debugging */
void malloc_stats(void) {
    size_t total_allocated = 0;
    size_t total_free = 0;
    int allocated_blocks = 0;
    int free_blocks = 0;
    
    struct mem_block *current = heap_start;
    while (current) {
        if (current->free) {
            total_free += current->size;
            free_blocks++;
        } else {
            total_allocated += current->size;
            allocated_blocks++;
        }
        current = current->next;
    }
    
    printf("Heap Statistics:\n");
    printf("  Total heap size: %zu bytes\n", heap_size);
    printf("  Allocated: %zu bytes in %d blocks\n", total_allocated, allocated_blocks);
    printf("  Free: %zu bytes in %d blocks\n", total_free, free_blocks);
    printf("  Overhead: %zu bytes\n", 
           (allocated_blocks + free_blocks) * sizeof(struct mem_block));
}