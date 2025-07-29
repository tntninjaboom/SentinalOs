/*
 * SentinalOS User Space C Library - Standard Library
 * Pentagon-Level Security Implementation
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

/* Memory allocation state */
static struct {
    void *heap_start;
    void *heap_end;
    size_t heap_size;
    size_t allocated;
    size_t peak_usage;
    uint32_t alloc_count;
    uint32_t free_count;
    bool initialized;
} heap_state;

/* Simple heap block header */
struct heap_block {
    size_t size;
    uint32_t magic;     /* Security canary */
    uint32_t flags;
    struct heap_block *next;
    struct heap_block *prev;
} __attribute__((packed));

#define HEAP_MAGIC 0xDEADBEEF
#define HEAP_FLAG_ALLOCATED 0x01
#define HEAP_FLAG_GUARD     0x02
#define MIN_BLOCK_SIZE      32

/* System call interface */
extern long syscall(long number, ...);

#define SYS_BRK         12
#define SYS_EXIT        60
#define SYS_GETPID      39
#define SYS_WRITE       1
#define SYS_READ        0

/* Initialize heap */
static void init_heap(void) {
    if (heap_state.initialized) return;
    
    /* Get initial heap from kernel */
    void *heap_start = (void*)syscall(SYS_BRK, 0);
    
    /* Expand heap to 1MB initially */
    size_t initial_size = 1024 * 1024;
    void *heap_end = (void*)syscall(SYS_BRK, (uintptr_t)heap_start + initial_size);
    
    if (heap_end == (void*)-1) {
        /* Heap allocation failed */
        return;
    }
    
    heap_state.heap_start = heap_start;
    heap_state.heap_end = heap_end;
    heap_state.heap_size = initial_size;
    heap_state.allocated = 0;
    heap_state.peak_usage = 0;
    heap_state.alloc_count = 0;
    heap_state.free_count = 0;
    heap_state.initialized = true;
    
    /* Initialize first free block */
    struct heap_block *first_block = (struct heap_block*)heap_start;
    first_block->size = initial_size - sizeof(struct heap_block);
    first_block->magic = HEAP_MAGIC;
    first_block->flags = 0;
    first_block->next = NULL;
    first_block->prev = NULL;
}

/* Expand heap */
static bool expand_heap(size_t needed_size) {
    size_t expand_size = (needed_size + 4095) & ~4095; /* Page align */
    void *new_end = (void*)syscall(SYS_BRK, (uintptr_t)heap_state.heap_end + expand_size);
    
    if (new_end == (void*)-1) {
        return false;
    }
    
    heap_state.heap_end = new_end;
    heap_state.heap_size += expand_size;
    return true;
}

/* Validate heap block */
static bool validate_block(struct heap_block *block) {
    if (!block) return false;
    if (block->magic != HEAP_MAGIC) return false;
    if ((uintptr_t)block < (uintptr_t)heap_state.heap_start) return false;
    if ((uintptr_t)block >= (uintptr_t)heap_state.heap_end) return false;
    return true;
}

/* Find free block */
static struct heap_block *find_free_block(size_t size) {
    struct heap_block *current = (struct heap_block*)heap_state.heap_start;
    
    while (current && (uintptr_t)current < (uintptr_t)heap_state.heap_end) {
        if (!validate_block(current)) {
            break; /* Heap corruption */
        }
        
        if (!(current->flags & HEAP_FLAG_ALLOCATED) && current->size >= size) {
            return current;
        }
        
        current = (struct heap_block*)((char*)current + sizeof(struct heap_block) + current->size);
    }
    
    return NULL;
}

/* Split block if too large */
static void split_block(struct heap_block *block, size_t size) {
    if (block->size < size + sizeof(struct heap_block) + MIN_BLOCK_SIZE) {
        return; /* Not worth splitting */
    }
    
    struct heap_block *new_block = (struct heap_block*)((char*)block + sizeof(struct heap_block) + size);
    new_block->size = block->size - size - sizeof(struct heap_block);
    new_block->magic = HEAP_MAGIC;
    new_block->flags = 0;
    new_block->next = block->next;
    new_block->prev = block;
    
    if (block->next) {
        block->next->prev = new_block;
    }
    block->next = new_block;
    block->size = size;
}

/* Coalesce free blocks */
static void coalesce_blocks(struct heap_block *block) {
    /* Coalesce with next block */
    struct heap_block *next = (struct heap_block*)((char*)block + sizeof(struct heap_block) + block->size);
    if ((uintptr_t)next < (uintptr_t)heap_state.heap_end && 
        validate_block(next) && !(next->flags & HEAP_FLAG_ALLOCATED)) {
        block->size += sizeof(struct heap_block) + next->size;
        block->next = next->next;
        if (next->next) {
            next->next->prev = block;
        }
    }
    
    /* Coalesce with previous block */
    if (block->prev && !(block->prev->flags & HEAP_FLAG_ALLOCATED)) {
        block->prev->size += sizeof(struct heap_block) + block->size;
        block->prev->next = block->next;
        if (block->next) {
            block->next->prev = block->prev;
        }
    }
}

void *malloc(size_t size) {
    if (size == 0) return NULL;
    
    if (!heap_state.initialized) {
        init_heap();
        if (!heap_state.initialized) {
            errno = ENOMEM;
            return NULL;
        }
    }
    
    /* Align size to prevent unaligned access */
    size = (size + 7) & ~7;
    
    /* Find or create a suitable block */
    struct heap_block *block = find_free_block(size);
    
    if (!block) {
        /* Try to expand heap */
        if (!expand_heap(size + sizeof(struct heap_block))) {
            errno = ENOMEM;
            return NULL;
        }
        block = find_free_block(size);
        if (!block) {
            errno = ENOMEM;
            return NULL;
        }
    }
    
    /* Split block if necessary */
    split_block(block, size);
    
    /* Mark as allocated */
    block->flags |= HEAP_FLAG_ALLOCATED;
    
    /* Update statistics */
    heap_state.allocated += size;
    heap_state.alloc_count++;
    if (heap_state.allocated > heap_state.peak_usage) {
        heap_state.peak_usage = heap_state.allocated;
    }
    
    return (char*)block + sizeof(struct heap_block);
}

void *calloc(size_t nmemb, size_t size) {
    /* Check for overflow */
    if (nmemb != 0 && size > SIZE_MAX / nmemb) {
        errno = ENOMEM;
        return NULL;
    }
    
    size_t total_size = nmemb * size;
    void *ptr = malloc(total_size);
    
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (!ptr) {
        return malloc(size);
    }
    
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    /* Get current block */
    struct heap_block *block = (struct heap_block*)((char*)ptr - sizeof(struct heap_block));
    
    if (!validate_block(block) || !(block->flags & HEAP_FLAG_ALLOCATED)) {
        errno = EINVAL;
        return NULL;
    }
    
    if (block->size >= size) {
        /* Current block is large enough */
        return ptr;
    }
    
    /* Allocate new block and copy data */
    void *new_ptr = malloc(size);
    if (!new_ptr) {
        return NULL;
    }
    
    memcpy(new_ptr, ptr, block->size < size ? block->size : size);
    free(ptr);
    
    return new_ptr;
}

void free(void *ptr) {
    if (!ptr) return;
    
    /* Get block header */
    struct heap_block *block = (struct heap_block*)((char*)ptr - sizeof(struct heap_block));
    
    if (!validate_block(block) || !(block->flags & HEAP_FLAG_ALLOCATED)) {
        /* Invalid free - security violation */
        abort();
    }
    
    /* Clear memory for security */
    memset(ptr, 0, block->size);
    
    /* Mark as free */
    block->flags &= ~HEAP_FLAG_ALLOCATED;
    
    /* Update statistics */
    heap_state.allocated -= block->size;
    heap_state.free_count++;
    
    /* Coalesce with adjacent free blocks */
    coalesce_blocks(block);
}

int atoi(const char *nptr) {
    if (!nptr) return 0;
    
    int result = 0;
    int sign = 1;
    
    /* Skip whitespace */
    while (*nptr == ' ' || *nptr == '\t' || *nptr == '\n' || 
           *nptr == '\r' || *nptr == '\f' || *nptr == '\v') {
        nptr++;
    }
    
    /* Handle sign */
    if (*nptr == '-') {
        sign = -1;
        nptr++;
    } else if (*nptr == '+') {
        nptr++;
    }
    
    /* Convert digits */
    while (*nptr >= '0' && *nptr <= '9') {
        result = result * 10 + (*nptr - '0');
        nptr++;
    }
    
    return result * sign;
}

long atol(const char *nptr) {
    if (!nptr) return 0;
    
    long result = 0;
    int sign = 1;
    
    /* Skip whitespace */
    while (*nptr == ' ' || *nptr == '\t' || *nptr == '\n' || 
           *nptr == '\r' || *nptr == '\f' || *nptr == '\v') {
        nptr++;
    }
    
    /* Handle sign */
    if (*nptr == '-') {
        sign = -1;
        nptr++;
    } else if (*nptr == '+') {
        nptr++;
    }
    
    /* Convert digits */
    while (*nptr >= '0' && *nptr <= '9') {
        result = result * 10 + (*nptr - '0');
        nptr++;
    }
    
    return result * sign;
}

void abort(void) {
    /* Write error message */
    const char *msg = "abort() called - terminating program\n";
    syscall(SYS_WRITE, 2, msg, strlen(msg));
    
    /* Terminate process */
    syscall(SYS_EXIT, 134); /* SIGABRT exit code */
    
    /* Should never reach here */
    while (1);
}

void exit(int status) {
    /* Clean up heap if needed */
    /* TODO: Implement atexit handlers */
    
    /* Terminate process */
    syscall(SYS_EXIT, status);
    
    /* Should never reach here */
    while (1);
}

int abs(int j) {
    return j < 0 ? -j : j;
}

long labs(long j) {
    return j < 0 ? -j : j;
}

/* Environment variables (simplified) */
char *getenv(const char *name) {
    /* TODO: Implement environment variable lookup */
    (void)name;
    return NULL;
}

int putenv(char *string) {
    /* TODO: Implement environment variable setting */
    (void)string;
    return -1;
}

/* Random number generation (simplified) */
static unsigned long rand_state = 1;

void srand(unsigned int seed) {
    rand_state = seed;
}

int rand(void) {
    rand_state = rand_state * 1103515245 + 12345;
    return (rand_state / 65536) % 32768;
}