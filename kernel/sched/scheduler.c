/*
 * SentinalOS Process Scheduler
 * Pentagon-Level Security with Process Isolation
 */

#include "kernel.h"

/* Process states */
enum proc_state {
    PROC_RUNNING,
    PROC_READY,
    PROC_BLOCKED,
    PROC_ZOMBIE,
    PROC_DEAD
};

/* Security levels */
enum security_level {
    SEC_UNCLASSIFIED = 0,
    SEC_CONFIDENTIAL = 1,
    SEC_SECRET = 2,
    SEC_TOPSECRET = 3,
    SEC_PENTAGON = 4
};

/* Process control block */
struct process {
    uint64_t pid;
    uint64_t ppid;
    enum proc_state state;
    enum security_level sec_level;
    
    /* CPU context */
    uint64_t rsp;     /* Stack pointer */
    uint64_t rbp;     /* Base pointer */
    uint64_t rip;     /* Instruction pointer */
    uint64_t rflags;  /* Flags register */
    
    /* General purpose registers */
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15;
    
    /* Memory management */
    uint64_t cr3;     /* Page table base */
    uint64_t stack_base;
    uint64_t stack_size;
    
    /* Security context */
    uint64_t stack_canary;
    uint32_t capabilities;
    bool privileged;
    
    /* Scheduling */
    uint64_t priority;
    uint64_t time_slice;
    uint64_t cpu_time;
    uint64_t creation_time;
    
    /* Process tree */
    struct process *parent;
    struct process *next_sibling;
    struct process *first_child;
    
    /* Scheduler queues */
    struct process *next;
    struct process *prev;
    
    char name[32];
} __packed;

/* Scheduler state */
static struct {
    struct process *current;
    struct process *ready_queue;
    struct process *blocked_queue;
    struct process process_table[256];
    uint64_t next_pid;
    uint64_t total_processes;
    uint64_t context_switches;
    bool initialized;
} sched_state;

/* Current running process */
struct process *current_process = NULL;

/* Process creation */
static struct process *alloc_process(void) {
    for (int i = 0; i < 256; i++) {
        if (sched_state.process_table[i].state == PROC_DEAD) {
            memset(&sched_state.process_table[i], 0, sizeof(struct process));
            return &sched_state.process_table[i];
        }
    }
    return NULL;
}

/* Add process to ready queue */
static void add_to_ready_queue(struct process *proc) {
    proc->state = PROC_READY;
    proc->next = sched_state.ready_queue;
    proc->prev = NULL;
    
    if (sched_state.ready_queue) {
        sched_state.ready_queue->prev = proc;
    }
    sched_state.ready_queue = proc;
}

/* Remove process from ready queue */
static void remove_from_ready_queue(struct process *proc) {
    if (proc->prev) {
        proc->prev->next = proc->next;
    } else {
        sched_state.ready_queue = proc->next;
    }
    
    if (proc->next) {
        proc->next->prev = proc->prev;
    }
    
    proc->next = NULL;
    proc->prev = NULL;
}

/* Security check for process operations */
static bool security_check(struct process *src, struct process *dest, int operation) {
    /* Pentagon-level security model */
    
    /* No read up, no write down (Bell-LaPadula) */
    if (operation == 0) { /* Read */
        return src->sec_level >= dest->sec_level;
    } else { /* Write */
        return src->sec_level <= dest->sec_level;
    }
}

/* Context switch implementation */
static void context_switch(struct process *from, struct process *to) {
    if (!from || !to) return;
    
    sched_state.context_switches++;
    
    /* Save current context */
    if (from) {
        __asm__ __volatile__(
            "pushfq\n\t"
            "mov %%rsp, %0\n\t"
            "mov %%rbp, %1\n\t"
            "mov %%rax, %2\n\t"
            "mov %%rbx, %3\n\t"
            "mov %%rcx, %4\n\t"
            "mov %%rdx, %5\n\t"
            "mov %%rsi, %6\n\t"
            "mov %%rdi, %7\n\t"
            "mov %%r8, %8\n\t"
            "mov %%r9, %9\n\t"
            "mov %%r10, %10\n\t"
            "mov %%r11, %11\n\t"
            "mov %%r12, %12\n\t"
            "mov %%r13, %13\n\t"
            "mov %%r14, %14\n\t"
            "mov %%r15, %15\n\t"
            "popfq\n\t"
            "mov %%rax, %16"
            : "=m" (from->rsp), "=m" (from->rbp),
              "=m" (from->rax), "=m" (from->rbx), "=m" (from->rcx), "=m" (from->rdx),
              "=m" (from->rsi), "=m" (from->rdi), "=m" (from->r8), "=m" (from->r9),
              "=m" (from->r10), "=m" (from->r11), "=m" (from->r12), "=m" (from->r13),
              "=m" (from->r14), "=m" (from->r15), "=m" (from->rflags)
            :
            : "memory"
        );
        
        from->state = PROC_READY;
    }
    
    /* Switch to new process */
    current_process = to;
    to->state = PROC_RUNNING;
    
    /* Load new context */
    __asm__ __volatile__(
        "mov %0, %%cr3\n\t"      /* Switch page tables */
        "mov %1, %%rsp\n\t"
        "mov %2, %%rbp\n\t"
        "mov %3, %%rax\n\t"
        "mov %4, %%rbx\n\t"
        "mov %5, %%rcx\n\t"
        "mov %6, %%rdx\n\t"
        "mov %7, %%rsi\n\t"
        "mov %8, %%rdi\n\t"
        "mov %9, %%r8\n\t"
        "mov %10, %%r9\n\t"
        "mov %11, %%r10\n\t"
        "mov %12, %%r11\n\t"
        "mov %13, %%r12\n\t"
        "mov %14, %%r13\n\t"
        "mov %15, %%r14\n\t"
        "mov %16, %%r15\n\t"
        "push %17\n\t"
        "popfq"
        :
        : "r" (to->cr3), "m" (to->rsp), "m" (to->rbp),
          "m" (to->rax), "m" (to->rbx), "m" (to->rcx), "m" (to->rdx),
          "m" (to->rsi), "m" (to->rdi), "m" (to->r8), "m" (to->r9),
          "m" (to->r10), "m" (to->r11), "m" (to->r12), "m" (to->r13),
          "m" (to->r14), "m" (to->r15), "m" (to->rflags)
        : "memory"
    );
}

/* Round-robin scheduler */
void schedule(void) {
    if (!sched_state.initialized || !sched_state.ready_queue) {
        return;
    }
    
    struct process *next = sched_state.ready_queue;
    
    /* Security check */
    if (current_process && !security_check(current_process, next, 0)) {
        KLOG_WARN("Process %lu blocked by security policy", next->pid);
        return;
    }
    
    /* Remove from ready queue */
    remove_from_ready_queue(next);
    
    /* Add current process back to ready queue if still running */
    if (current_process && current_process->state == PROC_RUNNING) {
        add_to_ready_queue(current_process);
    }
    
    /* Perform context switch */
    context_switch(current_process, next);
}

/* Create new process */
struct process *create_process(const char *name, enum security_level sec_level, bool privileged) {
    struct process *proc = alloc_process();
    if (!proc) {
        KLOG_ERR("Failed to allocate process: %s", name);
        return NULL;
    }
    
    /* Initialize process */
    proc->pid = sched_state.next_pid++;
    proc->ppid = current_process ? current_process->pid : 0;
    proc->state = PROC_READY;
    proc->sec_level = sec_level;
    proc->privileged = privileged;
    
    /* Set up stack */
    proc->stack_size = 0x4000; /* 16KB stack */
    proc->stack_base = (uint64_t)kmalloc_aligned(proc->stack_size, PAGE_SIZE);
    proc->rsp = proc->stack_base + proc->stack_size;
    
    /* Initialize security context */
    proc->stack_canary = get_stack_canary();
    proc->capabilities = privileged ? 0xFFFFFFFF : 0x00000001;
    
    /* Set up initial context */
    proc->rflags = 0x202; /* Enable interrupts */
    proc->creation_time = get_ticks();
    proc->priority = 10;  /* Normal priority */
    proc->time_slice = 10; /* 10ms time slice */
    
    /* Copy name */
    strncpy(proc->name, name, sizeof(proc->name) - 1);
    proc->name[sizeof(proc->name) - 1] = '\0';
    
    /* Set parent-child relationship */
    if (current_process) {
        proc->parent = current_process;
        proc->next_sibling = current_process->first_child;
        current_process->first_child = proc;
    }
    
    /* Add to ready queue */
    add_to_ready_queue(proc);
    sched_state.total_processes++;
    
    KLOG_INFO("Created process: %s (PID: %lu, Security: %d)", name, proc->pid, sec_level);
    
    return proc;
}

/* Initialize kernel idle process */
static void create_idle_process(void) {
    struct process *idle = &sched_state.process_table[0];
    
    memset(idle, 0, sizeof(struct process));
    idle->pid = 0;
    idle->state = PROC_RUNNING;
    idle->sec_level = SEC_PENTAGON;
    idle->privileged = true;
    strcpy(idle->name, "idle");
    
    /* Set as current process */
    current_process = idle;
    sched_state.current = idle;
    
    KLOG_INFO("Idle process created (PID: 0)");
}

void scheduler_init(void) {
    KLOG_INFO("Initializing Pentagon-level process scheduler...");
    
    /* Initialize scheduler state */
    memset(&sched_state, 0, sizeof(sched_state));
    sched_state.next_pid = 1;
    
    /* Mark all processes as dead initially */
    for (int i = 0; i < 256; i++) {
        sched_state.process_table[i].state = PROC_DEAD;
    }
    
    /* Create idle process */
    create_idle_process();
    
    /* Create init process */
    create_process("init", SEC_PENTAGON, true);
    
    sched_state.initialized = true;
    
    KLOG_INFO("Process scheduler initialized");
    KLOG_INFO("Security model: Bell-LaPadula with Pentagon classification");
}

/* Get process by PID */
struct process *get_process(uint64_t pid) {
    for (int i = 0; i < 256; i++) {
        if (sched_state.process_table[i].pid == pid && 
            sched_state.process_table[i].state != PROC_DEAD) {
            return &sched_state.process_table[i];
        }
    }
    return NULL;
}

/* Terminate process */
void terminate_process(uint64_t pid) {
    struct process *proc = get_process(pid);
    if (!proc) return;
    
    /* Security check */
    if (current_process && !security_check(current_process, proc, 1)) {
        KLOG_WARN("Process termination blocked by security policy");
        return;
    }
    
    /* Remove from queues */
    if (proc->state == PROC_READY) {
        remove_from_ready_queue(proc);
    }
    
    /* Clean up resources */
    if (proc->stack_base) {
        kfree((void*)proc->stack_base);
    }
    
    /* Mark as dead */
    proc->state = PROC_DEAD;
    sched_state.total_processes--;
    
    KLOG_INFO("Process %s (PID: %lu) terminated", proc->name, proc->pid);
    
    /* Schedule next process if this was current */
    if (proc == current_process) {
        current_process = NULL;
        schedule();
    }
}

/* Get scheduler statistics */
void sched_get_stats(uint64_t *processes, uint64_t *context_switches) {
    if (processes) *processes = sched_state.total_processes;
    if (context_switches) *context_switches = sched_state.context_switches;
}