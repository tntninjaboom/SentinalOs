/*
 * SentinalOS Process Management
 * Multi-tasking and Process Scheduling
 */

#include "../include/system.h"

/* Global process management state */
static struct process *current_process = NULL;
static struct process *process_list = NULL;
static struct process *ready_queue = NULL;
static uint32_t next_pid = 1;
static uint64_t scheduler_ticks = 0;

/* Process scheduler lock */
static volatile int scheduler_lock = 0;

/* Initialize process management */
void process_init(void) {
    debug_print("Initializing process management system\n");
    
    /* Create init process (PID 1) */
    struct process *init_proc = (struct process *)kmalloc(sizeof(struct process));
    if (!init_proc) {
        kernel_panic("Failed to allocate init process");
    }
    
    /* Initialize init process */
    init_proc->pid = 1;
    init_proc->ppid = 0;
    init_proc->state = PROCESS_RUNNING;
    init_proc->priority = 10;
    init_proc->uid = 0;
    init_proc->gid = 0;
    init_proc->euid = 0;
    init_proc->egid = 0;
    init_proc->security_level = 4; /* Pentagon level */
    init_proc->security_flags = 0x07; /* All security features enabled */
    strncpy(init_proc->name, "init", sizeof(init_proc->name));
    strncpy(init_proc->security_context, "system_u:system_r:init_t", 
            sizeof(init_proc->security_context));
    
    /* Allocate page directory */
    init_proc->page_directory = get_page_directory();
    
    /* Allocate kernel stack */
    init_proc->kernel_stack = (uint64_t)kmalloc(KERNEL_STACK_SIZE) + KERNEL_STACK_SIZE;
    init_proc->user_stack = 0x7FFFFFFF; /* Top of user space */
    
    /* Initialize CPU context */
    init_proc->context = (struct cpu_context *)kmalloc(sizeof(struct cpu_context));
    if (!init_proc->context) {
        kernel_panic("Failed to allocate init process context");
    }
    
    /* Clear open files */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        init_proc->open_files[i] = 0;
    }
    
    /* Add to process list */
    init_proc->next = NULL;
    init_proc->prev = NULL;
    process_list = init_proc;
    current_process = init_proc;
    
    debug_print("Init process created with PID 1\n");
}

/* Create a new process */
int process_create(const char *name, void (*entry_point)(void)) {
    /* Acquire scheduler lock */
    while (__sync_lock_test_and_set(&scheduler_lock, 1)) {
        /* Spin wait */
    }
    
    /* Allocate process structure */
    struct process *proc = (struct process *)kmalloc(sizeof(struct process));
    if (!proc) {
        __sync_lock_release(&scheduler_lock);
        return -1;
    }
    
    /* Initialize process */
    proc->pid = next_pid++;
    proc->ppid = current_process ? current_process->pid : 0;
    proc->state = PROCESS_READY;
    proc->priority = 20; /* Default priority */
    proc->uid = current_process ? current_process->uid : 0;
    proc->gid = current_process ? current_process->gid : 0;
    proc->euid = proc->uid;
    proc->egid = proc->gid;
    proc->memory_usage = 0;
    proc->cpu_time = 0;
    
    /* Security context inheritance */
    if (current_process) {
        proc->security_level = current_process->security_level;
        proc->security_flags = current_process->security_flags;
        strncpy(proc->security_context, current_process->security_context,
                sizeof(proc->security_context));
    } else {
        proc->security_level = 0;
        proc->security_flags = 0;
        strncpy(proc->security_context, "unconfined_u:unconfined_r:unconfined_t",
                sizeof(proc->security_context));
    }
    
    /* Set process name */
    strncpy(proc->name, name, sizeof(proc->name) - 1);
    proc->name[sizeof(proc->name) - 1] = '\0';
    
    /* Allocate page directory */
    proc->page_directory = (uint64_t *)kmalloc(PAGE_SIZE);
    if (!proc->page_directory) {
        kfree(proc);
        __sync_lock_release(&scheduler_lock);
        return -1;
    }
    
    /* Copy kernel page tables */
    uint64_t *kernel_pd = get_page_directory();
    for (int i = 256; i < 512; i++) { /* Copy kernel half */
        proc->page_directory[i] = kernel_pd[i];
    }
    
    /* Clear user half */
    for (int i = 0; i < 256; i++) {
        proc->page_directory[i] = 0;
    }
    
    /* Allocate stacks */
    proc->kernel_stack = (uint64_t)kmalloc(KERNEL_STACK_SIZE) + KERNEL_STACK_SIZE;
    proc->user_stack = 0x7FFFFFFF;
    
    /* Initialize CPU context */
    proc->context = (struct cpu_context *)kmalloc(sizeof(struct cpu_context));
    if (!proc->context) {
        kfree(proc->page_directory);
        kfree(proc);
        __sync_lock_release(&scheduler_lock);
        return -1;
    }
    
    /* Set up initial context */
    proc->context->rip = (uint64_t)entry_point;
    proc->context->rsp = proc->user_stack;
    proc->context->rflags = 0x202; /* Enable interrupts */
    proc->context->cs = 0x08; /* Kernel code segment */
    proc->context->ds = 0x10; /* Kernel data segment */
    proc->context->cr3 = (uint64_t)proc->page_directory;
    
    /* Clear registers */
    proc->context->rax = proc->context->rbx = proc->context->rcx = proc->context->rdx = 0;
    proc->context->rsi = proc->context->rdi = proc->context->rbp = 0;
    proc->context->r8 = proc->context->r9 = proc->context->r10 = proc->context->r11 = 0;
    proc->context->r12 = proc->context->r13 = proc->context->r14 = proc->context->r15 = 0;
    
    /* Clear open files */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        proc->open_files[i] = 0;
    }
    
    /* Add to process list */
    proc->next = process_list;
    if (process_list) {
        process_list->prev = proc;
    }
    proc->prev = NULL;
    process_list = proc;
    
    /* Add to ready queue */
    add_to_ready_queue(proc);
    
    __sync_lock_release(&scheduler_lock);
    
    debug_print("Created process '%s' with PID %d\n", name, proc->pid);
    security_audit_log("PROCESS_CREATE", proc->pid, name);
    
    return proc->pid;
}

/* Add process to ready queue */
static void add_to_ready_queue(struct process *proc) {
    if (!proc || proc->state != PROCESS_READY) {
        return;
    }
    
    /* Insert by priority (higher priority first) */
    if (!ready_queue || proc->priority > ready_queue->priority) {
        proc->next = ready_queue;
        if (ready_queue) {
            ready_queue->prev = proc;
        }
        proc->prev = NULL;
        ready_queue = proc;
    } else {
        struct process *curr = ready_queue;
        while (curr->next && curr->next->priority >= proc->priority) {
            curr = curr->next;
        }
        
        proc->next = curr->next;
        if (curr->next) {
            curr->next->prev = proc;
        }
        proc->prev = curr;
        curr->next = proc;
    }
}

/* Remove process from ready queue */
static void remove_from_ready_queue(struct process *proc) {
    if (!proc) {
        return;
    }
    
    if (proc->prev) {
        proc->prev->next = proc->next;
    } else {
        ready_queue = proc->next;
    }
    
    if (proc->next) {
        proc->next->prev = proc->prev;
    }
    
    proc->next = proc->prev = NULL;
}

/* Process scheduler */
void process_schedule(void) {
    /* Check if scheduling is disabled */
    if (scheduler_lock) {
        return;
    }
    
    /* Acquire scheduler lock */
    while (__sync_lock_test_and_set(&scheduler_lock, 1)) {
        /* Spin wait */
    }
    
    scheduler_ticks++;
    
    /* Save current process context if running */
    if (current_process && current_process->state == PROCESS_RUNNING) {
        /* In a real implementation, this would save CPU registers */
        current_process->state = PROCESS_READY;
        add_to_ready_queue(current_process);
    }
    
    /* Find next process to run */
    struct process *next_proc = ready_queue;
    
    /* Clean up zombie processes */
    struct process *proc = process_list;
    while (proc) {
        struct process *next = proc->next;
        if (proc->state == PROCESS_ZOMBIE) {
            /* Remove from process list */
            if (proc->prev) {
                proc->prev->next = proc->next;
            } else {
                process_list = proc->next;
            }
            
            if (proc->next) {
                proc->next->prev = proc->prev;
            }
            
            debug_print("Cleaning up zombie process %d\n", proc->pid);
            kfree(proc->context);
            kfree(proc->page_directory);
            kfree(proc);
        }
        proc = next;
    }
    
    /* Select next process */
    if (next_proc) {
        remove_from_ready_queue(next_proc);
        next_proc->state = PROCESS_RUNNING;
        current_process = next_proc;
        
        /* Switch to new process context */
        /* In a real implementation, this would load CPU registers and CR3 */
        
        debug_print("Switched to process %d (%s)\n", 
                   next_proc->pid, next_proc->name);
    } else {
        /* No processes to run - idle */
        current_process = NULL;
        debug_print("No processes to schedule - idling\n");
    }
    
    __sync_lock_release(&scheduler_lock);
}

/* Destroy a process */
int process_destroy(uint32_t pid) {
    struct process *proc = process_find_by_pid(pid);
    if (!proc) {
        return -1; /* Process not found */
    }
    
    /* Security check */
    if (current_process && 
        proc->uid != current_process->uid && 
        current_process->uid != 0) {
        return -1; /* Permission denied */
    }
    
    debug_print("Destroying process %d (%s)\n", pid, proc->name);
    security_audit_log("PROCESS_DESTROY", pid, proc->name);
    
    /* Close all open files */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (proc->open_files[i]) {
            /* Close file descriptor */
            proc->open_files[i] = 0;
        }
    }
    
    /* Free memory */
    if (proc->context) {
        kfree(proc->context);
    }
    
    if (proc->page_directory) {
        kfree(proc->page_directory);
    }
    
    /* Remove from queues */
    if (proc->state == PROCESS_READY) {
        remove_from_ready_queue(proc);
    }
    
    /* Remove from process list */
    if (proc->prev) {
        proc->prev->next = proc->next;
    } else {
        process_list = proc->next;
    }
    
    if (proc->next) {
        proc->next->prev = proc->prev;
    }
    
    /* If this was the current process, schedule next */
    if (proc == current_process) {
        current_process = NULL;
        process_schedule();
    }
    
    kfree(proc);
    return 0;
}

/* Get current process */
struct process *process_get_current(void) {
    return current_process;
}

/* Find process by PID */
struct process *process_find_by_pid(uint32_t pid) {
    struct process *proc = process_list;
    
    while (proc) {
        if (proc->pid == pid) {
            return proc;
        }
        proc = proc->next;
    }
    
    return NULL;
}

/* Get process statistics */
void process_get_stats(uint32_t *total_processes, uint32_t *running_processes, 
                      uint32_t *zombie_processes) {
    uint32_t total = 0, running = 0, zombie = 0;
    
    struct process *proc = process_list;
    while (proc) {
        total++;
        switch (proc->state) {
            case PROCESS_RUNNING:
            case PROCESS_READY:
                running++;
                break;
            case PROCESS_ZOMBIE:
                zombie++;
                break;
            default:
                break;
        }
        proc = proc->next;
    }
    
    if (total_processes) *total_processes = total;
    if (running_processes) *running_processes = running;
    if (zombie_processes) *zombie_processes = zombie;
}

/* Process list for debugging */
void process_list_all(void) {
    debug_print("\n=== Process List ===\n");
    debug_print("PID\tPPID\tState\tPriority\tName\t\tSecurity Level\n");
    debug_print("---\t----\t-----\t--------\t----\t\t--------------\n");
    
    struct process *proc = process_list;
    while (proc) {
        const char *state_names[] = {"READY", "RUNNING", "BLOCKED", "ZOMBIE", "TERMINATED"};
        debug_print("%d\t%d\t%s\t%d\t\t%s\t\t%d\n",
                   proc->pid, proc->ppid, 
                   state_names[proc->state], 
                   proc->priority, 
                   proc->name,
                   proc->security_level);
        proc = proc->next;
    }
    
    debug_print("===================\n\n");
}

/* Timer interrupt handler for scheduling */
void scheduler_timer_interrupt(void) {
    static uint64_t last_schedule = 0;
    
    /* Schedule every 10ms (100Hz) */
    if (scheduler_ticks - last_schedule >= 10) {
        last_schedule = scheduler_ticks;
        
        /* Update current process CPU time */
        if (current_process) {
            current_process->cpu_time++;
        }
        
        /* Preemptive scheduling */
        process_schedule();
    }
}

/* Process exit handler */
void process_exit(int status) {
    if (!current_process) {
        return;
    }
    
    debug_print("Process %d (%s) exiting with status %d\n", 
               current_process->pid, current_process->name, status);
    
    security_audit_log("PROCESS_EXIT", current_process->pid, current_process->name);
    
    /* Set to zombie state for parent to collect */
    current_process->state = PROCESS_ZOMBIE;
    
    /* Schedule next process */
    process_schedule();
}