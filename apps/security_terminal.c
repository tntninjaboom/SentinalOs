/*
 * SentinalOS Pentagon-Level Security Terminal
 * Secure Command Interface with Classification Awareness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include "../gui/include/sentinal_gui.h"

#define MAX_COMMAND_LENGTH 512
#define MAX_ARGS 32
#define HISTORY_SIZE 100

/* Security context for terminal */
struct terminal_security {
    gui_classification_t clearance;
    uint32_t session_id;
    bool audit_mode;
    char current_dir[256];
    time_t session_start;
};

/* Command history */
static char command_history[HISTORY_SIZE][MAX_COMMAND_LENGTH];
static int history_count = 0;
static int history_index = 0;

/* Pentagon-level banner */
static void print_security_banner(struct terminal_security *sec) {
    printf("\n");
    printf("███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗    ████████╗███████╗██████╗ ███╗   ███╗\n");
    printf("██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║\n");
    printf("███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗         ██║   █████╗  ██████╔╝██╔████╔██║\n");
    printf("╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝         ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║\n");
    printf("███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗       ██║   ███████╗██║  ██║██║ ╚═╝ ██║\n");
    printf("╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝\n");
    printf("\n");
    printf("                     Pentagon-Level Secure Command Interface\n");
    printf("                          Classification: TOP SECRET // SI\n");
    printf("                           Session ID: %u | Clearance: %d\n", 
           sec->session_id, sec->clearance);
    printf("                            *** AUTHORIZED USE ONLY ***\n");
    printf("\n");
}

/* Log security events */
static void log_security_event(struct terminal_security *sec, const char *event, const char *command) {
    time_t now = time(NULL);
    FILE *audit_log = fopen("/var/log/sentinal_terminal_audit.log", "a");
    
    if (audit_log) {
        fprintf(audit_log, "[%ld] Session=%u Event=%s Command='%s' Clearance=%d\n",
                now, sec->session_id, event, command ? command : "", sec->clearance);
        fclose(audit_log);
    }
    
    printf("[AUDIT] %s: %s\n", event, command ? command : "");
}

/* Add command to history */
static void add_to_history(const char *command) {
    if (strlen(command) == 0) return;
    
    strncpy(command_history[history_count % HISTORY_SIZE], command, MAX_COMMAND_LENGTH - 1);
    command_history[history_count % HISTORY_SIZE][MAX_COMMAND_LENGTH - 1] = '\0';
    history_count++;
    history_index = history_count;
}

/* Show command history */
static void show_history(struct terminal_security *sec) {
    printf("Command History (Classification: %d):\n", sec->clearance);
    
    int start = (history_count > HISTORY_SIZE) ? history_count - HISTORY_SIZE : 0;
    int end = history_count;
    
    for (int i = start; i < end; i++) {
        printf("  %3d: %s\n", i + 1, command_history[i % HISTORY_SIZE]);
    }
}

/* Execute pentagon command */
static int execute_pentagon_command(struct terminal_security *sec, char **args) {
    if (!args[0]) return 0;
    
    /* Pentagon-level security commands */
    if (strcmp(args[0], "classify") == 0) {
        if (!args[1]) {
            printf("Usage: classify <level> - Set security classification\n");
            printf("Levels: 0=UNCLASSIFIED, 1=CONFIDENTIAL, 2=SECRET, 3=TOP_SECRET, 4=PENTAGON\n");
            return 0;
        }
        
        int new_level = atoi(args[1]);
        if (new_level < 0 || new_level > 4) {
            printf("Invalid classification level\n");
            return 0;
        }
        
        if (new_level > sec->clearance) {
            printf("Access denied: Insufficient clearance for level %d\n", new_level);
            log_security_event(sec, "ACCESS_DENIED", args[0]);
            return 0;
        }
        
        sec->clearance = new_level;
        printf("Classification level set to %d\n", new_level);
        log_security_event(sec, "CLASSIFY_CHANGE", args[1]);
        return 0;
    }
    
    if (strcmp(args[0], "secstat") == 0) {
        printf("Pentagon-Level Security Status:\n");
        printf("  Session ID: %u\n", sec->session_id);
        printf("  Clearance Level: %d\n", sec->clearance);
        printf("  Audit Mode: %s\n", sec->audit_mode ? "ENABLED" : "DISABLED");
        printf("  Current Directory: %s\n", sec->current_dir);
        printf("  Session Duration: %ld seconds\n", time(NULL) - sec->session_start);
        return 0;
    }
    
    if (strcmp(args[0], "audit") == 0) {
        if (!args[1]) {
            printf("Audit mode: %s\n", sec->audit_mode ? "ENABLED" : "DISABLED");
            return 0;
        }
        
        if (strcmp(args[1], "on") == 0) {
            sec->audit_mode = true;
            printf("Audit mode enabled\n");
            log_security_event(sec, "AUDIT_ENABLED", NULL);
        } else if (strcmp(args[1], "off") == 0) {
            sec->audit_mode = false;
            printf("Audit mode disabled\n");
            log_security_event(sec, "AUDIT_DISABLED", NULL);
        } else {
            printf("Usage: audit [on|off]\n");
        }
        return 0;
    }
    
    if (strcmp(args[0], "history") == 0) {
        show_history(sec);
        return 0;
    }
    
    if (strcmp(args[0], "clear") == 0) {
        printf("\033[2J\033[H"); /* Clear screen */
        print_security_banner(sec);
        return 0;
    }
    
    if (strcmp(args[0], "exit") == 0 || strcmp(args[0], "quit") == 0) {
        printf("Terminating Pentagon-level secure session...\n");
        log_security_event(sec, "SESSION_END", NULL);
        return 1; /* Exit code */
    }
    
    /* Standard UNIX commands with security awareness */
    if (strcmp(args[0], "ls") == 0) {
        printf("Directory listing (Classification: %d):\n", sec->clearance);
        /* Execute ls with security context */
        execvp("ls", args);
        return 0;
    }
    
    if (strcmp(args[0], "pwd") == 0) {
        printf("Current directory: %s (Classification: %d)\n", sec->current_dir, sec->clearance);
        return 0;
    }
    
    if (strcmp(args[0], "cd") == 0) {
        if (!args[1]) {
            strncpy(sec->current_dir, "/home", sizeof(sec->current_dir) - 1);
        } else {
            strncpy(sec->current_dir, args[1], sizeof(sec->current_dir) - 1);
        }
        sec->current_dir[sizeof(sec->current_dir) - 1] = '\0';
        
        if (chdir(sec->current_dir) == 0) {
            printf("Changed directory to: %s\n", sec->current_dir);
        } else {
            printf("Directory change failed\n");
        }
        return 0;
    }
    
    /* Pentagon tools integration */
    if (strcmp(args[0], "pentesting") == 0) {
        if (sec->clearance < GUI_SECRET) {
            printf("Access denied: Pentagon-level tools require SECRET clearance or higher\n");
            log_security_event(sec, "PENTESTING_DENIED", NULL);
            return 0;
        }
        
        printf("Launching Pentagon-level pentesting sandbox...\n");
        log_security_event(sec, "PENTESTING_LAUNCH", NULL);
        
        /* Execute pentesting sandbox */
        system("../pentesting/sandbox/pentesting_sandbox --list");
        return 0;
    }
    
    if (strcmp(args[0], "sentinal_send") == 0) {
        printf("Launching Pentagon-level secure file transfer...\n");
        log_security_event(sec, "SENTINAL_SEND_LAUNCH", NULL);
        
        /* Build command line for sentinal_send */
        char command[1024] = "../userland/sentinal_send/build/sentinal_send";
        for (int i = 1; args[i]; i++) {
            strcat(command, " ");
            strcat(command, args[i]);
        }
        
        system(command);
        return 0;
    }
    
    /* Help command */
    if (strcmp(args[0], "help") == 0) {
        printf("Pentagon-Level Security Terminal Commands:\n\n");
        printf("Security Commands:\n");
        printf("  classify <level>  - Set security classification level\n");
        printf("  secstat          - Show security status\n");
        printf("  audit [on|off]   - Enable/disable audit mode\n");
        printf("  history          - Show command history\n");
        printf("  clear            - Clear screen\n");
        printf("  exit/quit        - Exit secure terminal\n\n");
        printf("System Commands:\n");
        printf("  ls               - List directory contents\n");
        printf("  pwd              - Print working directory\n");
        printf("  cd <dir>         - Change directory\n\n");
        printf("Pentagon Tools:\n");
        printf("  pentesting       - Launch pentesting sandbox\n");
        printf("  sentinal_send    - Launch secure file transfer\n\n");
        printf("Standard Commands:\n");
        printf("  Any standard UNIX command with security context\n");
        return 0;
    }
    
    /* Execute standard command with security context */
    if (sec->audit_mode) {
        log_security_event(sec, "COMMAND_EXEC", args[0]);
    }
    
    pid_t pid = fork();
    if (pid == 0) {
        /* Child process */
        execvp(args[0], args);
        printf("Command not found: %s\n", args[0]);
        exit(1);
    } else if (pid > 0) {
        /* Parent process */
        int status;
        waitpid(pid, &status, 0);
        
        if (sec->audit_mode && WEXITSTATUS(status) != 0) {
            log_security_event(sec, "COMMAND_FAILED", args[0]);
        }
    } else {
        printf("Failed to execute command\n");
    }
    
    return 0;
}

/* Parse command line into arguments */
static int parse_command(char *command, char **args) {
    int argc = 0;
    char *token = strtok(command, " \t\n");
    
    while (token && argc < MAX_ARGS - 1) {
        args[argc++] = token;
        token = strtok(NULL, " \t\n");
    }
    
    args[argc] = NULL;
    return argc;
}

/* Main terminal loop */
int main(int argc, char *argv[]) {
    struct terminal_security sec = {0};
    char command[MAX_COMMAND_LENGTH];
    char *args[MAX_ARGS];
    
    /* Initialize security context */
    sec.clearance = GUI_PENTAGON; /* Default to Pentagon level */
    sec.session_id = rand() ^ (rand() << 16);
    sec.audit_mode = true;
    sec.session_start = time(NULL);
    strcpy(sec.current_dir, "/home");
    
    /* Display security banner */
    print_security_banner(&sec);
    
    /* Log session start */
    log_security_event(&sec, "SESSION_START", NULL);
    
    printf("Pentagon-level secure terminal ready. Type 'help' for commands.\n\n");
    
    /* Main command loop */
    while (1) {
        /* Display secure prompt */
        printf("[PENTAGON:%d]%s$ ", sec.clearance, sec.current_dir);
        fflush(stdout);
        
        /* Read command */
        if (!fgets(command, sizeof(command), stdin)) {
            break;
        }
        
        /* Remove newline */
        size_t len = strlen(command);
        if (len > 0 && command[len - 1] == '\n') {
            command[len - 1] = '\0';
        }
        
        /* Skip empty commands */
        if (strlen(command) == 0) {
            continue;
        }
        
        /* Add to history */
        add_to_history(command);
        
        /* Parse command */
        int argc = parse_command(command, args);
        if (argc == 0) {
            continue;
        }
        
        /* Execute command */
        int result = execute_pentagon_command(&sec, args);
        if (result == 1) {
            break; /* Exit requested */
        }
        
        printf("\n");
    }
    
    /* Clean shutdown */
    printf("Pentagon-level secure terminal session ended.\n");
    log_security_event(&sec, "SESSION_END", NULL);
    
    return 0;
}