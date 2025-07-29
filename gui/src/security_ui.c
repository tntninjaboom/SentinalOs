/*
 * SentinalOS Pentagon-Level Security UI
 * User Authentication and Security Event Management
 */

#include "sentinal_gui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <termios.h>

/* Security event queue */
#define MAX_SECURITY_EVENTS 64

static struct gui_event security_event_queue[MAX_SECURITY_EVENTS];
static int event_queue_head = 0;
static int event_queue_tail = 0;
static int event_queue_count = 0;

/* Pentagon-level user authentication */
static int authenticate_user(struct gui_security_manager *manager) {
    char username[64];
    char password[128];
    struct termios old_flags, new_flags;
    
    printf("\n");
    printf("████████╗ ██████╗ ██████╗       ███████╗███████╗ ██████╗██████╗ ███████╗████████╗\n");
    printf("╚══██╔══╝██╔═══██╗██╔══██╗      ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝\n");
    printf("   ██║   ██║   ██║██████╔╝█████╗███████╗█████╗  ██║     ██████╔╝█████╗     ██║   \n");
    printf("   ██║   ██║   ██║██╔═══╝ ╚════╝╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║   \n");
    printf("   ██║   ╚██████╔╝██║           ███████║███████╗╚██████╗██║  ██║███████╗   ██║   \n");
    printf("   ╚═╝    ╚═════╝ ╚═╝           ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   \n");
    printf("\n");
    printf("                    SENTINAL-OS Pentagon-Level Security Desktop\n");
    printf("                           Classification: TOP SECRET // SI\n");
    printf("                            *** AUTHORIZED USE ONLY ***\n");
    printf("\n");
    
    /* Get username */
    printf("Security Clearance Username: ");
    fflush(stdout);
    
    if (fgets(username, sizeof(username), stdin) == NULL) {
        return -1;
    }
    
    /* Remove newline */
    size_t len = strlen(username);
    if (len > 0 && username[len - 1] == '\n') {
        username[len - 1] = '\0';
    }
    
    /* Get password without echo */
    printf("Pentagon Access Code: ");
    fflush(stdout);
    
    /* Disable echo */
    tcgetattr(STDIN_FILENO, &old_flags);
    new_flags = old_flags;
    new_flags.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_flags);
    
    if (fgets(password, sizeof(password), stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_flags);
        return -1;
    }
    
    /* Restore echo */
    tcsetattr(STDIN_FILENO, TCSANOW, &old_flags);
    printf("\n");
    
    /* Remove newline */
    len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }
    
    printf("\n[SECURITY] Validating Pentagon-level credentials...\n");
    sleep(1); /* Simulate authentication delay */
    
    /* Simple authentication (in production, use proper PAM/Kerberos) */
    if (strcmp(username, "pentagon_admin") == 0 && strcmp(password, "TopSecret2024!") == 0) {
        manager->user_clearance = GUI_PENTAGON;
        printf("[SECURITY] Authentication successful - Pentagon clearance granted\n");
    } else if (strcmp(username, "secret_user") == 0 && strcmp(password, "Secret123!") == 0) {
        manager->user_clearance = GUI_SECRET;
        printf("[SECURITY] Authentication successful - Secret clearance granted\n");
    } else if (strcmp(username, "conf_user") == 0 && strcmp(password, "Conf456!") == 0) {
        manager->user_clearance = GUI_CONFIDENTIAL;
        printf("[SECURITY] Authentication successful - Confidential clearance granted\n");
    } else {
        manager->user_clearance = GUI_UNCLASSIFIED;
        printf("[SECURITY] Authentication failed - Unclassified access only\n");
        
        /* Log failed authentication */
        gui_log_security_event(manager, "AUTH_FAILURE", username);
        return -1;
    }
    
    /* Clear password from memory */
    memset(password, 0, sizeof(password));
    
    /* Log successful authentication */
    char details[128];
    snprintf(details, sizeof(details), "User: %s, Clearance: %d", username, manager->user_clearance);
    gui_log_security_event(manager, "AUTH_SUCCESS", details);
    
    return 0;
}

/* Add security event to queue */
static int add_security_event(gui_event_type_t type, const char *message) {
    if (event_queue_count >= MAX_SECURITY_EVENTS) {
        return -1; /* Queue full */
    }
    
    struct gui_event *event = &security_event_queue[event_queue_tail];
    
    event->type = type;
    event->window_id = 0;
    event->timestamp = time(NULL);
    
    if (type == GUI_EVENT_SECURITY_ALERT) {
        event->data.security.violation_level = GUI_TOP_SECRET;
        strncpy(event->data.security.message, message, 127);
        event->data.security.message[127] = '\0';
    }
    
    event_queue_tail = (event_queue_tail + 1) % MAX_SECURITY_EVENTS;
    event_queue_count++;
    
    return 0;
}

/* Poll for GUI events */
int gui_poll_events(struct gui_security_manager *manager, struct gui_event *event) {
    if (!manager || !event) {
        return -1;
    }
    
    /* Check security event queue first */
    if (event_queue_count > 0) {
        *event = security_event_queue[event_queue_head];
        event_queue_head = (event_queue_head + 1) % MAX_SECURITY_EVENTS;
        event_queue_count--;
        return 1; /* Event available */
    }
    
    /* In real system, poll keyboard/mouse/network events */
    /* For demo, generate synthetic events occasionally */
    static int event_counter = 0;
    event_counter++;
    
    if (event_counter % 100 == 0) {
        /* Generate synthetic security alert */
        add_security_event(GUI_EVENT_SECURITY_ALERT, "Routine security scan completed");
        
        if (event_queue_count > 0) {
            *event = security_event_queue[event_queue_head];
            event_queue_head = (event_queue_head + 1) % MAX_SECURITY_EVENTS;
            event_queue_count--;
            return 1;
        }
    }
    
    return 0; /* No events */
}

/* Handle GUI events with security awareness */
int gui_handle_event(struct gui_security_manager *manager, const struct gui_event *event) {
    if (!manager || !event) {
        return -1;
    }
    
    switch (event->type) {
        case GUI_EVENT_KEY_PRESS:
            /* Log key events for high-classification windows */
            if (manager->secure_mode) {
                gui_log_security_event(manager, "KEY_PRESS", "Secure input detected");
            }
            break;
            
        case GUI_EVENT_MOUSE_CLICK:
            /* Verify mouse events for window focus changes */
            gui_log_security_event(manager, "MOUSE_CLICK", "Window interaction");
            break;
            
        case GUI_EVENT_WINDOW_CLOSE:
            /* Ensure proper cleanup of classified windows */
            gui_log_security_event(manager, "WINDOW_CLOSE", "Classified window closed");
            break;
            
        case GUI_EVENT_SECURITY_ALERT:
            /* Handle security violations */
            printf("[SECURITY_ALERT] Classification: %d, Message: %s\n",
                   event->data.security.violation_level,
                   event->data.security.message);
            
            /* In production, trigger security response procedures */
            if (event->data.security.violation_level >= GUI_SECRET) {
                printf("[SECURITY] Initiating security response protocol\n");
                /* Lock workstation, notify security team, etc. */
            }
            break;
            
        default:
            break;
    }
    
    return 0;
}

/* Initialize security UI system */
int gui_init_security_ui(struct gui_security_manager *manager) {
    if (!manager) {
        return -1;
    }
    
    printf("[SECURITY] Initializing Pentagon-level security interface...\n");
    
    /* Authenticate user */
    if (authenticate_user(manager) != 0) {
        printf("[SECURITY] Authentication required for GUI access\n");
        return -1;
    }
    
    /* Initialize security event monitoring */
    event_queue_head = 0;
    event_queue_tail = 0;
    event_queue_count = 0;
    
    /* Enable secure mode by default */
    manager->secure_mode = true;
    
    printf("[SECURITY] Security UI initialized - Clearance level: %d\n", manager->user_clearance);
    
    /* Add initial security event */
    add_security_event(GUI_EVENT_SECURITY_ALERT, "Pentagon-level desktop session started");
    
    return 0;
}

/* Display security status window */
int gui_show_security_status(struct gui_security_manager *manager) {
    if (!manager) {
        return -1;
    }
    
    /* Create security status window */
    int status_window = gui_create_window(manager, 50, 100, 400, 300,
                                         "Security Status", GUI_SECRET);
    
    if (status_window < 0) {
        return -1;
    }
    
    /* Find the window */
    struct sentinal_window *window = NULL;
    for (int i = 0; i < MAX_WINDOWS; i++) {
        if (manager->windows[i].window_id == status_window) {
            window = &manager->windows[i];
            break;
        }
    }
    
    if (!window) {
        return -1;
    }
    
    /* Draw security status information */
    gui_draw_rectangle(window, 0, 24, window->width, window->height - 24, GUI_COLOR_BLACK);
    
    char status_text[512];
    snprintf(status_text, sizeof(status_text),
             "PENTAGON-LEVEL SECURITY STATUS\n"
             "\n"
             "Session ID: %u\n"
             "User Clearance: %d\n"
             "Secure Mode: %s\n"
             "Active Windows: %d\n"
             "Security Events: %d\n"
             "\n"
             "*** CLASSIFIED SYSTEM ***\n"
             "*** AUTHORIZED USE ONLY ***",
             manager->session_id,
             manager->user_clearance,
             manager->secure_mode ? "ENABLED" : "DISABLED",
             manager->active_windows,
             event_queue_count);
    
    gui_draw_text(window, 10, 40, status_text, GUI_COLOR_GREEN);
    
    return status_window;
}

/* Shutdown security UI with proper cleanup */
int gui_shutdown_security_ui(struct gui_security_manager *manager) {
    if (!manager) {
        return -1;
    }
    
    printf("[SECURITY] Initiating secure shutdown...\n");
    
    /* Log shutdown event */
    gui_log_security_event(manager, "SYSTEM_SHUTDOWN", "Pentagon-level desktop session ended");
    
    /* Clear all windows */
    for (int i = 0; i < MAX_WINDOWS; i++) {
        if (manager->windows[i].window_id != 0) {
            gui_destroy_window(manager, manager->windows[i].window_id);
        }
    }
    
    /* Clear security event queue */
    memset(security_event_queue, 0, sizeof(security_event_queue));
    event_queue_head = 0;
    event_queue_tail = 0;
    event_queue_count = 0;
    
    /* Clear security manager */
    memset(manager, 0, sizeof(struct gui_security_manager));
    
    printf("[SECURITY] Pentagon-level desktop shutdown complete\n");
    
    return 0;
}