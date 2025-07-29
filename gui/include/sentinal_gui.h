#ifndef _SENTINAL_GUI_H
#define _SENTINAL_GUI_H

#include <stdint.h>
#include <stdbool.h>

/* Pentagon-Level GUI Security Framework */

/* Window management */
#define MAX_WINDOWS 32
#define MAX_WINDOW_TITLE 64
#define MAX_CLASSIFICATION_LABEL 32

/* Security classification levels for GUI elements */
typedef enum {
    GUI_UNCLASSIFIED = 0,
    GUI_CONFIDENTIAL = 1,
    GUI_SECRET = 2,
    GUI_TOP_SECRET = 3,
    GUI_PENTAGON = 4
} gui_classification_t;

/* Window structure with security context */
struct sentinal_window {
    uint32_t window_id;
    uint32_t x, y, width, height;
    gui_classification_t classification;
    char title[MAX_WINDOW_TITLE];
    char classification_label[MAX_CLASSIFICATION_LABEL];
    uint32_t owner_pid;
    uint8_t security_flags;
    bool visible;
    bool active;
    bool secure_input;
    uint32_t *framebuffer;
};

/* GUI Security Manager */
struct gui_security_manager {
    uint8_t user_clearance;
    uint32_t session_id;
    bool secure_mode;
    uint32_t active_windows;
    struct sentinal_window windows[MAX_WINDOWS];
};

/* Pentagon-Level Color Scheme */
#define GUI_COLOR_BLACK         0x000000
#define GUI_COLOR_RED           0xFF0000
#define GUI_COLOR_GREEN         0x00FF00
#define GUI_COLOR_YELLOW        0xFFFF00
#define GUI_COLOR_BLUE          0x0000FF
#define GUI_COLOR_MAGENTA       0xFF00FF
#define GUI_COLOR_CYAN          0x00FFFF
#define GUI_COLOR_WHITE         0xFFFFFF
#define GUI_COLOR_GRAY          0x808080
#define GUI_COLOR_DARK_GRAY     0x404040

/* Security color coding */
#define GUI_COLOR_UNCLASSIFIED  GUI_COLOR_GREEN
#define GUI_COLOR_CONFIDENTIAL  GUI_COLOR_BLUE
#define GUI_COLOR_SECRET        GUI_COLOR_YELLOW
#define GUI_COLOR_TOP_SECRET    GUI_COLOR_RED
#define GUI_COLOR_PENTAGON      GUI_COLOR_MAGENTA

/* Function prototypes */

/* Window Management */
int gui_init_window_manager(struct gui_security_manager *manager);
int gui_create_window(struct gui_security_manager *manager, 
                     uint32_t x, uint32_t y, uint32_t width, uint32_t height,
                     const char *title, gui_classification_t classification);
int gui_destroy_window(struct gui_security_manager *manager, uint32_t window_id);
int gui_show_window(struct gui_security_manager *manager, uint32_t window_id);
int gui_hide_window(struct gui_security_manager *manager, uint32_t window_id);

/* Security Functions */
int gui_verify_access(const struct gui_security_manager *manager, 
                     uint32_t window_id, uint32_t requesting_pid);
int gui_set_security_context(struct sentinal_window *window, 
                            gui_classification_t classification);
int gui_validate_user_clearance(const struct gui_security_manager *manager,
                               gui_classification_t required_level);

/* Rendering Functions */
int gui_draw_pixel(struct sentinal_window *window, uint32_t x, uint32_t y, uint32_t color);
int gui_draw_rectangle(struct sentinal_window *window, 
                      uint32_t x, uint32_t y, uint32_t width, uint32_t height, 
                      uint32_t color);
int gui_draw_text(struct sentinal_window *window, 
                 uint32_t x, uint32_t y, const char *text, uint32_t color);
int gui_draw_classification_banner(struct sentinal_window *window);

/* Event Handling */
typedef enum {
    GUI_EVENT_KEY_PRESS,
    GUI_EVENT_KEY_RELEASE,
    GUI_EVENT_MOUSE_MOVE,
    GUI_EVENT_MOUSE_CLICK,
    GUI_EVENT_WINDOW_CLOSE,
    GUI_EVENT_SECURITY_ALERT
} gui_event_type_t;

struct gui_event {
    gui_event_type_t type;
    uint32_t window_id;
    uint32_t timestamp;
    union {
        struct {
            uint32_t keycode;
            uint32_t modifiers;
        } key;
        struct {
            uint32_t x, y;
            uint32_t buttons;
        } mouse;
        struct {
            gui_classification_t violation_level;
            char message[128];
        } security;
    } data;
};

int gui_poll_events(struct gui_security_manager *manager, struct gui_event *event);
int gui_handle_event(struct gui_security_manager *manager, const struct gui_event *event);

/* Compositor Functions */
int gui_composite_scene(struct gui_security_manager *manager);
int gui_refresh_display(struct gui_security_manager *manager);

/* Security Audit */
int gui_log_security_event(const struct gui_security_manager *manager,
                          const char *event, const char *details);

#endif /* _SENTINAL_GUI_H */