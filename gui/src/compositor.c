/*
 * SentinalOS Pentagon-Level Compositor
 * Secure Window Composition with Classification Awareness
 */

#include "sentinal_gui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* External framebuffer access */
extern uint32_t *framebuffer;
extern uint32_t screen_width;
extern uint32_t screen_height;

/* Simple font rendering (8x16 bitmap font) */
static const uint8_t font_8x16[128][16] = {
    /* ASCII character bitmaps - simplified for demonstration */
    [' '] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['S'] = {0x3C,0x42,0x40,0x40,0x3C,0x02,0x02,0x42,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['E'] = {0x7E,0x40,0x40,0x40,0x7C,0x40,0x40,0x40,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['N'] = {0x42,0x62,0x52,0x4A,0x46,0x42,0x42,0x42,0x42,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['T'] = {0x7E,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['I'] = {0x3E,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x3E,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['A'] = {0x18,0x24,0x42,0x42,0x7E,0x42,0x42,0x42,0x42,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['L'] = {0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['-'] = {0x00,0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['O'] = {0x3C,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['G'] = {0x3C,0x42,0x40,0x40,0x4E,0x42,0x42,0x42,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['U'] = {0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['R'] = {0x7C,0x42,0x42,0x42,0x7C,0x48,0x44,0x42,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['D'] = {0x78,0x44,0x42,0x42,0x42,0x42,0x42,0x44,0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    [':'] = {0x00,0x00,0x18,0x18,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['0'] = {0x3C,0x42,0x46,0x4A,0x52,0x62,0x42,0x42,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['1'] = {0x08,0x18,0x08,0x08,0x08,0x08,0x08,0x08,0x3E,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['2'] = {0x3C,0x42,0x02,0x04,0x08,0x10,0x20,0x40,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
};

/* Draw pixel with bounds checking */
int gui_draw_pixel(struct sentinal_window *window, uint32_t x, uint32_t y, uint32_t color) {
    if (!window || !window->framebuffer) {
        return -1;
    }
    
    if (x >= window->width || y >= window->height) {
        return -1;
    }
    
    window->framebuffer[y * window->width + x] = color;
    return 0;
}

/* Draw filled rectangle */
int gui_draw_rectangle(struct sentinal_window *window,
                      uint32_t x, uint32_t y, uint32_t width, uint32_t height,
                      uint32_t color) {
    if (!window) {
        return -1;
    }
    
    for (uint32_t iy = y; iy < y + height && iy < window->height; iy++) {
        for (uint32_t ix = x; ix < x + width && ix < window->width; ix++) {
            gui_draw_pixel(window, ix, iy, color);
        }
    }
    
    return 0;
}

/* Draw text using bitmap font */
int gui_draw_text(struct sentinal_window *window,
                 uint32_t x, uint32_t y, const char *text, uint32_t color) {
    if (!window || !text) {
        return -1;
    }
    
    uint32_t start_x = x;
    
    for (const char *c = text; *c; c++) {
        if (*c == '\n') {
            y += 16;
            x = start_x;
            continue;
        }
        
        /* Get character bitmap */
        const uint8_t *char_bitmap = font_8x16[(uint8_t)*c];
        
        /* Draw character */
        for (int row = 0; row < 16; row++) {
            uint8_t row_data = char_bitmap[row];
            for (int col = 0; col < 8; col++) {
                if (row_data & (0x80 >> col)) {
                    gui_draw_pixel(window, x + col, y + row, color);
                }
            }
        }
        
        x += 8; /* Character width */
    }
    
    return 0;
}

/* Draw classification banner at top of window */
int gui_draw_classification_banner(struct sentinal_window *window) {
    if (!window) {
        return -1;
    }
    
    /* Determine banner color based on classification */
    uint32_t banner_color;
    switch (window->classification) {
        case GUI_UNCLASSIFIED: banner_color = GUI_COLOR_UNCLASSIFIED; break;
        case GUI_CONFIDENTIAL: banner_color = GUI_COLOR_CONFIDENTIAL; break;
        case GUI_SECRET: banner_color = GUI_COLOR_SECRET; break;
        case GUI_TOP_SECRET: banner_color = GUI_COLOR_TOP_SECRET; break;
        case GUI_PENTAGON: banner_color = GUI_COLOR_PENTAGON; break;
        default: banner_color = GUI_COLOR_GRAY; break;
    }
    
    /* Draw banner rectangle */
    gui_draw_rectangle(window, 0, 0, window->width, 24, banner_color);
    
    /* Draw classification text */
    char banner_text[128];
    snprintf(banner_text, sizeof(banner_text), "SENTINAL-OS :: %s :: %s",
             window->classification_label, window->title);
    
    gui_draw_text(window, 8, 4, banner_text, GUI_COLOR_WHITE);
    
    return 0;
}

/* Composite all visible windows to screen */
int gui_composite_scene(struct gui_security_manager *manager) {
    if (!manager || !framebuffer) {
        return -1;
    }
    
    /* Clear screen to black */
    for (uint32_t i = 0; i < screen_width * screen_height; i++) {
        framebuffer[i] = GUI_COLOR_BLACK;
    }
    
    /* Draw Pentagon-level system info at top of screen */
    char system_banner[256];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    snprintf(system_banner, sizeof(system_banner),
             "SENTINAL-OS :: PENTAGON-LEVEL SECURE DESKTOP :: %02d:%02d:%02d :: SESSION: %u",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             manager->session_id);
    
    /* Draw system banner at top of screen */
    for (uint32_t y = 0; y < 24; y++) {
        for (uint32_t x = 0; x < screen_width; x++) {
            framebuffer[y * screen_width + x] = GUI_COLOR_PENTAGON;
        }
    }
    
    /* Draw system banner text (simplified) */
    uint32_t banner_x = 16;
    uint32_t banner_y = 4;
    for (const char *c = system_banner; *c && banner_x < screen_width - 8; c++) {
        const uint8_t *char_bitmap = font_8x16[(uint8_t)*c];
        
        for (int row = 0; row < 16; row++) {
            uint8_t row_data = char_bitmap[row];
            for (int col = 0; col < 8; col++) {
                if (row_data & (0x80 >> col)) {
                    uint32_t pixel_x = banner_x + col;
                    uint32_t pixel_y = banner_y + row;
                    if (pixel_x < screen_width && pixel_y < screen_height) {
                        framebuffer[pixel_y * screen_width + pixel_x] = GUI_COLOR_WHITE;
                    }
                }
            }
        }
        banner_x += 8;
    }
    
    /* Composite visible windows */
    for (int i = 0; i < MAX_WINDOWS; i++) {
        struct sentinal_window *window = &manager->windows[i];
        
        if (window->window_id == 0 || !window->visible) {
            continue;
        }
        
        /* Draw classification banner for window */
        gui_draw_classification_banner(window);
        
        /* Blit window to screen framebuffer */
        for (uint32_t wy = 0; wy < window->height; wy++) {
            for (uint32_t wx = 0; wx < window->width; wx++) {
                uint32_t screen_x = window->x + wx;
                uint32_t screen_y = window->y + wy + 24; /* Offset for system banner */
                
                if (screen_x < screen_width && screen_y < screen_height) {
                    uint32_t pixel = window->framebuffer[wy * window->width + wx];
                    framebuffer[screen_y * screen_width + screen_x] = pixel;
                }
            }
        }
        
        /* Draw window border with classification color */
        uint32_t border_color;
        switch (window->classification) {
            case GUI_UNCLASSIFIED: border_color = GUI_COLOR_UNCLASSIFIED; break;
            case GUI_CONFIDENTIAL: border_color = GUI_COLOR_CONFIDENTIAL; break;
            case GUI_SECRET: border_color = GUI_COLOR_SECRET; break;
            case GUI_TOP_SECRET: border_color = GUI_COLOR_TOP_SECRET; break;
            case GUI_PENTAGON: border_color = GUI_COLOR_PENTAGON; break;
            default: border_color = GUI_COLOR_WHITE; break;
        }
        
        /* Draw border */
        for (uint32_t x = window->x; x < window->x + window->width && x < screen_width; x++) {
            if (window->y + 24 < screen_height) {
                framebuffer[(window->y + 24) * screen_width + x] = border_color;
            }
            if (window->y + window->height + 24 < screen_height) {
                framebuffer[(window->y + window->height + 24) * screen_width + x] = border_color;
            }
        }
        
        for (uint32_t y = window->y + 24; y < window->y + window->height + 24 && y < screen_height; y++) {
            if (window->x < screen_width) {
                framebuffer[y * screen_width + window->x] = border_color;
            }
            if (window->x + window->width < screen_width) {
                framebuffer[y * screen_width + window->x + window->width] = border_color;
            }
        }
        
        /* Add secure input indicator for high-classification windows */
        if (window->secure_input && window->active) {
            /* Draw secure input indicator (lock symbol) */
            uint32_t lock_x = window->x + window->width - 20;
            uint32_t lock_y = window->y + 28;
            
            for (int ly = 0; ly < 12; ly++) {
                for (int lx = 0; lx < 8; lx++) {
                    uint32_t screen_x = lock_x + lx;
                    uint32_t screen_y = lock_y + ly;
                    
                    if (screen_x < screen_width && screen_y < screen_height) {
                        /* Simple lock icon pattern */
                        if ((ly == 0 && lx >= 2 && lx <= 5) ||
                            (ly == 1 && (lx == 2 || lx == 5)) ||
                            (ly >= 2 && ly <= 4 && (lx == 1 || lx == 6)) ||
                            (ly >= 5)) {
                            framebuffer[screen_y * screen_width + screen_x] = GUI_COLOR_YELLOW;
                        }
                    }
                }
            }
        }
    }
    
    return 0;
}

/* Refresh display (in real system, would flush to hardware) */
int gui_refresh_display(struct gui_security_manager *manager) {
    if (!manager) {
        return -1;
    }
    
    /* In real system, this would trigger hardware refresh */
    printf("[GUI] Display refreshed - %d windows composited\n", manager->active_windows);
    
    return 0;
}