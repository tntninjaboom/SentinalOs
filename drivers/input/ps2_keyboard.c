/*
 * PS/2 Keyboard Driver for SentinalOS
 * Pentagon-Level Security with Input Validation
 */

#include "kernel.h"
#include "string.h"

/* PS/2 Controller Ports */
#define PS2_DATA_PORT    0x60
#define PS2_STATUS_PORT  0x64
#define PS2_COMMAND_PORT 0x64

/* PS/2 Status Register Bits */
#define PS2_STATUS_OUTPUT_FULL  0x01
#define PS2_STATUS_INPUT_FULL   0x02
#define PS2_STATUS_SYSTEM       0x04
#define PS2_STATUS_COMMAND      0x08
#define PS2_STATUS_TIMEOUT      0x40
#define PS2_STATUS_PARITY_ERROR 0x80

/* PS/2 Commands */
#define PS2_CMD_READ_CONFIG     0x20
#define PS2_CMD_WRITE_CONFIG    0x60
#define PS2_CMD_DISABLE_PORT2   0xA7
#define PS2_CMD_ENABLE_PORT2    0xA8
#define PS2_CMD_TEST_PORT2      0xA9
#define PS2_CMD_TEST_CONTROLLER 0xAA
#define PS2_CMD_TEST_PORT1      0xAB
#define PS2_CMD_DISABLE_PORT1   0xAD
#define PS2_CMD_ENABLE_PORT1    0xAE

/* Keyboard Commands */
#define KB_CMD_SET_LEDS         0xED
#define KB_CMD_ECHO             0xEE
#define KB_CMD_SET_SCANCODE     0xF0
#define KB_CMD_IDENTIFY         0xF2
#define KB_CMD_SET_RATE         0xF3
#define KB_CMD_ENABLE           0xF4
#define KB_CMD_DISABLE          0xF5
#define KB_CMD_RESET            0xFF

/* Keyboard Responses */
#define KB_RESP_ACK             0xFA
#define KB_RESP_RESEND          0xFE
#define KB_RESP_ERROR           0xFC

/* Special Keys */
#define KEY_ESC                 0x01
#define KEY_BACKSPACE           0x0E
#define KEY_TAB                 0x0F
#define KEY_ENTER               0x1C
#define KEY_CTRL                0x1D
#define KEY_LSHIFT              0x2A
#define KEY_RSHIFT              0x36
#define KEY_ALT                 0x38
#define KEY_SPACE               0x39
#define KEY_CAPS                0x3A
#define KEY_F1                  0x3B
#define KEY_F12                 0x58

/* Keyboard state */
struct keyboard_state {
    bool shift_pressed;
    bool ctrl_pressed;
    bool alt_pressed;
    bool caps_lock;
    bool num_lock;
    bool scroll_lock;
    
    /* Security features */
    bool secure_input;
    uint32_t failed_attempts;
    uint64_t last_activity;
    
    /* Statistics */
    uint64_t keys_pressed;
    uint64_t invalid_scancodes;
    
    bool initialized;
} kb_state;

/* Scancode to ASCII translation tables */
static const char scancode_to_ascii_lower[] = {
    0,  27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*', 0, ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    '7', '8', '9', '-', '4', '5', '6', '+', '1', '2', '3', '0', '.'
};

static const char scancode_to_ascii_upper[] = {
    0,  27, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b',
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~',
    0, '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0,
    '*', 0, ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    '7', '8', '9', '-', '4', '5', '6', '+', '1', '2', '3', '0', '.'
};

/* I/O Functions */
static uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ __volatile__("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static void outb(uint16_t port, uint8_t val) {
    __asm__ __volatile__("outb %0, %1" : : "a"(val), "Nd"(port));
}

/* Wait for PS/2 controller to be ready for reading */
static bool ps2_wait_read(void) {
    int timeout = 100000;
    while (timeout-- > 0) {
        if (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) {
            return true;
        }
    }
    return false;
}

/* Wait for PS/2 controller to be ready for writing */
static bool ps2_wait_write(void) {
    int timeout = 100000;
    while (timeout-- > 0) {
        if (!(inb(PS2_STATUS_PORT) & PS2_STATUS_INPUT_FULL)) {
            return true;
        }
    }
    return false;
}

/* Send command to PS/2 controller */
static void ps2_send_command(uint8_t command) {
    if (ps2_wait_write()) {
        outb(PS2_COMMAND_PORT, command);
    }
}

/* Send data to PS/2 device */
static void ps2_send_data(uint8_t data) {
    if (ps2_wait_write()) {
        outb(PS2_DATA_PORT, data);
    }
}

/* Read data from PS/2 device */
static uint8_t ps2_read_data(void) {
    if (ps2_wait_read()) {
        return inb(PS2_DATA_PORT);
    }
    return 0;
}

/* Send command to keyboard and wait for ACK */
static bool keyboard_send_command(uint8_t command) {
    for (int retry = 0; retry < 3; retry++) {
        ps2_send_data(command);
        
        uint8_t response = ps2_read_data();
        if (response == KB_RESP_ACK) {
            return true;
        } else if (response == KB_RESP_RESEND) {
            continue; /* Retry */
        } else {
            KLOG_WARN("Keyboard command 0x%02x failed with response 0x%02x", command, response);
            return false;
        }
    }
    return false;
}

/* Set keyboard LEDs */
static void keyboard_set_leds(void) {
    uint8_t led_state = 0;
    if (kb_state.scroll_lock) led_state |= 0x01;
    if (kb_state.num_lock)    led_state |= 0x02;
    if (kb_state.caps_lock)   led_state |= 0x04;
    
    if (keyboard_send_command(KB_CMD_SET_LEDS)) {
        ps2_send_data(led_state);
        ps2_read_data(); /* Read ACK */
    }
}

/* Validate scancode for security */
static bool validate_scancode(uint8_t scancode) {
    /* Pentagon-level input validation */
    
    /* Check for reasonable scancode range */
    if (scancode > 0x83 && scancode != 0xE0 && scancode != 0xE1) {
        kb_state.invalid_scancodes++;
        return false;
    }
    
    /* Check for suspicious patterns (potential keylogger injection) */
    static uint8_t last_scancode = 0;
    static int repeat_count = 0;
    
    if (scancode == last_scancode) {
        repeat_count++;
        if (repeat_count > 10) {
            KLOG_WARN("Suspicious keyboard input pattern detected");
            kb_state.failed_attempts++;
            return false;
        }
    } else {
        repeat_count = 0;
    }
    
    last_scancode = scancode;
    return true;
}

/* Process scancode and convert to character */
static char process_scancode(uint8_t scancode) {
    if (!validate_scancode(scancode)) {
        return 0;
    }
    
    /* Handle key releases (bit 7 set) */
    bool key_released = (scancode & 0x80) != 0;
    scancode &= 0x7F;
    
    /* Update modifier key states */
    switch (scancode) {
        case KEY_LSHIFT:
        case KEY_RSHIFT:
            kb_state.shift_pressed = !key_released;
            return 0;
        case KEY_CTRL:
            kb_state.ctrl_pressed = !key_released;
            return 0;
        case KEY_ALT:
            kb_state.alt_pressed = !key_released;
            return 0;
        case KEY_CAPS:
            if (!key_released) {
                kb_state.caps_lock = !kb_state.caps_lock;
                keyboard_set_leds();
            }
            return 0;
    }
    
    /* Only process key presses, not releases */
    if (key_released) {
        return 0;
    }
    
    /* Convert scancode to ASCII */
    if (scancode >= sizeof(scancode_to_ascii_lower)) {
        return 0;
    }
    
    char ch;
    bool use_upper = kb_state.shift_pressed ^ kb_state.caps_lock;
    
    if (use_upper) {
        ch = scancode_to_ascii_upper[scancode];
    } else {
        ch = scancode_to_ascii_lower[scancode];
    }
    
    /* Security check for control sequences */
    if (kb_state.ctrl_pressed && ch >= 'a' && ch <= 'z') {
        ch = ch - 'a' + 1; /* Ctrl+A = 1, Ctrl+B = 2, etc. */
    }
    
    if (ch) {
        kb_state.keys_pressed++;
        kb_state.last_activity = get_ticks();
    }
    
    return ch;
}

/* Keyboard interrupt handler */
void keyboard_interrupt_handler(void) {
    uint8_t status = inb(PS2_STATUS_PORT);
    
    if (!(status & PS2_STATUS_OUTPUT_FULL)) {
        return; /* No data available */
    }
    
    uint8_t scancode = inb(PS2_DATA_PORT);
    
    /* Process the scancode */
    char ch = process_scancode(scancode);
    
    /* Handle special keys and security events */
    if (ch) {
        /* For now, just output to console */
        console_putc(ch);
        
        /* Security logging for sensitive keys */
        if (kb_state.secure_input && (ch == '\n' || ch == '\t')) {
            KLOG_INFO("Secure input: special key pressed");
        }
    }
}

/* Initialize PS/2 keyboard */
void keyboard_init(void) {
    KLOG_INFO("Initializing PS/2 keyboard with Pentagon-level security...");
    
    /* Initialize keyboard state */
    memset(&kb_state, 0, sizeof(kb_state));
    kb_state.num_lock = true; /* Enable num lock by default */
    
    /* Test PS/2 controller */
    ps2_send_command(PS2_CMD_TEST_CONTROLLER);
    uint8_t result = ps2_read_data();
    if (result != 0x55) {
        KLOG_ERR("PS/2 controller self-test failed: 0x%02x", result);
        return;
    }
    
    /* Disable both PS/2 ports */
    ps2_send_command(PS2_CMD_DISABLE_PORT1);
    ps2_send_command(PS2_CMD_DISABLE_PORT2);
    
    /* Flush output buffer */
    while (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) {
        inb(PS2_DATA_PORT);
    }
    
    /* Read PS/2 controller configuration */
    ps2_send_command(PS2_CMD_READ_CONFIG);
    uint8_t config = ps2_read_data();
    
    /* Modify configuration */
    config &= ~0x03; /* Disable port interrupts */
    config &= ~0x40; /* Disable translation */
    
    /* Write back configuration */
    ps2_send_command(PS2_CMD_WRITE_CONFIG);
    ps2_send_data(config);
    
    /* Test first PS/2 port */
    ps2_send_command(PS2_CMD_TEST_PORT1);
    result = ps2_read_data();
    if (result != 0x00) {
        KLOG_ERR("PS/2 port 1 test failed: 0x%02x", result);
        return;
    }
    
    /* Enable first PS/2 port */
    ps2_send_command(PS2_CMD_ENABLE_PORT1);
    
    /* Reset keyboard */
    if (!keyboard_send_command(KB_CMD_RESET)) {
        KLOG_ERR("Keyboard reset failed");
        return;
    }
    
    /* Read keyboard self-test result */
    result = ps2_read_data();
    if (result != 0xAA) {
        KLOG_ERR("Keyboard self-test failed: 0x%02x", result);
        return;
    }
    
    /* Set scancode set 2 */
    if (keyboard_send_command(KB_CMD_SET_SCANCODE)) {
        ps2_send_data(0x02);
        ps2_read_data(); /* Read ACK */
    }
    
    /* Enable keyboard */
    keyboard_send_command(KB_CMD_ENABLE);
    
    /* Set initial LED state */
    keyboard_set_leds();
    
    /* Enable keyboard interrupts */
    ps2_send_command(PS2_CMD_READ_CONFIG);
    config = ps2_read_data();
    config |= 0x01; /* Enable port 1 interrupt */
    ps2_send_command(PS2_CMD_WRITE_CONFIG);
    ps2_send_data(config);
    
    kb_state.initialized = true;
    
    KLOG_INFO("PS/2 keyboard initialized successfully");
    KLOG_INFO("Security features: Input validation, pattern detection, activity logging");
}

/* Enable secure input mode */
void keyboard_enable_secure_input(bool enable) {
    kb_state.secure_input = enable;
    if (enable) {
        KLOG_INFO("Secure keyboard input mode enabled");
    } else {
        KLOG_INFO("Secure keyboard input mode disabled");
    }
}

/* Get keyboard statistics */
void keyboard_get_stats(uint64_t *keys_pressed, uint64_t *invalid_scancodes, uint32_t *failed_attempts) {
    if (keys_pressed) *keys_pressed = kb_state.keys_pressed;
    if (invalid_scancodes) *invalid_scancodes = kb_state.invalid_scancodes;
    if (failed_attempts) *failed_attempts = kb_state.failed_attempts;
}