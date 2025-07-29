/*
 * Basic string functions for SentinalOS kernel
 */

#include "kernel.h"
#include <stdarg.h>

size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++) != '\0');
    return dest;
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) return 0;
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

char *strcat(char *dest, const char *src) {
    char *d = dest + strlen(dest);
    while ((*d++ = *src++) != '\0');
    return dest;
}

void *memset(void *s, int c, size_t n) {
    unsigned char *p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dest;
}

void *memmove(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}

/* Simple printf implementation */
static void print_string(char **buf, size_t *remaining, const char *s) {
    while (*s && *remaining > 1) {
        **buf = *s++;
        (*buf)++;
        (*remaining)--;
    }
}

static void print_number(char **buf, size_t *remaining, unsigned long long num, int base, int width, int flags) {
    char digits[] = "0123456789abcdef";
    char temp[32];
    int i = 0;
    
    if (num == 0) {
        temp[i++] = '0';
    } else {
        while (num > 0) {
            temp[i++] = digits[num % base];
            num /= base;
        }
    }
    
    /* Pad with zeros if needed */
    while (i < width && *remaining > 1) {
        **buf = '0';
        (*buf)++;
        (*remaining)--;
        width--;
    }
    
    /* Reverse and print */
    while (i > 0 && *remaining > 1) {
        **buf = temp[--i];
        (*buf)++;
        (*remaining)--;
    }
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list args) {
    char *start = buf;
    size_t remaining = size;
    
    while (*fmt && remaining > 1) {
        if (*fmt != '%') {
            *buf++ = *fmt++;
            remaining--;
            continue;
        }
        
        fmt++; /* Skip '%' */
        
        /* Parse flags and width */
        int flags = 0;
        int width = 0;
        
        /* Simple format parsing */
        if (*fmt >= '0' && *fmt <= '9') {
            width = *fmt++ - '0';
        }
        
        switch (*fmt++) {
            case 'c': {
                int c = va_arg(args, int);
                if (remaining > 1) {
                    *buf++ = c;
                    remaining--;
                }
                break;
            }
            case 's': {
                const char *s = va_arg(args, const char*);
                if (!s) s = "(null)";
                print_string(&buf, &remaining, s);
                break;
            }
            case 'd':
            case 'i': {
                int num = va_arg(args, int);
                if (num < 0) {
                    if (remaining > 1) {
                        *buf++ = '-';
                        remaining--;
                    }
                    num = -num;
                }
                print_number(&buf, &remaining, num, 10, width, flags);
                break;
            }
            case 'u': {
                unsigned int num = va_arg(args, unsigned int);
                print_number(&buf, &remaining, num, 10, width, flags);
                break;
            }
            case 'x': {
                unsigned int num = va_arg(args, unsigned int);
                print_number(&buf, &remaining, num, 16, width, flags);
                break;
            }
            case 'X': {
                unsigned int num = va_arg(args, unsigned int);
                print_number(&buf, &remaining, num, 16, width, flags);
                break;
            }
            case 'p': {
                void *ptr = va_arg(args, void*);
                print_string(&buf, &remaining, "0x");
                print_number(&buf, &remaining, (uintptr_t)ptr, 16, 16, flags);
                break;
            }
            case '%': {
                if (remaining > 1) {
                    *buf++ = '%';
                    remaining--;
                }
                break;
            }
            default:
                /* Unknown format, just print it */
                if (remaining > 1) {
                    *buf++ = fmt[-1];
                    remaining--;
                }
                break;
        }
    }
    
    if (remaining > 0) {
        *buf = '\0';
    }
    
    return buf - start;
}

int snprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(buf, size, fmt, args);
    va_end(args);
    return ret;
}