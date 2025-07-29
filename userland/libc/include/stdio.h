#ifndef _STDIO_H
#define _STDIO_H

#include <stddef.h>
#include <stdarg.h>

/* File operations */
#define EOF (-1)
#define BUFSIZ 8192
#define FILENAME_MAX 256
#define FOPEN_MAX 256

/* File modes */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

/* Standard streams */
extern struct __FILE *stdin;
extern struct __FILE *stdout;
extern struct __FILE *stderr;

/* FILE structure */
typedef struct __FILE {
    int fd;
    int flags;
    int error;
    int eof;
    char *buffer;
    size_t buffer_size;
    size_t buffer_pos;
    size_t buffer_len;
} FILE;

/* File operations */
FILE *fopen(const char *filename, const char *mode);
FILE *fdopen(int fd, const char *mode);
int fclose(FILE *stream);
int fflush(FILE *stream);
void setbuf(FILE *stream, char *buffer);
int setvbuf(FILE *stream, char *buffer, int mode, size_t size);

/* Character I/O */
int fgetc(FILE *stream);
char *fgets(char *s, int size, FILE *stream);
int fputc(int c, FILE *stream);
int fputs(const char *s, FILE *stream);
int getc(FILE *stream);
int getchar(void);
char *gets(char *s);
int putc(int c, FILE *stream);
int putchar(int c);
int puts(const char *s);
int ungetc(int c, FILE *stream);

/* Block I/O */
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

/* File positioning */
int fgetpos(FILE *stream, fpos_t *pos);
int fseek(FILE *stream, long int offset, int whence);
int fsetpos(FILE *stream, const fpos_t *pos);
long int ftell(FILE *stream);
void rewind(FILE *stream);

/* Error handling */
void clearerr(FILE *stream);
int feof(FILE *stream);
int ferror(FILE *stream);
void perror(const char *s);

/* Formatted I/O */
int fprintf(FILE *stream, const char *format, ...);
int printf(const char *format, ...);
int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
int vfprintf(FILE *stream, const char *format, va_list ap);
int vprintf(const char *format, va_list ap);
int vsprintf(char *str, const char *format, va_list ap);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

int fscanf(FILE *stream, const char *format, ...);
int scanf(const char *format, ...);
int sscanf(const char *str, const char *format, ...);
int vfscanf(FILE *stream, const char *format, va_list ap);
int vscanf(const char *format, va_list ap);
int vsscanf(const char *str, const char *format, va_list ap);

/* File operations */
int remove(const char *filename);
int rename(const char *old, const char *new);
FILE *tmpfile(void);
char *tmpnam(char *s);

#endif /* _STDIO_H */