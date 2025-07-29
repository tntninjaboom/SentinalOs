#ifndef _STDLIB_H
#define _STDLIB_H

#include <stddef.h>

/* Memory management */
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

/* Program termination */
void abort(void) __attribute__((noreturn));
void exit(int status) __attribute__((noreturn));

/* String to number conversion */
int atoi(const char *nptr);
long atol(const char *nptr);
long long atoll(const char *nptr);
double atof(const char *nptr);

long strtol(const char *nptr, char **endptr, int base);
unsigned long strtoul(const char *nptr, char **endptr, int base);
long long strtoll(const char *nptr, char **endptr, int base);
unsigned long long strtoull(const char *nptr, char **endptr, int base);

/* Absolute value */
int abs(int j);
long labs(long j);
long long llabs(long long j);

/* Division */
typedef struct {
    int quot;
    int rem;
} div_t;

typedef struct {
    long quot;
    long rem;
} ldiv_t;

typedef struct {
    long long quot;
    long long rem;
} lldiv_t;

div_t div(int numer, int denom);
ldiv_t ldiv(long numer, long denom);
lldiv_t lldiv(long long numer, long long denom);

/* Random numbers */
int rand(void);
void srand(unsigned int seed);

#define RAND_MAX 32767

/* Environment */
char *getenv(const char *name);
int putenv(char *string);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);

/* System */
int system(const char *command);

/* Constants */
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* Maximum values */
#define MB_CUR_MAX 1

#endif /* _STDLIB_H */