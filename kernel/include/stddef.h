#ifndef _STDDEF_H
#define _STDDEF_H

/* Standard definitions for kernel */

/* NULL pointer */
#ifndef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void*)0)
#endif
#endif

/* size_t type */
#ifndef _SIZE_T_DEFINED
#define _SIZE_T_DEFINED
typedef unsigned long size_t;
#endif

/* ptrdiff_t type */
#ifndef _PTRDIFF_T_DEFINED
#define _PTRDIFF_T_DEFINED
typedef long ptrdiff_t;
#endif

/* wchar_t type */
#ifndef _WCHAR_T_DEFINED
#define _WCHAR_T_DEFINED
typedef int wchar_t;
#endif

/* Offset of a structure member */
#define offsetof(type, member) __builtin_offsetof(type, member)

/* Maximum alignment */
#define _Alignas(x) __attribute__((aligned(x)))
#define _Alignof(x) __alignof__(x)

#endif /* _STDDEF_H */