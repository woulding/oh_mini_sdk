/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal string source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "soc_osal.h"
#include "osal_inner.h"

int osal_strcmp(const char *s1, const char *s2)
{
    return strcmp(s1, s2);
}
int osal_strncmp(const char *s1, const char *s2, unsigned long size)
{
    if (s1 == NULL || s2 == NULL) {
        return OSAL_FAILURE;
    }
    return strncmp(s1, s2, size);
}

int osal_strcasecmp(const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}

int osal_strncasecmp(const char *s1, const char *s2, unsigned long size)
{
    return strncasecmp(s1, s2, size);
}

char *osal_strchr(const char *s, int n)
{
    return strchr(s, n);
}

char *osal_strnchr(const char *s, int count, int c)
{
    for (; (count--) != 0 && *s != '\0'; ++s) {
        if (*s == (char)c) {
            return (char *)s;
        }
    }
    return NULL;
}

char *osal_strrchr(const char *s, int c)
{
    return strrchr(s, c);
}

char *osal_strstr(const char *s1, const char *s2)
{
    return strstr(s1, s2);
}

int osal_strlen(const char *s)
{
    return (int)strlen(s);
}

int osal_strnlen(const char *s, int size)
{
    return (int)strnlen(s, (size_t)size);
}

char *osal_strpbrk(const char *s1, const char *s2)
{
    return strpbrk(s1, s2);
}

char *osal_strsep(char **s, const char *ct)
{
    return strsep(s, ct);
}

int osal_strspn(const char *s, const char *accept)
{
    return (int)strspn(s, accept);
}

int osal_strcspn(const char *s, const char *reject)
{
    return (int)strcspn(s, reject);
}

int osal_memcmp(const void *cs, const void *ct, int count)
{
    return memcmp(cs, ct, count);
}

void *osal_memchr(const void *s, int c, int n)
{
    return memchr(s, c, n);
}

void *osal_memchr_inv(const void *start, int c, int bytes)
{
    if (start == NULL) {
        osal_log("error param.\n");
        return NULL;
    }

    const unsigned char *p = start;
    while (bytes-- != 0) {
            if ((unsigned char)c != *p++) {
            return (void *)(p - 1);
        }
    }

    return NULL;
}

unsigned long long osal_strtoull(const char *cp, char **endp, unsigned int base)
{
    return strtoull(cp, endp, (int)base);
}

unsigned long osal_strtoul(const char *cp, char **endp, unsigned int base)
{
    return strtoul(cp, endp, (int)base);
}

long osal_strtol(const char *cp, char **endp, unsigned int base)
{
    return strtol(cp, endp, (int)base);
}

long long osal_strtoll(const char *cp, char **endp, unsigned int base)
{
    return strtoll(cp, endp, (int)base);
}
