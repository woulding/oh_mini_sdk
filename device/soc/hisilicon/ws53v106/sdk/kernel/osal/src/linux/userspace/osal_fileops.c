/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal fileops source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "soc_osal.h" /* because of ioctl redefine, soc_osal.h should not be the first included file */
#include "osal_inner.h"

FILE *klib_fopen(const char *filename, int flags, int mode)
{
    FILE *filp = NULL;
    if (flags == OSAL_O_RDONLY) {
        filp = fopen(filename, "rb");
    } else if (flags == (OSAL_O_CREAT | OSAL_O_WRONLY)) {
        filp = fopen(filename, "wb");
    } else if (flags == (OSAL_O_CREAT | OSAL_O_RDWR)) {
        filp = fopen(filename, "wb+");
    } else if (flags == OSAL_O_RDWR) {
        filp = fopen(filename, "rb+");
    } else {
        osal_log("invalidate file flags.");
    }
    return filp;
}

void klib_fclose(FILE *filp)
{
    if (filp != NULL) {
        fclose(filp);
    }
    return;
}

int klib_fwrite(const char *buf, unsigned long len, FILE *filp)
{
    size_t writelen;

    if (filp == NULL) {
        return -ENOENT;
    }

    writelen = fwrite(buf, (size_t)len, 1, filp);
    return (int)writelen;
}

int klib_fread(char *buf, unsigned int len, FILE *filp)
{
    size_t readlen;

    if (filp == NULL) {
        return -ENOENT;
    }

    readlen = fread(buf, len, 1, filp);
    return (int)readlen;
}

void *osal_klib_fopen(const char *filename, int flags, int mode)
{
    return (void *)klib_fopen(filename, flags, mode);
}

void osal_klib_fclose(void *filp)
{
    klib_fclose((FILE *)filp);
}

int osal_klib_fwrite(const char *buf, unsigned long size, void *filp)
{
    return klib_fwrite(buf, size, (FILE *)filp);
}

int osal_klib_fread(char *buf, unsigned long size, void *filp)
{
    return klib_fread(buf, (unsigned int)size, (FILE *)filp);
}
