/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal debug source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdio.h>
#include <stdarg.h>
#include "soc_osal.h"

void osal_printk(const char *fmt, ...)
{
    va_list args;

    if (fmt == NULL) {
        return;
    }

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
