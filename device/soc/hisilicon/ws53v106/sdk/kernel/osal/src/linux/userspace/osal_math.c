/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal math source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "soc_osal.h"
#include "osal_inner.h"

/* the result of u64/u32. */
unsigned long long osal_div_u64(unsigned long long dividend, unsigned int divisor)
{
    if (divisor == 0) {
        osal_printk("error: %s divisor cannot be zero.\n", __FUNCTION__);
        return OSAL_FAILURE;
    }
    return dividend / divisor;
}

/* the result of s64/s32. */
long long osal_div_s64(long long dividend, int divisor)
{
    if (divisor == 0) {
        osal_printk("error: %s divisor cannot be zero.\n", __FUNCTION__);
        return OSAL_FAILURE;
    }
    return dividend / divisor;
}

/* the result of u64/u64. */
unsigned long long osal_div64_u64(unsigned long long dividend, unsigned long long divisor)
{
    if (divisor == 0) {
        osal_printk("error: %s divisor cannot be zero.\n", __FUNCTION__);
        return OSAL_FAILURE;
    }
    return dividend / divisor;
}

/* the result of s64/s64. */
long long osal_div64_s64(long long dividend, long long divisor)
{
    if (divisor == 0) {
        osal_printk("error: %s divisor cannot be zero.\n", __FUNCTION__);
        return OSAL_FAILURE;
    }
    return dividend / divisor;
}

/* the remainder of u64/u32. */
unsigned long long osal_div_u64_rem(unsigned long long dividend, unsigned int divisor)
{
    if (divisor == 0) {
        osal_printk("error: %s divisor cannot be zero.\n", __FUNCTION__);
        return OSAL_FAILURE;
    }
    return dividend % divisor;
}

/* the remainder of s64/s32. */
long long osal_div_s64_rem(long long dividend, int divisor)
{
    if (divisor == 0) {
        osal_printk("error: %s divisor cannot be zero.\n", __FUNCTION__);
        return OSAL_FAILURE;
    }
    return dividend % divisor;
}

/* the remainder of u64/u64. */
unsigned long long osal_div64_u64_rem(unsigned long long dividend, unsigned long long divisor)
{
    if (divisor == 0) {
        osal_printk("error: %s divisor cannot be zero.\n", __FUNCTION__);
        return OSAL_FAILURE;
    }
    return dividend % divisor;
}

unsigned int osal_get_random_int(void)
{
    int fd = 0;
    unsigned int result = 0;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        osal_log("open /dev/urandom failed.\n");
        return OSAL_FAILURE;
    }
    read(fd, &result, sizeof(unsigned int));
    close(fd);
    return result;
}
