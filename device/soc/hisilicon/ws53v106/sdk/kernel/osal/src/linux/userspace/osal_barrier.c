/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal barrier source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include "soc_osal.h"
#include "osal_inner.h"

#define isb(option) __asm__ __volatile__ ("isb " #option : : : "memory")
#define dsb(option) __asm__ __volatile__ ("dsb " #option : : : "memory")
#define dmb(option) __asm__ __volatile__ ("dmb " #option : : : "memory")

void osal_mb(void)
{
#ifdef USER_BIT_64
    dsb(sy);
#else
    dsb();
#endif
}

void osal_rmb(void)
{
#ifdef USER_BIT_64
    dsb(ld);
#else
    dsb();
#endif
}

void osal_wmb(void)
{
    dsb(st);
}

void osal_smp_mb(void)
{
    dmb(ish);
}

void osal_smp_rmb(void)
{
#ifdef USER_BIT_64
    dmb(ishld);
#else
    dmb(ish);
#endif
}

void osal_smp_wmb(void)
{
    dmb(ishst);
}

void osal_isb(void)
{
    isb();
}

void osal_dsb(void)
{
#ifdef USER_BIT_64
    dsb(sy);
#else
    dsb();
#endif
}

void osal_dmb(void)
{
#ifdef USER_BIT_64
    dmb(sy);
#else
    dmb();
#endif
}
