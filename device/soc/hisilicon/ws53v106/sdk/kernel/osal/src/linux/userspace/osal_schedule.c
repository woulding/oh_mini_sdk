/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal schedule source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <sched.h>
#include "soc_osal.h"

void osal_yield(void)
{
    sched_yield();
}
