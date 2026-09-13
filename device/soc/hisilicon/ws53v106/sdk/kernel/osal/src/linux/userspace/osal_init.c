/*
 * Copyright (c) @CompanyNameMagicTag. 2020-2022. All rights reserved.
 * Description: osal main source file.
 * Create: 2020-07-30
 */

#include "osal_inner.h"
#include "soc_osal.h"
#include "osal_inner.h"

int osal_init(void)
{
    int ret;

    osal_user_device_init();
    ret = osal_user_proc_init();
    if (ret != OSAL_SUCCESS) {
        osal_user_device_exit();
        osal_log("osal_user_proc_init fail!\n");
        return OSAL_FAILURE;
    }

    return OSAL_SUCCESS;
}

void osal_exit(void)
{
    osal_user_proc_exit();
    osal_user_device_exit();
}
