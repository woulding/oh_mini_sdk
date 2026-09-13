/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal interrupt source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "securec.h"
#include "soc_osal.h"
#include "drval_irq.h"
#include "osal_inner.h"

int osal_irq_request(unsigned int irq, osal_irq_handler irq_handler, osal_irq_handler thread_handler,
    const char *name, void *dev)
{
    return drval_irq_request_irq(irq, irq_handler, thread_handler, name, dev);
}

void osal_irq_free(unsigned int irq, void *dev)
{
    drval_irq_free_irq(irq, dev);
}

int osal_in_interrupt(void)
{
    return drval_irq_in_interrupt();
}
