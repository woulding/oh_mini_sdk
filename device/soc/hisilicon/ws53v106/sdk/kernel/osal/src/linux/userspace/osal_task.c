/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal task source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "securec.h"
#include "soc_osal.h"
#include "osal_inner.h"

typedef struct osal_userspace_task {
    pthread_t th;
    pthread_attr_t attr;
} osal_userspace_task_t;

osal_task *osal_kthread_create(osal_kthread_handler handler, void *data, const char *name, unsigned int stack_size)
{
    int ret;
    osal_userspace_task_t *utask = NULL;
    utask = malloc(sizeof(osal_userspace_task_t));
    if (utask == NULL || handler == NULL) {
        osal_log("malloc error!\n");
        return NULL;
    }

    osal_task *p = malloc(sizeof(osal_task));
    if (p == NULL) {
        osal_log("malloc error!\n");
        free(utask);
        return NULL;
    }
    memset_s(p, sizeof(osal_task), 0, sizeof(osal_task));

    ret = pthread_create(&utask->th, NULL, (void *)handler, data);
    if (ret != 0) {
        osal_log("pthread_create error! ret:%d \n", ret);
        free(utask);
        free(p);
        return NULL;
    }
    p->task = utask;
    return p;
}

void osal_kthread_destroy(osal_task *task, unsigned int stop_flag)
{
    osal_userspace_task_t *utask = NULL;

    if (task == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }

    utask = (osal_userspace_task_t *)task->task;

    if (stop_flag != 0) {
        if (pthread_cancel(utask->th) != 0) {
            osal_log("pthread_cancel failed\n");
        }
    } else {
        if (pthread_detach(utask->th) != 0) {
            osal_log("pthread_detach failed!\n");
        }
    }
    free(utask);
    task->task = NULL;
    free(task);
}
