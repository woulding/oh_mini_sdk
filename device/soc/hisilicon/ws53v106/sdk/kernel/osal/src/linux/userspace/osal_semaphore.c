/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal semaphore source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <semaphore.h>
#include <stdlib.h>
#include <stdio.h>

#include "soc_osal.h"
#include "osal_inner.h"

#define PSHARE_MODE 0 // share semaphore between threads

int osal_sem_init(osal_semaphore *sem, int val)
{
    sem_t *p = NULL;
    if (sem == NULL || sem->sem != NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    p = malloc(sizeof(sem_t));
    if (p == NULL) {
        osal_log("kmalloc error!\n");
        return OSAL_FAILURE;
    }
    sem_init(p, PSHARE_MODE, (unsigned int)val);
    sem->sem = p;
    return OSAL_SUCCESS;
}

int osal_sem_down(osal_semaphore *sem)
{
    sem_t *p = NULL;

    if (sem == NULL || sem->sem == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    p = (sem_t *)(sem->sem);
    return sem_wait(p);
}

int osal_sem_down_interruptible(osal_semaphore *sem)
{
    sem_t *p = NULL;

    if (sem == NULL || sem->sem == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    p = (sem_t *)(sem->sem);
    return sem_wait(p);
}

int osal_sem_trydown(osal_semaphore *sem)
{
    sem_t *p = NULL;

    if (sem == NULL || sem->sem == NULL) {
        osal_log("parameter invalid!\n");
        return 1;
    }
    p = (sem_t *)(sem->sem);
    int ret = sem_trywait(p);
    return (ret == 0) ? 0 : 1;
}

void osal_sem_up(osal_semaphore *sem)
{
    sem_t *p = NULL;
    if (sem == NULL || sem->sem == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    p = (sem_t *)(sem->sem);
    sem_post(p);
}

void osal_sem_destroy(osal_semaphore *sem)
{
    sem_t *p = NULL;
    if (sem == NULL || sem->sem == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    p = (sem_t *)(sem->sem);
    sem_destroy(p);
    free(p);
    sem->sem = NULL;
}
