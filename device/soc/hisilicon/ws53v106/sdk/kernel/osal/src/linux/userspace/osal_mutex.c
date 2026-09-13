/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal mutex source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "soc_osal.h"
#include "osal_inner.h"

int osal_mutex_init(osal_mutex *mutex)
{
    pthread_mutex_t *p = NULL;

    if (mutex == NULL || mutex->mutex != NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    p = malloc(sizeof(pthread_mutex_t));
    if (p == NULL) {
        osal_log("malloc error!\n");
        return OSAL_FAILURE;
    }
    pthread_mutex_init(p, NULL);
    mutex->mutex = p;
    return OSAL_SUCCESS;
}

int osal_mutex_lock(osal_mutex *mutex)
{
    pthread_mutex_t *p = NULL;
    if (mutex == NULL || mutex->mutex == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    p = (pthread_mutex_t *)(mutex->mutex);
    pthread_mutex_lock(p);

    return OSAL_SUCCESS;
}

int osal_mutex_lock_interruptible(osal_mutex *mutex)
{
    return osal_mutex_lock(mutex);
}

int osal_mutex_trylock(osal_mutex *mutex)
{
    pthread_mutex_t *p = NULL;

    if (mutex == NULL || mutex->mutex == NULL) {
        osal_log("parameter invalid!\n");
        return FALSE;
    }
    p = (pthread_mutex_t *)(mutex->mutex);
    if (pthread_mutex_trylock(p) == 0) {
        return TRUE;
    }
    return FALSE;
}

void osal_mutex_unlock(osal_mutex *mutex)
{
    pthread_mutex_t *p = NULL;
    if (mutex == NULL || mutex->mutex == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    p = (pthread_mutex_t *)(mutex->mutex);
    pthread_mutex_unlock(p);
}

void osal_mutex_destroy(osal_mutex *mutex)
{
    pthread_mutex_t *p = NULL;
    if (mutex == NULL || mutex->mutex == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    p = (pthread_mutex_t *)(mutex->mutex);
    pthread_mutex_destroy(p);
    free(p);
    mutex->mutex = NULL;
}
