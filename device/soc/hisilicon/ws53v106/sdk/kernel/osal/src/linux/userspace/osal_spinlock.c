/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal spinlock source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "soc_osal.h"
#include "osal_inner.h"

int osal_spin_lock_init(osal_spinlock *lock)
{
    pthread_mutex_t *p = NULL;

    if (lock == NULL || lock->lock != NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    p = malloc(sizeof(pthread_mutex_t));
    if (p == NULL) {
        osal_log("malloc error!\n");
        return OSAL_FAILURE;
    }
    pthread_mutex_init(p, NULL);
    lock->lock = p;
    return OSAL_SUCCESS;
}

void osal_spin_lock(osal_spinlock *lock)
{
    pthread_mutex_t *p = NULL;
    if (lock == NULL || lock->lock == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    p = (pthread_mutex_t *)(lock->lock);
    pthread_mutex_lock(p);
}

int osal_spin_trylock(osal_spinlock *lock)
{
    pthread_mutex_t *p = NULL;

    if (lock == NULL || lock->lock == NULL) {
        osal_log("parameter invalid!\n");
        return FALSE;
    }
    p = (pthread_mutex_t *)(lock->lock);
    if (pthread_mutex_trylock(p) == 0) {
        return TRUE;
    }
    return FALSE;
}

void osal_spin_unlock(osal_spinlock *lock)
{
    pthread_mutex_t *p = NULL;
    if (lock == NULL || lock->lock == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    p = (pthread_mutex_t *)(lock->lock);
    pthread_mutex_unlock(p);
}

void osal_spin_lock_irqsave(osal_spinlock *lock, unsigned long *flags)
{
    pthread_mutex_t *p = NULL;
    if (lock == NULL || lock->lock == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    p = (pthread_mutex_t *)(lock->lock);
    pthread_mutex_lock(p);
}

void osal_spin_unlock_irqrestore(osal_spinlock *lock, unsigned long *flags)
{
    pthread_mutex_t *p = NULL;
    if (lock == NULL || lock->lock == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    p = (pthread_mutex_t *)(lock->lock);
    pthread_mutex_unlock(p);
}

void osal_spin_lock_destroy(osal_spinlock *lock)
{
    pthread_mutex_t *p = NULL;
    if (lock == NULL || lock->lock == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    p = (pthread_mutex_t *)(lock->lock);
    pthread_mutex_destroy(p);
    free(p);
    lock->lock = NULL;
}
