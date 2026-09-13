/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal wait source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */
#include <stdio.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include "soc_osal.h"
#include "osal_inner.h"

unsigned long osal_msecs_to_jiffies(const unsigned int m)
{
    return m;
}

typedef struct {
    bool signaled;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
} osal_userspace_wait;

int osal_wait_init(osal_wait *wait)
{
    osal_userspace_wait *uw = NULL;

    if (wait == NULL || wait->wait != NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }

    uw = malloc(sizeof(osal_userspace_wait));
    if (uw == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }

    uw->signaled = FALSE;

    if (pthread_mutex_init(&uw->mutex, NULL) != 0) {
        osal_log("init pEvent->mutex failed!\n");
        free(uw);
        return OSAL_FAILURE;
    }

    if (pthread_cond_init(&uw->condition, NULL) != 0) {
        osal_log("init pEvent->condition failed!\n");
        pthread_mutex_destroy(&uw->mutex);
        free(uw);
        return OSAL_FAILURE;
    }
    wait->wait = uw;
    return OSAL_SUCCESS;
}

#define WAIT_FOREVER 0xffffffff

static int osal_wait_timeout_handle(osal_userspace_wait *uw, const struct timespec *timeout, unsigned long ms,
    bool *flag)
{
    int ret = 0;

    if (uw == NULL || timeout == NULL || flag == NULL) {
        return OSAL_FAILURE;
    }

    if (ms == 0) {
        if (uw->signaled == FALSE) {
            *flag = TRUE;
        }
    } else if (ms == WAIT_FOREVER) {
        while (uw->signaled == FALSE) {
            pthread_cond_wait(&uw->condition, &uw->mutex);
        }
        uw->signaled = FALSE;
        return OSAL_SUCCESS;
    } else {
        while (uw->signaled == FALSE) {
            ret = pthread_cond_timedwait(&uw->condition, &uw->mutex, timeout);
            if (ret == ETIMEDOUT && uw->signaled == FALSE) {
                *flag = TRUE;
                break;
            }
        }
    }

    return OSAL_FAILURE;
}

int osal_wait_timeout_interruptible(osal_wait *wait, osal_wait_condition_func func, const void *param, unsigned long ms)
{
    osal_userspace_wait *uw = NULL;
    long timeout_us;
    struct timespec timeout;
    struct timeval last, curr;
    long remain_ms;
    int condition = 0;
    bool timeoutflag = FALSE;
    int ret;

    if (wait == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    uw = (osal_userspace_wait *)(wait->wait);
    if (uw == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }

    gettimeofday(&last, NULL);
    timeout_us = last.tv_usec + 1000 * ms; // 1000
    timeout.tv_sec = last.tv_sec + timeout_us / 1000000; // 1000000
    timeout.tv_nsec = (timeout_us % 1000000) * 1000; // 1000

    if (func != NULL) {
        condition = func(param);
    }
    if (condition == 0) {
        if (pthread_mutex_lock(&uw->mutex) != 0) {
            return OSAL_FAILURE;
        }
        ret = osal_wait_timeout_handle(uw, &timeout, ms, &timeoutflag);
        pthread_mutex_unlock(&uw->mutex);
        if (ret == OSAL_SUCCESS) {
            return ret;
        }
    }
    uw->signaled = FALSE;
    if (timeoutflag) {
        return OSAL_SUCCESS;
    }

    gettimeofday(&curr, NULL);
    remain_ms = (long)ms + (last.tv_usec - curr.tv_usec) / 1000 - (curr.tv_sec - last.tv_sec) * 1000; // 1000
    if (remain_ms <= 0) {
        return OSAL_SUCCESS;
    }
    return (int)remain_ms;
}

int osal_wait_interruptible(osal_wait *wait, osal_wait_condition_func func, const void *param)
{
    return osal_wait_timeout_interruptible(wait, func, param, WAIT_FOREVER);
}

int osal_wait_uninterruptible(osal_wait *wait, osal_wait_condition_func func, const void *param)
{
    return osal_wait_timeout_interruptible(wait, func, param, WAIT_FOREVER);
}


int osal_wait_timeout_uninterruptible(osal_wait *wait, osal_wait_condition_func func, const void *param,
    unsigned long ms)
{
    return osal_wait_timeout_interruptible(wait, func, param, ms);
}

void osal_wait_wakeup(osal_wait *wait)
{
    osal_userspace_wait *uw = NULL;

    if ((wait == NULL) || (wait->wait == NULL)) {
        osal_log("parameter invalid!\n");
        return;
    }

    uw = (osal_userspace_wait *)(wait->wait);
    if (pthread_mutex_lock(&uw->mutex) != 0) {
        osal_log("lock pEvent->mutex failed!\n");
        return;
    }

    pthread_cond_signal(&uw->condition);
    uw->signaled = TRUE;
    pthread_mutex_unlock(&uw->mutex);

    return;
}

void osal_wait_destroy(osal_wait *wait)
{
    osal_userspace_wait *uw = NULL;

    if ((wait == NULL) || (wait->wait == NULL)) {
        osal_log("parameter invalid!\n");
        return;
    }

    uw = (osal_userspace_wait *)(wait->wait);
    if (pthread_mutex_lock(&uw->mutex) != 0) {
        osal_log("lock pEvent->mutex failed!\n");
        return;
    }

    pthread_cond_destroy(&uw->condition);
    pthread_mutex_unlock(&uw->mutex);
    pthread_mutex_destroy(&uw->mutex);

    free(uw);
    wait->wait = NULL;
    return;
}
