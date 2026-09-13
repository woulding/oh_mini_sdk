/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal workqueue source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "soc_osal.h"
#include "osal_inner.h"

OSAL_LIST_HEAD(g_wq_list);
struct wq_node {
    struct osal_workqueue_ *osal_work;
    struct osal_list_head node;
};

static pthread_t g_workqueue_thread;
static int g_init_thread_flag = 0;

static osal_workqueue *osal_get_queue_work()
{
    struct osal_list_head *this = NULL;

    if (osal_list_empty(&g_wq_list)) {
        return NULL;
    }
    osal_list_for_each(this, &g_wq_list)
    {
        struct wq_node *ws = osal_list_entry(this, struct wq_node, node);
        if (ws->osal_work != NULL && ws->osal_work->queue_flag == 1) {
            return ws->osal_work;
        }
    }
    return NULL;
}

static int osal_del_work(osal_workqueue *work)
{
    struct osal_list_head *this = NULL;
    struct osal_list_head *next = NULL;

    if (osal_list_empty(&g_wq_list)) {
        osal_log("find work failed! g_wq_list is empty!\n");
        return OSAL_FAILURE;
    }
    osal_list_for_each_safe(this, next, &g_wq_list)
    {
        struct wq_node *ws = osal_list_entry(this, struct wq_node, node);
        if (ws->osal_work == work) {
            osal_list_del(this);
            free(ws);
            ws = NULL;
            return OSAL_SUCCESS;
        }
    }
    osal_log("del work failed!\n");
    return OSAL_FAILURE;
}

static void *osal_work_func(void *para)
{
    osal_workqueue *ow = NULL;

    while (1) {
        ow = osal_get_queue_work();
        if ((ow != NULL) && (ow->handler != NULL) && ow->queue_flag == 1) {
            ow->handler(ow);
            ow->queue_flag = 0;
        } else if (osal_list_empty(&g_wq_list)) {
            g_init_thread_flag = 0;
            return NULL;
        } else {
            usleep(100 * 1000); // sleep 100 * 1000 usec
        }
    }
    return NULL;
}

int osal_workqueue_init(osal_workqueue *work, osal_workqueue_handler handler)
{
    struct wq_node *w_node = NULL;
    int ret;
    if (work == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    w_node = malloc(sizeof(struct wq_node));
    if (w_node == NULL) {
        osal_log("osal_init_work kmalloc failed!\n");
        return OSAL_FAILURE;
    }
    work->handler = handler;
    w_node->osal_work = work;
    w_node->osal_work->queue_flag = 0;
    osal_list_add(&(w_node->node), &g_wq_list);

    if (g_init_thread_flag == 0) {
        ret = pthread_create(&g_workqueue_thread, NULL, osal_work_func, NULL);
        if (ret == 0) {
            g_init_thread_flag = 1;
        }
    }

    return OSAL_SUCCESS;
}

int osal_workqueue_schedule(osal_workqueue *work)
{
    if (work == NULL || work->handler == NULL) {
        return FALSE;
    }
    work->queue_flag = 1;
    return TRUE;
}

void osal_workqueue_destroy(osal_workqueue *work)
{
    if (work != NULL) {
        osal_del_work(work);
        work->handler = NULL;
    }
}
