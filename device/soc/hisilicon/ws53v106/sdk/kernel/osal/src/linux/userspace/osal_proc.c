/*
 * Copyright (c) @CompanyNameMagicTag. 2020-2022. All rights reserved.
 * Description: proc user space source file.
 * Create: 2020-10-12
 */

#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>
#include "securec.h"
#include "soc_osal.h"
#include "osal_inner.h"
#include "drval_proc.h"
#include "osal_inner.h"


typedef struct {
    int         thread_stop;
    pthread_t       thread;
} proc_thread;

typedef struct proc_hdl {
    osal_proc_entry proc_info;
    unsigned long show_buf;
    struct proc_hdl *next;
}proc_handler;
proc_handler *proc_head = NULL;
static proc_thread g_proc_thread;
static int g_proc_fd = -1;

void *ot_proc_thread(void *arg);

static proc_handler *add_list(const char *name)
{
    proc_handler *tmp;
    tmp = (proc_handler*)malloc(sizeof(proc_handler));
    if (tmp == NULL) {
        return NULL;
    }
    memset_s(tmp->proc_info.name, sizeof(tmp->proc_info.name), 0, sizeof(tmp->proc_info.name));
    memcpy_s(tmp->proc_info.name, sizeof(tmp->proc_info.name), name, strlen(name) + 1);
    tmp->next = proc_head;
    proc_head = tmp;
    return tmp;
}

static void del_list(void)
{
    proc_handler *tmp = proc_head;
    proc_handler *tmp2 = NULL;

    while (tmp != NULL) {
        tmp2 = tmp->next;
        free(tmp);
        tmp = tmp2;
    }
    proc_head = NULL;
}

static proc_handler *get_list_node(const char *name)
{
    proc_handler *tmp = proc_head;
    while (tmp != NULL) {
        if (!strcmp(tmp->proc_info.name, name)) {
            return tmp;
        }
        tmp = tmp->next;
    }
    return NULL;
}

static int del_list_node(const char *name)
{
    proc_handler *tmp = proc_head;
    proc_handler *pre = proc_head;
    while (tmp != NULL) {
        if (!strcmp(tmp->proc_info.name, name)) {
            if (tmp == pre) { // del head
                proc_head = tmp->next;
            } else {
                pre->next = tmp->next;
            }
            free(tmp);
            tmp = NULL;
            return OSAL_SUCCESS;
        }
        pre = tmp;
        tmp = tmp->next;
    }
    return OSAL_FAILURE;
}

osal_proc_entry *osal_create_proc_entry(const char *name, osal_proc_entry *parent)
{
    proc_handler *user_proc_info = NULL;
    int ret;
    drval_proc_name proc_name;
    if (name == NULL) {
        osal_log("name is NULL\n");
        return NULL;
    }

    if (strncpy_s(proc_name.name, sizeof(proc_name.name), name, strnlen(name, MAX_PROC_NAME_LEN)) != EOK) {
        osal_log("strncpy_s failed!\n");
        return NULL;
    }

    user_proc_info = get_list_node(name);
    if (user_proc_info != NULL) {
        osal_log("name has created\n");
        return &(user_proc_info->proc_info);
    }
    user_proc_info = add_list(name);
    if (user_proc_info == NULL) {
        return NULL;
    }
    ret = ioctl(g_proc_fd, USER_CREATE_PROC_ENTRY, &proc_name);
    if (ret != 0) {
        ret = del_list_node(name);
        osal_printk("USER_CREATE_PROC_ENTRY ioctl failed\n");
        return NULL;
    }

    return &(user_proc_info->proc_info);
}

void osal_remove_proc_entry(const char *name, osal_proc_entry *parent)
{
    int ret;
    drval_proc_name proc_name;
    if (name == NULL) {
        osal_log("proc name is NULL,can't remove\n");
        return;
    }

    if (strncpy_s(proc_name.name, sizeof(proc_name.name), name, strnlen(name, MAX_PROC_NAME_LEN)) != EOK) {
        osal_log("strncpy_s failed!\n");
        return;
    }

    ret = ioctl(g_proc_fd, USER_REMOVE_PROC_ENTRY, &proc_name);
    if (ret != 0) {
        osal_log("USER_REMOVE_PROC_ENTRY ioctl failed\n");
        return;
    }

    ret = del_list_node(name);
    if (ret != 0) {
        osal_log("remove proc %s entry failed\n", name);
        return;
    }
    return;
}

osal_proc_entry *osal_proc_mkdir(const char *name, osal_proc_entry *parent)
{
    osal_log("osal_proc_mkdir return NULL");
    return NULL;
}

void osal_seq_printf(void *seqfile, const char *fmt, ...)
{
    int len;
    va_list args = {0};
    drval_proc_show_buf *show_buf = NULL;
    osal_proc_entry *entry = (osal_proc_entry *)osal_container_of(seqfile, osal_proc_entry, seqfile);

    proc_handler *user_proc_info = get_list_node(entry->name);
    if (user_proc_info == NULL || fmt == NULL) {
        osal_log("user_proc_info or fmt is NULL\n");
        return;
    }
    show_buf = (drval_proc_show_buf*)(user_proc_info->show_buf);

    if (show_buf == NULL) {
        osal_log("show_buf is NULL\n");
        return;
    }
    /* log buffer overflow */
    if (show_buf->offset >= show_buf->size) {
        osal_log("userproc buffer(size=%u) overflow\n", show_buf->size);
        return;
    }
    va_start(args, fmt);

    len = vsnprintf_s(show_buf->buf + show_buf->offset, show_buf->size - show_buf->offset,
                      show_buf->size - show_buf->offset - 1, fmt, args);

    va_end(args);
    if (len == -1) {
        osal_log("vsnprintf_s failed\n");
        return;
    }
    show_buf->offset += len;
    return;
}

void osal_user_proc_exit(void)
{
    int ret = 0;
    del_list();
    g_proc_thread.thread_stop = TRUE;
    if (g_proc_fd < 0) {
        osal_log("g_proc_fd(%#x) error", g_proc_fd);
        return;
    }
    ioctl(g_proc_fd, USER_PROC_WAKE_GET_CMD, &ret);
    pthread_join(g_proc_thread.thread, NULL);
    if (g_proc_fd >= 0) {
        close(g_proc_fd);
        g_proc_fd = -1;
    }
    return;
}

int osal_user_proc_init(void)
{
    int ret;
    if (g_proc_fd < 0) {
        g_proc_fd = open("/dev/"DRVAL_PROC_DEVICE_NAME, O_RDWR);
    }
    if (g_proc_fd < 0) {
        osal_log("ca n not open /dev/%s, return %d\n", DRVAL_PROC_DEVICE_NAME, g_proc_fd);
        return -1;
    }
    g_proc_thread.thread_stop = FALSE;

    ret = pthread_create(&g_proc_thread.thread, NULL, ot_proc_thread, NULL);
    if (ret != 0) {
        close(g_proc_fd);
        g_proc_fd = -1;
        osal_log("Create userproc thread err!\n");
        return -1;
    }

    return 0;
}

static void ot_proc_read_write(proc_handler *user_proc_info, drval_proc_para *user_info, unsigned int ret)
{
    drval_proc_show_buf *show_buf = (drval_proc_show_buf*)malloc(sizeof(drval_proc_show_buf));
    if (show_buf == NULL) {
        osal_log("show_buf is NULL,return\n");
        return;
    }
    show_buf->buf = (char *)malloc(DRVAL_PROC_BUF_SIZE);
    if (show_buf->buf == NULL) {
        osal_log("show_buf->buf is NULL,return\n");
        free(show_buf);
        show_buf = NULL;
        return;
    }
    memset_s(show_buf->buf, DRVAL_PROC_BUF_SIZE, 0, DRVAL_PROC_BUF_SIZE);
    show_buf->offset = 0;
    show_buf->size   = DRVAL_PROC_BUF_SIZE;
    user_proc_info->show_buf = (unsigned long)((uintptr_t)show_buf);

    /* read */
    if (ret == 0) {
        user_proc_info->proc_info.read(&(user_info->entry));
        ret = ioctl(g_proc_fd, USER_PROC_WAKE_READ_TASK, show_buf);
        if (ret != 0) {
            osal_log("proc print failed\n");
        }
    /* write */
    } else {
        user_proc_info->proc_info.write(&(user_info->entry), user_info->write_buf.buf,
                                        user_info->write_buf.count, &(user_info->write_buf.ppos));
        ret = ioctl(g_proc_fd, USER_PROC_WAKE_WRITE_TASK, show_buf);
        if (ret != 0) {
            osal_log("proc write failed\n");
        }
    }
    if (show_buf != NULL) {
        if (show_buf->buf != NULL) {
            free(show_buf->buf);
            show_buf->buf = NULL;
        }
        user_proc_info->show_buf = 0;
        free(show_buf);
        show_buf = NULL;
    }
    return;
}

void *ot_proc_thread(void *arg)
{
    drval_proc_para user_info;
    int ret;
    while (g_proc_thread.thread_stop == 0) {
        memset_s(user_info.cmd, sizeof(user_info.cmd), 0, sizeof(user_info.cmd));
        memset_s(user_info.entry.name, sizeof(user_info.entry.name), 0, sizeof(user_info.entry.name));
        ret = ioctl(g_proc_fd, USER_PROC_GET_CMD, &user_info);
        if (ret != 0) {
            continue;
        }
        if (strlen(user_info.cmd) == 0 || strlen(user_info.entry.name) == 0) {
            osal_log("cmd or name length is 0,continue\n");
            continue;
        }

        ret = strncmp(DRVAL_PROC_READ_CMD, user_info.cmd, strlen(DRVAL_PROC_READ_CMD));
        proc_handler *user_proc_info = get_list_node(user_info.entry.name);
        if (user_proc_info == NULL) {
            osal_log("can't find entry of this name\n");
            continue;
        }
        ot_proc_read_write(user_proc_info, &user_info, ret);
    }
    return NULL;
}
