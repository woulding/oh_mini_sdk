/*
 * Copyright (c) @CompanyNameMagicTag. 2012-2022. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/version.h>
#include "soc_osal.h"
#include "securec.h"
#include "osal_errno.h"
#include "osal_inner.h"

char *g_klib_store_path = NULL;

static struct file *klib_fopen(const char *file, int flags, int mode)
{
    struct file *filp = filp_open(file, flags, mode);
    return (IS_ERR(filp)) ? NULL : filp;
}

static void klib_fclose(struct file *filp)
{
    if (filp != NULL) {
        filp_close(filp, NULL);
    }
    return;
}

static int klib_fwrite(const char *buf, unsigned long size, struct file *filp)
{
    int writelen;

    writelen = kernel_write(filp, buf, size, &filp->f_pos);
    return writelen;
}

static int klib_fread(char *buf, unsigned long size, struct file *filp)
{
    int readlen;
    readlen = kernel_read(filp, buf, size, &filp->f_pos);

    return readlen;
}

void *osal_klib_fopen(const char *file, int flags, int mode)
{
    if (file == NULL) {
        osal_log("file NULL!\n");
        return NULL;
    }

    return (void *)klib_fopen(file, flags, mode);
}
EXPORT_SYMBOL(osal_klib_fopen);

void osal_klib_fclose(void *filp)
{
    if (filp == NULL) {
        osal_log("filp NULL!\n");
        return;
    }

    klib_fclose((struct file *)filp);
}
EXPORT_SYMBOL(osal_klib_fclose);

int osal_klib_fwrite(const char *buf, unsigned long size, void *filp)
{
    if ((buf == NULL) || (filp == NULL)) {
        osal_log("buf&filp NULL!\n");
        return OSAL_FAILURE;
    }

    return klib_fwrite(buf, size, (struct file *)filp);
}
EXPORT_SYMBOL(osal_klib_fwrite);

int osal_klib_fread(char *buf, unsigned long size, void *filp)
{
    if ((buf == NULL) || (filp == NULL)) {
        osal_log("buf&filp NULL!\n");
        return OSAL_FAILURE;
    }

    return klib_fread(buf, size, (struct file *)filp);
}
EXPORT_SYMBOL(osal_klib_fread);

int osal_klib_fseek(long long offset, int whence, void *filp)
{
    int ret;
    loff_t res;

    if (filp == NULL) {
        osal_log("filp NULL!\n");
        return OSAL_FAILURE;
    }

    res = vfs_llseek(filp, offset, whence);
    ret = (int)res;
    if (res != (loff_t)ret) {
        ret = OSAL_EOVERFLOW;
    }

    return ret;
}
EXPORT_SYMBOL(osal_klib_fseek);

void osal_klib_fsync(void *filp)
{
    if (filp == NULL) {
        osal_log("filp NULL!\n");
        return;
    }

    vfs_fsync(filp, 0);
}
EXPORT_SYMBOL(osal_klib_fsync);

void osal_klib_set_store_path(char *path)
{
    g_klib_store_path = path;
}
EXPORT_SYMBOL(osal_klib_set_store_path);

int osal_klib_get_store_path(char *path, unsigned int path_size)
{
    int len;

#if defined (CONFIG_CLOSE_UART0) || defined (ANDROID_BUILD_USER)
    /* not support log when uart close or user version */
    if (osal_get_buildvariant() != OSAL_BUILDVARIANT_ENG) {
        return OSAL_SUCCESS;
    }
#endif

    if ((path == NULL) || (g_klib_store_path == NULL)) {
        osal_log("path Or g_klib_store_path NULL!\n");
        return OSAL_FAILURE;
    }

    len = (int)strlen(g_klib_store_path) + 1;
    if (len > path_size || path_size <= 1) {
        osal_log("path_size(%u) unvaild! len= %d.\n", path_size, len);
        return OSAL_FAILURE;
    }

    return memcpy_s(path, path_size, g_klib_store_path, len);
}
EXPORT_SYMBOL(osal_klib_get_store_path);
