/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal device source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include "securec.h"
#include "soc_osal.h"
#include "osal_inner.h"
#include "osal_ioctl.h"
#include "osal_inner.h"

#define OSAL_MAX_DEV_NAME_LEN 48
#define OSAL_MAX_DEV_NUM 1024
#define HIMEDIA_DYNAMIC_MINOR 64 // max devices
#define PAGE_SHIFT 12
#define DYNAMIC_MINORS 64 /* like dynamic majors */
#define DEV_MINOR_MASK 0xff
#define DEV_COUNT_MASK 0x3ff
#define DEV_COUNT_SHIFT 8

#define get_file_check_return(file) do {                          \
        if (osal_get_file(file) < 0) \
            return (-1); \
    } while (0)

#define put_file_check_return(file) do {                          \
        if (osal_put_file(file) < 0) \
            return (-1); \
    } while (0)

typedef struct osal_dev_info_ {
    osal_dev *dev;
    unsigned int count;
    struct osal_list_head node;
} osal_dev_info;

struct osal_private_data {
    osal_dev *dev;
    void *data;
    osal_poll table;
    int f_ref_cnt;
};

struct file {
    char name[OSAL_MAX_DEV_NAME_LEN];
    int fd;
    void *private_data;
};

static osal_mutex g_mutex = {
    .mutex = NULL
};
static osal_mutex g_osal_dev_sem = {
    .mutex = NULL
};

static OSAL_LIST_HEAD(g_osal_dev_list);
void **g_osal_minor_map[HIMEDIA_DYNAMIC_MINOR] = {0};
static unsigned char g_media_minors[DYNAMIC_MINORS / 8]; /* 8: bitmap 1Byte has 8 bit */

void osal_user_device_init(void)
{
    int ret = osal_mutex_init(&g_mutex);
    if (ret != OSAL_SUCCESS) {
        osal_log("ret = %#x\n", ret);
    }
    ret = osal_mutex_init(&g_osal_dev_sem);
    if (ret != OSAL_SUCCESS) {
        osal_log("ret = %#x\n", ret);
    }
}

void osal_user_device_exit(void)
{
    osal_mutex_destroy(&g_mutex);
    osal_mutex_destroy(&g_osal_dev_sem);
}

static int osal_get_file(struct file *file)
{
    struct osal_private_data *pdata = NULL;
    osal_mutex_lock(&g_mutex);
    pdata = file->private_data;
    if (pdata == NULL) {
        osal_mutex_unlock(&g_mutex);
        return OSAL_FAILURE;
    }

    pdata->f_ref_cnt++;
    osal_mutex_unlock(&g_mutex);

    return OSAL_SUCCESS;
}

static int osal_put_file(struct file *file)
{
    struct osal_private_data *pdata = NULL;
    osal_mutex_lock(&g_mutex);
    pdata = file->private_data;
    if (pdata == NULL) {
        osal_mutex_unlock(&g_mutex);
        return OSAL_FAILURE;
    }

    pdata->f_ref_cnt--;
    osal_mutex_unlock(&g_mutex);

    return OSAL_SUCCESS;
}

static int osal_open(struct file *file)
{
    struct osal_private_data *pdata = file->private_data;

    if (pdata->dev->fops->open != NULL) {
        return pdata->dev->fops->open((void *)&(pdata->data));
    }

    return OSAL_SUCCESS;
}

static ssize_t osal_read(struct file *file, char *buf, unsigned long size, long long *offset)
{
    struct osal_private_data *pdata = file->private_data;
    int ret = 0;

    get_file_check_return(file);

    if (pdata->dev->fops->read != NULL) {
        ret = pdata->dev->fops->read(buf, (int)size, (long *)offset, (void *)&(pdata->data));
    }

    put_file_check_return(file);
    return ret;
}

static ssize_t osal_write(struct file *file, const char *buf, unsigned long size, long long *offset)
{
    struct osal_private_data *pdata = file->private_data;
    int ret = -1;

    get_file_check_return(file);
    if (pdata->dev->fops->write != NULL) {
        ret = pdata->dev->fops->write(buf, (int)size, (long *)offset, (void *)&(pdata->data));
    }
    put_file_check_return(file);
    return ret;
}

static int osal_release(struct file *file)
{
    int ret = 0;
    struct osal_private_data *pdata = file->private_data;

    get_file_check_return(file);

    if (pdata->dev->fops->release != NULL) {
        ret = pdata->dev->fops->release((void *)&(pdata->data));
    }
    if (ret != 0) {
        put_file_check_return(file);
        osal_log("release failed!\n");
        return ret;
    }

    put_file_check_return(file);
    osal_mutex_lock(&g_mutex);
    if (pdata->f_ref_cnt != 0) {
        osal_log("release failed!\n");
        osal_mutex_unlock(&g_mutex);
        return OSAL_FAILURE;
    }
    free(file->private_data);
    file->private_data = NULL;
    osal_mutex_unlock(&g_mutex);

    return OSAL_SUCCESS;
}

static int do_osal_unlocked_ioctl(struct file *file, unsigned int cmd, void *arg)
{
    int ret = OSAL_FAILURE;
    struct osal_private_data *pdata = file->private_data;

    if (((_IOC_SIZE(cmd) == 0) && (_IOC_DIR(cmd) != _IOC_NONE))) {
        return OSAL_FAILURE;
    }

    if ((_IOC_DIR(cmd) != _IOC_NONE) && (((char *)(uintptr_t)arg) == NULL)) {
        osal_log("Input param err,it is null!\n");
        return OSAL_FAILURE;
    }

    if (pdata->dev->fops->cmd_list->handler != NULL) {
        ret = pdata->dev->fops->cmd_list->handler(cmd, arg, (void *)&(pdata->data));
    }
    return ret;
}

static int osal_unlocked_ioctl(struct file *file, unsigned int cmd, void *arg)
{
    int ret;

    get_file_check_return(file);
    ret = do_osal_unlocked_ioctl(file, cmd, arg);
    put_file_check_return(file);

    return ret;
}

struct file *get_file(int fd)
{
    int count, minor;
    struct file **osal_count_map;

    count = ((unsigned int)fd >> DEV_COUNT_SHIFT) & DEV_COUNT_MASK;
    minor = (unsigned int)fd & DEV_MINOR_MASK;

    osal_count_map = (struct file **)g_osal_minor_map[minor];
    if (osal_count_map == NULL) {
        return NULL;
    }

    return osal_count_map[count];
}

int get_dev_name(char *dst, const char *src, int len)
{
    int cnt = 0;
    char *q = dst;
    char *p = (char *)src;

    if ((dst == NULL) || (src == NULL) || (len <= 0)) {
        return -1;
    }

    while ((cnt < len) && (*p != '\0')) {
        if (*p == '/') {
            q = dst;
            p++;
        } else {
            *q = *p;
            p++;
            q++;
        }
        cnt++;
    }

    *q = '\0';

    return OSAL_SUCCESS;
}

unsigned int find_free_id(osal_dev *dev)
{
    struct file **osal_count_map = (struct file **)g_osal_minor_map[dev->minor];
    osal_dev_info *dev_node = NULL;
    unsigned int i;
    errno_t err;

    if (osal_count_map == NULL) {
        return OSAL_FAILURE;
    }
    dev_node = (osal_dev_info *)malloc(sizeof(osal_dev_info));
    if (dev_node == NULL) {
        osal_log("malloc error!\n");
        return OSAL_FAILURE;
    }
    err = memset_s(dev_node, sizeof(osal_dev_info), 0, sizeof(osal_dev_info));
    if (err != EOK) {
        free(dev_node);
        dev_node = NULL;
        osal_log("memset_s is failed.\n");
        return OSAL_FAILURE;
    }
    dev_node->dev = dev;

    for (i = 0; i < OSAL_MAX_DEV_NUM; i++) {
        if (osal_count_map[dev_node->count] == NULL) {
            break;
        } else {
            dev_node->count = (dev_node->count + 1) & DEV_COUNT_MASK;
        }
    }

    if (i >= OSAL_MAX_DEV_NUM) {
        return -1;
    } else {
        i = dev_node->count;
        dev_node->count = (dev_node->count + 1) & DEV_COUNT_MASK;
        return i;
    }
}

osal_dev *osal_find_dev(const char *name)
{
    osal_dev_info *c = NULL;
    int dev_find = 0;
    osal_mutex_lock(&g_osal_dev_sem);
    osal_list_for_each_entry(c, &g_osal_dev_list, node)
    {
        if (!strcmp(c->dev->name, name)) {
            dev_find = 1;
            break;
        }
    }

    if (dev_find == 0) {
        osal_mutex_unlock(&g_osal_dev_sem);
        return NULL;
    }
    osal_mutex_unlock(&g_osal_dev_sem);

    return c->dev;
}

int osal_opendev(const char *path, int flag, ...)
{
    char dev_name[OSAL_MAX_DEV_NAME_LEN];
    struct file **osal_count_map = NULL;
    osal_dev *dev = NULL;
    struct file *file = NULL;
    struct osal_private_data *pdata = NULL;
    int ret, fd;
    unsigned int count;

    ret = get_dev_name(dev_name, path, OSAL_MAX_DEV_NAME_LEN);
    if (ret != 0) {
        osal_log("osal_opendev get name fail.\n");
        return OSAL_FAILURE;
    }

    dev = osal_find_dev(dev_name);
    if (dev == NULL) {
        osal_log("osal_opendev not find dev.\n");
        return OSAL_FAILURE;
    }
    osal_count_map = (struct file **)g_osal_minor_map[dev->minor];
    if (osal_count_map == NULL) {
        return OSAL_FAILURE;
    }

    osal_mutex_lock(&g_osal_dev_sem);
    count = find_free_id(dev);
    if (count < 0) {
        osal_mutex_unlock(&g_osal_dev_sem);
        return OSAL_FAILURE;
    }

    file = (struct file *)malloc(sizeof(struct file));
    if (file == NULL) {
        osal_mutex_unlock(&g_osal_dev_sem);
        return OSAL_FAILURE;
    }
    (void)memset_s(file, sizeof(struct file), 0, sizeof(struct file));

    pdata = (struct osal_private_data *)malloc(sizeof(struct osal_private_data));
    if (pdata == NULL) {
        free(file);
        osal_mutex_unlock(&g_osal_dev_sem);
        return OSAL_FAILURE;
    }
    (void)memset_s(pdata, sizeof(struct osal_private_data), 0, sizeof(struct osal_private_data));

    fd = (count << DEV_COUNT_SHIFT) | dev->minor;
    pdata->dev = dev;
    file->private_data = pdata;
    file->fd = fd;
    if (memcpy_s(file->name, OSAL_MAX_DEV_NAME_LEN, dev->name, sizeof(dev->name))) {
        free(pdata);
        free(file);
        osal_mutex_unlock(&g_osal_dev_sem);
        return OSAL_FAILURE;
    }
    osal_count_map[count] = file;
    if (osal_open(file) != 0) {
        free(pdata);
        free(file);
        osal_count_map[count]  = NULL;
        osal_mutex_unlock(&g_osal_dev_sem);
        return OSAL_FAILURE;
    }

    osal_mutex_unlock(&g_osal_dev_sem);

    return fd;
}

int osal_closedev(int fd)
{
    struct file *file = NULL;
    struct file **osal_count_map = NULL;
    int count, minor;

    if (fd < 0) {
        return OSAL_FAILURE;
    }

    osal_mutex_lock(&g_osal_dev_sem);
    count = ((unsigned int)fd >> DEV_COUNT_SHIFT) & DEV_COUNT_MASK;
    minor = (unsigned int)fd & DEV_MINOR_MASK;

    osal_count_map = (struct file **)g_osal_minor_map[minor];
    if (osal_count_map == NULL) {
        osal_mutex_unlock(&g_osal_dev_sem);
        return OSAL_FAILURE;
    }

    file = osal_count_map[count];
    if (file != NULL) {
        if (file->private_data != NULL) {
            osal_release(file);
        }
        free(file);
        osal_count_map[count] = NULL;
    }

    osal_mutex_unlock(&g_osal_dev_sem);
    return OSAL_SUCCESS;
}

int osal_readdev(int fd, void *buf, unsigned long count)
{
    struct file *file = NULL;
    int ret = 0;

    if (fd < 0) {
        return -1;
    }
    file = get_file(fd);
    if (file != NULL) {
        ret = (int)osal_read(file, buf, count, NULL);
    }

    return ret;
}

int osal_writedev(int fd, const void *buf, unsigned long count)
{
    struct file *file = NULL;
    int ret = 0;

    if (fd < 0) {
        return -1;
    }
    file = get_file(fd);
    if (file != NULL) {
        ret = (int)osal_write(file, buf, count, NULL);
    }

    return ret;
}

int osal_ioctldev(int fd, unsigned int cmd, ...)
{
    struct file *file = NULL;
    int ret = 0;
    unsigned long arg = 0;
    va_list arg_ptr;

    if (fd < 0) {
        return -1;
    }

    if (_IOC_DIR(cmd) != _IOC_NONE) {
        va_start(arg_ptr, cmd);
        arg = va_arg(arg_ptr, unsigned long);
        va_end(arg_ptr);
    }

    file = get_file(fd);
    if (file != NULL) {
        ret = osal_unlocked_ioctl(file, cmd, (void *)arg);
    }

    return ret;
}

osal_dev *osal_dev_create(const char *name)
{
    osal_dev *dev = NULL;

    if (name == NULL) {
        osal_log("parameter invalid!\n");
        return NULL;
    }
    dev = (osal_dev *)malloc(sizeof(osal_dev));
    if (dev == NULL) {
        osal_log("malloc error!\n");
        return NULL;
    }
    (void)memset_s(dev, sizeof(osal_dev), 0, sizeof(osal_dev));
    if (strncpy_s(dev->name, OSAL_MAX_DEV_NAME_LEN, name, OSAL_MAX_DEV_NAME_LEN - 1)) {
        free(dev);
        return NULL;
    }
    return dev;
}

int osal_dev_destroy(osal_dev *dev)
{
    if (dev == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }

    osal_mutex_lock(&g_osal_dev_sem);
    free(dev);
    dev = NULL;
    osal_mutex_unlock(&g_osal_dev_sem);
    return OSAL_SUCCESS;
}

static void osal_releasedevice(osal_dev const *pdev)
{
    struct file **osal_count_map = (struct file **)g_osal_minor_map[pdev->minor];
    struct file *file = NULL;
    int i;

    if (osal_count_map == NULL) {
        return;
    }

    for (i = 0; i < OSAL_MAX_DEV_NUM; i++) {
        if (osal_count_map[i] != NULL) {
            file = osal_count_map[i];
            if (file->private_data != NULL) {
                osal_release(file);
            }
            free(file);
            osal_count_map[i] = NULL;
        }
    }

    free(osal_count_map);
    g_osal_minor_map[pdev->minor] = NULL;
    return;
}

static int osal_dev_check_minor(int *dev_minor)
{
    osal_dev_info *ptmp = NULL;

    /* check if registered */
    osal_list_for_each_entry(ptmp, &g_osal_dev_list, node)
    {
        if (ptmp->dev->minor == *dev_minor) {
            return -EBUSY;
        }
    }

    /* check minor */
    if (*dev_minor == 0) {
        int i = DYNAMIC_MINORS;

        while (--i >= 0) {
            if ((g_media_minors[(unsigned int)i >> 3] &   /* 3: left shift 3bit to locate the index of char array */
                (1 << ((unsigned int)i & 7))) == 0) {     /* 7: locate the bit in bitmap */
                break;
            }
        }
        if (i < 0) {
            return -EBUSY;
        }
        *dev_minor = i;
    }
    return OSAL_SUCCESS;
}

int osal_dev_register(osal_dev *dev)
{
    int ret;
    void *osal_count_map = NULL;
    osal_dev_info *dev_node = NULL;

    if ((dev == NULL) || (dev->fops == NULL)) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    dev_node = (osal_dev_info *)malloc(sizeof(osal_dev_info));
    if (dev_node == NULL) {
        osal_log("malloc error!\n");
        return OSAL_FAILURE;
    }
    if (memset_s(dev_node, sizeof(osal_dev_info), 0, sizeof(osal_dev_info)) != EOK) {
        free(dev_node);
        dev_node = NULL;
        osal_log("memset_s is failed.\n");
        return OSAL_FAILURE;
    }
    dev_node->dev = dev;
    dev->dev = (void *)dev_node;
    osal_mutex_lock(&g_osal_dev_sem);

    ret = osal_dev_check_minor(&(dev_node->dev->minor));
    if (ret != OSAL_SUCCESS) {
        osal_mutex_unlock(&g_osal_dev_sem);
        return ret;
    }

    if (dev_node->dev->minor < DYNAMIC_MINORS) {
        g_media_minors[dev_node->dev->minor >> 3] |= 1 << (dev_node->dev->minor & 7); /* 3, 7: bitmap write set bit 1 */
    } else {
        osal_mutex_unlock(&g_osal_dev_sem);
        return OSAL_FAILURE;
    }

    /*
     * Add it to the front, so that later devices can "override"
     * earlier defaults
     */
    osal_count_map = (void *)malloc(sizeof(struct file *) * OSAL_MAX_DEV_NUM);
    if (osal_count_map == NULL) {
        /* 3, 7: bitmap write set bit 0 */
        g_media_minors[dev_node->dev->minor >> 3] &= ~(1 << (dev_node->dev->minor & 7));
        osal_mutex_unlock(&g_osal_dev_sem);
        return OSAL_FAILURE;
    }
    (void)memset_s(osal_count_map, sizeof(struct file *) * OSAL_MAX_DEV_NUM,
                   0, sizeof(struct file *) * OSAL_MAX_DEV_NUM);
    g_osal_minor_map[dev_node->dev->minor] = osal_count_map;
    osal_list_add(&dev_node->node, &g_osal_dev_list);
    osal_mutex_unlock(&g_osal_dev_sem);

    return OSAL_SUCCESS;
}

void osal_dev_unregister(osal_dev *dev)
{
    osal_dev_info *ptmp = NULL;
    osal_dev_info *_ptmp = NULL;
    osal_dev_info *dev_node = NULL;
    if (dev == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }

    dev_node = (osal_dev_info *)(dev->dev);

    if (osal_list_empty(&dev_node->node)) {
        return;
    }

    osal_mutex_lock(&g_osal_dev_sem);

    osal_list_for_each_entry_safe(ptmp, _ptmp, &g_osal_dev_list, node)
    {
        /* if found, unregister device & driver */
        if (ptmp->dev->minor == dev->minor) {
            osal_list_del(&dev_node->node);
            osal_releasedevice(dev);
            g_media_minors[dev->minor >> 3] &= ~(1 << (dev->minor & 7)); /* 3, 7: bitmap write set bit 0 */
            break;
        }
    }
    osal_mutex_unlock(&g_osal_dev_sem);
    return;
}

void osal_poll_wait(osal_poll *table, osal_wait *wait)
{
    return;
}

void osal_pgprot_noncached(osal_vm *vm)
{
    return;
}

void osal_pgprot_cached(osal_vm *vm)
{
    return;
}

void osal_pgprot_writecombine(osal_vm *vm)
{
    return;
}

int osal_remap_pfn_range(osal_vm *vm, unsigned long addr, unsigned long pfn, unsigned long size)
{
    return 0;
}

