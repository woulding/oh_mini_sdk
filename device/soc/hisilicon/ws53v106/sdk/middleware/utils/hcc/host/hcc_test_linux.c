/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2023. All rights reserved.
 * Description: HCC TEST
 *
 */

#if !defined(CONFIG_3519D) && !defined(CONFIG_3516CV610)
#include <asm/unistd.h>
#include <asm/uaccess.h>
#endif
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include "securec.h"
#include "hcc_test.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_HCC_TEST_HOST_C

#undef THIS_MOD_ID
#define THIS_MOD_ID LOG_PFMODULE

#ifdef CONFIG_HCC_SUPPORT_TEST
td_u32 __attribute__((weak)) hcc_test_cmd_show_ext(const td_s8 *buf)
{
    return 0;
}

static ssize_t show_test_dbg(struct device *dev, struct kobj_attribute *attr, osal_char *buf)
{
    return hcc_test_cmd_show_ext(buf);
}

static ssize_t hcc_test_cmd_one_params_proc(const td_s8 *buf, hcc_test_cmd_args *cmd_args)
{
    td_s32 p1 = 0;
    td_s32 ret = 1;
    td_s32 cmd = 0;
    ret = sscanf_s(buf, "%d %d", &cmd, &p1);
    cmd_args->argv[cmd_args->argc++] = cmd;
    cmd_args->argv[cmd_args->argc++] = p1;
    return ret;
}

static ssize_t hcc_test_cmd_two_params_proc(const td_s8 *buf, hcc_test_cmd_args *cmd_args)
{
    td_s32 p1 = 0, p2 = 0;
    td_s32 ret = 1;
    td_s32 cmd = 0;
    ret = sscanf_s(buf, "%d %d %d", &cmd, &p1, &p2);
    cmd_args->argv[cmd_args->argc++] = cmd;
    cmd_args->argv[cmd_args->argc++] = p1;
    cmd_args->argv[cmd_args->argc++] = p2;
    return ret;
}

static ssize_t hcc_test_cmd_three_params_proc(const td_s8 *buf, hcc_test_cmd_args *cmd_args)
{
    td_s32 p1 = 0, p2 = 0, p3 = 0;
    td_s32 ret = 1;
    td_s32 cmd = 0;
    ret = sscanf_s(buf, "%d %d %d %d", &cmd, &p1, &p2, &p3);
    cmd_args->argv[cmd_args->argc++] = cmd;
    cmd_args->argv[cmd_args->argc++] = p1;
    cmd_args->argv[cmd_args->argc++] = p2;
    cmd_args->argv[cmd_args->argc++] = p3;
    return ret;
}

static ssize_t hcc_test_cmd_three_params_hex(const td_s8 *buf, hcc_test_cmd_args *cmd_args)
{
    td_u32 p1 = 0, p2 = 0, p3 = 0;
    td_s32 ret = 1;
    td_s32 cmd = 0;
    ret = sscanf_s(buf, "%d 0x%x 0x%x 0x%x", &cmd, &p1, &p2, &p3);
    cmd_args->argv[cmd_args->argc++] = cmd;
    cmd_args->argv[cmd_args->argc++] = p1;
    cmd_args->argv[cmd_args->argc++] = p2;
    cmd_args->argv[cmd_args->argc++] = p3;
    return ret;
}

static ssize_t hcc_test_cmd_init(const td_s8 *buf, td_s32 *cmd)
{
    if (buf == NULL) {
        printk("buf is NULL\n");
        return EXT_ERR_FAILURE;
    }

    if (sscanf_s(buf, "%d", cmd) < 1) {
        return EXT_ERR_FAILURE;
    }
    return EXT_ERR_SUCCESS;
}

static ssize_t store_test_dbg_end_proc(td_s32 ret, hcc_test_cmd_args *cmd_args, size_t count)
{
    if (ret < 1) {
        printk("cmd paras must more than 1 arguments!\n");
        return EXT_ERR_FAILURE;
    }

    if (cmd_args->argv[0] == HCC_TEST_CMD_REMOTE) {
        if (cmd_args->argc > 0) {
            hcc_test_proc_remote_cmd(&cmd_args->argv[1], cmd_args->argc - 1);
        }
    } else {
        hcc_test_proc_local_cmd(&cmd_args->argv[0], cmd_args->argc);
    }
    return count;
}

td_u32 __attribute__((weak)) hcc_test_cmd_ext(const td_s8 *buf, size_t count)
{
    return EXT_ERR_FAILURE;
}

#define REMOTE_CMD_STR "31"
static ssize_t store_test_dbg(struct device *dev, struct kobj_attribute *attr, const td_s8 *buf, size_t count)
{
    td_s32 cmd = 0;
    hcc_test_cmd_args cmd_args;
    td_s32 ret = 1;

    if (hcc_test_cmd_ext(buf, count) == EXT_ERR_SUCCESS) {
        return count;
    }

    cmd_args.argc = 0;
    ret = hcc_test_cmd_init(buf, &cmd);
    if (ret != EXT_ERR_SUCCESS) {
        return ret;
    }

    if (cmd == HCC_TEST_CMD_REMOTE) {
        cmd_args.argv[cmd_args.argc++] = cmd;
        buf = strstr(buf, REMOTE_CMD_STR);
        buf += strlen(REMOTE_CMD_STR);
        ret = hcc_test_cmd_init(buf, &cmd);
        if (ret != EXT_ERR_SUCCESS) {
            return ret;
        }
    }
    switch (cmd) {
        /* 不带参数 */
        case HCC_TEST_CMD_TEST_INIT:
        case HCC_TEST_CMD_M2S:
        case HCC_TEST_GET_CREDIT:
            cmd_args.argv[cmd_args.argc++] = cmd;
            ret = 1;
            break;
        /* 带1个参数 */
        case HCC_TEST_PRINT_BUS_INFO:
        case HCC_TEST_CMD_SET_QUEUE:
        case HCC_TEST_CMD_SET_TX_CHANNEL:
        case HCC_TEST_CMD_TEST_MSG:
        case HCC_TEST_CMD_TEST_REG_OPT:
            ret = hcc_test_cmd_one_params_proc(buf, &cmd_args);
            break;
        case HCC_TEST_PRINT_QUEUE_INFO:
            ret = hcc_test_cmd_two_params_proc(buf, &cmd_args);
            break;
        case HCC_TEST_CMD_SET_REG_ADDR:
            ret = hcc_test_cmd_three_params_hex(buf, &cmd_args);
            break;
        case HCC_TEST_CMD_INIT_ALL_PARAM_AND_START_TEST:
            ret = hcc_test_cmd_three_params_proc(buf, &cmd_args);
            break;
        default:
            break;
    }
    return store_test_dbg_end_proc(ret, &cmd_args, count);
}

static struct kobj_attribute hcc_test_dbg =
__ATTR(hcc_test_cmd, 0644, (void *)show_test_dbg, (void *)store_test_dbg);

static struct attribute *hcc_test_attrs[] = {
    &hcc_test_dbg.attr,
    TD_NULL,
    TD_NULL,
};
static struct attribute_group hcc_test_attr_grp = {
    .attrs = hcc_test_attrs,
};

struct kobject *g_sysfs_hcc_test = TD_NULL;
td_s32 hcc_test_cmd_ctrl_init(void)
{
    int status;
    g_sysfs_hcc_test = kobject_create_and_add("hcc_test_cmd", TD_NULL);
    if (g_sysfs_hcc_test == TD_NULL) {
        printk("Failed to creat g_sysfs_hcc_test !!!\n ");
        goto fail_g_sysfs_hcc_test;
    }

    status = sysfs_create_group(g_sysfs_hcc_test, &hcc_test_attr_grp);
    if (status) {
        printk("failed to create g_sysfs_hcc_test sysfs entries\n");
        goto fail_create_hcc_test_group;
    }

    return 0;

fail_create_hcc_test_group:
    kobject_put(g_sysfs_hcc_test);
fail_g_sysfs_hcc_test:
    return -EFAULT;
}

void hcc_test_cmd_ctrl_deinit(void)
{
    if (g_sysfs_hcc_test == NULL) {
        return;
    }
    sysfs_remove_group(g_sysfs_hcc_test, &hcc_test_attr_grp);
    kobject_put(g_sysfs_hcc_test);
    g_sysfs_hcc_test = NULL;
}
#endif
