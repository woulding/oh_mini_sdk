/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: sample common file.
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "securec.h"
#include "syschannel_host_comm.h"

/*****************************************************************************
  2 宏定义、全局变量
*****************************************************************************/
static sample_cmd_common g_cmd_com = {0};

/*****************************************************************************
  4 函数实现
*****************************************************************************/
osal_s32 sample_get_cmd_one_arg(const osal_char *pc_cmd, osal_char *pc_arg, osal_u32 pc_arg_len,
    osal_u32 *pul_cmd_offset)
{
    const osal_char *pc_cmd_copy = OSAL_NULL;
    osal_u32   pos = 0;

    if ((pc_cmd == OSAL_NULL) || (pc_arg == OSAL_NULL) || (pul_cmd_offset == OSAL_NULL)) {
        sample_log_print("pc_cmd/pc_arg/pul_cmd_offset null ptr error %pK, %pK, %pK!\n", \
            pc_cmd, pc_arg, pul_cmd_offset);
        return OSAL_NOK;
    }

    pc_cmd_copy = pc_cmd;

    while (*pc_cmd_copy != '\0' && !((*(pc_cmd_copy) == ',') && (*(pc_cmd_copy - 1) != '\\'))) {
        if ((*(pc_cmd_copy + 1) == ',') && (*(pc_cmd_copy) == '\\')) {
            ++pc_cmd_copy;
            continue;
        }
        pc_arg[pos] = *pc_cmd_copy;
        ++pos;
        ++pc_cmd_copy;

        if (pos >= pc_arg_len) {
            sample_log_print("ul_pos >= WLAN_CMD_NAME_MAX_LEN, ul_pos %d!\n", pos);
            return OSAL_NOK;
        }
    }

    pc_arg[pos]  = '\0';

    /* 字符串到结尾，返回错误码 */
    if (pos == 0) {
        sample_log_print("return param pc_arg is null!}\r\n");
        return OSAL_NOK;
    }
    *pul_cmd_offset = (osal_u32)(pc_cmd_copy - pc_cmd);

    return OSAL_OK;
}

osal_s32 sample_parse_cmd(osal_void *wdata, osal_char *cmd, ssize_t len, osal_void *msg)
{
    osal_u8                  cmd_id;
    osal_u32                 off_set = 0;
    osal_char                wlan_name[SAMPLE_CMD_MAX_LEN] = {0};

    if (cmd == OSAL_NULL) {
        return OSAL_NOK;
    }

    if (sample_get_cmd_one_arg(cmd, wlan_name, SAMPLE_CMD_MAX_LEN, &off_set) != OSAL_OK) {
        return OSAL_NOK;
    }
    cmd += (off_set + 1);

    for (cmd_id = 0; cmd_id < g_cmd_com.count; cmd_id++) {
        if (strcmp(g_cmd_com.cmd_tbl[cmd_id].cmd_name, wlan_name) == 0) {
            if (g_cmd_com.cmd_tbl[cmd_id].func(wdata, cmd, len, msg) != OSAL_OK) {
                sample_log_print("cmd exec fail!\n");
                return OSAL_NOK;
            }
            return OSAL_OK;
        }
    }

    return OSAL_NOK;
}

osal_s32 sample_sock_cmd_entry(osal_void *wdata, const char *cmd, ssize_t len, osal_void *msg)
{
    osal_char *pcmd = OSAL_NULL;
    osal_char *pcmd_tmp = OSAL_NULL;
    if (len > SAMPLE_CMD_MAX_LEN) {
        sample_log_print("command len > %d!\n", SAMPLE_CMD_MAX_LEN);
        return OSAL_NOK;
    }
    pcmd = malloc(SAMPLE_CMD_MAX_LEN);
    if (pcmd == OSAL_NULL) {
        return OSAL_NOK;
    }
    if (cmd != OSAL_NULL) {
        if (memcpy_s(pcmd, len, cmd, len) != EOK) {
            sample_log_print("command memcpy_s failed!\n");
            free(pcmd);
            return OSAL_NOK;
        }
    }

    pcmd[len] = '\0';
    pcmd_tmp = pcmd;
    if (sample_parse_cmd(wdata, pcmd_tmp, len, msg) != OSAL_OK) {
        free(pcmd);
        return OSAL_NOK;
    }
    free(pcmd);
    return OSAL_OK;
}

osal_s32 sample_register_cmd(sample_cmd_entry_stru *cmd_tbl, osal_u32 num)
{
    osal_u32 i;
    sample_cmd_common *tmp_list = OSAL_NULL;
    tmp_list = (sample_cmd_common *)&g_cmd_com;
    for (i = 0; i < num; i++) {
        if (cmd_tbl[i].cmd_name == OSAL_NULL || cmd_tbl[i].func == OSAL_NULL) {
            sample_log_print("SAMPLE_COMMON: register cmd table failed!\n");
            return OSAL_NOK;
        }
    }
    tmp_list->cmd_tbl = cmd_tbl;
    tmp_list->count = num;
    return OSAL_OK;
}

