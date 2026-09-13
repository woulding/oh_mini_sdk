/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: sample common file.
 * Create: 2018-08-04
 */

#ifndef __SAMPLE_COMMON_H__
#define __SAMPLE_COMMON_H__

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "osal_types.h"
#include "syschannel_base.h"
/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define SAMPLE_CMD_MAX_LEN 1500
/*****************************************************************************
  3 ö�١��ṹ�嶨��
*****************************************************************************/
typedef osal_s32(*sample_cmd_func)(osal_void *wdata, osal_char *param, osal_u32 len, osal_void *pmsg);
typedef struct {
    osal_char           *cmd_name;    /* 命令字符串 */
    sample_cmd_func      func;        /* 命令对应处理函数 */
} sample_cmd_entry_stru;

typedef struct {
    sample_cmd_entry_stru *cmd_tbl;   /* 命令表 */
    osal_u32               count;     /* 命令总数 */
} sample_cmd_common;

/*****************************************************************************
  4 ��������
*****************************************************************************/
osal_s32 sample_get_cmd_one_arg(const osal_char *pc_cmd, osal_char *pc_arg, osal_u32 pc_arg_len,
    osal_u32 *pul_cmd_offset);

osal_s32 sample_parse_cmd(osal_void *wdata, osal_char *cmd, ssize_t len, osal_void *msg);

osal_s32 sample_sock_cmd_entry(osal_void *wdata, const char *cmd, ssize_t len, osal_void *msg);

osal_s32 sample_register_cmd(sample_cmd_entry_stru *cmd_tbl, osal_u32 num);

#endif

