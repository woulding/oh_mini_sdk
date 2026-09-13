/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 * Description: APF hmac function.
 * Create: 2022-10-14
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "hmac_apf.h"
#include "msg_apf_rom.h"
#include "frw_util_notifier.h"
#include "hmac_feature_interface.h"
#include "hmac_ccpriv.h"
#include "hmac_ext_if.h"
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
#include "soc_customize_wifi.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef  THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_WIFI_HOST_HMAC_APF_C

#undef THIS_MOD_ID
#define THIS_MOD_ID DIAG_MOD_ID_WIFI_HOST

/*****************************************************************************
  2 全局变量定义
*****************************************************************************/
/* APF规则信息全局结构体 */
mac_apf_stru g_hmac_st_apf = {0};
osal_u8 g_hmac_st_apf_ip[OAL_IPV4_ADDR_SIZE] = {0};
#ifdef _PRE_WLAN_FEATURE_POWERSAVE
OAL_CONST int8_t g_apf_cmd[] = "120c9400cd06007c00c888a27c00c388a47c00be88b87c00b988cd7c00b488e384002d08066a0ea2a30600\
010800060412147a1201829b021a1c7a970068a28c06ffffffffffff6a26a2840400000000728184004008000a1782211112149c001a1fffab0d2a1\
0820e446a3239a207068411035f9e9f725b82028972570a1e52f07a50e00a217a4bff68a24006ffffffffffff723f723c7c000c86dd68a22d06ffff\
ffffffff722c0a147a073a0a267a22ff721f0a367a1b858217886a26a20210ff0200000000000000000000000000017201";
#else
OAL_CONST osal_s8 g_apf_cmd[] = "120c9400d706007c00d288a27c00cd88a47c00c888b87c00c388cd7c00be88e384002d08066a0ea2ad0600\
010800060412147a120182a5021a1c7aa10068a29606ffffffffffff6a26a28e04c0a83207728b84004a08000a17821c1112149c00151fffab0d2a1\
0820e446a3239a202068411035f9e9f72650a1e52f07a5fe01a1e7e00000054ffffffff7e0000004bc0a832ff68a24006ffffffffffff723f723c7c\
000c86dd68a22d06ffffffffffff722c0a147a073a0a267a22ff721f0a367a1b858217886a26a20210ff0200000000000000000000000000017201";
#endif

/*****************************************************************************
  3 函数实现
*****************************************************************************/

/*****************************************************************************
 功能描述  : 将apf规则字符串转为16进制
*****************************************************************************/
OAL_STATIC osal_u32 hmac_apf_program_parse_hex(const osal_u8 *input, osal_u32 input_len, osal_u8 **output,
    osal_u32 *output_len)
{
    osal_char     *end_ptr = NULL;
    osal_char     tmp_buf[HMAC_APF_HEX_BYTE_SIZE + 1]; /* 每两个字符转为一个0xaa十六进制数 */
    osal_u32      index;
    osal_u32      half_len = input_len >> 1;

    *output_len = half_len;
    for (index = 0; index < half_len; index++) {
        tmp_buf[0] = (osal_char)input[index * HMAC_APF_HEX_BYTE_SIZE];
        tmp_buf[1] = (osal_char)input[index * HMAC_APF_HEX_BYTE_SIZE + 1];
        tmp_buf[HMAC_APF_HEX_BYTE_SIZE] = '\0';

        (*output)[index] = (osal_u8)osal_strtol(tmp_buf, &end_ptr, HMAC_APF_HEX_NAME);

        if (end_ptr != tmp_buf + HMAC_APF_HEX_BYTE_SIZE) {
            oam_error_log0(0, OAM_SF_APF, "hmac_apf_program_parse_hex::parse hex fail.");
            return OAL_FAIL;
        }
    }
    return OAL_SUCC;
}

/*****************************************************************************
 功能描述  : 处理apf规则字符串
*****************************************************************************/
OAL_STATIC osal_u32 hmac_apf_param_to_program(const osal_u8 *param, osal_u32 param_len, osal_u8 *program,
    osal_u32 *program_len)
{
    const osal_u8 *copy = param;
    osal_u8       *temp_program;
    osal_u32       position = 0;
    osal_u32       ret;
    osal_u32       len = param_len;

    /* 去掉字符串开始的空格 */
    while (*copy == ' ') {
        copy++;
        len--;
    }

    /* 校验输入参数(apf规则)有效长度 */
    if (len >= APF_PROGRAM_MAX_LEN || len <= 0) {
        oam_error_log0(0, OAM_SF_APF, "hmac_apf_param_to_program::program len invalid.");
        return OAL_FAIL;
    }

    temp_program = (osal_u8 *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, APF_PROGRAM_MAX_LEN, OSAL_TRUE);
    if (temp_program == NULL) {
        oam_error_log0(0, OAM_SF_APF, "hmac_apf_param_to_program::alloc program fail.");
        return OAL_FAIL;
    }

    /* 复制规则 */
    while ((*copy != ' ') && (*copy != '\0') && position < APF_PROGRAM_MAX_LEN) {
        temp_program[position] = *copy;
        position++;
        copy++;
    }
    temp_program[position] = '\0';

    /* 转为十六进制串 */
    ret = hmac_apf_program_parse_hex(temp_program, position, &program, program_len);
    oal_mem_free(temp_program, OSAL_TRUE);
    if (ret != OAL_SUCC) {
        oam_error_log1(0, OAM_SF_APF, "hmac_apf_param_to_program::parse hex fail[%u].", ret);
        return ret;
    }
    return OAL_SUCC;
}

/*****************************************************************************
 功能描述  : 更新APF过滤规则中自己的IP地址
*****************************************************************************/
OSAL_STATIC osal_void hmac_apf_update_st_apf(osal_void)
{
    frw_msg msg2device = {0};
    osal_s32 ret;
    osal_u32 j;
    osal_u32 i;

    if (g_hmac_st_apf.program_len < APF_PROGRAM_IPV4_END) {
        return;
    }
    /* 从第76 - 79字符是IPV4地址 */
    for (j = APF_PROGRAM_IPV4_BEGIN, i = 0; j <= APF_PROGRAM_IPV4_END; j++, i++) {
        g_hmac_st_apf.program[j] = ((osal_u8 *)(g_hmac_st_apf_ip))[i];
    }

    if (g_hmac_st_apf.is_enabled == OAL_TRUE) {
        // 下发事件更新apf规则
        frw_msg_init((osal_u8 *)&g_hmac_st_apf, sizeof(mac_apf_stru), OSAL_NULL, 0, &msg2device);
        ret = send_cfg_to_device(0, WLAN_MSG_H2D_C_CFG_APF_EXEC, &msg2device, OSAL_TRUE);
        if (ret != OAL_SUCC) {
            oam_error_log1(0, OAM_SF_APF, "{hmac_apf_update_st_apf:: send apf on to device fail [%d]!}", ret);
        }
    }
}

OSAL_STATIC osal_bool hmac_apf_set_ip_addr_etc(osal_void *notify_data)
{
    if (notify_data == OAL_PTR_NULL) {
        oam_error_log0(0, OAM_SF_PWR, "{hmac_apf_set_ip_addr_etc::The ip_addr is NULL. }");
        return OSAL_FALSE;
    }
    (osal_void)memcpy_s(g_hmac_st_apf_ip, sizeof(g_hmac_st_apf_ip), notify_data, sizeof(g_hmac_st_apf_ip));
    hmac_apf_update_st_apf();
    return OSAL_TRUE;
}

/*****************************************************************************
 功能描述  : APF功能开关
*****************************************************************************/
OSAL_STATIC osal_bool hmac_apf_filter_switch(osal_void *notify_data)
{
    frw_msg                     msg2device = {0};
    oal_bool_enum_uint8         device_apf_msg;
    osal_s32                    ret;
    oal_bool_enum_uint8 apf_switch = *(oal_bool_enum_uint8 *)notify_data;
    osal_u32 pps_rate = 0;
    osal_void *fhook = hmac_get_feature_fhook(HMAC_FHOOK_AUTO_FREQ_PPS);

    if (apf_switch >= OAL_BUTT) {
        return OSAL_FALSE;
    }

    if (fhook != OSAL_NULL) {
        ((hmac_get_pps_handle_pps_rate_cb)fhook)(&pps_rate);
    }

    /* 如果apf已处状态和设置状态一致 则直接返回 */
    if (g_hmac_st_apf.is_enabled == apf_switch) {
        return OSAL_TRUE;
    }

    /* 开关状态置为关 */
    if (apf_switch == OAL_FALSE) {
        oam_warning_log0(0, OAM_SF_APF, "hmac_apf_filter_switch::disable");
        device_apf_msg = OAL_FALSE;
        g_hmac_st_apf.is_enabled = OAL_FALSE;

        // 下发事件将device的apf功能给关了
        frw_msg_init((osal_u8 *)&device_apf_msg, sizeof(oal_bool_enum_uint8), OSAL_NULL, 0, &msg2device);
        /* snyc ps config to device */
        ret = send_cfg_to_device(0, WLAN_MSG_H2D_C_CFG_APF_EXEC, &msg2device, OSAL_TRUE);
        if (ret != OAL_SUCC) {
            oam_error_log1(0, OAM_SF_APF, "{hmac_apf_filter_switch:: send apf off to device fail [%d]!}", ret);
            return OSAL_FALSE;
        }
        return OSAL_TRUE;
    }

    if ((g_hmac_st_apf.program_len != 0) && (pps_rate <= PPS_VALUE_1)) {
        g_hmac_st_apf.is_enabled = OAL_TRUE;

        oam_warning_log3(0, OAM_SF_APF, "hmac_apf_filter_switch:enable[%hhu] program len[%hu], over[%u]",
            g_hmac_st_apf.is_enabled, g_hmac_st_apf.program_len, PPS_VALUE_1);

        // 下发事件开apf功能
        frw_msg_init((osal_u8 *)&g_hmac_st_apf, sizeof(mac_apf_stru), OSAL_NULL, 0, &msg2device);
        ret = send_cfg_to_device(0, WLAN_MSG_H2D_C_CFG_APF_EXEC, &msg2device, OSAL_TRUE);
        if (ret != OAL_SUCC) {
            oam_error_log1(0, OAM_SF_APF, "{hmac_apf_filter_switch:: send apf on to device fail [%d]!}", ret);
            return OSAL_FALSE;
        }
    } else {
        oam_warning_log0(0, OAM_SF_APF, "hmac_apf_filter_switch::can't enable apf.");
    }
    return OSAL_TRUE;
}

/*****************************************************************************
 功能描述  : 强制停止APF
*****************************************************************************/
OSAL_STATIC osal_s32 hmac_config_force_stop_filter(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
    oal_bool_enum_uint8 uc_switch = OAL_FALSE;
    hmac_device_stru *hmac_device;
    osal_u8 force_stop_filter;

    if (hmac_vap == OAL_PTR_NULL || msg == OAL_PTR_NULL) {
        oam_warning_log0(0, OAM_SF_APF, "hmac_config_force_stop_filter:: NULL ptr error.");
        return OAL_ERR_CODE_PTR_NULL;
    }

    if (hwifi_get_apf_enable() == OSAL_FALSE) {
        oam_warning_log0(0, OAM_SF_APF, "{hmac_config_force_stop_filter: apf isn't supported.}");
        return OAL_SUCC;
    }

    hmac_device = hmac_res_get_mac_dev_etc(hmac_vap->device_id);
    if (hmac_device == OAL_PTR_NULL) {
        oam_warning_log0(0, OAM_SF_APF, "hmac_config_force_stop_filter::hmac_device NULL error");
        return OAL_ERR_CODE_PTR_NULL;
    }

    force_stop_filter = (*((osal_s32 *)msg->data) == OSAL_SWITCH_ON);
    /* 在暗屏情况下, force_stop_filter不使能时，开启apf过滤; 使能时，强制关闭apf */
    if ((hmac_device->in_suspend == OSAL_TRUE) && (force_stop_filter == OAL_FALSE)) {
        // 打开apf
        uc_switch = OAL_TRUE;
    }
    hmac_apf_filter_switch(&uc_switch);
    return OAL_SUCC;
}

/*****************************************************************************
 功能描述  : 配置APF过滤条件
*****************************************************************************/
OSAL_STATIC osal_void hmac_apf_filter_install(const mac_apf_filter_cmd_stru *apf_filter_cmd)
{
    osal_u8 *program = apf_filter_cmd->program;
    osal_u16 program_len = apf_filter_cmd->program_len;

    if (program_len > APF_PROGRAM_MAX_LEN) {
        oam_error_log2(0, OAM_SF_APF, "{hmac_apf_filter_install::program_len [%hu] > APF_PROGRAM_MAX_LEN[%d]!.}",
            program_len, APF_PROGRAM_MAX_LEN);
        return;
    }

    if (memcpy_s(g_hmac_st_apf.program, APF_PROGRAM_MAX_LEN, program, program_len) != EOK) {
        oam_error_log0(0, OAM_SF_APF, "hmac_apf_filter_install::memcpy fail.");
        return;
    }
    g_hmac_st_apf.program_len = program_len;
    hmac_apf_update_st_apf();
    g_hmac_st_apf.install_timestamp = (osal_u32)(osal_get_time_stamp_ms() >> BIT_OFFSET_10); /* 秒级时间戳 */

    oam_warning_log1(0, OAM_SF_APF, "{hmac_apf_filter_install::set_apf_filter succ, program_len[%hu].}",
        g_hmac_st_apf.program_len);
    return;
}

/*****************************************************************************
 功能描述  : 删除APF过滤条件
*****************************************************************************/
OSAL_STATIC osal_bool hmac_apf_filter_del_user(osal_void *notify_data)
{
    frw_msg                     msg2device = {0};
    oal_bool_enum_uint8         device_apf_msg;
    osal_s32                    ret;
    hmac_vap_stru *hmac_vap = OSAL_NULL;
    hmac_user_stru *hmac_user = (hmac_user_stru *)notify_data;

    hmac_vap = mac_res_get_hmac_vap(hmac_user->vap_id);
    if (hmac_vap == OSAL_NULL) {
        oam_warning_log1(0, 0, "{hmac_apf_filter_del_user:vap[%d] is null.}", hmac_user->vap_id);
        return OSAL_FALSE;
    }

    if (!is_legacy_sta(hmac_vap)) {
        return OSAL_TRUE;
    }

    /* 如果apf正打开，则发事件关闭 */
    if (g_hmac_st_apf.is_enabled == OSAL_TRUE) {
        device_apf_msg = OSAL_FALSE;
        frw_msg_init((osal_u8 *)&device_apf_msg, sizeof(oal_bool_enum_uint8), OSAL_NULL, 0, &msg2device);
        /* snyc ps config to device */
        ret = send_cfg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_APF_EXEC, &msg2device, OSAL_TRUE);
        if (ret != OAL_SUCC) {
            oam_error_log1(0, OAM_SF_APF, "{hmac_apf_filter_uninstall:: send apf off to device fail [%d]!}", ret);
        }
        g_hmac_st_apf.is_enabled = OAL_FALSE;
    }
    oam_warning_log1(0, OAM_SF_APF, "dmac_apf_filter_uninstall::program_len[%hu].", g_hmac_st_apf.program_len);
    (osal_void)memset_s(g_hmac_st_apf_ip, sizeof(g_hmac_st_apf_ip), 0, sizeof(g_hmac_st_apf_ip));
    return OSAL_TRUE;
}

#ifndef CONFIG_HAS_EARLYSUSPEND
#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
OSAL_STATIC osal_s32 hmac_config_set_apf_enable(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
    dmac_ip_addr_config_stru *ip_addr_info = (dmac_ip_addr_config_stru *)msg->data;
    osal_u8 enable = OSAL_FALSE;

    if (hwifi_get_apf_enable() == OSAL_FALSE || !is_legacy_sta(hmac_vap)) {
        oam_warning_log0(0, OAM_SF_APF, "{hmac_config_set_apf_enable::apf isn't supported.}");
        return OAL_SUCC;
    }

    if (ip_addr_info->type != DMAC_CONFIG_IPV4 || ip_addr_info->oper >= DMAC_IP_OPER_BUTT) {
        oam_warning_log0(0, OAM_SF_APF, "{hmac_config_set_apf_enable::ip param invalid.}");
        return OAL_SUCC;
    }

    if (ip_addr_info->oper == DMAC_IP_ADDR_DEL) {
        (osal_void)memset_s(g_hmac_st_apf_ip, OAL_IPV4_ADDR_SIZE, 0, OAL_IPV4_ADDR_SIZE);
    }

    if (ip_addr_info->oper == DMAC_IP_ADDR_ADD && (oal_memcmp(ip_addr_info->ip_addr, 0, OAL_IPV4_ADDR_SIZE) != 0)) {
        enable = OSAL_TRUE;
        if (oal_memcmp(g_hmac_st_apf_ip, ip_addr_info->ip_addr, OAL_IPV4_ADDR_SIZE) != 0) {
            (osal_void)hmac_apf_set_ip_addr_etc((osal_void *)(ip_addr_info->ip_addr));
        }
    }
    (osal_void)hmac_apf_filter_switch((osal_void *)&enable);
    return OAL_SUCC;
}
#endif

/*****************************************************************************
 函 数 名  : hmac_config_set_suspend_mode
 功能描述  : 设置亮暗屏状态
*****************************************************************************/
OSAL_STATIC osal_s32 hmac_config_set_suspend_mode(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
    hmac_device_stru *hmac_device = hmac_res_get_mac_dev_etc(hmac_vap->device_id);
    if (!hmac_device) {
        oam_error_log1(0, OAM_SF_CFG, "vap_id[%d] hmac_config_set_suspend_mode:hmac_device is null ptr!",
            hmac_vap->vap_id);
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* 0:亮屏 1:暗屏 */
    if (*(msg->data) == 0) {
        hmac_do_suspend_action_etc(hmac_device, OAL_FALSE);
    } else {
        hmac_do_suspend_action_etc(hmac_device, OAL_TRUE);
    }

    return OAL_SUCC;
}
#endif

/*****************************************************************************
 功能描述:
 1.当apf_filter_cmd->cmd_type == APF_SET_FILTER_CMD时，
   下发APF过滤规则到dmac
 2.当apf_filter_cmd->cmd_type != APF_SET_FILTER_CMD时，
   上报HMAC侧当前APF过滤规则
*****************************************************************************/
OSAL_STATIC osal_s32 hmac_config_apf_filter_cmd(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
    mac_apf_filter_cmd_stru *apf_filter_cmd = OSAL_NULL;
    frw_msg msg2device;
    osal_s32 ret;
    osal_u32 i;

    if (hmac_vap == OSAL_NULL || msg == OSAL_NULL || msg->data == OSAL_NULL) {
        oam_error_log0(0, OAM_SF_APF, "{hmac_config_apf_filter_cmd::mac_vap or param or msg->data is null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    apf_filter_cmd = (mac_apf_filter_cmd_stru *)msg->data;
    if (apf_filter_cmd->cmd_type == APF_SET_FILTER_CMD) {
        hmac_apf_filter_install(apf_filter_cmd);
        /* 规则发生变动需要看目前是否开启apf,如果开启则需要重新下发规则给device */
        if (g_hmac_st_apf.is_enabled == OAL_TRUE) {
            frw_msg_init((osal_u8 *)&g_hmac_st_apf, sizeof(mac_apf_stru), OSAL_NULL, 0, &msg2device);
            ret = send_cfg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_APF_EXEC, &msg2device, OSAL_TRUE);
            if (ret != OAL_SUCC) {
                oam_error_log1(0, OAM_SF_APF, "{hmac_config_apf_filter_cmd:: send apf on to device fail [%d]!}", ret);
                return ret;
            }
        }
    } else if (apf_filter_cmd->cmd_type == APF_GET_FILTER_CMD) {
        for (i = 0; i < g_hmac_st_apf.program_len; ++i) {
            wifi_printf_always("%02x", g_hmac_st_apf.program[i]);
        }
    }

    return OAL_SUCC;
}

OSAL_STATIC osal_s32 hmac_apf_set_default_list(hmac_vap_stru *hmac_vap)
{
    mac_apf_filter_cmd_stru apf_filter_cmd = {0};
    frw_msg msg_info;
    osal_u8 *buff_program = NULL;
    osal_u32 program_len = 0;
    osal_u32 ret;

    buff_program = (osal_u8 *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, APF_PROGRAM_MAX_LEN, OSAL_TRUE);
    if (buff_program == NULL) {
        oam_error_log0(0, OAM_SF_APF, "hmac_apf_set_default_list::alloc program fail.");
        return OAL_FAIL;
    }

    /* 获取program及长度 */
    ret = hmac_apf_param_to_program((osal_u8 *)g_apf_cmd, (osal_u32)osal_strlen((const char*)g_apf_cmd),
        buff_program, &program_len);
    if (ret != OAL_SUCC) {
        oal_mem_free(buff_program, OAL_TRUE);
        oam_error_log1(0, OAM_SF_APF, "{hmac_apf_set_default_list::parse arg failed [%d].}", ret);
        return OAL_FAIL;
    }

    apf_filter_cmd.cmd_type = APF_SET_FILTER_CMD;
    apf_filter_cmd.program_len = (osal_u16)program_len;
    apf_filter_cmd.program = buff_program;
    frw_msg_init((osal_u8*)&apf_filter_cmd, OAL_SIZEOF(mac_apf_filter_cmd_stru), OSAL_NULL, 0, &msg_info);
    hmac_config_apf_filter_cmd(hmac_vap, &msg_info);
    /* 释放动态申请内存 */
    oal_mem_free(buff_program, OAL_TRUE);
    return OAL_SUCC;
}

/*****************************************************************************
 功能描述  : ccpriv命令 配置apf过滤规则
*****************************************************************************/
OAL_STATIC osal_s32 hmac_ccpriv_set_apf_list(hmac_vap_stru *hmac_vap, const osal_s8 *param)
{
    if (hmac_vap == NULL || param == NULL) {
        oam_error_log0(0, OAM_SF_APF, "hmac_ccpriv_set_apf_list::hmac_vap or param is null.");
        return OAL_FAIL;
    }

    if (hwifi_get_apf_enable() == OSAL_FALSE) {
        oam_warning_log0(0, OAM_SF_APF, "{hmac_ccpriv_set_apf_list::apf isn't supported.}");
        return OAL_SUCC;
    }
    return hmac_apf_set_default_list(hmac_vap);
}

/*****************************************************************************
 功能描述  : ccpriv命令 显示apf filter到串口
*****************************************************************************/
OAL_STATIC osal_s32 hmac_ccpriv_get_apf_list(hmac_vap_stru *hmac_vap, const osal_s8 *param)
{
    mac_apf_filter_cmd_stru apf_filter_cmd = {0};
    frw_msg msg_info;

    if (hmac_vap == NULL || param == NULL) {
        oam_error_log0(0, OAM_SF_APF, "hmac_ccpriv_get_apf_list::net_dev or param is null.");
        return OAL_FAIL;
    }

    if (hwifi_get_apf_enable() == OSAL_FALSE) {
        oam_warning_log0(0, OAM_SF_APF, "{hmac_ccpriv_get_apf_list::apf isn't supported.}");
        return OAL_SUCC;
    }

    apf_filter_cmd.cmd_type = APF_GET_FILTER_CMD;
    (osal_void)memset_s(&msg_info, OAL_SIZEOF(msg_info), 0, OAL_SIZEOF(msg_info));
    msg_info.data = (osal_u8*)&apf_filter_cmd;
    msg_info.data_len = (osal_u16)OAL_SIZEOF(mac_apf_filter_cmd_stru);
    hmac_config_apf_filter_cmd(hmac_vap, &msg_info);
    return OAL_SUCC;
}

/*****************************************************************************
 功能描述  : ccpriv命令 设置暗屏
*****************************************************************************/
OAL_STATIC osal_s32 hmac_ccpriv_suspend_mode(hmac_vap_stru *hmac_vap, const osal_s8 *param)
{
    frw_msg msg_info;
    osal_u8 value = 0;
    osal_s32 ret;

    if (hmac_vap == OSAL_NULL || param == OSAL_NULL) {
        oam_error_log0(0, OAM_SF_APF, "hmac_ccpriv_suspend_mode::net_dev or param is null.");
        return OAL_FAIL;
    }

    if (hwifi_get_apf_enable() == OSAL_FALSE) {
        oam_warning_log0(0, OAM_SF_APF, "{hmac_ccpriv_suspend_mode::apf isn't supported.}");
        return OAL_SUCC;
    }

    ret = hmac_ccpriv_get_u8_with_check_max(&param, OAL_TRUE, &value);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{hmac_ccpriv_suspend_mode::return err_code[%u]!}", ret);
        return ret;
    }

    (osal_void)memset_s(&msg_info, OAL_SIZEOF(msg_info), 0, OAL_SIZEOF(msg_info));
    msg_info.data = (osal_u8*)&value;
    msg_info.data_len = (osal_u16)OAL_SIZEOF(value);
#ifndef CONFIG_HAS_EARLYSUSPEND
    hmac_config_set_suspend_mode(hmac_vap, &msg_info);
#endif
    return OAL_SUCC;
}

OSAL_STATIC osal_bool hmac_apf_vap_init(osal_void *notify_data)
{
    hmac_vap_stru *hmac_vap = (hmac_vap_stru *)notify_data;

    if (!is_legacy_sta(hmac_vap)) {
        return OSAL_TRUE;
    }

    (osal_void)memset_s(&g_hmac_st_apf, sizeof(mac_apf_stru), 0, sizeof(mac_apf_stru));
    (osal_void)memset_s(g_hmac_st_apf_ip, OAL_IPV4_ADDR_SIZE, 0, OAL_IPV4_ADDR_SIZE);

    hmac_apf_set_default_list(hmac_vap);
    return OSAL_TRUE;
}

osal_u32 hmac_apf_init(osal_void)
{
    /* 注册监听 */
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_DEL_USER, hmac_apf_filter_del_user);
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_INETADDR_NOTIFIER_UP, hmac_apf_set_ip_addr_etc);
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_SUSPEND_CHANGE, hmac_apf_filter_switch);
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_ADD_VAP, hmac_apf_vap_init);

    /* 注册消息 */
    frw_msg_hook_register(WLAN_MSG_W2H_CFG_SET_FILTER_LIST, hmac_config_apf_filter_cmd);
    frw_msg_hook_register(WLAN_MSG_W2H_CFG_FORCE_STOP_FILTER, hmac_config_force_stop_filter);
#ifndef CONFIG_HAS_EARLYSUSPEND
#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    frw_msg_hook_register(WLAN_MSG_W2H_CFG_SET_SUSPEND_MODE, hmac_config_set_apf_enable);
#else
    frw_msg_hook_register(WLAN_MSG_W2H_CFG_SET_SUSPEND_MODE, hmac_config_set_suspend_mode);
#endif
#endif
    /* api注册 */
    hmac_ccpriv_register((const osal_s8 *)"set_apf_list", hmac_ccpriv_set_apf_list);
    hmac_ccpriv_register((const osal_s8 *)"get_apf_list", hmac_ccpriv_get_apf_list);
    hmac_ccpriv_register((const osal_s8 *)"suspend_mode", hmac_ccpriv_suspend_mode);
    return OAL_SUCC;
}

osal_void hmac_apf_deinit(osal_void)
{
    /* 去注册监听 */
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_DEL_USER, hmac_apf_filter_del_user);
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_INETADDR_NOTIFIER_UP, hmac_apf_set_ip_addr_etc);
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_SUSPEND_CHANGE, hmac_apf_filter_switch);
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_ADD_VAP, hmac_apf_vap_init);

    /* 去注册消息 */
    frw_msg_hook_unregister(WLAN_MSG_W2H_CFG_SET_FILTER_LIST);
    frw_msg_hook_unregister(WLAN_MSG_W2H_CFG_FORCE_STOP_FILTER);
#ifndef CONFIG_HAS_EARLYSUSPEND
    frw_msg_hook_unregister(WLAN_MSG_W2H_CFG_SET_SUSPEND_MODE);
#endif
    /* api去注册 */
    hmac_ccpriv_unregister((const osal_s8 *)"set_apf_list");
    hmac_ccpriv_unregister((const osal_s8 *)"get_apf_list");
    hmac_ccpriv_unregister((const osal_s8 *)"suspend_mode");
    return;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
