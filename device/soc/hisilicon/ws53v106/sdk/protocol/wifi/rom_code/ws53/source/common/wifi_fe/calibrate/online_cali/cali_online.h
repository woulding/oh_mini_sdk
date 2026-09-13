/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: cali_online.c 的头文件
 * Date: 2022-10-20
 */

#ifndef __CALI_ONLINE_H__
#define __CALI_ONLINE_H__
/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "cali_online_tx_pwr.h"
#include "cali_online_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define ONLINE_CALI_CUS_FB_LVL_NUM                 (2)     /* 功率校准区分高低两个档位 */
#define ONLINE_CALI_INIT_ENTRY_DELAY_TIMER_PERIOD  (200) /* INIT状态进入延迟 */
#define ONLINE_CALI_GO_TO_NEXT_STATE_DELAY_TIME    (100) /* 延时1000ms进入下一个状态 */

#define ONLINE_IQ_CALI_STATUS_INIT        0
#define ONLINE_IQ_CALI_STATUS_COMPLETE    1

// online校准类型定义
#define ONLINE_CALI_TYPE_TX_PWR   0
#define ONLINE_CALI_TYPE_TX_IQ    1
#define ONLINE_CALI_TYPE_RX_IQ    2
#define ONLINE_CALI_TYPE_BUTT     3

// online_iq type类型定义
#define ONLINE_IQ_TYPE_TX   0
#define ONLINE_IQ_TYPE_RX   1
#define ONLINE_IQ_TYPE_BUTT 2

// online_iq H2D消息类型定义
#define ONLINE_IQ_H2D_MSG_START_TX_CALI 0
#define ONLINE_IQ_H2D_MSG_END_TX_CALI   1
#define ONLINE_IQ_H2D_MSG_START_RX_CALI 2
#define ONLINE_IQ_H2D_MSG_END_RX_CALI   3

// online_iq D2H消息类型定义
#define ONLINE_IQ_D2H_MSG_TX_CALI_SUCCESS   0
#define ONLINE_IQ_D2H_MSG_RX_CALI_SUCCESS   1

/*****************************************************************************
  3 枚举定义
*****************************************************************************/

/* ONLINE TX CALI状态机状态枚举 */
typedef enum {
    ONLINE_CALI_STATE_INIT    = 0,  /* 初始运行状态 */
    ONLINE_CALI_STATE_DYN_PWR = 1,  /* 动态功率状态 */
    ONLINE_CALI_STATE_TX_IQ   = 2,  /* online_tx_iq校准 */
    ONLINE_CALI_STATE_RX_IQ   = 3,  /* online_rx_iq校准 */
    ONLINE_CALI_STATE_BUTT          /* 最大状态 */
} online_tx_cali_state;

/* ONLINE DEBUG SWITCH日志开关枚举 */
typedef enum {
    ONLINE_DEBUG_SWITCH_DYN_PWR = 0,
    ONLINE_DEBUG_SWITCH_TX_IQ   = 1,
    ONLINE_DEBUG_SWITCH_RX_IQ   = 2,
    ONLINE_DEBUG_SWITCH_BUTT
} online_debug_switch_enum;

/* ONLINE TX CALI状态机事件枚举 */
typedef enum {
    ONLINE_CALI_EVENT_TX_NOTIFY             = 0,       /* 发送时online校准处理事件 */
    ONLINE_CALI_EVENT_TX_COMPLETE           = 1,       /* 发送完成时online校准处理事件 */
    ONLINE_CALI_EVENT_DYN_PWR_COMPLETE      = 2,       /* 动态功率校准完成处理事件 */
    ONLINE_CALI_EVENT_ONLINE_TX_IQ_COMPLETE = 3,       /* online tx iq校准完毕 */
    ONLINE_CALI_EVENT_ONLINE_RX_IQ_COMPLETE = 4,       /* online rx iq校准完毕 */
    ONLINE_CALI_EVENT_ONLINE_TX_IQ_TIMEOUT  = 5,       /* online tx iq校准超时 */
    ONLINE_CALI_EVENT_ONLINE_RX_IQ_TIMEOUT  = 6,       /* online rx iq校准超时 */
    ONLINE_CALI_EVENT_CHANNEL_CHANGE        = 7,       /* 信道改变时处理事件 */
    ONLINE_CALI_EVENT_BW_CHANGE             = 8,       /* 带宽改变时处理事件 */
    ONLINE_CALI_EVENT_EQUIPE_CHANGE         = 9,       /* 装备校准时处理事件 */
    ONLINE_CALI_EVENT_BUTT
} online_cali_event_tpye;
/*****************************************************************************
  4 全局变量声明
*****************************************************************************/
/*****************************************************************************
  5 消息头定义
*****************************************************************************/
/*****************************************************************************
  6 消息定义
*****************************************************************************/
/*****************************************************************************
  7 STRUCT定义
*****************************************************************************/

typedef struct {
    oal_fsm_stru st_oal_fsm;
    oal_bool_enum_uint8 en_is_fsm_attached;
    osal_u8 auc_resv[3]; /* 3代表3个字节 */
} online_cali_tx_fsm_info_stru;
typedef struct {
    osal_u8 uc_chip_id;
    osal_u8 uc_device_id;
    osal_u8 online_cali_mask[WLAN_CALI_BAND_BUTT];
    osal_u8 online_debug_switch;             /* online校准是否执行的日志开关, bits参照online_debug_switch_enum */
    frw_timeout_stru next_state_delay_timer; /* 初始化进入的定时器 */
    online_cali_tx_fsm_info_stru st_online_tx_cali_fsm;
    online_cali_dyn_stru dyn_cali_val; /* 动态校准结构体 */
} online_cali_stru;

/*****************************************************************************
  8 UNION定义
*****************************************************************************/
/*****************************************************************************
  9 OTHERS定义
*****************************************************************************/
/*****************************************************************************
  10 函数声明
*****************************************************************************/
osal_u32 online_cali_trans_to_next_state(online_cali_stru *rf_cali);
online_cali_stru *online_cali_get_alg_rf_online_cali_ctx(osal_void);
osal_u32 online_rf_cali_fsm_trans_to_state(online_cali_tx_fsm_info_stru *online_cali_fsm, osal_u8 state);
osal_u32 online_rf_cali_handle_event(online_cali_stru *rf_cali, osal_u16 type,
    osal_u16 event_data_len, osal_u8 *event_data);
osal_void online_set_cali_id(online_cali_stru *alg_rf_cali, osal_u8 chip_id, osal_u8 dev_id);

osal_bool online_cali_mask_is_enable(osal_u8 cali_type);
osal_void online_cali_tx_iq_state_entry(osal_void *ctx);
osal_u32 online_cali_tx_iq_event(osal_void *ctx, osal_u16 event, osal_u16 event_data_len, osal_void *event_data);
osal_void online_cali_rx_iq_state_entry(osal_void *ctx);
osal_u32 online_cali_rx_iq_event(osal_void *ctx, osal_u16 event, osal_u16 event_data_len, osal_void *event_data);
osal_void online_cali_go_to_next_state_after_delay(osal_u16 delay_time);
osal_void online_iq_init_cali_status(osal_void);
osal_void online_iq_set_cali_status(osal_u8 iq_type, osal_u8 cali_status);
osal_s32 online_cali_to_idle(osal_void);
#ifdef _PRE_WLAN_ONLINE_IQ_CALI
osal_void online_cali_cmd_proc(osal_u8 type);
#endif
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif  // __CALI_ONLINE_TX_PWR_H__