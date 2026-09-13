/*
 * Copyright (c) @CompanyNameMagicTag 2018-2020. All rights reserved.
 * Description:  common logging producer interface - need to change name of log.h in all the protocol core files
 * Author: @CompanyNameTag
 * Create:
 */

#ifndef _LOG_DEF_BT_H_
#define _LOG_DEF_BT_H_

typedef enum {
// only for btc extern part
    _BT_FILE_ID_EXT_START = 0,
    _BTC_FILE_ID_EXT_START = 1,
    PATCH_LM_TASK_C,
    PATCH_LLD_ISO_PDU_C,
    PATCH_LLD_CIS_C,
    PATCH_LLC_CIS_C,
    HAL_ACCUMULATION_C,
	LM_GLE_ACB_SRV_CS_C,
	EVT_TASK_GLE_CS_C,
    _BTC_FILE_ID_EXT_END = 1000,
    _CHBA_FILE_ID_EXT_START = 1001,
    SLE_CHBA_NETDEV_C,
    ACHBA_SLE_INTERFACE_C,
    SLE_CHBA_NETDEV_ACHBA_MSG_C,
    ACHBA_NETDEV_C,
    SLE_CHBA_NETDEV_THREAD_C,
    SLE_CHBA_NETDEV_BTS_CALL_C,
    SLE_CHBA_NETDEV_LINK_MNG_C,
    _CHBA_FILE_ID_EXT_END = 1022,
    _BT_FILE_ID_EXT_END = 1023,
} log_file_list_enum_bt_t;
#endif
