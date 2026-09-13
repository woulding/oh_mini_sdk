/*
* Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2020-2022. All rights reserved.
* Description: Header file of main.c.
*/

/*****************************************************************************
    头文件包含
*****************************************************************************/
#include "stdio.h"

#include <securec.h>
#include "soc_wifi_api.h"
#include "oam_ext_if.h"
#include "oal_types.h"
#include "lwip/tcpip.h"
#ifdef _PRE_WLAN_FEATURE_CENTRALIZE
#ifdef BOARD_FPGA_WIFI
#include "abb_config.h"
#include "mpw0_poweron.h"
#endif
#endif
#include "hal_phy.h"
#include "hal_mac.h"
#include "oal_util_hcm.h"
#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
#include "soc_mmc.h"
#include "firmware.h"
#endif
#undef  THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_WIFI_HOST_WIFI_MAIN_C

#undef THIS_MOD_ID
#define THIS_MOD_ID DIAG_MOD_ID_WIFI_HOST

int wifi_host_task(void *param)
{
    td_s32 ret = OAL_SUCC;
#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
    init_sdio_pinmux();
    sdio_drv_context_init();
    firmware_download();
#endif
#ifdef _PRE_WLAN_FEATURE_CENTRALIZE
#ifdef BOARD_FPGA_WIFI
    // 共核编译的直接在host初始化abb 其他情况在device初始化中完成
    hh503_abb5_init_pre();
    mpw0_poweron();
#endif
#endif
    unref_param(param);
    wifi_printf("-->wifi_host_task enter.\n");

    ret = uapi_wifi_init(1, 1);
    if (ret != OAL_SUCC) {
        wifi_printf("Fail to uapi_wifi_init!\n");
        return OAL_FAIL;
    }

    tcpip_init(NULL, NULL);

    wifi_printf("-->wifi_host_task finish.\n");
    return OAL_SUCC;
}

int wifi_init_task(void)
{
    osal_task *result = NULL;
    /* stack 大小: 8 * 1024 */
    result = osal_adapt_kthread_create(wifi_host_task, OSAL_NULL, "wifi_host", (8 * 1024));
    if (result == NULL) {
        return OAL_FAIL;
    }
    return OAL_SUCC;
}
