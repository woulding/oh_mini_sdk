/*
 * Copyright (c) CompanyNameMagicTag 2020-2020. All rights reserved.
 * Description: Header file for hal_soc.h.
 * Create: 2020-7-3
 */

#ifndef __HAL_SOC_H__
#define __HAL_SOC_H__

#include "osal_types.h"
#ifdef BUILD_UT
#include "wifi_ut_stub.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define HH503_SSI0_MST_RB_BASE_ADDR            0x40080000

typedef enum {
    WITP_SOC_BANK_0 = 0,
    WITP_SOC_RF_W_C0_CTL_1,
    WITP_SOC_RF_W_C1_CTL_2,
    WITP_SOC_W_CTL_3,
    WITP_SOC_COEX_CTL_4,

    WITP_SOC_BANK_BUTT
} hh503_soc_bank_idx_enum;

#ifndef BUILD_UT
#define HH503_SOC_PHY_WLMAC_CGR 0x59000800
#else
#define HH503_SOC_PHY_WLMAC_CGR (osal_u32)g_soc_phy_wlmac_cgr_addr
#endif

/* Define the union u_phy_wlmac_cgr */
typedef union {
    /* Define the struct bits */
    struct {
        osal_u32 soft_rst_wcpu_mem_ctl_n : 1; /* [0] */
        osal_u32 reserved                : 1; /* [1] */
        osal_u32 mac_main_div_num        : 6; /* [7..2] */
        osal_u32 mac_main_clken          : 1; /* [8] */
        osal_u32 wtop_div_en             : 1; /* [9] */
        osal_u32 reserved_0              : 6; /* [15..10] */
    } bits;
    /* Define an unsigned member */
    osal_u16 u16;
} u_phy_wlmac_cgr;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of hal_soc.h */
