/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: Provides tcxo trim port \n
 *
 * History: \n
 * 2024-01-31， Create file. \n
 */

#ifndef XO_TRIM_PORTING_H
#define XO_TRIM_PORTING_H

#include <stdint.h>
#include "std_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define EXT_EFUSE_XO_TRIM_1_ID 36
#define EXT_EFUSE_XO_TRIM_2_ID 38
#define EXT_EFUSE_XO_TRIM_3_ID 40
#define XO_TRIM_1_PG1 288
#define XO_TRIM_2_PG2 304
#define XO_TRIM_3_PG3 320
#define SIZE_1_BITS 1
#define SIZE_4_BITS 4
#define SIZE_8_BITS 8
#define EFUSE_GROUP_MAX 3
#define CMU_XO_CORE_CTRIM (0x57031028)
#define CMU_XOCLKOUTDIE_EN (0x57004600)

#ifdef _PRE_WLAN_FEATURE_MFG_TEST
void cmu_xo_trim_init(void);
void cmu_xo_trim_temp_comp_print(void);
#endif
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
