/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 * Description: 产线涉及到的hal层接口
 */
#ifndef FE_HAL_EQUIPMENT_H
#define FE_HAL_EQUIPMENT_H
#include "osal_types.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
#define FE_EFUSE_GROUP_MAX 3                   // 产测数据有三组
#define FE_EFUSE_CALI_BAND_NUM 3               // rssi comp参数个数
#define FE_EFUSE_LOCK_BYTES 4                  // lock锁
// 对齐产线：三条曲线efuse使用同一个锁定位，不单独分开
#define FE_EFUSE_CURVE_11B_1_LOCK_BIT 12
#define FE_EFUSE_CURVE_OFDM20_1_LOCK_BIT 12
#define FE_EFUSE_CURVE_OFDM40_1_LOCK_BIT 12
#define FE_EFUSE_RSSI_BAND123_1_LOCK_BIT 15
#define FE_EFUSE_CURVE_11B_2_LOCK_BIT 16
#define FE_EFUSE_CURVE_OFDM20_2_LOCK_BIT 16
#define FE_EFUSE_CURVE_OFDM40_2_LOCK_BIT 16
#define FE_EFUSE_RSSI_BAND123_2_LOCK_BIT 19
#define FE_EFUSE_CURVE_11B_3_LOCK_BIT 20
#define FE_EFUSE_CURVE_OFDM20_3_LOCK_BIT 20
#define FE_EFUSE_CURVE_OFDM40_3_LOCK_BIT 20
#define FE_EFUSE_RSSI_BAND123_3_LOCK_BIT 23
typedef enum {
    FE_EFUSE_PG_LOCK_ID = 102,
    FE_EFUSE_CURVE_11B_1_ID = 174,
    FE_EFUSE_CURVE_OFDM20_1_ID = 178,
    FE_EFUSE_CURVE_OFDM40_1_ID = 182,
    FE_EFUSE_RSSI_BAND123_1_ID = 186,
    FE_EFUSE_CURVE_11B_2_ID = 188,
    FE_EFUSE_CURVE_OFDM20_2_ID = 192,
    FE_EFUSE_CURVE_OFDM40_2_ID = 196,
    FE_EFUSE_RSSI_BAND123_2_ID = 200,
    FE_EFUSE_CURVE_11B_3_ID = 202,
    FE_EFUSE_CURVE_OFDM20_3_ID = 206,
    FE_EFUSE_CURVE_OFDM40_3_ID = 210,
    FE_EFUSE_RSSI_BAND123_3_ID = 214,
    FE_EFUSE_MAX_ID = 256,
} fe_efuse_byte;

osal_u32 fe_efuse_get_all_power_cali(osal_u8 *value, osal_u8 len);
osal_u32 fe_efuse_get_all_rssi_comp(osal_u8 *value, osal_u8 len);
#endif // _PRE_PLAT_FEATURE_CUSTOMIZE

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif  // FE_HAL_EQUIPMENT_H