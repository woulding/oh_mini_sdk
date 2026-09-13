/*
 * Copyright (c) CompanyNameMagicTag 2023-2023. All rights reserved.
 * Description: Header file for hal_mfg.c
 */

#ifndef HAL_MFG_H
#define HAL_MFG_H

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "hal_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define XO_TRIM_ENABLE 1
#define MFG_MODE_ENABLE 1
#define XO_TRIM_DISABLE 0
#define CMD_MAX_LEN 256
#define WLAN_CFG_CON_OFFSET_NUM 2
#define WLAN_CFG_CMU_XO_TRIM_NUM 2
#define WLAN_CFG_MAC_GROUP_NUM 3
#define WLAN_CFG_POWER_INFO_NUM 6
#define RSSI_OFFSET_SIZE 3
#define WLAN_CFG_TEMPER_GEARS_STEP 10
#define EFUSE_GROUP_MAX 3
#define EFUSE_NAME_LEN 16
#define EFUSE_MAX_LEN 24
#define WLAN_EFUSE_REAMIN_NUM 4
#define WLAN_CFG_ONE_POWER_PARAM_NUM 8
#define SIZE_1_BITS 1
#define SIZE_3_BITS 3
#define SIZE_4_BITS 4
#define SIZE_5_BITS 5
#define SIZE_8_BITS 8
#define XO_TRIM_1_PG1 288
#define XO_TRIM_2_PG2 304
#define XO_TRIM_3_PG3 320
#define TEMPERATURE_1_PG1 817
#define TEMPERATURE_2_PG2 818
#define TEMPERATURE_3_PG3 819
#define POWER_1_PG12 828
#define POWER_2_PG16 832
#define POWER_3_PG20 836
#define RSSI_1_PG15 831
#define RSSI_2_PG19 835
#define RSSI_3_PG23 839
#define WLAN_CFG_COARSE_MIN_NUM 0
#define WLAN_CFG_COARSE_MAX_NUM 63
#define WLAN_CFG_FINE_MIN_NUM 0
#define WLAN_CFG_FINE_MAX_NUM 15
#define CMU_XO_CORE_CTRIM (0x57031028)
#define CMU_XOCLKOUTDIE_EN (0x57004600)

typedef enum {
    EXT_EFUSE_XO_TRIM_1_ID = 36,
    EXT_EFUSE_TEMPERATURE_1_ID = 37,
    EXT_EFUSE_XO_TRIM_2_ID = 38,
    EXT_EFUSE_TEMPERATURE_2_ID = 39,
    EXT_EFUSE_XO_TRIM_3_ID = 40,
    EXT_EFUSE_TEMPERATURE_3_ID = 41,
    EXT_EFUSE_11B_HIGN_1_ID = 174,
    EXT_EFUSE_11B_LOW_1_ID = 176,
    EXT_EFUSE_OFDM_20M_HIGN_1_ID = 178,
    EXT_EFUSE_OFDM_20M_LOW_1_ID = 180,
    EXT_EFUSE_OFDM_40M_HIGN_1_ID = 182,
    EXT_EFUSE_OFDM_40M_LOW_1_ID = 184,
    EXT_EFUSE_RSSI_1_ID = 186,
    EXT_EFUSE_11B_HIGN_2_ID = 188,
    EXT_EFUSE_11B_LOW_2_ID = 190,
    EXT_EFUSE_OFDM_20M_HIGN_2_ID = 192,
    EXT_EFUSE_OFDM_20M_LOW_2_ID = 194,
    EXT_EFUSE_OFDM_40M_HIGN_2_ID = 196,
    EXT_EFUSE_OFDM_40M_LOW_2_ID = 198,
    EXT_EFUSE_RSSI_2_ID = 200,
    EXT_EFUSE_11B_HIGN_3_ID = 202,
    EXT_EFUSE_11B_LOW_3_ID = 204,
    EXT_EFUSE_OFDM_20M_HIGN_3_ID = 206,
    EXT_EFUSE_OFDM_20M_LOW_3_ID = 208,
    EXT_EFUSE_OFDM_40M_HIGN_3_ID = 210,
    EXT_EFUSE_OFDM_40M_LOW_3_ID = 212,
    EXT_EFUSE_RSSI_3_ID = 214,
    EXT_EFUSE_IPV4_MAC_ADDR_01_ID = 216,
    EXT_EFUSE_IPV4_MAC_ADDR_02_ID = 222,
    EXT_EFUSE_IPV4_MAC_ADDR_03_ID = 228,
    EXT_EFUSE_MAX = 255
} efuse_id;

typedef enum {
    EFUSE_OP_READ,               /* efuse读操作 */
    EFUSE_OP_WRITE,              /* efuse写操作 */
    EFUSE_OP_REMAIN,             /* efuse查询可用组数 */
    EFUSE_OP_READ_ALL_MFG_DATA   /* 读取efuse所有校准数据 */
} efuse_op;

typedef struct {
    osal_char efuse_name[EFUSE_NAME_LEN]; /* efuse功能名 */
    osal_u32 len;                         /* 数据长度 */
    osal_u8 val[CMD_MAX_LEN];             /* 操作数据 */
    osal_u8 op;                           /* 操作类型 */
    osal_u8 resv[3];                      /* 保留3字节，4字节对齐 */
} efuse_operate_stru;

typedef struct {
    osal_u8 *data;
    osal_u8 len;
} efuse_mfg_data_status;

typedef struct {
    osal_u16 band1_hign;
    osal_u16 band1_low;
    osal_u16 ofdm_20m_hign;
    osal_u16 ofdm_20m_low;
    osal_u16 ofdm_40m_hign;
    osal_u16 ofdm_40m_low;
} efuse_power_offset_stru;

typedef struct {
    osal_u16 xo_trim;                        /* 产测频偏校正码值 */
    osal_u8 resv[2];
    efuse_power_offset_stru pwr_offset;      /* 功率校准数据 */
    osal_u16 rssi_offset;                    /* rssi校准数据 */
    osal_u8 temp;                            /* 产测温度档位 */
    osal_u8 resv2;
} efuse_mfg_data_stru;

typedef struct {
    osal_char efuse_name[EFUSE_NAME_LEN];
    osal_u8 id[EFUSE_GROUP_MAX];
    osal_u32 lock_bit[EFUSE_GROUP_MAX];
} efuse_id_info_stru;

/* Define the union u_cmu_xo_sig */
typedef union {
    /* Define the struct bits */
    struct {
        osal_u16 rg_cmu_xo_trim_fine : 4; /* [3..0] */
        osal_u16 rg_cmu_xo_trim_coarse : 6; /* [9..4] */
        osal_u16 rg_cmu_xo_trim_rev : 1; /* [10] */
        osal_u16 reserved_0 : 5; /* [15..11] */
    } bits;

    /* Define an unsigned member */
    osal_u16 u16;
} u_cmu_xo_sig;

osal_void hal_set_xo_trim_coarse(osal_u32 xo_trim_coarse, osal_u32 *coarse_reg);
osal_void hal_set_xo_trim_fine(osal_u32 xo_trim_fine, osal_u32 *fine_reg);
osal_void hal_get_xo_trim(osal_u32 *xo_trim_coarse, osal_u32 *xo_trim_fine);
osal_s32 hal_read_efuse_cmu_xo_trim(osal_u8 *coarse_reg, osal_u8 *fine_reg);
osal_s32 hal_efuse_cmu_xo_trim_write(osal_u8 coarse_reg, osal_u8 fine_reg);
osal_s32 hal_efuse_write_temp(osal_u8 gears);
osal_s32 hal_efuse_read_temp(osal_void);
osal_s32 hal_config_efuse_operate(efuse_operate_stru *param);
osal_s32 hal_efuse_write_power_info(osal_s32 *power_info, osal_u32 len);
osal_s32 hal_read_efuse_read_power_info(osal_void);
osal_s32 hal_set_efuse_rssi_offset(osal_u8 *rssi_param, osal_u32 len);
osal_s32 hal_get_efuse_rssi_offset(osal_void);
osal_s32 hal_efuse_status(osal_void);
osal_void hal_set_mfg_mode(osal_u8 mode);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
