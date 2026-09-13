/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: Provides V155 adc register operation api \n
 *
 * History: \n
 * 2024-02-01， Create file. \n
 */

#ifndef HAL_ADC_V155_REGS_OP_H
#define HAL_ADC_V155_REGS_OP_H

#include <stdint.h>
#include <stdbool.h>
#include "errcode.h"
#include "hal_adc_v155_regs_def.h"
#include "adc_porting.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define ARR_LEN 2

extern adc_regs_t *g_adc_regs;
extern mcu_diag_regs_t *g_mcu_diag_regs;

static inline void hal_adc_simu_cfg1(void)
{
    uint32_t data;
    data = 0x2AA6010;
    g_adc_regs->da_lsadc_rwreg_1 = data;
}

static inline void hal_adc_simu_cfg2(void)
{
    uint32_t data;
    data = 0x2085;
    g_adc_regs->da_lsadc_rwreg_2 = data;
}

static inline void hal_adc_simu_cfg3(void)
{
    uint32_t data;
    data = 0xC;
    g_adc_regs->da_lsadc_rwreg_3 = data;
}

static inline void hal_adc_simu_cfg4(void)
{
    adc_enable_data_t data;
    data.d32 = 0x260;
    g_adc_regs->lsadc_ctrl_11 = data.d32;
}

static inline void hal_adc_simu_cfg5(void)
{
    adc_enable_data_t data;
    data.d32 = 0x103F8;
    g_adc_regs->lsadc_ctrl_11 = data.d32;
}

static inline void hal_adc_simu_cfg6(void)
{
    adc_enable_data_t data;
    data.d32 = 0x1FFFF;
    g_adc_regs->lsadc_ctrl_11 = data.d32;
}

static inline void hal_adc_offset_cali_state_clr(void)
{
    adc_offset_cali_state_clr_data_t data;
    data.d32 = g_adc_regs->cfg_adc_offset_cali_state_clr;
    data.b.offset_cali_finish_clr = 1;
    g_adc_regs->cfg_adc_offset_cali_state_clr = data.d32;
    data.d32 = g_adc_regs->cfg_adc_offset_cali_state_clr;
    data.b.offset_cali_finish_clr = 0;
    g_adc_regs->cfg_adc_offset_cali_state_clr = data.d32;
}

static inline void hal_adc_offset_cali_data_spi_refresh(void)
{
    adc_offset_cali_spi_refresh_data_t data;
    data.d32 = g_adc_regs->cfg_adc_offset_cali_data_spi_refresh;
    data.b.offset_cali_spi_refresh = 1;
    g_adc_regs->cfg_adc_offset_cali_data_spi_refresh = data.d32;
    data.d32 = g_adc_regs->cfg_adc_offset_cali_data_spi_refresh;
    data.b.offset_cali_spi_refresh = 0;
    g_adc_regs->cfg_adc_offset_cali_data_spi_refresh = data.d32;
}

static inline void hal_adc_offset_cali_set(void)
{
    adc_offset_cali_data_t data;
    data.d32 = g_adc_regs->cfg_adc_offset_cali;
    data.b.offset_cali_mode = 1;
    data.b.offset_cali_loop_sel = 0;
    data.b.offset_cali_inverse = 0;
    data.b.offset_cali_acc_cycle_sel = 0;
    data.b.offset_cali_range_sel = 0;
    g_adc_regs->cfg_adc_offset_cali = data.d32;
}

static inline void hal_adc_offset_cali_enable(uint32_t value)
{
    adc_offset_cali_en_data_t data;
    data.d32 = g_adc_regs->cfg_adc_offset_cali_en;
    data.b.offset_cali_en = value;
    g_adc_regs->cfg_adc_offset_cali_en = data.d32;
}

static inline uint32_t hal_adc_offset_cali_sts(void)
{
    adc_offset_cali_sts_data_t data;
    data.d32 = g_adc_regs->rpt_adc_offset_cali_finish_sts;
    return data.b.offset_cali_finish;
}

static inline uint32_t hal_adc_auto_offset_cali_data_get(void)
{
    adc_rpt_offset_cali_data_t data;
    data.d32 = g_adc_regs->rpt_adc_offset_cali_data;
    return data.b.offset_cali_data;
}

static inline void hal_adc_manual_offset_cali_set(uint32_t value)
{
    adc_offset_cali_data_t data;
    data.d32 = g_adc_regs->cfg_adc_offset_cali;
    data.b.offset_cali_mode = 0;
    data.b.offset_cali_data_spi = value;
    g_adc_regs->cfg_adc_offset_cali = data.d32;
}

static inline void hal_adc_cfg_offset_cali_data_enable(void)
{
    adc_cfg_offset_cali_en_data_t data;
    data.d32 = g_adc_regs->cfg_adc_offset_cali_data_en;
    data.b.offset_data_en = 1;
    g_adc_regs->cfg_adc_offset_cali_data_en = data.d32;
}

static inline void hal_adc_cfg_cap_cali_finish_clr(void)
{
    cfg_cap_cali_finish_clr_data_t data;
    data.d32 = g_adc_regs->cfg_cap_cali_finish_clr;
    data.b.finish_clr = 1;
    g_adc_regs->cfg_cap_cali_finish_clr = data.d32;
    data.d32 = g_adc_regs->cfg_cap_cali_finish_clr;
    data.b.finish_clr = 0;
    g_adc_regs->cfg_cap_cali_finish_clr = data.d32;
}

static inline void hal_adc_cfg_intr_gain_state_clr(void)
{
    cfg_intr_gain_state_clr_data_t data;
    data.d32 = g_adc_regs->cfg_intr_gain_state_clr;
    data.b.gain_state_clr = 1;
    g_adc_regs->cfg_intr_gain_state_clr = data.d32;
    data.d32 = g_adc_regs->cfg_intr_gain_state_clr;
    data.b.gain_state_clr = 0;
    g_adc_regs->cfg_intr_gain_state_clr = data.d32;
}

static inline void hal_adc_date_spi_refresh_clr(void)
{
    cfg_cap_cali_data_spi_refresh_data_t data;
    data.d32 = g_adc_regs->cfg_cap_cali_data_spi_refresh;
    data.b.spi_refresh = 1;
    g_adc_regs->cfg_cap_cali_data_spi_refresh = data.d32;
    data.d32 = g_adc_regs->cfg_cap_cali_data_spi_refresh;
    data.b.spi_refresh = 0;
    g_adc_regs->cfg_cap_cali_data_spi_refresh = data.d32;
}

static inline void hal_adc_cfg_cap_cali_set(void)
{
    cfg_adc_cap_cali_data_t data;
    data.d32 = g_adc_regs->cfg_adc_cap_cali;
    data.b.mode = 1;
    data.b.alg_sel = 0;
    data.b.acc_cycle_sel = 0x2;
    data.b.start_index = 0x4;
    data.b.weight_sel = 1;
    data.b.dac_setting_dly_ctrl = 1;
    g_adc_regs->cfg_adc_cap_cali = data.d32;
}

static inline void hal_adc_cfg_cap_cali_enable(uint32_t value)
{
    cfg_adc_cap_cali_en_data_t data;
    data.d32 = g_adc_regs->cfg_adc_cap_cali_en;
    data.b.en = value;
    g_adc_regs->cfg_adc_cap_cali_en = data.d32;
}

static inline uint32_t hal_adc_rpt_cap_cali_sts(void)
{
    rpt_cap_cali_sts0_data_t data;
    data.d32 = g_adc_regs->rpt_cap_cali_sts_0;
    return data.b.finish;
}

static inline void hal_adc_start_sample(void)
{
    adc_scan_start_and_stop_data_t data;
    data.d32 = g_adc_regs->lsadc_ctrl_8;
    data.b.lsadc_start = 1;
    g_adc_regs->lsadc_ctrl_8 = data.d32;
}

static inline void hal_adc_stop_sample(void)
{
    adc_scan_start_and_stop_data_t data;
    data.d32 = g_adc_regs->lsadc_ctrl_8;
    data.b.lsadc_stop = 1;
    g_adc_regs->lsadc_ctrl_8 = data.d32;
}

static inline void hal_adc_ch_man_mode_set(void)
{
    cha_manu_ctrl_data_t data;
    data.d32 = g_adc_regs->lsadc_ctrl_12;
    data.b.lsadc_scan_ch_man = 0;
    data.b.lsadc_scan_ch_man_sel = 0;
    g_adc_regs->lsadc_ctrl_12 = data.d32;
}

static inline uint16_t hal_adc_start_addr_low_get(void)
{
    return g_mcu_diag_regs->cfg_mcu_diag_sample_start_addr_l;
}

static inline uint16_t hal_adc_start_addr_high_get(void)
{
    return g_mcu_diag_regs->cfg_mcu_diag_sample_start_addr_h;
}

static inline uint16_t hal_adc_length_low_get(void)
{
    return g_mcu_diag_regs->cfg_mcu_diag_sample_length_l;
}

static inline uint16_t hal_adc_length_high_get(void)
{
    return g_mcu_diag_regs->cfg_mcu_diag_sample_length_h;
}

static inline uint32_t hal_adc_sample_data_ready(void)
{
    sample_done_data_t data;
    data.d32 = g_mcu_diag_regs->mcu_diag_sample_done;
    return data.b.signal;
}

void hal_adc_auto_scan_mode_set(adc_channel_t ch, bool en);

errcode_t hal_adc_diag_sample_cfg(void);

void hal_adc_free_buffer(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif