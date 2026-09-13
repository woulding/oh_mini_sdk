/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: Provides V155 adc register operation api \n
 *
 * History: \n
 * 2024-02-01， Create file. \n
 */

#include "common_def.h"
#include "stdlib.h"
#include "hal_adc_v155_regs_op.h"

#define ADDR_OFFSET 16

adc_regs_t *g_adc_regs = NULL;
mcu_diag_regs_t *g_mcu_diag_regs = NULL;
uint32_t *g_buffer = NULL;

errcode_t hal_adc_v155_regs_init(void)
{
    g_adc_regs = (adc_regs_t *)adc_port_base_addr_get();
    g_mcu_diag_regs = (mcu_diag_regs_t *)adc_port_mcu_diag_addr_get();
    return ERRCODE_SUCC;
}

static void hal_adc_reg_scan_ch_set(adc_channel_t channel, adc_ctrl_data_t *data, uint32_t value)
{
    adc_channel_data_t ch_set;
    ch_set.d32 = data->d32;
    switch (channel) {
        case ADC_CHANNEL_0:
            ch_set.b.channel_0 = value;
            break;
        case ADC_CHANNEL_1:
            ch_set.b.channel_1 = value;
            break;
        case ADC_CHANNEL_2:
            ch_set.b.channel_2 = value;
            break;
        case ADC_CHANNEL_3:
            ch_set.b.channel_3 = value;
            break;
        case ADC_CHANNEL_4:
            ch_set.b.channel_4 = value;
            break;
        case ADC_CHANNEL_5:
            ch_set.b.channel_5 = value;
            break;
        case ADC_CHANNEL_6:
            ch_set.b.channel_6 = value;
            break;
        case ADC_CHANNEL_7:
            ch_set.b.channel_7 = value;
            break;
        default:
            break;
    }
    data->d32 = ch_set.d32;
}

typedef enum hal_adc_sample_mode {
    AVERAGE_OF_ONE_SAMPLE = 0,              /*  一次平均采样模式  */

    AVERAGE_OF_TWO_SAMPLES,                 /*  两次平均采样模式  */

    AVERAGE_OF_FOUR_SAMPLES,                /*  四次平均采样模式  */

    AVERAGE_OF_EIGHT_SAMPLES,               /*  八次平均采样模式  */

    SAMPLE_MODE_MAX_NUM
} hal_adc_sample_mode_t;

void hal_adc_auto_scan_mode_set(adc_channel_t ch, bool en)
{
    adc_ctrl_data_t data;
    hal_adc_sample_mode_t mode = AVERAGE_OF_EIGHT_SAMPLES;
    data.d32 = g_adc_regs->lsadc_ctrl_0;
    uint32_t status = (uint32_t)en;
    hal_adc_reg_scan_ch_set(ch, &data, status);
    if (en) {
        data.b.equ_model_sel = mode;
        data.b.sample_cnt = 0x6;
        data.b.satrt_cnt = 0x1A;
        data.b.cast_cnt = 0x20;
    }
    g_adc_regs->lsadc_ctrl_0 = data.d32;
}

errcode_t hal_adc_diag_sample_cfg(void)
{
    g_buffer = (uint32_t*)malloc(ARR_LEN * sizeof(uint32_t));
    if (g_buffer == NULL) {
        return ERRCODE_FAIL;
    }
    uint32_t addr = (uint32_t)g_buffer;

    g_mcu_diag_regs->cfg_monitor_sel = 0x1;
    g_mcu_diag_regs->cfg_mcu_diag_trace_save_sel = 0x1;
    g_mcu_diag_regs->cfg_mcu_diag_monitor_clock = 0x1FF;

    g_mcu_diag_regs->cfg_mcu_diag_sample_sel = 0x6;
    g_mcu_diag_regs->cfg_mcu_diag_sample_length_l = ARR_LEN;
    g_mcu_diag_regs->cfg_mcu_diag_sample_length_h = 0;
    g_mcu_diag_regs->cfg_mcu_diag_sample_start_addr_l = addr & 0xFFFF;
    g_mcu_diag_regs->cfg_mcu_diag_sample_start_addr_h = addr >> ADDR_OFFSET;
    g_mcu_diag_regs->cfg_mcu_diag_sample_end_addr_l = 0x7FFF;
    g_mcu_diag_regs->cfg_mcu_diag_sample_end_addr_h = 0x2006;

    g_mcu_diag_regs->cfg_mcu_diag_sample_mode = 0x0;
    g_mcu_diag_regs->cfg_mcu_diag_sample_mode = 0x200;
    g_mcu_diag_regs->cfg_mcu_diag_sample_mode = 0x300;
    return ERRCODE_SUCC;
}

void hal_adc_free_buffer(void)
{
    free(g_buffer);
    g_buffer = NULL;
}