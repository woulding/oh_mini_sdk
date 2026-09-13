/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: Provides V155 adc register \n
 *
 * History: \n
 * 2024-02-01， Create file. \n
 */

#ifndef HAL_ADC_V155_REGS_DEF_H
#define HAL_ADC_V155_REGS_DEF_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef struct adc_regs {
    volatile uint32_t lsadc_ctrl_0;
    volatile uint32_t lsadc_ctrl_1;
    volatile uint32_t lsadc_ctrl_2;
    volatile uint32_t lsadc_ctrl_3;
    volatile uint32_t lsadc_ctrl_4;
    volatile uint32_t lsadc_ctrl_6;
    volatile uint32_t lsadc_ctrl_7;
    volatile uint32_t lsadc_ctrl_8;
    volatile uint32_t lsadc_ctrl_9;
    volatile uint32_t lsadc_ctrl_11;
    volatile uint32_t lsadc_ctrl_12;

    volatile uint32_t cfg_adc_offset_cali;
    volatile uint32_t cfg_adc_offset_cali_en;
    volatile uint32_t cfg_adc_offset_cali_data_en;
    volatile uint32_t cfg_adc_offset_cali_data_spi_refresh;
    volatile uint32_t cfg_adc_offset_cali_state_clr;
    volatile uint32_t rpt_adc_offset_cali_zero_num;
    volatile uint32_t rpt_adc_offset_cali_finish_sts;
    volatile uint32_t rpt_adc_offset_cali_sts;
    volatile uint32_t rpt_adc_offset_cali_curr_st;
    volatile uint32_t rpt_adc_offset_cali_data;

    volatile uint32_t cfg_cap_cali_wac1_spi;
    volatile uint32_t cfg_cap_cali_wac2_spi;
    volatile uint32_t cfg_cap_cali_wac3_spi;
    volatile uint32_t cfg_cap_cali_wac4_spi;
    volatile uint32_t cfg_cap_cali_wac5_spi;
    volatile uint32_t cfg_cap_cali_wac6_spi;
    volatile uint32_t cfg_cap_cali_wac7_spi;
    volatile uint32_t cfg_cap_cali_wac8_spi;
    volatile uint32_t cfg_cap_cali_wac9_spi;
    volatile uint32_t cfg_cap_cali_wac10_spi;
    volatile uint32_t cfg_cap_cali_wac11_spi;
    volatile uint32_t rpt_intr_gain_cali_gain;
    volatile uint32_t rpt_gain_dataout_31b;

    volatile uint32_t cfg_adc_cap_cali;
    volatile uint32_t cfg_adc_cap_cali_en;
    volatile uint32_t cfg_gain_cali_en;
    volatile uint32_t cfg_cap_cali_data_spi_refresh;
    volatile uint32_t cfg_cap_cali_finish_clr;
    volatile uint32_t cfg_intr_gain_state_clr;
    volatile uint32_t rpt_cap_cali_sts_0;
    volatile uint32_t rpt_cap_cali_sts_1;

    volatile uint32_t rpt_cap_cali_wt_1;
    volatile uint32_t rpt_cap_cali_wt_2;
    volatile uint32_t rpt_cap_cali_wt_3;
    volatile uint32_t rpt_cap_cali_wt_4;
    volatile uint32_t rpt_cap_cali_wt_5;
    volatile uint32_t rpt_cap_cali_wt_6;
    volatile uint32_t rpt_cap_cali_wt_7;
    volatile uint32_t rpt_cap_cali_wt_8;
    volatile uint32_t rpt_cap_cali_wt_9;
    volatile uint32_t rpt_cap_cali_wt_10;
    volatile uint32_t rpt_cap_cali_wt_11;
    volatile uint32_t rpt_cap_cali_curr_st;

    volatile uint32_t cfg_ctc_filter_bybass;
    volatile uint32_t cfg_data_sel;
    volatile uint32_t cfg_offset;
    volatile uint32_t cfg_gain;
    volatile uint32_t cfg_cic_filter_en;
    volatile uint32_t cfg_cic_osr;
    volatile uint32_t cfg_cic_trigger_rst;

    volatile uint32_t da_lsadc_rwreg_1;
    volatile uint32_t da_lsadc_rwreg_2;
    volatile uint32_t da_lsadc_rwreg_3;
    volatile uint32_t da_lsadc_rwreg_4;
} adc_regs_t;

typedef struct mcu_diag_regs {
    volatile uint32_t cfg_monitor_sel;
    volatile uint32_t cfg_mcu_diag_trace_save_sel;
    volatile uint32_t cfg_mcu_diag_cpu_trace;
    volatile uint32_t cfg_mcu_diag_monitor_clock;

    volatile uint32_t reserved[60];

    volatile uint32_t cfg_mcu_diag_sample_sel;
    volatile uint32_t cfg_mcu_diag_sample_mode;
    volatile uint32_t cfg_mcu_diag_sample_length_l;
    volatile uint32_t cfg_mcu_diag_sample_length_h;
    volatile uint32_t cfg_mcu_diag_sample_start_addr_l;
    volatile uint32_t cfg_mcu_diag_sample_start_addr_h;
    volatile uint32_t cfg_mcu_diag_sample_end_addr_l;
    volatile uint32_t cfg_mcu_diag_sample_end_addr_h;
    volatile uint32_t mcu_diag_sample_done_addr_l;
    volatile uint32_t mcu_diag_sample_done_addr_h;
    volatile uint32_t mcu_diag_sample_done;
    volatile uint32_t cfg_aux_adc_sample_period;
} mcu_diag_regs_t;

typedef union adc_channel_data {
    uint32_t d32;
    struct {
        uint32_t channel_0                    :  1;
        uint32_t channel_1                    :  1;
        uint32_t channel_2                    :  1;
        uint32_t channel_3                    :  1;
        uint32_t channel_4                    :  1;
        uint32_t channel_5                    :  1;
        uint32_t channel_6                    :  1;
        uint32_t channel_7                    :  1;
        uint32_t reserved                     : 24;
    } b;
} adc_channel_data_t;

typedef union adc_ctrl_data {
    uint32_t d32;
    struct {
        uint32_t channel                      :  8;
        uint32_t equ_model_sel                :  2;
        uint32_t sample_cnt                   :  5;
        uint32_t satrt_cnt                    :  8;
        uint32_t cast_cnt                     :  7;
        uint32_t reserved                     :  2;
    } b;
} adc_ctrl_data_t;

typedef union adc_fifo_data_str {
    uint32_t d32;
    struct {
        uint32_t reserved1                    :  2;
        uint32_t data                         : 12;
        uint32_t channel                      :  3;
        uint32_t reserved2                    : 15;
    } b;
} adc_fifo_data_str_t;

typedef union adc_enable_data {
    uint32_t d32;
    struct {
        uint32_t da_lsadc_en                  : 16;
        uint32_t da_lsadc_rstn                :  1;
        uint32_t reserved                     : 15;
    } b;
} adc_enable_data_t;

typedef union adc_offset_cali_state_clr_data {
    uint32_t d32;
    struct {
        uint32_t offset_cali_finish_clr       :  1;
        uint32_t reserved                     : 31;
    } b;
} adc_offset_cali_state_clr_data_t;

typedef union adc_offset_cali_spi_refresh_data {
    uint32_t d32;
    struct {
        uint32_t offset_cali_spi_refresh      :  1;
        uint32_t reserved                     : 31;
    } b;
} adc_offset_cali_spi_refresh_data_t;

typedef union adc_offset_cali_data {
    uint32_t d32;
    struct {
        uint32_t offset_cali_mode             :  1;
        uint32_t offset_cali_loop_sel         :  1;
        uint32_t offset_cali_inverse          :  1;
        uint32_t reserved1                    :  1;
        uint32_t offset_cali_acc_cycle_sel    :  2;
        uint32_t offset_cali_range_sel        :  2;
        uint32_t offset_cali_data_spi         :  6;
        uint32_t reserved2                    :  2;
        uint32_t offset_cali_adc_data_inv     :  1;
        uint32_t reserved                     : 15;
    } b;
} adc_offset_cali_data_t;

typedef union adc_offset_cali_en_data {
    uint32_t d32;
    struct {
        uint32_t offset_cali_en               :  1;
        uint32_t reserved                     : 31;
    } b;
} adc_offset_cali_en_data_t;

typedef union adc_offset_cali_sts_data {
    uint32_t d32;
    struct {
        uint32_t offset_cali_finish           :  1;
        uint32_t reserved                     : 31;
    } b;
} adc_offset_cali_sts_data_t;

typedef union adc_rpt_offset_cali_data {
    uint32_t d32;
    struct {
        uint32_t offset_cali_data             :  6;
        uint32_t offset_cali_loop_cnt         :  6;
        uint32_t reserved                     : 20;
    } b;
} adc_rpt_offset_cali_data_t;

typedef union adc_cfg_offset_cali_en_data {
    uint32_t d32;
    struct {
        uint32_t offset_data_en               :  1;
        uint32_t reserved                     : 31;
    } b;
} adc_cfg_offset_cali_en_data_t;

typedef union cfg_cap_cali_finish_clr_data {
    uint32_t d32;
    struct {
        uint32_t finish_clr                   :  1;
        uint32_t reserved                     : 31;
    } b;
} cfg_cap_cali_finish_clr_data_t;

typedef union cfg_intr_gain_state_clr_data {
    uint32_t d32;
    struct {
        uint32_t gain_state_clr               :  1;
        uint32_t reserved                     : 31;
    } b;
} cfg_intr_gain_state_clr_data_t;

typedef union cfg_cap_cali_data_spi_refresh_data {
    uint32_t d32;
    struct {
        uint32_t spi_refresh                  :  1;
        uint32_t reserved                     : 31;
    } b;
} cfg_cap_cali_data_spi_refresh_data_t;

typedef union cfg_adc_cap_cali_data {
    uint32_t d32;
    struct {
        uint32_t mode                         :  1;
        uint32_t alg_sel                      :  1;
        uint32_t acc_cycle_sel                :  2;
        uint32_t start_index                  :  4;
        uint32_t weight_sel                   :  1;
        uint32_t dac_setting_dly_ctrl         :  1;
        uint32_t reserved1                    :  2;
        uint32_t cap_selman                   :  4;
        uint32_t sh_en_man                    :  1;
        uint32_t pn_sel_man                   :  1;
        uint32_t reserved2                    : 14;
    } b;
} cfg_adc_cap_cali_data_t;

typedef union cfg_adc_cap_cali_en_data {
    uint32_t d32;
    struct {
        uint32_t en                           :  1;
        uint32_t reserved                     : 31;
    } b;
} cfg_adc_cap_cali_en_data_t;

typedef union rpt_cap_cali_sts0_data {
    uint32_t d32;
    struct {
        uint32_t finish                       :  1;
        uint32_t reserved1                    :  7;
        uint32_t error                        :  1;
        uint32_t reserved2                    : 23;
    } b;
} rpt_cap_cali_sts0_data_t;

typedef union adc_scan_start_and_stop_data {
    uint32_t d32;
    struct {
        uint32_t lsadc_start                  :  1;
        uint32_t lsadc_stop                   :  1;
        uint32_t reserved                     : 30;
    } b;
} adc_scan_start_and_stop_data_t;

typedef union cha_manu_ctrl_data {
    uint32_t d32;
    struct {
        uint32_t lsadc_scan_ch_man            :  2;
        uint32_t lsadc_scan_ch_man_sel        :  1;
        uint32_t reserved                     : 29;
    } b;
} cha_manu_ctrl_data_t;

typedef union sample_done_data {
    uint32_t d32;
    struct {
        uint32_t signal                       :  1;
        uint32_t reserved                     : 31;
    } b;
} sample_done_data_t;

errcode_t hal_adc_v155_regs_init(void);


#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif