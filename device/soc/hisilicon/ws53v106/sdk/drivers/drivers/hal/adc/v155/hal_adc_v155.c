/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: Provides V155 HAL adc \n
 *
 * History: \n
 * 2024-02-01， Create file. \n
 */
#include "common_def.h"
#include "tcxo.h"
#include "hal_adc.h"
#include "osal_debug.h"
#include "pinctrl_porting.h"
#include "adc_porting.h"
#include "osal_types.h"
#include "hal_adc_v155_regs_op.h"
#include "hal_adc_v155.h"

#define VOLTAGE_UPPER_LIMIT 1800
#define CH_NUM 8
#define DELAY_5US 5
#define DELAY_100US 100
#define DELAY_128US 128
#define DELAY_160US 160
#define DELAY_200US 200
#define MANUAL_CALI_LOW_LIMIT1 0
#define MANUAL_CALI_UPPER_LIMIT1 3
#define MANUAL_CALI_LOW_LIMIT2 4
#define MANUAL_CALI_UPPER_LIMIT2 31
#define MANUAL_CALI_LOW_LIMIT3 32
#define MANUAL_CALI_UPPER_LIMIT3 59
#define MANUAL_CALI_LOW_LIMIT4 60
#define MANUAL_CALI_UPPER_LIMIT4 63
#define MANUAL_CALI_GAIN 3
#define MANUAL_CALI_THRESHOLD 63
#define COUNT_THRESHOLD  1000
#define DATA_SPLICE 16
#define ADDR_OFFSET 4

static hal_adc_callback_t g_adc_receive_data_callback = NULL;

uint32_t g_fifo_data[ARR_LEN];
uint32_t g_ch_output_data[CH_NUM][ARR_LEN];
uint32_t g_ch_data_cnt[CH_NUM];

static bool g_adc_auto_scan_status = false;

static errcode_t hal_adc_v155_init(void)
{
    if (hal_adc_v155_regs_init() != ERRCODE_SUCC) {
        return ERRCODE_ADC_REG_ADDR_INVALID;
    }
    return ERRCODE_SUCC;
}

static errcode_t hal_adc_v155_deinit(void)
{
    return ERRCODE_SUCC;
}

static void hal_adc_simulation_cfg(void)
{
    hal_adc_simu_cfg1();
    hal_adc_simu_cfg2();
    hal_adc_simu_cfg3();
    hal_adc_simu_cfg4();
    uapi_tcxo_delay_us(DELAY_5US);
    hal_adc_simu_cfg5();
    hal_adc_simu_cfg6();
}

static void hal_adc_offset_auto_cali(void)
{
    hal_adc_offset_cali_state_clr();
    hal_adc_offset_cali_data_spi_refresh();
    hal_adc_offset_cali_set();
    hal_adc_offset_cali_enable(1);
    uapi_tcxo_delay_us(DELAY_100US);
    uint32_t cnt = 0;
    while (hal_adc_offset_cali_sts() != 1) {
        if (cnt > COUNT_THRESHOLD) {
            break;
        }
        cnt++;
    }
    hal_adc_offset_cali_enable(0);
}

static void hal_adc_offset_manual_cali(void)
{
    uint32_t auto_cali_data;
    uint32_t temp;
    auto_cali_data = hal_adc_auto_offset_cali_data_get();
    if (auto_cali_data <= MANUAL_CALI_UPPER_LIMIT1) {
        temp = 0;
    } else if (auto_cali_data >= MANUAL_CALI_LOW_LIMIT2 && auto_cali_data <= MANUAL_CALI_UPPER_LIMIT2) {
        temp = auto_cali_data - MANUAL_CALI_GAIN;
    } else if (auto_cali_data >= MANUAL_CALI_LOW_LIMIT3 && auto_cali_data <= MANUAL_CALI_UPPER_LIMIT3) {
        temp = auto_cali_data + MANUAL_CALI_GAIN;
    } else if (auto_cali_data >= MANUAL_CALI_LOW_LIMIT4 && auto_cali_data <= MANUAL_CALI_UPPER_LIMIT4) {
        temp = MANUAL_CALI_THRESHOLD;
    }
    hal_adc_manual_offset_cali_set(temp);
    hal_adc_offset_cali_enable(1);
    hal_adc_cfg_offset_cali_data_enable();
    hal_adc_offset_cali_data_spi_refresh();
    uapi_tcxo_delay_us(DELAY_128US);
    uint32_t cnt = 0;
    while (hal_adc_offset_cali_sts() != 1) {
        if (cnt > COUNT_THRESHOLD) {
            break;
        }
        cnt++;
    }
    hal_adc_offset_cali_enable(0);
}

static void hal_adc_cap_auto_cali(void)
{
    hal_adc_cfg_cap_cali_finish_clr();
    hal_adc_cfg_intr_gain_state_clr();
    hal_adc_date_spi_refresh_clr();
    hal_adc_cfg_cap_cali_set();
    hal_adc_cfg_cap_cali_enable(1);
    uapi_tcxo_delay_us(DELAY_160US);
    uint32_t cnt = 0;
    while (hal_adc_rpt_cap_cali_sts() != 1) {
        if (cnt > COUNT_THRESHOLD) {
            break;
        }
        cnt++;
    }
    hal_adc_cfg_cap_cali_enable(0);
    hal_adc_simu_cfg2();
}

static void hal_adc_calibration(void)
{
    hal_adc_offset_auto_cali();
    hal_adc_offset_manual_cali();
    hal_adc_cap_auto_cali();
}

static void hal_adc_v155_power_en(afe_scan_mode_t afe_scan_mode, bool on)
{
    unused(afe_scan_mode);
    if (on) {
        adc_port_soft_rst();
        hal_adc_simulation_cfg();
        hal_adc_calibration();
    }
}

static errcode_t hal_adc_v155_channel_set(adc_channel_t ch, bool on)
{
    return adc_port_channel_set(ch, on);
}

static void hal_adc_fifo_data_print(void)
{
    adc_fifo_data_str_t ret;
    uint32_t code, ch, index, voltage;
    uint16_t adc_base = 0x1 << 12;
    uint16_t data_s = 0, data_b = 0, data_k = 0;
    bool next = false;

    memset_s(g_ch_data_cnt, sizeof(uint32_t) * CH_NUM, 0, sizeof(uint32_t) * CH_NUM);

    adc_port_get_cali_param((uint8_t *)&data_s, (uint8_t *)&data_b, (uint8_t *)&data_k);

    for (uint32_t i = 0; i < ARR_LEN; i++) {
        ret.d32 = g_fifo_data[i];
        code = ret.b.data;
        ch = ret.b.channel;
        index = g_ch_data_cnt[ch];
        g_ch_data_cnt[ch]++;
        uint64_t result = (uint64_t)code;
        if (data_s == 1) {
            voltage = (uint32_t)(result * VOLTAGE_UPPER_LIMIT * (data_k - data_b) / (adc_base * data_k));
        } else {
            voltage = (uint32_t)(result * VOLTAGE_UPPER_LIMIT * (data_k + data_b) / (adc_base * data_k));
        }

        g_ch_output_data[ch][index] = voltage;
    }
    for (uint32_t idx = 0; idx < CH_NUM; idx++) {
        if (g_ch_data_cnt[idx] > 0 && g_adc_receive_data_callback != NULL) {
            g_adc_receive_data_callback(idx, g_ch_output_data[idx], g_ch_data_cnt[idx], &next);
        }
    }
}

static void hal_adc_v155_auto_scan_enable(bool en)
{
    if (en) {
        errcode_t ret = hal_adc_diag_sample_cfg();
        if (ret != ERRCODE_SUCC) {
            return;
        }
        hal_adc_start_sample();
        g_adc_auto_scan_status = true;
        uapi_tcxo_delay_us(DELAY_200US);
    } else {
        hal_adc_stop_sample();
        hal_adc_free_buffer();
        g_adc_auto_scan_status = false;
    }
}

static errcode_t hal_adc_v155_auto_scan_ch_enable(adc_channel_t ch, bool en)
{
    hal_adc_auto_scan_mode_set(ch, en);
    if (!en) {
        hal_adc_fifo_data_print();
        hal_adc_v155_auto_scan_enable(false);
    }
    return ERRCODE_SUCC;
}

static void hal_adc_read_diag_data(void)
{
    uint16_t len_low = hal_adc_length_low_get();
    uint16_t len_high = hal_adc_length_high_get();
    uint32_t len = (len_high << DATA_SPLICE) | len_low;
    uint16_t temp_start_addr_low = hal_adc_start_addr_low_get();
    uint16_t temp_start_addr_high = hal_adc_start_addr_high_get();
    uint32_t start_addr = (temp_start_addr_high << DATA_SPLICE) | temp_start_addr_low;

    memset_s(g_fifo_data, sizeof(uint32_t) * ARR_LEN, 0, sizeof(uint32_t) * ARR_LEN);
    uint32_t loop = 0;
    uint32_t index = 0;
    while (loop < len) {
        if (index < ARR_LEN) {
            g_fifo_data[index++] = readl(start_addr + ADDR_OFFSET * loop);
        } else {
            index = 0;
        }
        loop++;
    }
}

static errcode_t hal_adc_v155_auto_scan_ch_config(adc_channel_t ch, hal_adc_scan_config_t *config,
                                                  hal_adc_callback_t callback)
{
    unused(config);
    g_adc_receive_data_callback = callback;
    hal_adc_v155_channel_set(ch, true);
    hal_adc_v155_auto_scan_ch_enable(ch, true);
    hal_adc_ch_man_mode_set();
    hal_adc_v155_auto_scan_enable(true);
    uint32_t cnt = 0;
    while (hal_adc_sample_data_ready() != 1) {
        if (cnt > COUNT_THRESHOLD) {
            break;
        }
        cnt++;
    }
    hal_adc_read_diag_data();
    return ERRCODE_SUCC;
}

static bool hal_adc_v155_auto_scan_is_enabled(void)
{
    return g_adc_auto_scan_status;
}

void hal_adc_irq_handler(void)
{
    /* 不支持中断模式 */
}

static int32_t hal_adc_v155_manual_sample(adc_channel_t channel)
{
    unused(channel);
    return 0;
}

static hal_adc_funcs_t g_hal_adc_v155_funcs = {
    .init = hal_adc_v155_init,
    .deinit = hal_adc_v155_deinit,
    .power_en = hal_adc_v155_power_en,
    .ch_set = hal_adc_v155_channel_set,
#if defined(CONFIG_ADC_SUPPORT_AUTO_SCAN)
    .ch_config = hal_adc_v155_auto_scan_ch_config,
    .ch_enable = hal_adc_v155_auto_scan_ch_enable,
    .enable = hal_adc_v155_auto_scan_enable,
    .isenable = hal_adc_v155_auto_scan_is_enabled,
#endif /* CONFIG_ADC_SUPPORT_AUTO_SCAN */
    .manual = hal_adc_v155_manual_sample
};

hal_adc_funcs_t *hal_adc_v155_funcs_get(void)
{
    return &g_hal_adc_v155_funcs;
}
