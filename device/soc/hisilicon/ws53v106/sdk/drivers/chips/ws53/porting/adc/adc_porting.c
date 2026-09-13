/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides adc port \n
 *
 * History: \n
 * 2022-09-16， Create file. \n
 */

#include "chip_core_irq.h"
#include "common_def.h"
#include "soc_osal.h"
#include "pinctrl_porting.h"
#include "pinctrl.h"
#include "debug_print.h"
#include "hal_adc_v155.h"
#include "efuse_porting.h"
#include "chip_io.h"
#include "tcxo.h"
#include "clock_recover.h"
#include "adc_porting.h"

#define ADC_BASE_ADDR 0x5208A000
#define CLDO_CRG_RST_SOFT_CFG1 0x52000054
#define MCU_DIAG_ADDR 0x52004100
#define CHA_0_ADDR 0x57036024
#define CHA_1_ADDR 0x5703602C
#define CHA_2_ADDR 0x57036030
#define CHA_3_ADDR 0x57036044
#define CHA_4_ADDR 0x57036098
#define CHA_5_ADDR 0x57036060
#define CHA_6_ADDR 0x57036064
#define CHA_7_ADDR 0x57036058
#define LSADC_APB_CLKEN_OFFSET 2
#define GLB_CLKEN_LSADC_OFFSET 12
#define DELAY_1US 1

static uintptr_t g_adc_base_addr =  (uintptr_t)ADC_BASE_ADDR;
static uintptr_t g_mcu_diag_addr =  (uintptr_t)MCU_DIAG_ADDR;

uint16_t g_voltage = 0;

uintptr_t adc_port_base_addr_get(void)
{
    return g_adc_base_addr;
}

uintptr_t adc_port_mcu_diag_addr_get(void)
{
    return g_mcu_diag_addr;
}

void adc_port_clock_enable(bool on)
{
    unused(on);
}

void adc_port_init_clock(adc_clock_t clock)
{
    unused(clock);
}

void adc_port_register_hal_funcs(void)
{
    hal_adc_register_funcs(hal_adc_v155_funcs_get());
}

static int32_t irq_adc_handler(int32_t irq_num, const void *tmp)
{
    unused(irq_num);
    unused(tmp);
    hal_adc_irq_handler();
    return 0;
}

void adc_port_register_irq(void)
{
    int ret = osal_irq_request(LSADC_IRQN, (osal_irq_handler)irq_adc_handler, NULL, NULL, NULL);
    if (ret != 0) {
        print_str("adc_port_register_irq failed: %d\r\n", ret);
    } else {
        print_str("adc_port_register_irq succeed: %d\r\n", ret);
    }
    osal_irq_enable(LSADC_IRQN);
}

void adc_port_unregister_hal_funcs(void)
{
    hal_adc_unregister_funcs();
}

void adc_port_unregister_irq(void)
{
    osal_irq_disable(LSADC_IRQN);
    osal_irq_free(LSADC_IRQN, NULL);
}

void adc_port_power_on(bool on)
{
    if (on) {
        reg16_setbit(M_CTL_RB_M_CLKEN1, LSADC_APB_CLKEN_OFFSET);
        reg16_setbit(M_CTL_RB_GLB_CLKEN, GLB_CLKEN_LSADC_OFFSET);
    } else {
        reg16_clrbit(M_CTL_RB_M_CLKEN1, LSADC_APB_CLKEN_OFFSET);
        reg16_clrbit(M_CTL_RB_GLB_CLKEN, GLB_CLKEN_LSADC_OFFSET);
    }
}

hal_adc_type_info_t *adc_port_get_cfg(void)
{
    return NULL;
}

void adc_port_soft_rst(void)
{
    reg_clrbit(CLDO_CRG_RST_SOFT_CFG1, 0, POS_13);
    uapi_tcxo_delay_us(DELAY_1US);
    reg_setbit(CLDO_CRG_RST_SOFT_CFG1, 0, POS_13);
    uapi_tcxo_delay_us(DELAY_1US);
}

errcode_t adc_port_channel_set(adc_channel_t ch, bool on)
{
    if (ch >= ADC_CHANNEL_MAX_NUM) {
        return ERRCODE_ADC_INVALID_CH_TYPE;
    }
    if (on) {
        switch (ch) {
            case ADC_CHANNEL_0:
                writel(CHA_0_ADDR, 0);
                break;
            case ADC_CHANNEL_1:
                writel(CHA_1_ADDR, 0);
                break;
            case ADC_CHANNEL_2:
                writel(CHA_2_ADDR, 0);
                break;
            case ADC_CHANNEL_3:
                writel(CHA_3_ADDR, 0);
                break;
            case ADC_CHANNEL_4:
                writel(CHA_4_ADDR, 0);
                break;
            case ADC_CHANNEL_5:
                writel(CHA_5_ADDR, 0);
                break;
            case ADC_CHANNEL_6:
                writel(CHA_6_ADDR, 0);
                break;
            case ADC_CHANNEL_7:
                writel(CHA_7_ADDR, 0);
                break;
            default:
                break;
        }
    }
    return ERRCODE_SUCC;
}

static void adc_port_callback(uint8_t ch, uint32_t *buffer, uint32_t length, bool *next)
{
    unused(next);
    unused(ch);
    g_voltage = (uint16_t)buffer[length - 1];
}

errcode_t adc_port_read(uint8_t channel, uint16_t *data)
{
    uapi_adc_power_en(AFE_GADC_MODE, true);

#if defined(CONFIG_ADC_SUPPORT_AUTO_SCAN)
    errcode_t ret;
    adc_scan_config_t config = {0};
    ret = uapi_adc_auto_scan_ch_enable(channel, config, adc_port_callback);
    if (ret != ERRCODE_SUCC) {
        return ret;
    }
    ret = uapi_adc_auto_scan_ch_disable(channel);
    if (ret != ERRCODE_SUCC) {
        return ret;
    }
    *data = g_voltage;
#endif
    uapi_adc_power_en(AFE_GADC_MODE, false);
    return ERRCODE_SUCC;
}

void adc_port_get_cali_param(uint8_t *data_s, uint8_t *data_b, uint8_t *data_k)
{
    uint16_t cali_data_abs = 0x0; /* cali offset */
    uint8_t data_sign = 0; /* 0: positive 1: negative */

    *(uint16_t *)data_b = cali_data_abs;
    *(uint16_t *)data_s = data_sign;
    *(uint16_t *)data_k = 1 << 14; /* 14: cali offset base */
}