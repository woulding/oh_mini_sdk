/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides pinctrl port \n
 *
 * History: \n
 * 2022-08-25， Create file. \n
 */
#include "pinctrl_porting.h"
#include "hal_pinctrl.h"
#include "board_fpga.h"
#include "hal_pinctrl_ws53.h"

#ifndef bit
#define bit(x) (1UL << (uint32_t)(x))
#endif

typedef enum {
    PIO_MODE_0 = bit(0),
    PIO_MODE_1 = bit(1),
    PIO_MODE_2 = bit(2),
    PIO_MODE_3 = bit(3),
    PIO_MODE_4 = bit(4),
    PIO_MODE_5 = bit(5),
    PIO_MODE_6 = bit(6),
    PIO_MODE_7 = bit(7),
    PIO_MODE_NONE = 0,
} pio_mode_t;

static uint8_t const g_pio_pins_avaliable_mode[PIN_MAX_NUMBER] = {
    /* S_MGPIO0 管脚复用:
        0:s_mgpio[0]
        1:sdio_data[2]
        2:i2c0_bir_clk
        3:uart_l0_rxd
        4:pwm1p
        5:bt_freq
        6:ant_sel0
        7:diag_out[6] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    0, // S_MGPIO1 不存在

    /* S_MGPIO2 管脚复用:
        0:s_mgpio[2]
        1:sdio_cmd
        2:spi0_rxd
        7:diag_out[8] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_MGPIO3 管脚复用:
        0:s_mgpio[3]
        1:sdio_clk_in
        2:spi0_sclk
        7:diag_out[9] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_MGPIO4 管脚复用:
        0:s_mgpio[4]
        1:sdio_data[0]
        2:spi0_txd
        7:diag_out[10] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_MGPIO5 管脚复用:
        0:s_mgpio[5]
        1:uart_h1_txd
        7:diag_out[10] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_7,

    0, // S_MGPIO6 不存在

    0, // S_MGPIO7 不存在

    /* S_MGPIO8 管脚复用:
        0:s_mgpio[8]
        1:uart_h0_txd
        2:spi0_sclk
        3:i2c1_bir_clk
        4:bts_sample
        7:diag_out[14] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_7,

    /* S_MGPIO9 管脚复用:
        0:s_mgpio[9]
        1:uart_h0_rxd
        2:spi0_txd
        3:i2c1_bir_data
        4:btc_pta_denied
        7:diag_out[15] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_7,

    /* S_MGPIO10 管脚复用:
        0:s_mgpio[10]
        1:spi0_cs0_n
        2:uart_h1_cts
        4:pwm0p
        5:i2s_ws
        6:ant_sel1
        7:diag_out[1] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    0, // S_MGPIO11 不存在

    /* S_MGPIO12 管脚复用:
        0:s_mgpio[12]
        1:spi0_rxd
        2:uart_h1_txd
        4:btc_bt_freq
        5:i2s_din
        6:ant_sel0
        7:diag_out[0] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_MGPIO13 管脚复用:
        0:s_mgpio[13]
        1:spi0_txd
        2:uart_h1_rxd
        3:i2c0_bir_clk
        4:btc_bt_state
        5:i2s_dout
        7:diag_out[7] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_7,

    /* S_MGPIO14 管脚复用:
        0:s_mgpio[14]
        1:spwmn
        2:ssi_data
        3:i2c0_bir_data
        4:wb_slp_sync_pulse
        5:bt_active
        6:uart_h1_cts
        7:diag_out[4] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_MGPIO15 管脚复用:
        0:s_mgpio[15]
        1:spwmp
        2:ssi_clk
        4:btc_bt_active
        5:bt_status
        6:uart_h1_rts
        7:diag_out[4] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    0, // S_MGPIO16 不存在

    /* S_MGPIO17 管脚复用:
        0:s_mgpio[17]
        1:qspi_clk
        2:uart_h0_txd
        3:i2s_sclk
        5:bt_active
        6:bt_sp_samp_p
        7:diag_out[6] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_MGPIO18 管脚复用:
        0:s_mgpio[18]
        1:qspi_data[0]
        2:uart_h0_rxd
        3:i2s_dout
        4:wb_slp_sync_pulse
        5:bt_status
        6:bts_sample
        7:diag_out[3] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_MGPIO19 管脚复用:
        0:s_mgpio[19]
        1:qspi_data[1]
        2:pwm2p
        3:i2s_din
        5:bt_freq
        6:btc_pta_denied
        7:diag_out[4] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_MGPIO20 管脚复用:
        0:s_mgpio[20]
        1:qspi_cs0
        2:pwm2n
        3:i2s_ws
        5:wlan_active
        6:btc_bt_freq
        7:diag_out[8] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_MGPIO21 管脚复用:
        0:s_mgpio[21]
        1:pwm0p
        2:uart_h0_rts
        3:i2c0_bir_clk
        4:wb_slp_sync_pulse
        5:bt_status
        6:btc_bt_state
        7:diag_out[3] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_MGPIO22 管脚复用:
        0:s_mgpio[22]
        1:pwm3p
        2:uart_h0_cts
        3:i2c0_bir_data
        5:wlan_active
        6:ant_sel1
        7:diag_out[11] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    0, // S_MGPIO23 不存在

    /* S_MGPIO24 管脚复用:
        0:s_mgpio[24]
        1:sfc_data[0]
        2:qspi_data[0]
        7:diag_out[0] */
    0, // PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_MGPIO25 管脚复用:
        0:s_mgpio[25]
        1:sfc_data[1]
        2:qspi_data[1]
        7:diag_out[1] */
    0, // PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_MGPIO26 管脚复用:
        0:s_mgpio[26]
        1:sfc_data[2]
        2:qspi_data[2]
        7:diag_out[2] */
    0, // PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_MGPIO27 管脚复用:
        0:s_mgpio[27]
        1:sfc_data[3]
        2:qspi_data[3]
        7:diag_out[3] */
    0, // PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_MGPIO28 管脚复用:
        0:s_mgpio[28]
        1:sfc_clk
        2:qspi_clk
        7:diag_out[4] */
    0, // PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_MGPIO29 管脚复用:
        0:s_mgpio[29]
        1:sfc_cs
        2:qspi_cs0
        7:diag_out[5] */
    0, // PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    0, // S_MGPIO30 不存在

    0, // S_MGPIO31 不存在

    /* S_AGPIO0 管脚复用:
        0:s_mgpio[6]
        1:uart_h0_rts
        2:spi0_rxd
        3:wb_slp_sync_pulse
        4:wlmac_tsf_pulse
        7:diag_out[12] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_7,

    /* S_AGPIO1 管脚复用:
        0:s_agpio[1]
        1:uart_l0_txd
        7:diag_out[3] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_7,

    /* S_AGPIO2 管脚复用:
        0:s_agpio[2]
        1:uart_l0_rxd
        2:pwm0p
        7:diag_out[2] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_AGPIO3 管脚复用:
        0:s_agpio[3]
        1:i2c1_bir_clk
        2:pwm0n
        7:diag_out[0] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_AGPIO4 管脚复用:
        0:s_agpio[4]
        1:i2c1_bir_data
        2:uart_h1_rxd
        7:diag_out[1] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_AGPIO5 管脚复用:
        0:s_agpio[5]
        1:sdio_data[1]
        2:spi0_cs0_n
        7:diag_out[11] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_AGPIO6 管脚复用:
        0:s_mgpio[1]
        1:sdio_data[3]
        2:i2c0_bir_data
        3:uart_l0_txd
        4:pwm1n
        5:wlan_active
        6:ant_sel1
        7:diag_out[7] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_AGPIO7 管脚复用:
        0:s_mgpio[11]
        1:spi0_sclk
        2:uart_h1_rts
        4:pwm0n
        5:i2s_sclk
        7:diag_out[2] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_7,

    /* S_AGPIO8 管脚复用:
        0:s_mgpio[16]
        1:qspi_data[3]
        2:pwm3n
        7:diag_out[5] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_7,

    /* S_AGPIO9 管脚复用:
        0:s_mgpio[7]
        1:uart_h0_cts
        2:spi0_cs0_n
        3:qspi_data[2]
        4:bt_sp_samp_p
        6:ant_sel0
        7:diag_out[13] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_6 | PIO_MODE_7,

    /* S_AGPIO10 管脚复用:
        0:s_agpio[6]
        1:uart_l0_txd
        7:diag_out[4] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_7,

    /* S_AGPIO11 管脚复用:
        0:s_agpio[7]
        1:uart_l0_rxd
        7:diag_out[5] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_7,

    0, // S_AGPIO12 RST_N pinmux 不可配

    /* S_SGPIO0 S_MGPIO14 管脚复用:
        0:s_mgpio[14]
        1:spwmn
        2:ssi_data
        3:i2c0_bir_data
        4:wb_slp_sync_pulse
        5:bt_active
        6:uart_h1_cts
        7:diag_out[4] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_SGPIO1 S_MGPIO15 管脚复用:
        0:s_mgpio[15]
        1:spwmp
        2:ssi_clk
        4:btc_bt_active
        5:bt_status
        6:uart_h1_rts
        7:diag_out[4] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,

    /* S_SGPIO2 S_MGPIO21 管脚复用:
        0:s_mgpio[21]
        1:pwm0p
        2:uart_h0_rts
        3:i2c0_bir_clk
        4:wb_slp_sync_pulse
        5:bt_status
        6:btc_bt_state
        7:diag_out[3] */
    PIO_MODE_0 | PIO_MODE_1 | PIO_MODE_2 | PIO_MODE_3 | PIO_MODE_4 | PIO_MODE_5 | PIO_MODE_6 | PIO_MODE_7,
};

void get_pio_func_config(size_t *pin_num, hal_pio_config_t **pin_func_array)
{
    if (pin_num == NULL || pin_func_array == NULL) { return; }
    *pin_num = sizeof(g_pio_function_config) / sizeof(g_pio_function_config[0]);
    *pin_func_array = g_pio_function_config;
}

bool pin_check_mode_is_valid(pin_t pin, pin_mode_t mode)
{
    return (bool)((g_pio_pins_avaliable_mode[pin] >> (uint8_t)mode) & 1U);
}

void pin_port_register_hal_funcs(void)
{
    hal_pin_register_funcs(hal_pin_ws53_funcs_get());
}

void pin_port_unregister_hal_funcs(void)
{
    hal_pin_unregister_funcs();
}

#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
void qpsi0_pin_config_pull_down(void)
{
#define QSPI_D0_PAD_CTL 0x570360A0
#define QSPI_D1_PAD_CTL 0x570360A4
#define QSPI_D2_PAD_CTL 0x570360A8
#define QSPI_D3_PAD_CTL 0x570360AC
#define QSPI_CLK_PAD_CTL 0x570360B0
#define QSPI_CS0_PAD_CTL 0x570360B4

#define PIN_PULL_START_BIT 3
#define PIN_PULL_BITS_NUM 2

    uapi_reg_setbits(QSPI_D0_PAD_CTL, PIN_PULL_START_BIT, PIN_PULL_BITS_NUM, PIN_PULL_DOWN);
    uapi_reg_setbits(QSPI_D1_PAD_CTL, PIN_PULL_START_BIT, PIN_PULL_BITS_NUM, PIN_PULL_DOWN);
    uapi_reg_setbits(QSPI_D2_PAD_CTL, PIN_PULL_START_BIT, PIN_PULL_BITS_NUM, PIN_PULL_DOWN);
    uapi_reg_setbits(QSPI_D3_PAD_CTL, PIN_PULL_START_BIT, PIN_PULL_BITS_NUM, PIN_PULL_DOWN);
    uapi_reg_setbits(QSPI_CLK_PAD_CTL, PIN_PULL_START_BIT, PIN_PULL_BITS_NUM, PIN_PULL_DOWN);
    uapi_reg_setbits(QSPI_CS0_PAD_CTL, PIN_PULL_START_BIT, PIN_PULL_BITS_NUM, PIN_PULL_DOWN);
    return;
}
#endif

