/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: clock recover
 *
 * Create: 2024-01-02
 */

#ifndef CLOCK_RECOVER_H
#define CLOCK_RECOVER_H

#include <bits/alltypes.h>

#define DELAY_1_US      1
#define DELAY_10_US     10
#define DELAY_50_US     50
#define DELAY_130_US    130
#define DELAY_250_US    250

#define DATA_WIDTH_2    2
#define DATA_WIDTH_3    3
#define DATA_WIDTH_4    4
#define DATA_WIDTH_6    6
#define DATA_WIDTH_8    8
#define DATA_WIDTH_12   12
#define DATA_WIDTH_16   16

#define CLOCK_SWITCH_MAX_WAIT_TIME_US           1000000
#define SFC_STS_BIT_MASK                        0
#define CORE_LOCK_BIT_MASK                      1
#define M_SLP_STS                               0x570305E4
#define B_SLP_STS                               0x570305E8

#define RC_CALI_INIT_DURTION 0x20
#define RC_CALI_DEFAULT_DURTION 0x40
#define BIT_TO_BYTE 8
#define EFUSE_CHIP_SELECT_START_BIT 1357
#define EFUSE_CHIP_SELECT_MASK 0x20
#define UART_DBG_CFG_SHIFT_BIT 8
#define UART_BAUD_RATE_SHIFT_BIT 16

/* 0x57030604 */
#define PM_PLAT_LPC_MODE_MASK       0
#define PM_PLAT_FREQ_MODE_MASK      1
#define PM_PLAT_CCORE_RTC_MASK      2
#define PM_PLAT_UDSLEEP_MASK        3
#define PM_PLAT_RC_SWITCH_MASK      4
#define PM_PLAT_RC32K_ONLY          5
#define MCU_MODE_2_MASK             6
#define MCU_MODE_3_MASK             7
#define MCU_MODE_4_MASK             8
#define MCU_MODE_MASK_OFFSET        6
#define MCU_MODE_MASK_LEN           3

#define CLK32K_DET_RST              0x5700847c
#define CLK32K_DET_CFG              0x57008480
#define CLK32K_DET_VAL              0x57008484
#define CLK32K_DET_STS              0x57008488
#define CLK32K_DET_RES_L            0x5700848c
#define CLK32K_DET_RES_H            0x57008490
#define CLK32K_DET_SEL              0x57008494

#define EFUSE_ULP_SEL1      0x57031004
#define ULP_GPIO_CLK_CFG    0x57030024

#define XO_32K_FORCE        0x57030950  // XO 32K force config
#define XO_32K_STS          0x57030954  // XO 32K status
#define XO_32K_CFG          0x570304B0  // XO 32K config
#define SEM1_STS_REG        0x57031208  // PLL
#define SEM2_STS_REG        0x57031210  // GPIO
#define SEM3_STS_REG        0x57031218  // UART
#define GPIO_CFG_STS        0x570305F4  // 0x570305EC和0x570305F0蓝牙低功耗使用
#define UART_DBG_CFG        0x570305FC  // debug UART配置
#define UART_CFG_STS        0x57030600
#define ULP_PM_PLAT_ENABLE_REG 0x57030604
#define MCU_MODE_COMMON_REG ULP_PM_PLAT_ENABLE_REG
#define ULP_AON_XO_32K_ABNOR 0x57030954
#define RC_CALI_RESULT      0x5703072C  // rc clk cali result
#define UART_BAUD_RATE_LSB  0x57030724  // 波特率低位寄存器地址
#define UART_BAUD_RATE_MSB  0x57030728  // 波特率高位寄存器地址
#define SFC_LOCK_ACORE_STS  0x5703071C  // ACORE SFC状态
#define SFC_LOCK_CCORE_STS  0x57030720  // CCORE SFC状态
#define SOFT_REBOOT_FLAG    0x57030718  // 软重启标志

#define CMU_LDO1_CFG                            0x57008304
#define CMU_LDO2_CFG                            0x57008308
#define CMU_LDO_PD                              0x57008300
#define XO_CLK_OUT_EN                           0x5700840C
#define CMU_FNPLL_SIG                           0x57008540
#define CMU_FNPLL_CFG0_H                        0x57008500
#define CMU_CLK_320M_WDBB                       0x57008608
#define CMU_CLK_480M_WDBB                       0x5700860C
#define CMU_CLK_FLASH                           0x57008610

#define MSUB_NOR_CFG        0x520003E0
#define MSUB_SLP_CFG        0x520003E4
#define COM_BUS_CR_CH1      0x52000584

#define M_CTL_RB_M_CLKEN0       0x52000040
#define M_CTL_RB_M_CLKEN1       0x52000044
#define M_CTL_RB_M_CLKEN2       0x52000048
#define C_CTL_RB_BCRG_CKEN_0    0x59000810
#define C_CTL_RB_BCRG_CKEN_1    0x59000814

#define GLB_CLKEN_LASDC_OFFSET      12
#define XIP_CLKEN0_OFFSET           4
#define M_CTL_RB_GLB_CLKEN          0x52000548
#define M_CTL_RB_XIP_CLKEN0         0x52001240
#define M_CTL_RB_COM_DLL2           0x52000540
#define M_CTL_RB_MCU_PERP_SPI_CR    0x5200055C
#define M_CTL_RB_XIP_QSPI_CR        0x52000574
#define M_CTL_RB_LSADC_DEBUG_DIVER  0x52000604
#define M_CTL_RB_PWM_M_DIV3         0x5200007C

/* MGPIO7/MGPIO10/MGPIO12/MGPIO20/MGPIO22 蓝牙共存可能使用管脚不配置pull down */
#define S_MGPIO0_PAD_CTL_REG            0x57036040
#define S_MGPIO7_PAD_CTL_REG            0x5703605C // 蓝牙共存天线配置管脚，不配置pull down
#define S_MGPIO10_PAD_CTL_REG           0x57036068 // 蓝牙共存天线配置管脚，不配置pull down
#define S_MGPIO12_PAD_CTL_REG           0x57036070 // 蓝牙共存天线配置管脚，不配置pull down、uart h1 txd
#define S_MGPIO16_PAD_CTL_REG           0x57036080
#define S_MGPIO17_PAD_CTL_REG           0x57036084 // uart h0 txd
#define S_MGPIO18_PAD_CTL_REG           0x57036088 // uart h0 rxd
#define S_MGPIO20_PAD_CTL_REG           0x57036090 // 蓝牙共存天线配置管脚，不配置pull down
#define S_MGPIO22_PAD_CTL_REG           0x57036098 // gpio22之后的为flash不配置pull down
#define COEX_WLACT_ANTSEL_PINMUX_EN     0x570306E8

#define CONTUINUE_LOCKED_TIMES  3

typedef union {
    struct {
        uint32_t reserved1 : 1;
        uint32_t mdiag_clken : 1;
        uint32_t i2s_clken : 1;
        uint32_t reserved2 : 3;
        uint32_t mtop_glue_trigger_clken : 1;
        uint32_t pwm_clken : 1;
        uint32_t reserved3 : 3;
        uint32_t sdio_dev_clken : 1;
        uint32_t reserved4 : 2;
        uint32_t sec_pwm_clken : 1;
        uint32_t reserved5 : 1;
    } bits;

    uint32_t    u32;
} u_m_cken_0;

typedef union {
    struct {
        uint32_t mtimer_clken : 1;
        uint32_t sdio_ahb_clken : 1;
        uint32_t lsadc_apb_clken : 1;
        uint32_t reserved1 : 1;
        uint32_t uart_h0_clken : 1;
        uint32_t reserved2 : 1;
        uint32_t i2c0_clken : 1;
        uint32_t i2c1_clken : 1;
        uint32_t reserved3 : 3;
        uint32_t spi3_ms_clken : 1;
        uint32_t reserved4 : 4;
    } bits;

    uint32_t    u32;
} u_m_cken_1;

typedef union {
    struct {
        uint32_t clk_monitor_cken      : 1   ; /* [0] */
        uint32_t clk_tsensor_apb_cken  : 1   ; /* [1] */
        uint32_t clk_diag_ctl_apb_cken : 1   ; /* [2] */
        uint32_t clk_wdt_apb_cken      : 1   ; /* [3] */
        uint32_t clk_timer_apb_cken    : 1   ; /* [4] */
        uint32_t clk_rf_ctl_apb_cken   : 1   ; /* [5] */
        uint32_t clk_coex_apb_cken     : 1   ; /* [6] */
        uint32_t csub_glue_trigger_clken : 1   ; /* [7] */
        uint32_t clk_cvs_cken          : 1   ; /* [8] */
        uint32_t clk_coex_cken         : 1   ; /* [9] */
        uint32_t clk_rf_test_cken      : 1   ; /* [10] */
        uint32_t clk_wdt_xo_cken       : 1   ; /* [11] */
        uint32_t clk_timer_xo_cken     : 1   ; /* [12] */
        uint32_t clk_diag_ref_1m_cken  : 1   ; /* [13] */
        uint32_t clk_tsensor_1m_cken   : 1   ; /* [14] */
        uint32_t rf_ctl_cken           : 1   ; /* [15] */
    } bits;

    uint32_t    u32;
} u_b_cken_0;

typedef union {
    struct {
        uint32_t rf_adc_cken           : 1   ; /* [0] */
        uint32_t rf_dac_wifi_cken      : 1   ; /* [1] */
        uint32_t rf_dac_bsle_cken      : 1   ; /* [2] */
        uint32_t wifi_320m_xo_cken     : 1   ; /* [3] */
        uint32_t clk_mac_cken          : 1   ; /* [4] */
        uint32_t hpm_top_clken         : 1   ; /* [5] */
        uint32_t cache_top_clken       : 1   ; /* [6] */
        uint32_t wifi_apb_clken        : 1   ; /* [7] */
        uint32_t reserved_0            : 1   ; /* [8] */
        uint32_t cfg_adc_clk_inv_en    : 1   ; /* [9] */
        uint32_t cfg_dac_wifi_inv_en   : 1   ; /* [10] */
        uint32_t cfg_dac_bsle_inv_en   : 1   ; /* [11] */
        uint32_t reserved_1            : 4   ; /* [15..12] */
    } bits;

    uint32_t    u32;
} u_b_cken_1;

typedef enum {
    CLOCK_SWITCH_COREA,
    CLOCK_SWITCH_COREC,
} clock_switch_core;

typedef enum {
    FREQ_SWITCH_XO,
    FREQ_SWITCH_PLL,
} clock_switch_freq;

typedef struct {
    uint32_t work_cali_result;
    uint32_t update_cali_result;
    uint16_t cali_duration;
    uint16_t resv;
} rc_cali_res_stru;

typedef void (*fnpll_delay_func)(void);

void cpu32m_udelay(uint32_t us_cnt);
bool fnpll_init(void);
void sfc_switch_clock(bool pll);

void ccore_ram_exit_sd_mode(void);
void ccore_switch_pll_clock(void);
void ccore_suspend_ctl_rb(void);
void ccore_resume_ctl_rb(void);
void acore_suspend_ctl_rb(void);
void acore_resume_ctl_rb(void);
void system_crg_cfg(void);
void pm_port_save_udsleep_wakeup_src(void);
uint32_t pm_port_switch_system_freq(clock_switch_freq switch_freq);
void pm_port_enter_udsleep(void);
int32_t pm_port_get_udsleep_wakeup_src(const uint8_t agpio_array[], uint8_t agpio_cnt, bool wakeup[]);
void pm_port_exit_udsleep(void);
void pm_core_port_enter_udsleep(void);
void pm_core_port_exit_udsleep(void);
uint32_t system_request_switch(uint8_t type, uint8_t *param);
uint32_t system_switch_pll_clock(void);
void system_set_pll_clock_flag(uint8_t close);
uint8_t system_get_pll_clock_flag(void);
uint8_t system_get_udsleep_flag(void);
void system_close_peripheral_crg(void);
void system_pll_register_delay_func(fnpll_delay_func func);
void pm_gpio_cfg_suspend(clock_switch_core core_t);
uint8_t pm_peripheral_resume(clock_switch_core core_t);

void dbb_clock_enable(void);
void rf_power_recover(void);
void ccore_rc_cali_enable(uint16_t rc_duration);
void ccore_rc_cali_result_refresh(void);
void ccore_set_rc_cali_result(uint32_t result);
uint32_t ccore_get_rc_cali_result(void);
void ccore_rc_cali_enable_proc(uint16_t rc_duration);
void ccore_wait_lock_complete(uint8_t type);
uint8_t get_chip_type(void);
uint8_t get_rc_switch_status(void);
void cpu_cache_reset(void);
void ccore_sfc_lock(void);

void dmmu_remap_reg_restore(void);
#endif
