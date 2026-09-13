/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved. \n
 *
 * Description: Provides pm sleep port \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-01-13， Create file. \n
 */

#include "chip_io.h"
#include "chip_core_irq.h"
#include "platform_core.h"

#if defined(__LITEOS__)
#include "los_task_pri.h"
#elif defined(__FREERTOS__)
#include "FreeRTOS.h"
#include "hwi.h"
#include "cache.h"
#endif
#include "gpio.h"
#include "non_os.h"
#include "arch_barrier.h"
#include "arch_encoding.h"
#include "common_def.h"
#include "systick.h"
#include "systick_porting.h"
#include "rtc.h"
#include "tcxo.h"
#include "sfc.h"
#include "spi.h"
#include "ipc.h"
#include "uart.h"
#include "pwm.h"
#include "dma.h"
#include "gpio.h"
#include "pinctrl.h"
#include "flash_recover.h"
#include "security_init.h"
#include "flash_patch_porting.h"
#include "mcpu_trace_porting.h"
#include "clock_recover.h"
#include "pm_veto.h"
#include "pm_dev.h"
#include "watchdog.h"
#include "pm_veto_porting.h"
#include "tsensor_porting.h"
#include "pm_sleep_porting.h"
#if defined(CONFIG_DRIVER_SUPPORT_I2C) && defined(CONFIG_I2C_SUPPORT_LPM)
#include "i2c.h"
#include "pinctrl.h"
#endif

#define ULP_CLR_DELAY_CYCLE         1000

#define FLASH_HEAD_ADDR             0x00400000
#define FLASH_MEM_SIZE              0x00400000

#define PM_MS_PER_TICK              10
#define PM_TCXO_DELAY_US            50
#define PM_RTC_HEARTBEAT_MS         10000

#define ULP_AON_CTL_MCPU_POR_RST_PC_H_REG       (ULP_AON_CTL_RB_ADDR + 0x820)
#define ULP_AON_CTL_MCPU_POR_RST_PC_L_REG       (ULP_AON_CTL_RB_ADDR + 0x824)

#define PMU1_CTL_LPM_MCU_ALW_TO_SLP_REG         (ULP_AON_CTL_RB_ADDR + 0x3A0)
#define PMU1_CTL_LPM_B_ALW_TO_SLP               (ULP_AON_CTL_RB_ADDR + 0x3BC)

/* Ulp sleep event. */
#define ULP_AON_CTL_ULP_SLP_EVT_STS_REG         (ULP_AON_CTL_RB_ADDR + 0x1C8)
#define ULP_AON_CTL_ULP_SLP_EVT_CLR_REG         (ULP_AON_CTL_RB_ADDR + 0x1CC)

/* Ulp sleep interrupt. */
#define ULP_AON_CTL_ULP_SLP_INT_STS_REG         (ULP_AON_CTL_RB_ADDR + 0x1C0)
#define ULP_AON_CTL_ULP_SLP_INT_CLR_REG         (ULP_AON_CTL_RB_ADDR + 0x1C4)
#define ULP_AON_CTL_ULP_SLP_INT_EN_REG          (ULP_AON_CTL_RB_ADDR + 0x1D4)

/* Ulp wakeup interrupt. */
#define ULP_AON_CTL_ULP_WKUP_INT_STS_REG        (ULP_AON_CTL_RB_ADDR + 0x1E0)
#define ULP_AON_CTL_ULP_WKUP_INT_CLR_REG        (ULP_AON_CTL_RB_ADDR + 0x1E4)
#define ULP_AON_CTL_ULP_WKUP_INT_EN_REG         (ULP_AON_CTL_RB_ADDR + 0x1F4)

/* Ulp wakeup event. */
#define ULP_AON_CTL_ULP_WKUP_EVT_STS_REG        (ULP_AON_CTL_RB_ADDR + 0x1E8)
#define ULP_AON_CTL_ULP_WKUP_EVT_CLR_REG        (ULP_AON_CTL_RB_ADDR + 0x1EC)
#define ULP_AON_CTL_ULP_WKUP_EVT_EN_REG         (ULP_AON_CTL_RB_ADDR + 0x1F0)

/* Ulp mem off. */
#define ULP_AON_MEMORY_RETENRION_CEOFF_REG      (ULP_AON_CTL_RB_ADDR + 0x250)

#define PM_M_WDT_INT_WKUP                       7
#define PM_M_RTC_INT_WKUP                       6
#define PM_SEC_RTC_INT_WKUP                     5
#define PM_JLINK_WKUP                           4
#define PM_UART_H1_RXD_WKUP                     3
#define PM_UART_L0_RXD_WKUP                     2
#define PM_ULP_GPIO_INT_WKUP                    1
#define PM_A_SDIO_WKUP                          0
#define PM_ULP_WKUP_ALL_MASK                    0xFF

#ifdef CONFIG_UART_L0_NOT_SUPPORT_RX
#define PM_ULP_WKUP_MASK                        (BIT(PM_M_WDT_INT_WKUP) | \
                                                BIT(PM_M_RTC_INT_WKUP) | \
                                                BIT(PM_SEC_RTC_INT_WKUP) | \
                                                BIT(PM_JLINK_WKUP) | \
                                                BIT(PM_UART_H1_RXD_WKUP) | \
                                                BIT(PM_ULP_GPIO_INT_WKUP) | \
                                                BIT(PM_A_SDIO_WKUP))
#else
#define PM_ULP_WKUP_MASK                        (BIT(PM_M_WDT_INT_WKUP) | \
                                                BIT(PM_M_RTC_INT_WKUP) | \
                                                BIT(PM_SEC_RTC_INT_WKUP) | \
                                                BIT(PM_JLINK_WKUP) | \
                                                BIT(PM_UART_H1_RXD_WKUP) | \
                                                BIT(PM_UART_L0_RXD_WKUP) | \
                                                BIT(PM_ULP_GPIO_INT_WKUP) | \
                                                BIT(PM_A_SDIO_WKUP))
#endif

#define PM_UART_VETO_MASK                       (BIT(PM_JLINK_WKUP) | \
                                                BIT(PM_UART_L0_RXD_WKUP) | \
                                                BIT(PM_UART_H1_RXD_WKUP))

/* Wakeup event. */
#define PMU1_CTL_LPM_MCPU_WKUP_EVT_CLR_REG      (PMU1_CTL_RB_BASE + 0x210)
#define PMU1_CTL_LPM_MCPU_WKUP_EVT_EN_REG       (PMU1_CTL_RB_BASE + 0x214)
#define PMU1_CTL_LPM_MCPU_WKUP_EVT_STS_REG      (PMU1_CTL_RB_BASE + 0x218)
/* Wakeup interrupt. */
#define PMU1_CTL_LPM_MCPU_WKUP_INT_CLR_REG      (PMU1_CTL_RB_BASE + 0x220)
#define PMU1_CTL_LPM_MCPU_WKUP_INT_EN_REG       (PMU1_CTL_RB_BASE + 0x224)
#define PMU1_CTL_LPM_MCPU_WKUP_INT_STS_REG      (PMU1_CTL_RB_BASE + 0x228)

#define PM_LPM_MCPU_BWDT_INT_WKUP               6
#define PM_LPM_MCPU_DAP_MCPU_WKUP               5
#define PM_LPM_MCPU_SSI_MCPU_WKUP               4
#define PM_LPM_MCPU_M_GPIO_INT_WKUP             3
#define PM_LPM_MCPU_COM_UART_H0_RXD_WKUP        2
#define PM_LPM_MCPU_SPI3_INT_WKUP               1
#define PM_LPM_MCPU_B2M_IPC_INT_WKUP            0
#define PM_LPM_MCPU_WKUP_ALL_MASK               0x7F
#define PM_LPM_MCPU_WKUP_MASK                   (BIT(PM_LPM_MCPU_BWDT_INT_WKUP) | \
                                                BIT(PM_LPM_MCPU_DAP_MCPU_WKUP) | \
                                                BIT(PM_LPM_MCPU_SSI_MCPU_WKUP) | \
                                                BIT(PM_LPM_MCPU_M_GPIO_INT_WKUP) | \
                                                BIT(PM_LPM_MCPU_COM_UART_H0_RXD_WKUP) | \
                                                BIT(PM_LPM_MCPU_SPI3_INT_WKUP) | \
                                                BIT(PM_LPM_MCPU_B2M_IPC_INT_WKUP))

/* Sleep event. */
#define PMU1_CTL_LPM_MCPU_SLP_EVT_CLR_REG       (ULP_AON_CTL_RB_ADDR + 0x3A4)
#define PMU1_CTL_LPM_MCPU_SLP_EVT_EN_REG        (ULP_AON_CTL_RB_ADDR + 0x3A8)
#define PMU1_CTL_LPM_MCPU_SLP_EVT_STS_REG       (ULP_AON_CTL_RB_ADDR + 0x3AC)
/* Sleep int. */
#define PMU1_CTL_LPM_MCPU_SLP_INT_CLR_REG       (ULP_AON_CTL_RB_ADDR + 0x3B0)
#define PMU1_CTL_LPM_MCPU_SLP_INT_EN_REG        (ULP_AON_CTL_RB_ADDR + 0x3B4)
#define PMU1_CTL_LPM_MCPU_SLP_INT_STS_REG       (ULP_AON_CTL_RB_ADDR + 0x3B8)

#define PM_LPM_MCPU_SLEEPING_SLP                1
#define PM_LPM_MCPU_SLEEPDEEP_SLP               0
#define PM_LPM_MCPU_SLP_ALL_MASK                0x3
#define PM_LPM_MCPU_SLP_MASK                    BIT(PM_LPM_MCPU_SLEEPING_SLP)

#define PMU1_CTL_RST_MAN_REG                    (PMU1_CTL_RB_BASE + 0xE4)
#define PM_RST_PWR_C1_CRG_N_FRC_ON              2
#define PM_RST_PWR_C1_LOGIC_N_FRC_ON            1
#define PM_RST_PWR_C1_CPU_N_FRC_ON              0
#define PM_RST_PWR_C1_FRC_ON_MASK               (BIT(PM_RST_PWR_C1_CRG_N_FRC_ON) | \
                                                BIT(PM_RST_PWR_C1_LOGIC_N_FRC_ON) | \
                                                BIT(PM_RST_PWR_C1_CPU_N_FRC_ON))

#define ULP_AON_CTL_RST_BOOT_32K_N_CFG_REG      (ULP_AON_CTL_RB_ADDR + 0x134)
#define ULP_AON_CTL_PMU_CLDO_EN_CFG_REG         (ULP_AON_CTL_RB_ADDR + 0x128)
#define ULP_AON_CTL_CLDO_MAN_REG                (ULP_AON_CTL_RB_ADDR + 0x200)
#define PM_PMU_CLDO_EN_MAN_ON                   0x111
#define PM_PMU_CLDO_EN_AUTO                     0

#define ULP_AON_CTL_PAD_CONTROL_REG             (ULP_AON_CTL_RB_ADDR + 0x840)
#define PM_PAD_CONTROL_BY_ULP                   1
#define PM_PAD_CONTROL_BY_AON                   0

#define ULP_AON_CTL_ULP_GPIO_CLK_CFG_REG        (ULP_AON_CTL_RB_ADDR + 0x24)
#define PM_PCLK_INTR_SEL_BIT                    1
#define PM_PCLK_INTR_EN_BIT                     0

#define SEM0_STS_REG                            (ULP_AON_CTL_RB_ADDR + 0x1200)
#define X2B_SOFT_INT_EN                         (B_CTL_RB_BASE + 0x600)
#define X2B_SOFT_INT_ALL_MASK                   0x3
#define X2M_SOFT_INT_EN                         (M_CTL_RB_BASE + 0x20)
#define X2M_SOFT_INT_ALL_MASK                   0x3
#define PMU1_CTL_LPM_BCPU_WKUP_EN               (PMU1_CTL_RB_BASE + 0x134)
#define PMU1_CTL_LPM_BCPU_WKUP_INT_EN           (PMU1_CTL_RB_BASE + 0x144)

#if defined(__LITEOS__)
#define PM_OS_TICKS_PER_S   LOSCFG_BASE_CORE_TICK_PER_SECOND
#define PM_OS_TICKS_PER_MS  (PM_OS_TICKS_PER_S / LOSCFG_BASE_CORE_TICK_PER_SECOND)
#elif defined(__FREERTOS__)
#define PM_OS_TICKS_PER_S   configTICK_RATE_HZ
#define PM_OS_TICKS_PER_MS  (PM_OS_TICKS_PER_S / configTICK_RATE_HZ)
#endif

#define UART_VETO_MS                            1000

#define M_SYS_CUR_STS                           0x52000D00

#define STS_WORK                                     0
#define STS_PRE_WORK                                 3
#define STS_SLEEPING                                 7

#ifdef BOARD_FPGA
#define SYSTICK_CLOCK_32K 31902
#else
#define SYSTICK_CLOCK_32K 32768
#endif

static uint64_t g_entry_sleep_count = 0;
static uint64_t g_exit_sleep_count = 0;

static uint64_t g_suspend_count = 0;
static uint64_t g_resume_count = 0;

#if defined(CONFIG_PM_DEBUG)
static pm_sleep_debug_t g_pm_sleep_debug = {0};
static uint32_t g_wakeup_sts_cnt[PM_WKUP_MAX] = {0};
static void pm_port_wakeup_sts(uint32_t reg_value);
#endif /* CONFIG_PM_DEBUG */

#define WFI_HOLD_CYCLE               20000

#define PM_SLEEP_CPU_SUSPEND_REG_NUM 128
uint32_t g_cpu_suspend_regs[PM_SLEEP_CPU_SUSPEND_REG_NUM] = { 0 };
static uint32_t g_cpu_reset_pc;

#define PM_SLEEP_IRQ_SUSPEND_REG_NUM 3
#ifdef CONFIG_LPM_DISABLE_INT_BEFORE_SLEEP
uint32_t g_irq_suspend_regs[PM_SLEEP_IRQ_SUSPEND_REG_NUM] = {0};
#endif

static rtc_handle_t g_pm_rtc = NULL;
static uint32_t g_gpio16_pad_ctrl_val = 0;

uint32_t hal_pin_get_pull_regaddr(pin_t pin);

static void pm_rtc1_irq(uintptr_t data)
{
    unused(data);
}

void pm_wakeup_rtc_init(void)
{
    uapi_rtc_init();
    uint8_t *rtcintpri = int_get_maucintpri();
    uapi_rtc_adapter(RTC_1, RTC_1_IRQN, rtcintpri[RTC_1_IRQN]);
    uapi_rtc_create(RTC_1, &g_pm_rtc);
}

void pm_wakeup_rtc_start(uint32_t time_ms)
{
    uapi_rtc_start(g_pm_rtc, time_ms, pm_rtc1_irq, 1);
}

void pm_record_rtc_start(void)
{
    uapi_rtc_start_hw_rtc(RTC_0, RTC_HW_MAX_MS);
}

void pm_record_rtc_stop(void)
{
    uapi_rtc_stop_hw_rtc(RTC_0);
}

#define RC_CALI_RESULT_DEFAULT 62500
uint32_t g_rc_cali_result = RC_CALI_RESULT_DEFAULT;

/* 校准结果：64个systick周期的时间内，32M时钟经过的周期数 */
static void pm_port_refresh_rc_cali_result(void)
{
    uint32_t rc_cali_result;
    uapi_reg_read(RC_CALI_RESULT, rc_cali_result);
    g_rc_cali_result = (rc_cali_result == 0) ? RC_CALI_RESULT_DEFAULT : rc_cali_result;
}

static uint32_t pm_port_rc_cali_result(void)
{
    return g_rc_cali_result;
}

void pm_port_start_tickless(void)
{
    pm_port_refresh_rc_cali_result();
    g_entry_sleep_count = uapi_systick_get_count();
#if defined(__LITEOS__)
    os_tick_timer_disable();
#elif defined(__FREERTOS__)
    vTimerDisable();
#endif
}

static void pm_port_tickless_compensation(uint32_t ticks)
{
    uapi_rtc_stop(g_pm_rtc);
    g_exit_sleep_count = uapi_systick_get_count();
    uint64_t actual_sleep_count = g_exit_sleep_count - g_entry_sleep_count;
    uint32_t remain_count;
    uint32_t compensation_ticks;
    uint32_t actual_sleep_ticks;
    uint32_t cycle_per_tick = (tcxo_porting_ticks_per_usec_get() * US_PER_MS * PM_MS_PER_TICK);

    actual_sleep_count = actual_sleep_count * pm_port_rc_cali_result() / RC_CALI_DEFAULT_DURTION;
    actual_sleep_ticks = (uint32_t)(actual_sleep_count / cycle_per_tick);
    remain_count = actual_sleep_count % cycle_per_tick;
    /* less than 1 tick, use tick timer to compensate */
    compensation_ticks = os_tick_timer_compensation(remain_count);
    if (actual_sleep_ticks > ticks) {
        oal_ticks_restore(ticks + compensation_ticks);
    } else {
        oal_ticks_restore(actual_sleep_ticks + compensation_ticks);
    }
}

void pm_port_stop_tickless(uint32_t sleep_ms)
{
    uint32_t cur_ticks = sleep_ms / 10;
    pm_port_tickless_compensation(cur_ticks);
#if defined(__LITEOS__)
    os_tick_timer_enable();
#elif defined(__FREERTOS__)
    vTimerEnable();
#endif
}

uint32_t pm_port_get_sleep_ms(void)
{
    uint32_t sleep_ms = oal_get_sleep_ticks() * PM_MS_PER_TICK;
    return sleep_ms;
}

void pm_port_allow_deepsleep(bool allow)
{
    if (allow == 0) {
        writew(ULP_AON_CTL_ULP_WKUP_EVT_EN_REG, 0); /* 防止uart初始化管脚复用模式切换时误识别为唤醒信号 */
    }
    writew(PMU1_CTL_LPM_MCU_ALW_TO_SLP_REG, (uint16_t)allow);
}

static volatile uint32_t g_enter_wfi = 0;
static volatile uint32_t g_sys_sts = 0;
static volatile uint32_t g_wfi7_cnt = 0;
static volatile uint32_t g_wfi7_ra = 0;

void pm_port_enter_wfi(void)
{
    g_enter_wfi = 0;
    g_wfi7_cnt = 0;

    dsb();
    wfi();
    isb();
    nop();
    nop();
    nop();
    nop();

    /* 下列代码变量访问仅为维测使用,在掉电过程应该不访问内存,正式方案应该仅直接读寄存器循环等待 */
    g_sys_sts = readl(M_SYS_CUR_STS);
    while ((g_sys_sts != STS_WORK) && (g_sys_sts != STS_PRE_WORK)) {
        g_sys_sts = readl(M_SYS_CUR_STS);
        if (g_sys_sts == STS_SLEEPING) {
            g_wfi7_cnt++;
            g_wfi7_ra = (uint32_t)(uintptr_t)__builtin_return_address(0);
        }
        g_enter_wfi++;
    }
}

void pm_port_start_wakeup_timer(uint32_t sleep_ms)
{
    /* 经过校准后的32K RC时钟频率转换得到的休眠时间 */
    uint64_t sleep_ms_cali = ((uint64_t)sleep_ms * RC_CALI_RESULT_DEFAULT / pm_port_rc_cali_result());
    /* 最大唤醒时间 = U32_MAX / 32768 * 1000 - 1 = 131,070,999 ms ~= 36h */
    uint32_t sleep_ms_in_range = (uint32_t)(sleep_ms_cali > RTC_MAX_MS ? RTC_MAX_MS : sleep_ms_cali);
    pm_wakeup_rtc_start(sleep_ms_in_range);
}

void pm_port_lightsleep_config(void)
{
#if defined(CONFIG_PM_DEBUG)
    g_pm_sleep_debug.pm_ls_count++;
#endif /* CONFIG_PM_DEBUG */
    return;
}

void pm_port_light_wakeup_config(void)
{
#if defined(CONFIG_PM_DEBUG)
    g_pm_sleep_debug.pm_ls_wkup_count++;
#endif /* CONFIG_PM_DEBUG */
    return;
}

static uint32_t g_pull_down_save = 0;
static uint32_t g_pull_down_skip = 0;
void pm_port_skip_pull_down(pin_t pin)
{
    uint32_t gpio_pd_reg_offset;
    uint32_t gpio_pd_reg = hal_pin_get_pull_regaddr(pin);
    /* 控制MGPIO0~MGPIO22的pulldown */
    if ((gpio_pd_reg >= S_MGPIO0_PAD_CTL_REG) && (gpio_pd_reg <= S_MGPIO22_PAD_CTL_REG)) {
        gpio_pd_reg_offset = (gpio_pd_reg - S_MGPIO0_PAD_CTL_REG) / DATA_WIDTH_4;
        g_pull_down_skip |= (1 << gpio_pd_reg_offset);
    }
}

static bool gpio_pull_down_skip(uint32_t reg_addr)
{
    uint32_t i;
    uint32_t coex_wlact_en;
    uint32_t mgpio_reg[] = { S_MGPIO7_PAD_CTL_REG, S_MGPIO10_PAD_CTL_REG, S_MGPIO12_PAD_CTL_REG,
        S_MGPIO20_PAD_CTL_REG, S_MGPIO22_PAD_CTL_REG };

    if (((1 << ((reg_addr - S_MGPIO0_PAD_CTL_REG) / DATA_WIDTH_4)) & g_pull_down_skip) != 0) {
        return true;
    }

    /* 蓝牙共存GPIO */
    coex_wlact_en = readl(COEX_WLACT_ANTSEL_PINMUX_EN);
    coex_wlact_en = coex_wlact_en >> 0x2; // 低2位未使用
    for (i = 0; i < sizeof(mgpio_reg) / sizeof(uint32_t); i++) {
        if ((reg_addr == mgpio_reg[i]) && ((coex_wlact_en & (1 << i)) != 0)) {
            return true;
        }
    }

    return false;
}

static void pm_port_gpio_pull_down_suspend(void)
{
    uint32_t reg_addr;
    uint32_t i = 0;

    g_pull_down_save = 0;
    for (reg_addr = S_MGPIO0_PAD_CTL_REG; reg_addr <= S_MGPIO22_PAD_CTL_REG; reg_addr += DATA_WIDTH_4) {
        if (reg_addr == S_MGPIO16_PAD_CTL_REG) {
            g_gpio16_pad_ctrl_val = readl(reg_addr);
            reg_setbit(reg_addr, 0, POS_3);
            continue;
        }
        g_pull_down_save |= reg_getbits(reg_addr, 0, POS_4, 1) << i;
        if (!gpio_pull_down_skip(reg_addr)) {
            reg_setbit(reg_addr, 0, POS_4); // pull down enable
        }
        i++;
    }
}

static void pm_port_gpio_pull_down_resume(void)
{
    uint32_t reg_addr;
    uint32_t i = 0;

    for (reg_addr = S_MGPIO0_PAD_CTL_REG; reg_addr <= S_MGPIO22_PAD_CTL_REG; reg_addr += DATA_WIDTH_4) {
        if (reg_addr == S_MGPIO16_PAD_CTL_REG) {
            writel(reg_addr, g_gpio16_pad_ctrl_val);
            continue;
        }
        if (!gpio_pull_down_skip(reg_addr)) {
            if ((g_pull_down_save & (1 << i)) == 0) {
                reg_clrbit(reg_addr, 0, POS_4); // pull down disable
            }
        }
        i++;
    }
}

void pm_port_exit_udsleep(void)
{
    writew(ULP_AON_MEMORY_RETENRION_CEOFF_REG, 0); /* 关闭内存可掉电 */
    writew(PMU1_CTL_LPM_MCU_ALW_TO_SLP_REG, 0);

    writew(PMU1_CTL_LPM_MCPU_SLP_EVT_EN_REG, 0);                              // Disable.
    for (int i = 0; i < ULP_CLR_DELAY_CYCLE; i++) {
        nop();
    }

    writew(PMU1_CTL_LPM_MCPU_SLP_EVT_CLR_REG, PM_LPM_MCPU_SLP_ALL_MASK);    // Clear status.
    writew(ULP_AON_CTL_ULP_WKUP_EVT_EN_REG, 0);                     // Disable.
    writew(ULP_AON_CTL_ULP_WKUP_EVT_CLR_REG, PM_ULP_WKUP_ALL_MASK); // Clear status.

    writel(M_SLP_STS, 0);
    writel(B_SLP_STS, 0);
}

#define DELAY_CNT_MAX   0x4000
#define TRY_CNT_MAX     0x10000
void pm_port_enter_udsleep(void)
{
    int32_t i, read_cnt;
    int try_cnt = TRY_CNT_MAX;
    uint32_t gpio_intr_en;
    uapi_watchdog_disable();
    uapi_pm_dev_suspend();

    gpio_intr_en = readl(GPIO1_BASE_ADDR + 0xC);
    reg32_setbit(MSUB_SLP_CFG, 0x0);
    reg_clrbit(EFUSE_ULP_SEL1, 0, POS_7); // 下电前CMU_XLDO_VOUT_CTRL_sel使用efuse配置

    writew(ULP_AON_MEMORY_RETENRION_CEOFF_REG, 0xA5A5); /* 内存可掉电 */
    /* acore rom start addr: 0x10000 */
    writew(ULP_AON_CTL_MCPU_POR_RST_PC_H_REG, 0x1);
    writew(ULP_AON_CTL_MCPU_POR_RST_PC_L_REG, 0);
    writew(PMU1_CTL_LPM_MCU_ALW_TO_SLP_REG, 1);
    reg_clrbit(0x520003e4, 0, POS_0); /* A核cg配置为低功耗时关闭 */

    writew(0x57000044, 0); /* 禁止GPIO中断 */
    /* Aon sleep event. */
    writew(PMU1_CTL_LPM_MCPU_SLP_EVT_EN_REG, PM_LPM_MCPU_SLP_MASK);         // Enable.
    writew(PMU1_CTL_LPM_MCPU_WKUP_EVT_EN_REG, 0);                           // Disable.

    /* 循环清除状态强制睡眠 */
    while (try_cnt-- > 0) {
        writew(0x570048f0, 0x0); /* 清强制睡眠票 */
        writew(PMU1_CTL_RB_BASE + 0x130, 0xF);       // Clear BCPU status.
        writew(GPIO1_BASE_ADDR + 0xC, 0x0);  // close gpio intterrupt.
        dsb();

        writew(PMU1_CTL_LPM_MCPU_WKUP_EVT_CLR_REG, PM_LPM_MCPU_WKUP_ALL_MASK);  // Clear status.
        /* Ulp wakeup event. */
        writew(ULP_AON_CTL_ULP_WKUP_EVT_EN_REG, 0);                     // Disable.
        writew(ULP_AON_CTL_ULP_WKUP_EVT_CLR_REG, PM_ULP_WKUP_ALL_MASK); // Clear status.
        read_cnt = TRY_CNT_MAX;
        while ((readw(ULP_AON_CTL_ULP_WKUP_EVT_STS_REG) != 0) && (read_cnt-- > 0)) {}

        writew(GPIO1_BASE_ADDR + 0x2C, 0xffffffff);  // Clear GPIO interrupt.
        writew(GPIO1_BASE_ADDR + 0xC, gpio_intr_en);  // open gpio intterrupt.
        dsb();

        writel(ULP_GPIO_CLK_CFG, 0x3); // GPIO切32K时钟
        writew(ULP_AON_CTL_ULP_WKUP_EVT_EN_REG, BIT(PM_ULP_GPIO_INT_WKUP));      // Enable.
        read_cnt = TRY_CNT_MAX;
        while ((readw(ULP_AON_CTL_ULP_WKUP_EVT_EN_REG) != BIT(PM_ULP_GPIO_INT_WKUP))  && (read_cnt-- > 0)) {}

        writew(0x570048f0, 0x3); /* 投强制睡眠票 */
        dsb();
        for (i = 0; i < DELAY_CNT_MAX; i++) { // 延时
            nop();
        }

        /* 假如被GPIO唤醒，把GPIO切换为32M再去清除GPIO状态 */
        writel(ULP_GPIO_CLK_CFG, 0x0);
        writel(ULP_GPIO_CLK_CFG, 0x1);
        dsb();
    }
    /* 异常保护复位系统 */
    reg_clrbit(0x57030980, 0x0, 0x0);
}

static void pm_port_sleep_evt_cfg(void)
{
    /* Aon sleep event. */
    writew(PMU1_CTL_LPM_MCPU_SLP_EVT_EN_REG, PM_LPM_MCPU_SLP_MASK);         // Enable.

    writew(PMU1_CTL_LPM_MCPU_WKUP_EVT_EN_REG, 0);                           // Disable.
    writew(PMU1_CTL_LPM_MCPU_WKUP_EVT_CLR_REG, PM_LPM_MCPU_WKUP_ALL_MASK);  // Clear status.
    writew(PMU1_CTL_LPM_MCPU_WKUP_EVT_EN_REG, PM_LPM_MCPU_WKUP_MASK);       // Enable.

#ifdef CONFIG_LPM_DISABLE_INT_BEFORE_SLEEP
    writew(PMU1_CTL_LPM_MCPU_WKUP_INT_EN_REG, 0);                           // Disable.
    writew(PMU1_CTL_LPM_MCPU_WKUP_INT_CLR_REG, PM_LPM_MCPU_WKUP_ALL_MASK);  // Clear status.
    writew(PMU1_CTL_LPM_MCPU_WKUP_INT_EN_REG, PM_LPM_MCPU_WKUP_MASK);       // Enable.
#endif

    /* Ulp wakeup event. */
    writew(ULP_AON_CTL_ULP_WKUP_EVT_EN_REG, 0);                     // Disable.
    writew(ULP_AON_CTL_ULP_WKUP_EVT_CLR_REG, PM_ULP_WKUP_ALL_MASK); // Clear status.
    writew(ULP_AON_CTL_ULP_WKUP_EVT_EN_REG, PM_ULP_WKUP_MASK);      // Enable.

#ifdef CONFIG_LPM_DISABLE_INT_BEFORE_SLEEP
    writew(ULP_AON_CTL_ULP_WKUP_INT_EN_REG, 0);                     // Disable.
    writew(ULP_AON_CTL_ULP_WKUP_INT_CLR_REG, PM_ULP_WKUP_ALL_MASK); // Clear status.
    writew(ULP_AON_CTL_ULP_WKUP_INT_EN_REG, PM_ULP_WKUP_MASK);      // Enable.
#endif
}

void pm_port_deepsleep_config(void)
{
#ifdef CONFIG_LPM_DISABLE_INT_BEFORE_SLEEP
    suspend_irq();
#endif
    reg32_setbit(MSUB_SLP_CFG, 0x0);
#ifdef BOARD_ASIC
    acore_suspend_ctl_rb();
#endif
    sfc_flash_suspend();
    uapi_uart_suspend(0);
    writel(UART_CFG_STS, 0x0); // 睡眠前清除uart配置状态
    uapi_tcxo_suspend(0);
#if defined(CONFIG_DRIVER_SUPPORT_I2C) && defined(CONFIG_I2C_SUPPORT_LPM)
    uapi_i2c_suspend(0);
#endif
#if defined(CONFIG_DRIVER_SUPPORT_GPIO) && defined(CONFIG_GPIO_SUPPORT_LPM)
    uapi_gpio_suspend(0);
#endif
#if defined(CONFIG_DRIVER_SUPPORT_PINCTRL) && defined(CONFIG_PINCTRL_SUPPORT_LPM)
    uapi_pin_suspend(0);
#endif
#if defined(CONFIG_DRIVER_SUPPORT_PWM) && defined(CONFIG_PWM_SUPPORT_LPM)
    uapi_pwm_suspend(0);
#endif
#if defined(CONFIG_DRIVER_SUPPORT_SPI) && defined(CONFIG_SPI_SUPPORT_LPM)
    uapi_spi_suspend(SPI_BUS_0);
    uapi_spi_suspend(SPI_BUS_1);
#endif
    g_suspend_count = uapi_systick_get_count();
#if defined(CONFIG_PM_DEBUG)
    g_pm_sleep_debug.pm_ds_count++;
#endif /* CONFIG_PM_DEBUG */
    reg32_setbit(M_SLP_STS, SFC_STS_BIT_MASK);
    pm_port_sleep_evt_cfg();
#ifdef BOARD_ASIC
    pm_port_gpio_pull_down_suspend();
    pm_gpio_cfg_suspend(CLOCK_SWITCH_COREA);
#endif
    dsb();
}

void pm_port_deep_wakeup_config(void)
{
#ifdef CONFIG_LPM_DISABLE_INT_BEFORE_SLEEP
    resume_irq();
#endif
    uint32_t wkup_sts = readl(ULP_AON_CTL_ULP_WKUP_EVT_STS_REG);
    if ((wkup_sts & PM_UART_VETO_MASK) != 0) {
        uapi_pm_add_sleep_veto_with_timeout(PM_UART_VETO_ID, UART_VETO_MS);
    }
#if defined(CONFIG_PM_DEBUG)
    pm_port_wakeup_sts(wkup_sts);
    g_pm_sleep_debug.pm_ds_wkup_count++;
#endif /* CONFIG_PM_DEBUG */
    writew(PMU1_CTL_LPM_MCPU_SLP_EVT_EN_REG, 0);                              // Disable.
    for (int i = 0; i < ULP_CLR_DELAY_CYCLE; i++) {
        nop();
    }

    writew(PMU1_CTL_LPM_MCPU_SLP_EVT_CLR_REG, PM_LPM_MCPU_SLP_ALL_MASK);    // Clear status.
    writew(ULP_AON_CTL_ULP_WKUP_EVT_EN_REG, 0);                     // Disable.
    writew(ULP_AON_CTL_ULP_WKUP_EVT_CLR_REG, PM_ULP_WKUP_ALL_MASK); // Clear status.
    dsb();
    while (readl(PMU1_CTL_LPM_MCPU_SLP_EVT_STS_REG) != 0) {}
}

void pm_port_cpu_suspend(void)
{
    // pc = pc_h << 16 + pc_l
    g_cpu_reset_pc = (readl(ULP_AON_CTL_MCPU_POR_RST_PC_H_REG) << 16) | (readl(ULP_AON_CTL_MCPU_POR_RST_PC_L_REG));
    // pc_h: pc >> 16
    writew(ULP_AON_CTL_MCPU_POR_RST_PC_H_REG, (uint16_t)((uint32_t)(uintptr_t)lowpower_cpu_resume >> 16));
    writew(ULP_AON_CTL_MCPU_POR_RST_PC_L_REG, (uint16_t)((uint32_t)(uintptr_t)lowpower_cpu_resume));
    lowpower_cpu_suspend(); // Must be placed at the end of this function
}

static void sfc_ipc_resume(void)
{
    /* double-checked before and after get the semaphore. */
    while (readl(SEM0_STS_REG) != 0) {}
    readl(SEM0_STS_REG);
    uint32_t b_sts = reg32_getbit(B_SLP_STS, SFC_STS_BIT_MASK);
    if (b_sts == 0) {
        reg32_clrbit(M_SLP_STS, SFC_STS_BIT_MASK);
        writel(SEM0_STS_REG, 0x1);
        return ;
    }

    dmmu_remap_reg_restore();
    /* sfc recover */
    sfc_flash_resume();
    /* recover IPC wakeup event and irq */
    writel(PMU1_CTL_LPM_BCPU_WKUP_EN, 0x1);        // 配置IPC唤醒使能
    writel(PMU1_CTL_LPM_BCPU_WKUP_INT_EN, 0x1);
    reg32_clrbit(M_SLP_STS, SFC_STS_BIT_MASK);
    writel(SEM0_STS_REG, 0x1);
}

static void pm_port_tcxo_resume(void)
{
    g_resume_count = uapi_systick_get_count();
    uint64_t systick_compensation = g_resume_count - g_suspend_count;
    uint64_t tcxo_compensation = convert_count_2_us(systick_compensation);
    uapi_tcxo_resume((uintptr_t)&tcxo_compensation);
}

void pm_port_cpu_resume(void)
{
#ifdef BOARD_ASIC
    uint32_t ret = true;
#endif
    sfc_ipc_resume();
#ifdef BOARD_ASIC
    if (system_get_pll_clock_flag() == 0) {
        ret = system_switch_pll_clock();
    } else {
        ret = (reg32_getbit(NMI_CTL_REG_BASE_ADDR, NMI_CWDT) != 0) ? false: true;
    }
#if defined(CONFIG_PM_DEBUG)
    if (ret == true) {
        g_pm_sleep_debug.pm_all_wkup_count++;
    }
#endif /* CONFIG_PM_DEBUG */

    pm_port_gpio_pull_down_resume();
    pm_peripheral_resume(CLOCK_SWITCH_COREA);
    acore_resume_ctl_rb();
#endif
    cpu_cache_reset();
#ifdef CONFIG_ACORE_CPU_TRACE
    mcpu_trace_resume();
#endif
    patch_init();
    pm_port_tcxo_resume();
    while (readl(SEM3_STS_REG) != 0) {}
    uapi_uart_resume(0);
    writel(SEM3_STS_REG, 0x1);
#if defined(CONFIG_DRIVER_SUPPORT_PINCTRL) && defined(CONFIG_PINCTRL_SUPPORT_LPM)
    uapi_pin_resume(0);
#endif
#if defined(CONFIG_DRIVER_SUPPORT_GPIO) && defined(CONFIG_GPIO_SUPPORT_LPM)
    uapi_gpio_resume(0);
#endif
#if defined(CONFIG_DRIVER_SUPPORT_PWM) && defined(CONFIG_PWM_SUPPORT_LPM)
    uapi_pwm_resume(0);
#endif
#if defined(CONFIG_DRIVER_SUPPORT_SPI) && defined(CONFIG_SPI_SUPPORT_LPM)
    uapi_spi_resume(SPI_BUS_0);
    uapi_spi_resume(SPI_BUS_1);
#endif
    uapi_dma_resume(0);
    uapi_tsensor_init();
    uapi_drv_cipher_env_resume();
#if defined(CONFIG_DRIVER_SUPPORT_I2C) && defined(CONFIG_I2C_SUPPORT_LPM)
    uapi_i2c_resume(0);
#endif
    non_os_nmi_config(NMI_CWDT, true);
}

uint16_t pm_port_get_sleep_event_status(void)
{
    return readw(PMU1_CTL_LPM_MCPU_SLP_EVT_STS_REG);
}

uint16_t pm_port_get_wakeup_event_status(void)
{
    return readw(ULP_AON_CTL_ULP_WKUP_EVT_STS_REG);
}

#if defined(CONFIG_PM_DEBUG)
static void pm_port_wakeup_sts(uint32_t reg_value)
{
    uint32_t value = reg_value;
    for (uint32_t i = 0; i < PM_WKUP_MAX; i++) {
        if ((value & 1) == 1) {
            g_wakeup_sts_cnt[i]++;
        }
        value = value >> 1;
    }
}

uint32_t pm_port_get_wakeup_cnt(uint32_t index)
{
    return g_wakeup_sts_cnt[index];
}

pm_sleep_debug_t pm_port_get_debug_info(void)
{
    return g_pm_sleep_debug;
}
#endif /* CONFIG_PM_DEBUG */

#ifdef CONFIG_LPM_DISABLE_INT_BEFORE_SLEEP
void pm_wkup_irq(void)
{
    writew(PMU1_CTL_LPM_MCPU_WKUP_INT_EN_REG, 0);                           // Disable.
    writew(PMU1_CTL_LPM_MCPU_WKUP_INT_CLR_REG, PM_LPM_MCPU_WKUP_ALL_MASK);  // Clear status.
    writew(ULP_AON_CTL_ULP_WKUP_INT_EN_REG, 0);                     // Disable.
    writew(ULP_AON_CTL_ULP_WKUP_INT_CLR_REG, PM_ULP_WKUP_ALL_MASK); // Clear status.
    osal_irq_clear(M_WAKEUP_IRQN);
    return ;
}
#endif
