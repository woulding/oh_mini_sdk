/**
 * Copyright (c) CompanyNameMagicTag 2022-2023. All rights reserved.
 * Description: Application core main function for standard
 * Author: @CompanyNameTag
 * Create: 2022-07-27, Create file.
 */
#include "cmsis_os2.h"
#include "ipc.h"
#include "ipc_porting.h"
#include "msg_chl.h"
#include "string.h"
#include "rtc.h"
#include "rtc_porting.h"
#include "timer.h"
#include "app_os_init.h"
#include "log_common.h"
#include "gpio.h"
#include "chip_io.h"
#include "memory_core.h"
#include "clocks.h"
#include "uart.h"
#include "log_uart.h"
#include "log_memory_region.h"
#include "securec.h"
#include "pinctrl_porting.h"
#include "pinctrl.h"
#include "tcxo.h"
#include "tcxo_porting.h"
#include "mcpu_trace_porting.h"
#include "application_version.h"
#include "arch_trace.h"
#include "systick.h"
#include "systick_porting.h"
#include "upg_common_porting.h"
#include "watchdog.h"
#include "dma.h"
#include "security_init.h"
#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
#include "sfc.h"
#endif
#ifdef MBEDTLS_HARDEN_OPEN
#include "mbedtls_harden_adapt.h"
#endif

#if CHIP_ASIC
#include "clock_calibration.h"
#include "hal_clocks_glb.h"
#include "pm.h"
#endif
#ifdef CONFIG_SYSTEM_VIEW
#include "SEGGER_SYSVIEW_Conf.h"
#include "SEGGER_SYSVIEW.h"
#endif
#include "cpu_utils.h"
#include "exception.h"
#include "reboot_porting.h"
#include "log_oml_exception.h"
#include "los_task_pri.h"
#ifdef __LITEOS__
#include "los_init_pri.h"
#endif
#include "oam_trace.h"
#if (ENABLE_LOW_POWER == YES)
#include "pm.h"
#include "idle_config.h"
#endif
#include "watchdog_porting.h"
#include "dfx_system_init.h"
#include "pmp_cfg.h"

#include "share_mem_config.h"
#include "dyn_mem.h"
#include "flash_patch_porting.h"
#include "debug_print.h"

#ifdef AT_COMMAND
#include "at_config.h"
#include "at_product.h"
#include "test_suite_uart.h"
#ifdef CONFIG_AT_SUPPORT_ZDIAG
#include "at_zdiag.h"
#endif
#ifdef CONFIG_SUPPORT_WIFI
#include "at_cmd_register.h"
#endif

#ifdef BTH_TASK_EXIST
#include "at_bt_cmd_register.h"
#endif
#endif

#ifdef CONFIG_AT_SUPPORT_PLT
#include "at_plt_cmd_register.h"
#endif

#include "uart_porting.h"
#include "trng_ipc_acore_buffer.h"
#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
#include "partition.h"
#include "mac_addr.h"
#ifdef CONFIG_MIDDLEWARE_SUPPORT_NV
#include "nv.h"
#include "nv_config.h"
#if (defined(CONFIG_NV_SUPPORT_ENCRYPT) && (defined(NV_YES)) && (CONFIG_NV_SUPPORT_ENCRYPT == NV_YES))
#include "cipher.h"
#endif
#endif
#endif
#ifdef BOARD_ASIC
#include "clock_recover.h"
#endif
#include "tsensor_porting.h"
#include "efuse.h"
#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
#include "xo_trim_porting.h"
#endif
#ifdef CONFIG_MIDDLEWARE_SUPPORT_LFS
#include "littlefs_adapt.h"
#endif

#define WDT_TIMEOUT_S 30
#define IMG_NUM_MAX   2
#define IMG_SEC       0
#define IMG_HIFI      1
#define BT_CLOCK_EN_REG           (PMU1_CTL_RB_BASE + 0x00E0)
#define BT_CLOCK_EN_BIT           (10)
#define BT_SOFT_RST               (GLB_CTL_M_RB_BASE + 0x00B8)
#define NFC_SOFT_RST              (GLB_CTL_D_RB_BASE + 0x0200)
#define DTCM_SHARE_MODE           0xF90
#define SHARE_MODE_GT             12
#define SHARE_MODE_CFG            8

void hardware_config_init(void)
{
    uapi_gpio_init();
    return;
    size_t pin_num;
    hal_pio_config_t *pio_func = NULL;
    bool result = false;

    get_pio_func_config(&pin_num, &pio_func);
    for (pin_t i = S_MGPIO0; i < pin_num; i++) {
        if (pio_func[i].func != HAL_PIO_FUNC_INVALID) {
            if (pio_func[i].func == HAL_PIO_FUNC_DEFAULT_HIGH_Z) {
                result = uapi_pin_set_mode(i, (pin_mode_t)HAL_PIO_FUNC_GPIO);
                uapi_gpio_set_dir(i, GPIO_DIRECTION_INPUT);
            } else {
                result = uapi_pin_set_mode(i, (pin_mode_t)pio_func[i].func);
                result = uapi_pin_set_ds(i, (pin_drive_strength_t)pio_func[i].drive);
            }
            if (pio_func[i].pull != HAL_PIO_PULL_MAX) {
                uapi_pin_set_pull(i, (pin_pull_t)pio_func[i].pull);
            }
            UNUSED(result);
        }
    }
}

static void cpu_cache_init(void)
{
    ArchICacheFlush();
    ArchDCacheInvalidate();
    ArchICacheEnable(CACHE_32KB);
    ArchICachePrefetchEnable(CACHE_PREF_4_LINES);
    ArchDCacheEnable(CACHE_4KB);
    return;
}

#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
static sfc_flash_config_t g_sfc_cfg = {
    .read_type = STANDARD_READ,
    .write_type = PAGE_PROGRAM,
    .mapping_addr = 0x400000,
    .mapping_size = 0x800000,
};
#endif

// 当前WDT时钟门控未打开, 初始化时钟门控, 初始化WDT并去使能(无踢狗)
static void watchdog_init(void)
{
    uintptr_t wdt_clk_reg = HAL_SOFT_RST_CTL_BASE + HAL_GLB_CTL_M_ATOP1_L_REG_OFFSET;
    uapi_reg_setbit16(wdt_clk_reg, HAL_AWDT_PERP_CK_EN_BIT);
    uapi_reg_setbit16(wdt_clk_reg, HAL_AWDT_CLK_EN_BIT);

    watchdog_turnon_clk();
    watchdog_func_adapt(CHIP_WDT_TIMEOUT_64S);
    uapi_watchdog_init(CHIP_WDT_TIMEOUT_64S);
    uapi_watchdog_enable(CHIP_WDT_MODE_INTERRUPT);
#ifdef TEST_SUITE
    // testsuite版本去使能watchdog
    uapi_watchdog_disable();
    uapi_watchdog_deinit();
#endif
    ccore_wdt_irq_register();
}

#ifdef AT_COMMAND

static void at_base_api_queue_create(uint32_t msg_count, uint32_t msg_size, unsigned long *queue_id)
{
    osal_msg_queue_create(NULL, msg_count, queue_id, 0, msg_size);
}

static uint32_t at_base_api_msg_queue_write(unsigned long queue_id, void *msg_ptr,
                                            uint32_t msg_size, uint32_t timeout)
{
    return osal_msg_queue_write_copy(queue_id, msg_ptr, msg_size, timeout);
}

static uint32_t at_base_api_msg_queue_read(unsigned long queue_id, void *buf_ptr,
                                           uint32_t *buf_size, uint32_t timeout)
{
    return osal_msg_queue_read_copy(queue_id, buf_ptr, buf_size, timeout);
}

static void at_base_api_task_pause(void)
{
    osal_yield();
}

static void* at_base_api_malloc(uint32_t size)
{
    return osal_kmalloc(size, OSAL_GFP_ATOMIC);
}

static void at_base_api_free(void *addr)
{
    osal_kfree(addr);
}

static void at_base_api_register(void)
{
    at_base_api_t base_api = {
        .msg_queue_create_func = at_base_api_queue_create,
        .msg_queue_write_func = at_base_api_msg_queue_write,
        .msg_queue_read_func = at_base_api_msg_queue_read,
        .task_pause_func = at_base_api_task_pause,
        .malloc_func = at_base_api_malloc,
        .free_func = at_base_api_free,
    };
    uapi_at_base_api_register(base_api);
}
#endif

static void sys_fault_handler(uint32_t exc_type, exc_context_t *exc_buff_addr)
{
    (void)OsDbgTskInfoGet(OS_ALL_TASK_MASK);
    OsExcStackInfo();
#if !defined(FPGA_WS53_PLT_ONLY) && (CONFIG_SUPPORT_WIFI)
    sys_mem_show();
#endif
    do_fault_handler(exc_type, exc_buff_addr);
}

static void LOS_NMIHandler(exc_context_t *exc_buff_addr)
{
    (void)OsDbgTskInfoGet(OS_ALL_TASK_MASK);
    OsExcStackInfo();
    do_hard_fault_handler(exc_buff_addr);
}

static void prepare_main_task(void)
{
    ArchSetExcUserHook((EXC_PROC_FUNC)riscv_cpu_trace_disable);
    ArchSetExcHook((EXC_PROC_FUNC)sys_fault_handler);
    ArchSetNMIHook((NMI_PROC_FUNC)LOS_NMIHandler);
    OsSetMainTask();
    OsCurrTaskSet(OsGetMainTask());
}

static ccore_cc_symbols_t *ccore_cc_symbols = (ccore_cc_symbols_t *)(CCORE_RAM_START_ADDR);

uint32_t get_log_buff(void)
{
    return ccore_cc_symbols->logbuff_start + ACCORE_MEM_ADDR_OFFSET;
}

static uint32_t get_ipc_share_mem_addr(void)
{
    return ccore_cc_symbols->ipc_share_mem_start + ACCORE_MEM_ADDR_OFFSET;
}

void copy_to_ccore(void)
{
#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
    uint32_t head_data = 0;
#endif
    PRINT("Copy Flash Code to C Ram\n");

    /* 设置Ccore复位后初始PC值: 0x10000 */
    writel(BCPU_POR_RST_PC_H_ADDR, BCPU_POR_RST_PC_H_VAL);
    writel(BCPU_POR_RST_PC_L_ADDR, BCPU_POR_RST_PC_L_VAL);

    if (system_get_udsleep_flag()) {
        pm_port_exit_udsleep();
        writel(0x10010000, 0x0000006f); // 0x10000: Ccore复位后初始PC值; 0x0000006f: equal to asm("j .")
        writel(0x57004134, 0x1);            // 配置IPC唤醒使能
        writel(0x52000034, (0x1 << 1));     // 产生IPC中断, 唤醒C核
        uapi_tcxo_delay_us(200);            // 清C核cache前200us延时
    } else {
        /* 1:解复位，0复位 */
        writel(HAL_SOFT_RST_2_GLB_B, RESET_CRG_CCORE_VALUE); // 3: Ccore解复位lgc,crg
        uapi_tcxo_delay_us(5);   // 5us delay
#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
        head_data = readl(0x10010000);
#endif
        writel(0x10010000, 0x0000006f); // 0x10000: Ccore复位后初始PC值; 0x0000006f: equal to asm("j .")

        writel(HAL_SOFT_RST_2_GLB_B, RESET_CCORE_VALUE); // Ccore解复位all(lgc,crg&cpu)
        uapi_tcxo_delay_us(1);
    }

    writel(MAN_ALL, 1); // 清C核的cache
    uint32_t reg_data = readl(MAN_ALL);
    while ((reg_data & (1 << MAN_ALL_DONE_OFFSET)) == 0) {
        reg_data = readl(MAN_ALL);
    }
    writel(HAL_SOFT_RST_2_GLB_B, 0); // Ccore复位all(lgc,crg&cpu)
    writel(HAL_SOFT_RST_2_GLB_B, RESET_CRG_CCORE_VALUE); // 3: Ccore解复位lgc,crg
#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
    uapi_tcxo_delay_us(5);   // 5us delay
    writel(0x10010000, head_data);
#else
    // 拷贝C核的booting code to Ccore's RAM from flash
    errno_t sec_ret = memcpy_s((void *)(CCORE_RAM_START_ADDR), CCORE_RAM_START_LENGTH,
                               (void *)(FALSH_CCORE_PROGRAM_ORIGIN + CCORE_ROM_LENGTH), CCORE_RAM_START_LENGTH);
    if (sec_ret != EOK) {
        PRINT("Memory process is error, sec_ret %d", sec_ret);
        return;
    }
#endif
    ccore_dyn_mem_cfg(); // 配置C核的动态内存配置
}

#define IPC_CH0_ID 0
#define IPC_CH1_ID 1
static void ipc_init(void)
{
    ipc_memory_manage_t config_rx[CORE_IPC_RX_PIPE_NUM] = IPC_MEMORY_INIT_RX_CONFIG;
    ipc_memory_manage_t config_tx[CORE_IPC_TX_PIPE_NUM] = IPC_MEMORY_INIT_TX_CONFIG;

    PRINT("ipc addr:0x%08x\r\n", get_ipc_share_mem_addr());

    writel(HAL_IPC_SOFT_RST_N, IPC_SOFT_RST_VALUE);
    config_rx[IPC_CH0_ID].start_addr = get_ipc_share_mem_addr();
    config_rx[IPC_CH0_ID].total_len =  IPC_BUFF_SHARE_CH0_RX_LEN;
    config_rx[IPC_CH1_ID].start_addr = config_rx[IPC_CH0_ID].start_addr + config_rx[IPC_CH0_ID].total_len;
    config_rx[IPC_CH1_ID].total_len =  IPC_BUFF_SHARE_CH1_RX_LEN;
    ipc_port_memory_init(config_rx, CORE_IPC_RX_PIPE_NUM, IPC_DIR_RX);

    config_tx[IPC_CH0_ID].start_addr = get_ipc_share_mem_addr() + IPC_BUFF_SHARE_CH0_RX_LEN + IPC_BUFF_SHARE_CH1_RX_LEN;
    config_tx[IPC_CH0_ID].total_len =  IPC_BUFF_SHARE_CH0_TX_LEN;
    config_tx[IPC_CH1_ID].start_addr = config_tx[IPC_CH0_ID].start_addr + config_tx[IPC_CH0_ID].total_len;
    config_tx[IPC_CH1_ID].total_len =  IPC_BUFF_SHARE_CH1_TX_LEN;
    ipc_port_memory_init(config_tx, CORE_IPC_TX_PIPE_NUM, IPC_DIR_TX);
    uapi_ipc_init();
}

// 外设工作时钟设置
#ifdef BOARD_FPGA
#define SYSTICK_CLOCK_32K  31902
#define RTC_CLOCK_32K      31902
#elif defined(BOARD_ASIC)
#define SYSTICK_CLOCK_32K  32768
#define RTC_CLOCK_32K      32768
#endif

#define FPGA_TCXO_CLOCK_30M     30
#define FPGA_AGPIO_CLK_CFG_REG_ADDR 0x57030024
#define FPGA_AGPIO_CLK_EN_BIT 0
#define FPGA_WATCHDOG_CLOCK_32K 31902

#define CLOCK_32M 32000000
#define FPGA_TCXO_CLOCK_32M     32
static void dev_work_clock_init(void)
{
    systick_porting_ticks_per_sec_set((uint64_t)SYSTICK_CLOCK_32K);
    rtc_porting_clock_value_update(RTC_CLOCK_32K);
#ifndef BOARD_ASIC
    watchdog_port_set_clock(FPGA_WATCHDOG_CLOCK_32K);
#endif
    timer_porting_clock_value_set(CLOCK_32M);
    uart_port_set_clock_value(0, CLOCK_32M);
    tcxo_porting_ticks_per_usec_set(FPGA_TCXO_CLOCK_32M);
    // AGPIO时钟初始化
    reg16_setbit(FPGA_AGPIO_CLK_CFG_REG_ADDR, FPGA_AGPIO_CLK_EN_BIT);
}

#ifdef BOARD_ASIC
/* 利用tcxo校准systick */
static uint64_t systick_count1;
static uint64_t tcxo_count1;
#include "soc_osal.h"

static void systick_cali_xclk_upper_half(void)
{
    uint32_t irq_sts = osal_irq_lock();
    systick_count1 = uapi_systick_get_count();
    tcxo_count1 = uapi_tcxo_get_us();
    osal_irq_restore(irq_sts);
}

void systick_cali_xclk_bottom_half(void)
{
    uint32_t cali_clock;
    uint64_t systick_count2;
    uint64_t tcxo_count2;

    uint32_t irq_sts = osal_irq_lock();
    systick_count2 = uapi_systick_get_count();
    tcxo_count2 = uapi_tcxo_get_us();
    osal_irq_restore(irq_sts);

    /*
     *   Increase of actual systic_count        Increase of us count
     *  (systick_count2 - systick_count1)    (tcxo_count2 - tcxo_count1)
     *  --------------------------------  =  ---------------------------
     *        g_systick_clock                      1000000us(1s)
     *
     *  1000000.0: 使用浮点计算中间结果
     */
    cali_clock = (uint32_t)(((systick_count2 - systick_count1) * 1000000.0) /
                            (tcxo_count2 - tcxo_count1));
    systick_porting_ticks_per_sec_set(cali_clock);
}


#endif

static void close_default_clock(void)
{
#ifdef BOARD_ASIC
#ifndef TEST_SUITE
    u_m_cken_0 m_cken_0;
    u_m_cken_1 m_cken_1;

    m_cken_0.u32 = readl(M_CTL_RB_M_CLKEN0);
    m_cken_0.bits.i2s_clken = 0;
    m_cken_0.bits.mtop_glue_trigger_clken = 0;
    m_cken_0.bits.pwm_clken = 0;
#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
    m_cken_0.bits.sdio_dev_clken = 0;
#endif
    writel(M_CTL_RB_M_CLKEN0, m_cken_0.u32);

    m_cken_1.u32 = readl(M_CTL_RB_M_CLKEN1);
#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
    m_cken_1.bits.sdio_ahb_clken = 0;
#endif
    m_cken_1.bits.lsadc_apb_clken = 0;
    m_cken_1.bits.i2c0_clken = 0;
    m_cken_1.bits.i2c1_clken = 0;
    m_cken_1.bits.spi3_ms_clken = 0;
    writel(M_CTL_RB_M_CLKEN1, m_cken_1.u32);

    writel(M_CTL_RB_PWM_M_DIV3, 0x0);
    writel(M_CTL_RB_COM_DLL2, 0);
    writel(M_CTL_RB_MCU_PERP_SPI_CR, 0);
    writel(M_CTL_RB_XIP_QSPI_CR, 0);
    writel(M_CTL_RB_LSADC_DEBUG_DIVER, 0);
    reg32_clrbit(M_CTL_RB_GLB_CLKEN, GLB_CLKEN_LASDC_OFFSET);
    reg32_clrbitmsk(M_CTL_RB_XIP_CLKEN0, ~(1 << XIP_CLKEN0_OFFSET));
#endif
#if defined(TEST_SUITE) || defined(_PRE_WLAN_FEATURE_MFG_TEST)
#define MICLDO_EN 0x5703022C
    reg32_setbit(MICLDO_EN, POS_0);
    uapi_tcxo_delay_us(60);             // 60 us
    reg32_setbit(MICLDO_EN, POS_1);
    uapi_tcxo_delay_us(2);             // 2 us
#endif
#endif
}


void pll_clk_efuse_cfg(void);

void ssb_uart_reset(void)
{
#define L0_TXD_PIN S_AGPIO1
#define L0_RXD_PIN S_AGPIO2
    uapi_pin_set_pull(L0_TXD_PIN, PIN_PULL_NONE);
    uapi_pin_set_pull(L0_RXD_PIN, PIN_PULL_NONE);
    uapi_pin_set_mode(L0_TXD_PIN, PIN_MODE_0);
    uapi_pin_set_mode(L0_RXD_PIN, PIN_MODE_0);
}

static void ccore_start_run(void)
{
    writel(HAL_SOFT_RST_2_GLB_B, RESET_CCORE_VALUE); // Ccore解复位all(lgc,crg&cpu)
}

static void hw_init(void)
{
    if (system_get_udsleep_flag()) {
        pm_port_save_udsleep_wakeup_src();
    }
    close_default_clock();
#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
    uapi_partition_init();
#endif
    panic_init();
    uapi_pin_init();
    uapi_gpio_init();
#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
    qpsi0_pin_config_pull_down();
#endif
    ssb_uart_reset();
#ifdef SW_UART_DEBUG
#ifdef CONFIG_DEBUG_UART_SUPPORT
    sw_debug_uart_init(DEBUG_UART_BAUD_RATE);
#endif
    PRINT("dbg init succ\r\n");
#endif
    uapi_systick_init();
    uapi_timer_init();
    uapi_timer_adapter(1, TIMER_1_IRQN, irq_prio(TIMER_1_IRQN));
    uapi_rtc_init();
    uapi_rtc_adapter(RTC_0, RTC_0_IRQN, irq_prio(RTC_0_IRQN));
    uapi_rtc_adapter(RTC_1, RTC_1_IRQN, irq_prio(RTC_1_IRQN));
    uapi_dma_init();
    uapi_dma_open();
    uapi_efuse_init();
    pll_clk_efuse_cfg();
    uapi_tsensor_init();
#if (ENABLE_LOW_POWER == YES)
    uapi_pm_lpc_init();
#endif
#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
    uapi_sfc_init((sfc_flash_config_t *)&g_sfc_cfg);
#endif
    watchdog_init();
    ccore_switch_pll_clock();
#ifdef CONFIG_MIDDLEWARE_SUPPORT_NV
    uapi_nv_init();
#endif
#if defined(SW_UART_DEBUG) && defined(CONFIG_DYNAMIC_UART_ID_BINDDING) && defined(CONFIG_DEBUG_UART_SUPPORT)
    sw_debug_uart_reinit(DEBUG_UART_BAUD_RATE);
#endif
    reboot_port_rst_reason_dump();
    copy_to_ccore();
    log_memory_region_init();
    ccore_start_run();
    ipc_init();
    ws53_upg_init();
    uapi_drv_cipher_env_init();
#ifdef CONFIG_MIDDLEWARE_SUPPORT_NV
#if (defined(CONFIG_NV_SUPPORT_ENCRYPT) && (defined(NV_YES)) && (CONFIG_NV_SUPPORT_ENCRYPT == NV_YES))
    uapi_drv_cipher_symc_init();
#endif
#endif
#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
    init_dev_addr();
#endif
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
    cmu_xo_trim_init();
#endif
}
#if defined(SUPPORT_DFX_LOG) && !defined(_PRE_FEATURE_WS53_DEVICE_MODE)
static void dfx_init(void)
{
    log_init();
    log_init_after_rtos();
#ifdef CONFIG_HSO_UART_SUPPORT
    log_uart_port_init();
#endif
    log_uart_init_after_rtos();
}
#endif

void main(const void *startup_details_table)
{
    UNUSED(startup_details_table);
    patch_init();
    dev_work_clock_init();
    uapi_tcxo_init();
    pmp_enable();
    cpu_cache_init();
    prepare_main_task();
    BoardConfig();
    osKernelInitialize();
    hw_init();
#if defined(MBEDTLS_HARDEN_OPEN) && !defined(_PRE_FEATURE_WS53_DEVICE_MODE)
    (void)mbedtls_adapt_register_func();
#endif
#ifdef AT_COMMAND
#ifdef CONFIG_AT_UART_SUPPORT
    at_uart_init(AT_UART_BAUD_RATE);
#endif
    at_base_api_register();
#ifdef CONFIG_SUPPORT_WIFI
    at_sys_cmd_register();
#endif
#ifdef CONFIG_AT_SUPPORT_PLT
    at_plt_cmd_register();
#endif
#ifdef BTH_TASK_EXIST
    at_bt_cmd_register();
#endif
#ifdef CONFIG_AT_SUPPORT_ZDIAG
    zdiag_at_init();
#endif
#endif
#if defined(SUPPORT_DFX_LOG) && !defined(_PRE_FEATURE_WS53_DEVICE_MODE)
    dfx_init();
#endif
    sec_trng2_updata_reigister();
    LOS_MsgChl_Init();
#if defined(HSO_SUPPORT) && !defined(_PRE_FEATURE_WS53_DEVICE_MODE)
    dfx_system_init();
    hal_register_exception_dump_callback(log_exception_dump);
    cpu_utils_init();
#endif
#ifdef CONFIG_SYSTEM_VIEW
    SEGGER_SYSVIEW_Conf();
#endif
    /* Enable MCPU trace */
#ifdef CONFIG_ACORE_CPU_TRACE
    mcpu_trace_init(PING_PANG_MODE);
#endif
    /* Set the initialisation routine to run immediately as soon as RTOS starts */
    /* Note the cast, as uint32_t and uint32_t are treated as different on some compilers. */
    PRINT("Init Os Task\n");
#ifdef CONFIG_MIDDLEWARE_SUPPORT_LFS
    fs_adapt_mount();
#endif
    systick_cali_xclk_upper_half();
    app_os_init(NULL, 0);

    /* Start LiteOS */
    (void)osKernelStart();
}

/* 在链接脚本中保证start_addr/load_addr/size是4字节对齐的 */
__attribute__((section(".text.runtime.init"))) void copy_bin_to_ram(unsigned int *start_addr,
    const unsigned int *load_addr, unsigned int size)
{
#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
    unused(start_addr);
    unused(load_addr);
    unused(size);
#else
    unsigned int i;

    for (i = 0; i < size / sizeof(unsigned int); i++) {
        *(start_addr + i) = *(load_addr + i);
    }
#endif
}

/* 在链接脚本中保证start_addr/end_addr是4字节对齐的 */
__attribute__((section(".text.runtime.init"))) void init_mem_value(unsigned int *start_addr,
    const unsigned int *end_addr, unsigned int init_val)
{
    unsigned int *dest = start_addr;

    while (dest < end_addr) {
        *dest = init_val;
        dest++;
    }
}

__attribute__((section(".text.runtime.init"))) void do_runtime_init(void)
{
    /* copy rom_data from flash to SRAM */
    copy_bin_to_ram(&__romdata_begin__, &__romdata_load__, (unsigned int)&__romdata_size__);
    /* clear rom_bss on SRAM */
    init_mem_value(&__rombss_begin__, &__rombss_end__, 0);

    /* copy rom_ram_cb from flash to SRAM */
    copy_bin_to_ram(&__rom_ram_cb_begin__, &__rom_ram_cb_load__, (unsigned int)&__rom_ram_cb_size__);

    /* copy patch remap table&cmp from flash to SRAM */
    copy_bin_to_ram(&__patch_begin__, &__patch_load__, (unsigned int)&__patch_size__);

    /* copy sram_text from flash to SRAM */
    copy_bin_to_ram(&__sramtext_begin__, &__sramtext_load__, (unsigned int)&__sramtext_size__);

    /* copy data from flash to SRAM */
    copy_bin_to_ram(&__sramdata_begin__, &__sramdata_load__, (unsigned int)&__sramdata_size__);
    copy_bin_to_ram(&__flashdata_begin__, &__flashdata_load__, (unsigned int)&__flashdata_size__);
    copy_bin_to_ram(&__data_begin__, &__data_load__, (unsigned int)&__data_size__);

    /* clear bss on SRAM */
    init_mem_value(&__bss_begin__, &__bss_end__, 0);
#ifdef WS53_APP_VERSION
    init_mem_value(&__itcm_bss_begin__, &__itcm_bss_end__, 0);
#endif
#ifdef CONFIG_MCU_MODE_3
    init_mem_value(&__em_ram_begin__, &__em_ram_end__, 0);
#endif

    return;
}
__attribute__((section(".text.runtime.init"))) void runtime_init(const void *startup_details_table)
{
    acore_dyn_mem_cfg();
#ifdef CONFIG_MCU_MODE_3
    ccore_dyn_mem_cfg();
    writel(HAL_SOFT_RST_2_GLB_B, RESET_CRG_CCORE_VALUE);
#endif
    do_runtime_init();

    /* Jump to main */
    main(startup_details_table);
}

