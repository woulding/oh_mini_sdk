/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: low power control interface
 * Author:
 * Create:
 */
#include "low_power_control.h"
#include "pmu.h"
#include "pmu_interrupt.h"
#include "hal_clocks_glb.h"
#include "hal_pmu_ldo.h"
#include "panic.h"
#include "securec.h"
#include "tcxo.h"
#include "pmu_cmu.h"
#include "pmu_pg.h"
#include "flash.h"
#include "hal_xip.h"
#include "non_os.h"
#include "clocks_core.h"
#if (GNSS_EXIST == YES)
#include "hal_pmu_peripheral_gnss.h"
#endif
#include "hal_pmu_peripheral_bt.h"
#include "pmu_ldo.h"

#ifdef SUPPORT_PARTITION_INFO
#include "partition.h"
#endif

#ifndef BUILD_APPLICATION_SSB
#if (DSP_EXIST == YES && !CHIP_BRANDY)
#include "hal_cpu_hifi.h"
#endif
#include "connectivity_log.h"
#ifdef MASTER_LOAD_SLAVE
#include "hal_cpu_core.h"
#include "cpu_load.h"
#endif
#endif
#ifdef BUILD_APPLICATION_STANDARD
#include "log_oam_logger.h"
#include "log_def.h"
#endif
#if (SECURITY_EXIST == YES)
#include "clocks_switch.h"
#endif
#if (BTH_WITH_SMART_WEAR == YES)
#include "gpio.h"
#include "pinctrl_porting.h"
#if (GNSS_EXIST == YES)
#include "epmu.h"
#endif

#define PRODUCT_AW_GT_MODE_ADDR        0x87004A10 // save AW&GT mode addr for wear
#define PRODUCT_AW_MODE_FLAG           0xAAAA4157 // save AW&GT mode value for wear
#define PRODUCT_BOARD_TYPE_ADDR        0x10FD2000 // save V3 or before V3 board type for wear
// save board type flag V3 and before V3(12100/12101/12102/12104/12105/12106), when before v3(12103)
#define PRODUCT_BOARD_TYPE_BEFORE_V3   12103 // not V3 board flag
// reuse sys cfg share mem log region, now used 32byte, reserve 8Byte for it
#define PRODUCT_BOARD_TYPE_ADDR_SHM    (SYSTEM_CFG_REGION_START + 40)
#endif

#define ULP_AON_DMLDO_EN_REG                    (ULP_AON_CTL_RB_ADDR + 0x40C)
#define ULP_AON_EN_DMLDO_BIT                    0
#define ULP_AON_EN_DMLDO_SW_BIT                 5

#define PMU_MAN_1_REG                           (PMU1_CTL_RB_BASE + 0xD8)
#define ULP_AON_BBLDO2_EN_REG                   (ULP_AON_CTL_RB_ADDR + 0x404)
#define ULP_AON_EN_BBLDO2_BIT                   0

#if (CHIP_ASIC && (EMBED_FLASH_EXIST == YES))
#define M3_LOAD_ADDR (BT_XIP_REMAP + 0x80000000)
#else
#define M3_LOAD_ADDR (BT_FLASH_REGION_START)
#endif

#define M3_SRAM_ORIGIN_APP_MAPPING  0xA6000000

#define GNSS_LOAD_ADDR (GNSS_FLASH_REGION_START)
#define GNSS_SRAM_ORIGIN_APP_MAPPING  0xA8000000

#if !CHIP_BS25
#define HIFI0_LOAD_ADDR (DSP_FLASH_REGION_START)
#if CHIP_LIBRA
#define HIFI1_LOAD_ADDR (GNSS_FLASH_REGION_START)
#else
#define HIFI1_LOAD_ADDR (DSP1_FLASH_REGION_START)
#endif
#endif
#define REG_CHECK_TIMEOUT   500

#define DELAY_TIME_30US     30
#define DSP_REGION_START    0x58000000
#define DSP_REGION_LEN      0x1000000
#define DMIC_EN_BYPASS_INTERVAL 30
#define SLAVE_RUN_DELAY     1ULL

#ifndef BUILD_APPLICATION_SSB
static bool low_power_xip_control(low_power_control_e type)
{
    UNUSED(type);
    return true;
}

static bool low_power_m3_load(void)
{
#ifdef MASTER_LOAD_SLAVE
    non_os_enter_critical();
    cpu_load_image((void *)((uintptr_t)(M3_LOAD_ADDR)), CORE_IMAGES_BT);
    hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_CPU, HAL_SOFT_RST_DERESET);
    uapi_tcxo_delay_ms(SLAVE_RUN_DELAY);
    non_os_exit_critical();
#else
    void* bt_load_addr = NULL;
    while (hal_xip_is_enable((xip_id_t)0) == false) {}
    non_os_enter_critical();
    flash_porting_set_bt_power_on_flag(false);

#ifdef SUPPORT_PARTITION_INFO
    errno_t err_code;
    partition_information_t info;

    err_code = uapi_partition_get_info(PARTITION_BT_IMAGE, &info);
    if (err_code != ERRCODE_SUCC) {
        oml_pf_log_print0(LOG_BCORE_PLT_INFO_SYS, LOG_NUM_LIB_LOG, LOG_LEVEL_ERROR, "get bt image info failed\n");
        return false;
    }
    bt_load_addr = (void *)((uintptr_t)(info.part_info.addr_info.addr + FLASH_START_ADDR + FLASH_SIGN_HEADER));
#else
    bt_load_addr = (void *)((uintptr_t)(M3_LOAD_ADDR));
#endif

    uint32_t sec_ret = (uint32_t)memcpy_s((void *)(M3_SRAM_ORIGIN_APP_MAPPING),
                                          BT_VECTORS_LENGTH,
                                          bt_load_addr,
                                          BT_VECTORS_LENGTH);
    non_os_exit_critical();
    if (sec_ret != 0) {
        panic(PANIC_LOW_POWER, __LINE__);
        return false; //lint !e527  unreachable code
    }
    hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_CPU, HAL_SOFT_RST_DERESET);
#endif
    set_slave_cpu_power_mode(SLAVE_CPU_BT, SLAVE_CPU_POWER_ON);
    return true;
}

#if defined(BS25_DEBUG_ENABLE) && (BS25_DEBUG_ENABLE == YES)
static void low_power_bt_power_up_and_run(void)
{
    // BT_SUB 复位
    writew(0x570000B8, 0);
    // b_soc power on
    writew(0x57004028, 0x101);
    uapi_tcxo_delay_us(30); // delay 30us
    while ((readw(0x57004028) & 0x10) == 0) {}
    writew(0x57004028, 0x11);

    // BMEM/B_DIAG_MEM power on
    writew(0x57004034, 0xF0F);
    uapi_tcxo_delay_us(30); // delay 30us
    while ((readw(0x57004034) & 0xF0) == 0) {}
    writew(0x57004034, 0xFF);

    writew(0x570000B8, 0x1);    // b crg
    writew(0x570000B8, 0x3);    // b lgc
    non_os_enter_critical();
    (void)memcpy_s((void *)(M3_SRAM_ORIGIN_APP_MAPPING), BT_VECTORS_LENGTH, \
                   (void *)((uintptr_t)(M3_LOAD_ADDR)), BT_VECTORS_LENGTH);
    non_os_exit_critical();
    writew(0x570000B8, 0x7);    // b cpu
}
#endif

static bool low_power_m3_power_control(low_power_control_e type)
{
    if (type == LOW_POWER_BT_POWER_UP_AND_RUN) {
#if defined(BS25_DEBUG_ENABLE) && (BS25_DEBUG_ENABLE == YES)
    low_power_bt_power_up_and_run();
    return true;
#endif
#if CHIP_ASIC
        low_power_m3_power_control_private(type);
        hal_pmu_baon_perip_config(HAL_PMU_BAON_PERIP_RTC, HAL_PMU_PERIP_REQUEST_EXIT_LOW_POWER);
        pmu_lpm_system_bypass_bt_status(TURN_OFF);
        pmu1_dig_pg_b_mem_power_on(TURN_ON); // BMEM/B_DIAg_MEM pwr on
#endif
        // Reset b sub
        hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_CRG, HAL_SOFT_RST_RESET);
        hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_LGC, HAL_SOFT_RST_RESET);
        hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_CPU, HAL_SOFT_RST_RESET);

#if CHIP_ASIC
        pmu1_dig_pg_b_soc_power_on(TURN_ON); // b_soc pwr on
#endif
#if (!CHIP_BS25)
        // BT adc depends on this power supply.
        hal_pmu_cmu_pd_cfg_control(XO2ANA_PD_AUDIO, TURN_OFF);
#endif
        // Disable XO2RF & XO2BT_ADC gating
        hal_pmu_cmu_clk_cfg_control(CLK_XO2RF_GT, TURN_OFF);
        hal_pmu_cmu_clk_cfg_control(CLK_XO2BT_ADC_GT, TURN_OFF);

        // dereset b sub, and run
        hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_CRG, HAL_SOFT_RST_DERESET);
        hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_LGC, HAL_SOFT_RST_DERESET);
#if CHIP_BS25_FPGA
        writel(0x59000814, 0x711);   // just for BS25 fpga version
#elif CHIP_BRANDY_FPGA
        writel(0x59000720, 0x10);
#endif
        return low_power_m3_load();
    } else if (type == LOW_POWER_BT_POWER_OFF) {
        hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_CRG, HAL_SOFT_RST_RESET);
        hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_LGC, HAL_SOFT_RST_RESET);
        hal_clocks_glb_bt_soft_reset_control(HAL_SOFT_RST2_B_CPU, HAL_SOFT_RST_RESET);
#if CHIP_ASIC
        pmu1_dig_pg_b_soc_power_on(TURN_OFF);
        pmu1_dig_pg_b_mem_power_on(TURN_OFF);
        hal_pmu_cmu_clk_cfg_control(CLK_XO2RF_GT, TURN_ON); // Enable XO2RF & XO2BT_ADC gating
        hal_pmu_cmu_clk_cfg_control(CLK_XO2BT_ADC_GT, TURN_ON);
        hal_pmu_baon_perip_config(HAL_PMU_BAON_PERIP_RTC, HAL_PMU_PERIP_REQUEST_RESET);
        pmu_lpm_system_bypass_bt_status(TURN_ON);
        low_power_m3_power_control_private(type);
#endif
        set_slave_cpu_power_mode(SLAVE_CPU_BT, SLAVE_CPU_POWER_OFF);
        return true;
    }

    return false;
}

#if DSP_EXIST == YES
static void low_power_dsp_mpu(void)
{
#if (BTH_WITH_SMART_WEAR == NO)
    mpu_config_t mpu_dsp_power_off_cfg = {
        DSP_REGION_START, DSP_REGION_LEN, MPU_FORBID_USER_FORBID, MPU_REGION_NBUFFER, MPU_REGION_NEXECUTE,
        MPU_REGION_TEX_000, MPU_REGION_NCACHE, MPU_REGION_SHARE, 0x0 };
    mpu_config_t mpu_dsp_power_on_cfg = {
        DSP_REGION_START, DSP_REGION_LEN, MPU_RW_USER_RW, MPU_REGION_NBUFFER, MPU_REGION_EXECUTE,
        MPU_REGION_TEX_001, MPU_REGION_NCACHE, MPU_REGION_SHARE, 0x0 };
    if ((get_dsp_power_up_status(SLAVE_CPU_DSP0) == false) && (get_dsp_power_up_status(SLAVE_CPU_DSP1) == false)) {
        mpu_disable();
        mpu_region_enable(MPU_REGION_10, mpu_dsp_power_off_cfg);
        mpu_enable(true, false);
    } else {
        mpu_disable();
        mpu_region_enable(MPU_REGION_10, mpu_dsp_power_on_cfg);
        mpu_enable(true, false);
    }
#endif
}

static void low_power_dsp_power_up_and_run(void)
{
    if (get_dsp_power_up_status(SLAVE_CPU_DSP0) == true) {
        return;
    }
#if CHIP_ASIC && !CHIP_SOCMN1
    // I2s enable
    clocks_system_i2s_clk_config(I2S_CLOCK_SOURCE_PLL);
#endif

    hal_clocks_glb_dsp_soft_reset_control(HAL_SOFT_RST_RESET);
    pmu1_dig_pg_audio_sub_power_on(TURN_ON); // audio sub power on

    low_power_dsp_power_control_private(LOW_POWER_DSP_POWER_UP_AND_RUN);

    hal_clocks_glb_dsp_soft_reset_control(HAL_SOFT_RST_DERESET);
    hal_pmu_codec_clock_reset_init();
    hal_pmu_codec_clock_enable(HAL_HIFI_CORE_0);
#if (BTH_WITH_SMART_WEAR == YES)
    hal_pmu_dsp1_mem_clock_enable();
#else
    hal_pmu_codec_clock_disable(HAL_HIFI_CORE_1);
#endif

    uapi_tcxo_delay_us(500ULL);
    set_dsp_power_up_status(SLAVE_CPU_DSP0, true);
    low_power_dsp_mpu();
#if (BTH_WITH_SMART_WEAR == YES)
    low_power_hifi_download(LOW_POWER_DSP_POWER_UP_AND_RUN);
#endif
}

#if DUAL_DSP_EXIST == YES
static void low_power_dsp1_power_on(void)
{
    if (get_dsp_power_up_status(SLAVE_CPU_DSP1) == true) {
        return;
    }
    hal_pmu_codec_clock_enable(HAL_HIFI_CORE_1);

    uapi_tcxo_delay_us(500ULL);
    set_dsp_power_up_status(SLAVE_CPU_DSP1, true);
    low_power_dsp_mpu();
#if (BTH_WITH_SMART_WEAR == YES)
    low_power_hifi_download(LOW_POWER_DSP1_POWER_UP_AND_RUN);
#endif
#ifdef BUILD_APPLICATION_STANDARD
    oml_pf_log_print0(LOG_BCORE_PLT_INFO_SYS, LOG_NUM_LIB_LOG, LOG_LEVEL_INFO, "DSP1 power on\n");
#endif
}
#endif

static bool low_power_dsp_power_control(low_power_control_e type)
{
    if (type == LOW_POWER_DSP_POWER_UP_AND_RUN) {
        low_power_dsp_power_up_and_run();
#ifdef BUILD_APPLICATION_STANDARD
        oml_pf_log_print0(LOG_BCORE_PLT_INFO_SYS, LOG_NUM_LIB_LOG, LOG_LEVEL_INFO, "DSP0 power on\n");
#endif
        return true;
    }
#if (DUAL_DSP_EXIST == YES)
    if (type == LOW_POWER_DSP1_POWER_UP_AND_RUN) {
        low_power_dsp1_power_on();
        return true;
    }
#endif
    if ((type == LOW_POWER_DSP_POWER_OFF) && (get_slave_cpu_power_mode(SLAVE_CPU_DSP0) == SLAVE_CPU_POWER_ON)) {
        hal_pmu_reset_and_disable_codec(HAL_HIFI_CORE_0);
        hal_pmu_codec_clock_reset_deinit();

        pmu1_dig_pg_audio_sub_power_on(TURN_OFF);
        low_power_dsp_power_control_private(LOW_POWER_DSP_POWER_OFF);
#if CHIP_ASIC
        clocks_system_i2s_clk_config(I2S_CLOCK_SOURCE_MAX); // I2s clk disable
#endif
        hal_clocks_glb_dsp_soft_reset_control(HAL_SOFT_RST_RESET);
        set_dsp_power_up_status(SLAVE_CPU_DSP0, false);
        set_slave_cpu_power_mode(SLAVE_CPU_DSP0, SLAVE_CPU_POWER_OFF);
        low_power_dsp_mpu();
#ifdef BUILD_APPLICATION_STANDARD
        oml_pf_log_print0(LOG_BCORE_PLT_INFO_SYS, LOG_NUM_LIB_LOG, LOG_LEVEL_INFO, "DSP0 power off\n");
#endif
        return true;
    }
#if (DUAL_DSP_EXIST == YES)
    if ((type == LOW_POWER_DSP1_POWER_OFF) && (get_slave_cpu_power_mode(SLAVE_CPU_DSP1) == SLAVE_CPU_POWER_ON)) {
        hal_pmu_reset_and_disable_codec(HAL_HIFI_CORE_1);
        set_dsp_power_up_status(SLAVE_CPU_DSP1, false);
        set_slave_cpu_power_mode(SLAVE_CPU_DSP1, SLAVE_CPU_POWER_OFF);
        low_power_dsp_mpu();
#ifdef BUILD_APPLICATION_STANDARD
        oml_pf_log_print0(LOG_BCORE_PLT_INFO_SYS, LOG_NUM_LIB_LOG, LOG_LEVEL_INFO, "DSP1 power off\n");
#endif
        return true;
    }
#endif
    return false;
}
#endif

#if (SECURITY_EXIST == YES)
static bool low_power_sec_power_control(low_power_control_e type)
{
    if (type == LOW_POWER_SEC_POWER_UP) {
        hal_clocks_glb_sec_soft_reset_control(HAL_SOFT_RST2_S_CPU, HAL_SOFT_RST_RESET);
        hal_clocks_glb_sec_soft_reset_control(HAL_SOFT_RST2_S_LGC, HAL_SOFT_RST_RESET);
        hal_clocks_glb_sec_soft_reset_control(HAL_SOFT_RST2_S_CRG, HAL_SOFT_RST_RESET);

        pmu1_dig_pg_sec_sub_power_on(TURN_ON);
        system_ccrg_clock_config(CLOCKS_CCRG_MODULE_SEC, CLOCKS_CLK_SRC_TCXO_2X, CLOCK_DIV_1);

        hal_clocks_glb_sec_soft_reset_control(HAL_SOFT_RST2_S_CRG, HAL_SOFT_RST_DERESET);
        hal_clocks_glb_sec_soft_reset_control(HAL_SOFT_RST2_S_LGC, HAL_SOFT_RST_DERESET);
        hal_clocks_glb_sec_soft_reset_control(HAL_SOFT_RST2_S_CPU, HAL_SOFT_RST_DERESET);
        set_slave_cpu_power_mode(SLAVE_CPU_SEC, SLAVE_CPU_POWER_ON);
        return true;
    } else if (type == LOW_POWER_SEC_POWER_OFF) { // close clk router, and keep cpu reset, just for low power.
        hal_clocks_glb_sec_soft_reset_control(HAL_SOFT_RST2_S_CPU, HAL_SOFT_RST_RESET);
        system_ccrg_clock_config(CLOCKS_CCRG_MODULE_SEC, CLOCKS_CLK_SRC_MAX, CLOCK_DIV_1);
        set_slave_cpu_power_mode(SLAVE_CPU_SEC, SLAVE_CPU_POWER_OFF);
        return true;
    }
    return false;
}
#endif

#if (GNSS_EXIST == YES)
static bool low_power_gnss_power_control(low_power_control_e type)
{
    if (type == LOW_POWER_GNSS_POWER_UP_AND_RUN) {
#if CHIP_ASIC
        pmu_ldo_pmu4_inldo4_xldo2_enable(TURN_ON);
        pmu_ldo_gnss_tcxo_enable(TURN_ON);
        pmu1_dig_pg_g_soc_power_on(TURN_ON);
        pmu_lpm_system_bypass_gnss_status(TURN_OFF);
        epmu_buck_ldo_vset_eco_cfg(EPMU_BUCK_LDO_BUS_BUCK1_SIMO0P8, EPMU_0P8_VSET_0V73);

        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_CPU, HAL_SOFT_RST_RESET);
        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_CRG, HAL_SOFT_RST_RESET);
        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_LGC, HAL_SOFT_RST_RESET);

        hal_clocks_glb_gcpu_wait_control((switch_type_t)true);

        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_CRG, HAL_SOFT_RST_DERESET);
        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_LGC, HAL_SOFT_RST_DERESET);
        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_CPU, HAL_SOFT_RST_DERESET);

        hal_pmu_gaon_perip_config(HAL_PMU_GCPU_PERIP_RTC, HAL_PMU_PERIP_REQUEST_DERESET);

#ifndef MASTER_LOAD_SLAVE
        non_os_enter_critical();
        uint32_t sec_ret = (uint32_t)memcpy_s((void *)(GNSS_SRAM_ORIGIN_APP_MAPPING),
                                              GNSS_VECTORS_LENGTH,
                                              (void *)((uintptr_t)(GNSS_LOAD_ADDR)),
                                              GNSS_VECTORS_LENGTH);
        if (sec_ret != 0) {
            panic(PANIC_LOW_POWER, __LINE__);
            return false; //lint !e527  unreachable code
        }
        non_os_exit_critical();
#else
        cpu_load_image((void *)((uintptr_t)(GNSS_LOAD_ADDR)), CORE_IMAGES_EXTERN0);
#endif
        low_power_gnss_chip_init_config_load();
        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_CTRL, HAL_SOFT_RST_DERESET);
        hal_clocks_glb_gcpu_wait_control((switch_type_t)false);
        uapi_tcxo_delay_ms(SLAVE_RUN_DELAY);
#else
        reg_writew(0x52000000, 0x57C, 0x5);    // gnss sub cr ctrl
        reg_writew(0x52000000, 0x580, 0x5);    // gnss cpu cr ctrl
        reg_writew(0x57000000, 0x4668, 0x1FF); // gnss sub dereset
        reg_writew(0x57000000, 0xFC, 0x3);     // gnss sub dereset
        reg_writew(0x57000000, 0x1F4, 0x0);    // gnss wait for jlink
        reg16_setbit(0x57000168, 0x4);           // enable gnss rtc clk
        non_os_enter_critical();
        uint32_t sec_ret = (uint32_t)memcpy_s((void *)(GNSS_SRAM_ORIGIN_APP_MAPPING),
                                              GNSS_VECTORS_LENGTH,
                                              (void *)((uintptr_t)(GNSS_LOAD_ADDR)),
                                              GNSS_VECTORS_LENGTH);
        non_os_exit_critical();
        reg_writew(0x57000000, 0xFC, 0x0);     // gnss sub reset
        reg_writew(0x57000000, 0x4668, 0x0);   // gnss sub reset
        reg_writew(0x57000000, 0x4668, 0x1FF); // gnss sub dereset
        reg_writew(0x57000000, 0xFC, 0x3);     // gnss sub dereset
        if (sec_ret) {
            panic(PANIC_LOW_POWER, __LINE__);
            return false; //lint !e527  unreachable code
        }
#endif
        set_slave_cpu_power_mode(SLAVE_CPU_GNSS, SLAVE_CPU_POWER_ON);
        return true;
    } else if (type == LOW_POWER_GNSS_POWER_OFF) {
        hal_pmu_gaon_perip_config(HAL_PMU_GCPU_PERIP_RTC, HAL_PMU_PERIP_REQUEST_RESET);
        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_CPU, HAL_SOFT_RST_RESET);
        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_LGC, HAL_SOFT_RST_RESET);
        hal_clocks_glb_gnss_soft_reset_control(HAL_SOFT_RST2_G_CRG, HAL_SOFT_RST_RESET);
        pmu1_dig_pg_g_soc_power_on(TURN_OFF);
        pmu_ldo_gnss_tcxo_enable(TURN_OFF);
        pmu_ldo_pmu4_inldo4_xldo2_enable(TURN_OFF);
        pmu_lpm_system_bypass_gnss_status(TURN_ON);
        epmu_buck_ldo_vset_eco_cfg(EPMU_BUCK_LDO_BUS_BUCK1_SIMO0P8, EPMU_0P8_VSET_0V55);
        pmu_wakeup_wait_time_init();
        return true;
    }
    return false;
}
#endif

bool low_power_control(low_power_control_e type)
{
    if (type <= LOW_POWER_XIP_DISABLE) {
        return low_power_xip_control(type);
    } else if (type <= LOW_POWER_BT_POWER_OFF) {
        return low_power_m3_power_control(type);
#if (DSP_EXIST == YES)
    } else if (type <= LOW_POWER_DSP_POWER_OFF) {
        non_os_enter_critical();
        bool dsp_power_status = low_power_dsp_power_control(type);
        non_os_exit_critical();
        return dsp_power_status;
#endif
#if (SECURITY_EXIST == YES) && (GNSS_EXIST == YES)
    } else if (type <= LOW_POWER_SEC_POWER_OFF) {
        return low_power_sec_power_control(type);
    } else if (type <= LOW_POWER_GNSS_POWER_OFF) {
        return low_power_gnss_power_control(type);
#endif
    }

    panic(PANIC_LPC, __LINE__);
    return false;  //lint !e527 Unreachable code
}

#if (SMART_WATCH_BT_COEX_PIN_SWITCH == YES)
product_mode_e get_aw_gt_mode(void)
{
    if (readl(PRODUCT_AW_GT_MODE_ADDR) == PRODUCT_AW_MODE_FLAG) {
        return PRODUCT_AW_MODE;
    } else {
        return PRODUCT_GT_MODE;
    }
}

void set_board_type(void)
{
    uint32_t board_type;
    board_type = readl(PRODUCT_BOARD_TYPE_ADDR);
    writel(PRODUCT_BOARD_TYPE_ADDR_SHM, board_type);
#ifdef BUILD_APPLICATION_STANDARD
    oml_pf_log_print1(LOG_BCORE_PLT_INFO_SYS, LOG_NUM_LIB_LOG, LOG_LEVEL_INFO, "Set board type:%d\n", board_type);
#endif
}

board_type_e get_board_type(void)
{
    if (readl(PRODUCT_BOARD_TYPE_ADDR_SHM) == PRODUCT_BOARD_TYPE_BEFORE_V3) {
        return BOARD_TYPE_BEFORE_V3;
    } else {
        return BOARD_TYPE_V3;
    }
}

static void low_power_pull_down_gpio(pin_t pin)
{
    gpio_select_core(pin, CORES_APPS_CORE);
    uapi_pin_set_mode(pin, HAL_PIO_FUNC_GPIO);
    uapi_gpio_set_dir(pin, GPIO_DIRECTION_INPUT);
    uapi_pin_set_pull(pin, HAL_PIO_PULL_DOWN);
}

void low_power_set_coex_gpio_power_on(void)
{
    uint32_t aw_gt_mode;
    uint32_t board_type;

    aw_gt_mode = get_aw_gt_mode();
    board_type = get_board_type();

    // coex pinmux, just when L_AGPIO4 MODE is 0, then can set as gpio
    gpio_select_core(L_AGPIO4, CORES_APPS_CORE);
    // just when S_MGPIO23 MODE is 0, then can set as gpio
    gpio_select_core(S_MGPIO23, CORES_APPS_CORE);

    if (((aw_gt_mode == PRODUCT_AW_MODE) && (board_type == BOARD_TYPE_V3)) ||
        ((aw_gt_mode == PRODUCT_GT_MODE) && (board_type == BOARD_TYPE_BEFORE_V3))) {
        uapi_pin_set_pull(L_AGPIO4, HAL_PIO_PULL_UP);
        uapi_pin_set_pull(S_MGPIO23, HAL_PIO_PULL_DOWN);
    } else if (((aw_gt_mode == PRODUCT_AW_MODE) && (board_type == BOARD_TYPE_BEFORE_V3)) ||
               ((aw_gt_mode == PRODUCT_GT_MODE) && (board_type == BOARD_TYPE_V3))) {
        uapi_pin_set_pull(L_AGPIO4, HAL_PIO_PULL_DOWN);
        uapi_pin_set_pull(S_MGPIO23, HAL_PIO_PULL_UP);
    }

    if (aw_gt_mode == PRODUCT_GT_MODE) {
        low_power_pull_down_gpio(L_AGPIO5); // BT_ACT
        low_power_pull_down_gpio(L_AGPIO6); // BT_FREQ
        low_power_pull_down_gpio(L_AGPIO7); // BT_PRIO
        low_power_pull_down_gpio(L_AGPIO8); // WLAN_ACT
    } else {
        uapi_pin_set_mode(L_AGPIO5, HAL_PIO_FUNC_BT_ACT);
        uapi_pin_set_mode(L_AGPIO6, HAL_PIO_FUNC_BT_FREQ);
        uapi_pin_set_mode(L_AGPIO7, HAL_PIO_FUNC_BT_PRIO);
        uapi_pin_set_mode(L_AGPIO8, HAL_PIO_FUNC_WLAN_ACT);
        uapi_pin_set_pull(L_AGPIO8, HAL_PIO_PULL_DOWN);
    }
    gpio_select_core(L_AGPIO4, CORES_BT_CORE);
    gpio_select_core(S_MGPIO23, CORES_BT_CORE);
    gpio_select_core(L_MGPIO30, CORES_BT_CORE);
    gpio_select_core(L_MGPIO31, CORES_BT_CORE);
}

static void low_power_set_coex_gpio_power_off(void)
{
    low_power_pull_down_gpio(L_AGPIO5); // BT_ACT
    low_power_pull_down_gpio(L_AGPIO6); // BT_FREQ
    low_power_pull_down_gpio(L_AGPIO7); // BT_PRIO
    low_power_pull_down_gpio(L_AGPIO8); // WLAN_ACT
    low_power_pull_down_gpio(L_MGPIO28); // UART_L1_TXD
    low_power_pull_down_gpio(L_MGPIO29); // UART_L1_RXD
    low_power_pull_down_gpio(L_MGPIO30); // GPIO3_19
    low_power_pull_down_gpio(L_MGPIO31); // GPIO3_20
}

bool low_power_control_coex(low_power_control_e type)
{
    if (type == LOW_POWER_BT_POWER_UP_AND_RUN) {
        low_power_set_coex_gpio_power_on();
        return low_power_m3_power_control(type);
    } else if (type == LOW_POWER_BT_POWER_OFF) {
        low_power_set_coex_gpio_power_off();
        return low_power_m3_power_control(type);
    }

    panic(PANIC_LPC, __LINE__);
    return false;  //lint !e527 Unreachable code
}
#endif

#if (!CHIP_BS25) && (CORE == MASTER_BY_ALL)
void low_power_dmic_config(switch_type_t enable)
{
    hal_ulp_dmldo_enable(enable);
    uapi_tcxo_delay_us((uint64_t)DMIC_EN_BYPASS_INTERVAL);
    hal_ulp_dmldo_enable_bypass(enable);
}

void low_power_ioldo_config(switch_type_t enable)
{
    hal_pmu_manual_config_control(IOLDO_EN, enable);
    hal_pmu_manual_config_control(IOLDO_EN_DELAY, enable);
    hal_pmu_manual_select_control(IOLDO_EN, TURN_ON);
    hal_pmu_manual_select_control(IOLDO_EN_DELAY, TURN_ON);
}

switch_type_t low_power_get_ioldo_config(hal_pmu_man_sel_t control_id)
{
    return (switch_type_t)reg16_getbit(PMU_MAN_1_REG, (uint16_t)control_id);
}

void low_power_load_switch_config(hal_load_switch_type_t load_switch, switch_type_t enable)
{
    hal_pmu_load_switch_power_control(load_switch, enable);
}

void low_power_mipi_config(switch_type_t enable)
{
    hal_pmu_mipildo_enable(enable);
}

void low_power_hifi_download(low_power_control_e type)
{
#if (DSP_EXIST == YES && !CHIP_BRANDY)
    non_os_enter_critical();
    if (type == LOW_POWER_DSP_POWER_UP_AND_RUN) {
        if (get_dsp_power_up_status(SLAVE_CPU_DSP0)) {
            set_slave_cpu_power_mode(SLAVE_CPU_DSP0, SLAVE_CPU_POWER_ON);
            hifi_download((void *)((uintptr_t)HIFI0_LOAD_ADDR), DRV_HIFI_0);
            // Run
            hal_pmu_reset_and_disable_codec(HAL_HIFI_CORE_1);
            hal_pmu_reset_and_enable_codec(HAL_HIFI_CORE_0);
        } else {
            panic(PANIC_LOW_POWER, __LINE__);
        }
    }
#if (DUAL_DSP_EXIST == YES)
    if (type == LOW_POWER_DSP1_POWER_UP_AND_RUN) {
        if (get_dsp_power_up_status(SLAVE_CPU_DSP1)) {
            set_slave_cpu_power_mode(SLAVE_CPU_DSP1, SLAVE_CPU_POWER_ON);
            hifi_download((void *)((uintptr_t)HIFI1_LOAD_ADDR), DRV_HIFI_1);
            // Run
            hal_pmu_reset_and_enable_codec(HAL_HIFI_CORE_1);
        } else {
            panic(PANIC_LOW_POWER, __LINE__);
        }
    }
#endif
    non_os_exit_critical();
#else
    UNUSED(type);
#endif
}
#endif
#endif
