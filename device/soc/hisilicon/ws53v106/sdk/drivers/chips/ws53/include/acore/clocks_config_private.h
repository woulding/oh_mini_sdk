/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:  CLOCKS CONFIG PRIVATE HEADER.
 *
 * Create: 202-04-13
 */
#ifndef CLOCKS_CONFIG_PRIVATE_H
#define CLOCKS_CONFIG_PRIVATE_H

#if !defined(BUILD_APPLICATION_FSB) && !defined(BUILD_APPLICATION_ROM)
#include "clocks_types.h"

/**
 * @addtogroup connectivity_drivers_non_os_clocks
 * @{
 */

// ULPFLL_MCU_CORE config: 128M
#define ULPFLL_MCU_CORE_FCW                 0xFA0
#define ULPFLL_MCU_CORE_POSTDIV             0
#define ULPFLL_MCU_CORE_KDCO_CTRL           0

// ULPFLL_MCU_LS config: 128M
#define ULPFLL_MCU_LS_FCW                   0xFA0
#define ULPFLL_MCU_LS_POSTDIV               0
#define ULPFLL_MCU_LS_KDCO_CTRL             0

// FNPLL_AUDIO config: 49.152M
#define FNPLL_AUDIO_FBDIV_NUM               0xF
#define FNPLL_AUDIO_FRAC_H_NUM              0x5C
#define FNPLL_AUDIO_FRAC_L_NUM              0x28f6
#define FNPLL_AUDIO_POSTDIV1_NUM            0x5
#define FNPLL_AUDIO_POSTDIV2_NUM            0x2

// FNPLL_MCU_HS config: 580M.
#define FNPLL_MCU_HS_FBDIV_NUM              0x12
#define FNPLL_MCU_HS_FRAC_H_NUM             0x20
#define FNPLL_MCU_HS_FRAC_L_NUM             0x0
#define FNPLL_MCU_HS_POSTDIV1_NUM           0x1
#define FNPLL_MCU_HS_POSTDIV2_NUM           0x1

static const cmu_fll_config_t g_ulpfll_mcu_core_cfg = {
    ULPFLL_MCU_CORE_FCW,
    ULPFLL_MCU_CORE_POSTDIV,
    ULPFLL_MCU_CORE_KDCO_CTRL
};

static const cmu_fll_config_t g_ulpfll_mcu_ls_cfg = {
    ULPFLL_MCU_LS_FCW,
    ULPFLL_MCU_LS_POSTDIV,
    ULPFLL_MCU_LS_KDCO_CTRL
};

static const cmu_pll_config_t g_fnpll_mcu_hs_cfg = {
    FNPLL_MCU_HS_FBDIV_NUM,
    FNPLL_MCU_HS_FRAC_H_NUM,
    FNPLL_MCU_HS_FRAC_L_NUM,
    FNPLL_MCU_HS_POSTDIV1_NUM,
    FNPLL_MCU_HS_POSTDIV2_NUM
};

static const cmu_pll_config_t g_fnpll_audio_cfg = {
    FNPLL_AUDIO_FBDIV_NUM,
    FNPLL_AUDIO_FRAC_H_NUM,
    FNPLL_AUDIO_FRAC_L_NUM,
    FNPLL_AUDIO_POSTDIV1_NUM,
    FNPLL_AUDIO_POSTDIV2_NUM
};

/**
 * @brief  Get the system clocks configuration for the specified clock level.
 * @param  clk_level The clock level.
 * @return The system clocks configuration.
 */
const clocks_clk_cfg_t *clocks_system_all_clocks_get(system_clocks_config_t clk_level);

/**
 * @}
 */
#endif

#endif