/**
 * Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved. \n
 *
 * Description: Provides PM core fsm defines \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-05-05, Create file. \n
 */
#ifndef PM_CORE_DEFINES_H
#define PM_CORE_DEFINES_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup middleware_pm_core_defines PM Core defines
 * @ingroup  middleware_pm
 * @{
 */

typedef enum pm_fsm_service_id_enum {
    TEST_STUB_SERV_ID,
    PM_BTC_ID,
    PM_WLAN_ID,
    PM_PF_ID,
    PM_ID_NUM
}pm_fsm_service_id_enum_t;

typedef enum pm_sleep_evt_enum {
    BT_PSC_EN_SLP = 0x0,
    BCPU_SLEEPING_SLP,
    BCPU_SLEEPDEEP_SLP,

    PM_SLEEP_EVT_NUM
} pm_sleep_evt_enum_t;

typedef enum pm_wkup_evt_enum {
    M2B_IPC_INT_WKUP,
    B_GPIO_INT_WKUP,
    SSI_BCPU_WKUP,
    DAP_BCPU_WKUP,
    C_SDIO_WKUP,
    EXT2_TBTT_INTR_WKUP,
    EXT1_TBTT_INTR_WKUP,
    EXT0_TBTT_INTR_WKUP,
    B_RTC_INT_WKUP,
    EXT_P2P_NOA_INTR_WKUP,
    GPIO_INT_WKUP,
    UART_L0_RXD_WKUP,
    OSC_EN_WKUP,
    PM_WKUP_EVT_NUM,
} pm_wkup_evt_enum_t;

/* Registers */

#if defined(CONFIG_PM_DEBUG)
typedef enum pc_record_enum {
    BEF_CPU_SUS,
    AFT_CPU_SUS,
    BEF_WFI,
    AFT_WFI,
    AFT_WKUP_STS,
    AFT_WKUP_RET
} pc_record_enum_t;
#endif /* CONFIG_PM_DEBUG */


/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
