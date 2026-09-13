/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: SDIO SLAVE
 *
 * Create: 2021-07-1
 */

#ifndef SDIO_SLAVE_H
#define SDIO_SLAVE_H

#include "hal_sdio_slave.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup connectivity_drivers_cmsis_sdio_slave SDIO Slave
 * @ingroup  connectivity_drivers_cmsis
 * @{
 */
#define SDIO_SLAVE_INT_TRN_MAX      32

/**
 * @brief  sdio slave globle interrupt type
 */
typedef enum {
    SDIO_SLAVE_FTYPE_FUN0 = 0,
    SDIO_SLAVE_FTYPE_FUN1,
    SDIO_SLAVE_FTYPE_MEM,
    SDIO_SLAVE_FTYPE_MAX,
} sdio_slave_func_type_t;

/**
 * @brief  sdio slave fn0 interrupt transaction
 */
typedef enum {
    /* SDIO_INTRPT interrupt */
    AHBSOFT_RST_INT_TRN = 0,
    VOLT_SWITCH_CMD_INT_TRN,
    CMD19_RD_STRT_TRN,
    CMD19_RD_TRANS_OVER_TRN,
    FN0_WR_START_TRN,
    FN0_WR_TRN_OVER_TRN,
    FN0_RD_START_TRN,
    FN0_RD_TRN_OVER_TRN,
    FN0_RD_TRN_ERR_TRN,
    FN0_ADMA_END_INT_TRN,
    FN0_ADMA_INT_TRN,
    FN0_ADMA_ERR_TRN,
    FN0_RESERVED_TRN,
} sdio_slave_fn0_trn_t;

/**
 * @brief  sdio slave fn1 interrupt transaction
 */
typedef enum {
    /* AHB Interrupt Trn */
    FN1_WR_OVER_TRN = 0,
    FN1_RD_OVER_TRN,
    FN1_RD_ERROR_TRN,
    FN1_RST_TRN,
    SD_HOST_FN1_MSG_RDY_TRN,
    FN1_ACK_TO_ARM_TRN,
    FN1_SDIO_RD_START_TRN,
    FN1_SDIO_WR_START_TRN,
    FN1_ADMA_END_INT_TRN,
    FN1_SUSPEND_TRN,
    FN1_RESUME_TRN,
    FN1_ADMA_INT_TRN,
    FN1_ADMA_ERR_TRN,
    FN1_EN_INT_TRN,
    FN1_RESERVED_TRN,
} sdio_slave_fn1_trn_t;

/**
 * @brief  sdio slave mem interrupt transaction
 */
typedef enum {
    /* AHB MEM Interrupt */
    MEM_PWD_UPDATE_TRN,
    MEM_ERASE_TRN,
    MEM_PRE_ERASE_TRN,
    MEM_SD_RD_START_TRN,
    MEM_SD_WR_START_TRN,
    MEM_SD_WR_OVER_TRN,
    MEM_SD_RD_OVER_TRN,
    MEM_SEC_ERASE_PULSE_TRN,
    MEM_CHGE_SEC_WR_PULSE_TRN,
    MEM_ADMA_END_INT_TRN,
    MEM_UPDATE_CSD_TRN,
    MEM_CMD20_IN_TRN,
    MEM_ADMA_INT_TRN,
    MEM_ADMA_ERR_TRN,
    MEM_CMD6_SWTCH_TRN,
    MEM_XPC_AHB_TRN,
    MEM_RESERVED_TRN,
} sdio_slave_mem_trn_t;

typedef void (*sdio_slave_func)(void);

/**
 * @brief  sdio slave fn0/fn1/mem transaction callback func
 */
typedef struct {
    sdio_slave_func  fun0_funcs[SDIO_SLAVE_INT_TRN_MAX];
    sdio_slave_func  fun1_funcs[SDIO_SLAVE_INT_TRN_MAX];
    sdio_slave_func  mem_funcs[SDIO_SLAVE_INT_TRN_MAX];
} sdio_salve_callback_func_t;

/**
 * @brief  Sdio Slaver Func CallBack register
 * @param  type                Registering Function Types (0 fn0, 1 fn1, 2 mem)
 * @param  int_trn             Interrupt Subtransaction Type
 * @param  func                Functions to be registered
 * @return hal_sdio_ret_type_t
 */
int32_t sdio_slave_callback_register(sdio_slave_func_type_t type, uint32_t int_trn, sdio_slave_func func);
/**
 * @brief  Sdio Slaver Func CallBack register For FN0
 */
void sdio_slave_fn0_int_process(void);

/**
 * @brief  Sdio Slaver Func CallBack register For FN1
 */
void sdio_slave_fn1_int_process(void);

/**
 * @brief  Sdio Slaver Func CallBack register For MEM
 */
void sdio_slave_mem_int_process(void);

/**
 * @brief  Sdio Slaver init
 */
int32_t sdio_slave_init(void);

/**
 * @brief  Sdio Slaver Global interrupt handling function
 */
void sdio_slave_handler(void);

/**
 * @}
 */
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif