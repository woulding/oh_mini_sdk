/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides sfc port template \n
 *
 * History: \n
 * 2022-11-30， Create file. \n
 */

#ifdef BUILD_NOOSAL
#include "hal_sfc_v150.h"
#include "debug_print.h"
#include "hal_sfc_v150_regs_op.h"
#include "tcxo.h"
#include "sfc.h"
#include "sfc_porting.h"
#include "sfc_protect.h"
#include "sfc_protect_gd25le32e.h"

#include "boot_serial.h"

#define SR_READ_RETRY_TIMES (3)

static inline bool is_sr1_valid(uint8_t sr1)
{
    return ((sr1 & SR1_VALID_MASK) == SR1_VALID_VAL);
}

static inline bool is_sr2_valid(uint8_t sr2)
{
    return ((sr2 & SR2_VALID_MASK) == SR2_VALID_VAL);
}

static void sfc_port_delay_us(void)
{
#define DELAY_US_MAX 100
    uapi_tcxo_delay_us((uapi_tcxo_get_count() % DELAY_US_MAX) + 1);
}

static bool sfc_port_is_sr_valid(uint8_t rd_cmd)
{
    bool valid;
    uint8_t sr = (uint8_t)sfc_port_read_sr(rd_cmd);

    if (rd_cmd == SPI_CMD_RDSR_1) {
        valid = is_sr1_valid(sr);
        if (!valid) {
            boot_msg1("SR1 needs fixing:", sr);
        }
    } else {
        valid = is_sr2_valid(sr);
        if (!valid) {
            boot_msg1("SR2 needs fixing:", sr);
        }
    }
    return valid;
}

static errcode_t sfc_port_gd25le32e_read_sr(uint8_t rd_cmd)
{
    uint32_t i;
    bool valid;

    for (i = 0; i < SR_READ_RETRY_TIMES; i++) {
        valid = sfc_port_is_sr_valid(rd_cmd);
        sfc_port_delay_us();
        if (!valid) {
            return ERRCODE_FAIL;
        }
    }
    return ERRCODE_SUCC;
}

errcode_t sfc_port_fix_sr_gd25le32e(void)
{
    errcode_t err1;
    errcode_t err2;
    uint32_t i;
#define SR_FIX_DELAY_MS  60
    for (i = 0; i < SR_READ_RETRY_TIMES; i++) {
        err1 = sfc_port_gd25le32e_read_sr(SPI_CMD_RDSR_1);
        err2 = sfc_port_gd25le32e_read_sr(SPI_CMD_RDSR_2);
        if ((err1 == ERRCODE_SUCC) && (err2 == ERRCODE_SUCC)) {
            if (i == 0) {
                boot_msg0("No need to fix SR!");
            } else {
                boot_msg0("SR fix ok!");
            }
            return ERRCODE_SUCC;
        }
        sfc_port_write_sr(false, SR1_VALID_VAL, SR2_VALID_VAL);
        uapi_tcxo_delay_ms(SR_FIX_DELAY_MS);
    }
    return ERRCODE_FAIL;
}
#endif