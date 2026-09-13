/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description:  RISCV31 PATCH.
 *
 * Create:  2023-06-02
 */
#ifndef RISCV31_PATCH_H
#define RISCV31_PATCH_H

#include "chip_io.h"
#include "arch_barrier.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef struct {
    uint32_t *cmp_start_addr;
    uint32_t *remap_addr;
    bool off_region;   /*!< The jump range, false for within 1MB, true for out of the 1M range. */
    uint8_t flplacmp0_en;
    uint8_t flplacmp1_en;
} riscv_cfg_t;

/**
 * @brief  Ctrl寄存器 +  Remap寄存器 + CMP数量.
 */
typedef struct {
    uint32_t ctrl_reg;
    uint32_t remap_run_addr;
    uint32_t patch_used_num;
} cmp_header_t;

/**
 * @brief  Initialises the riscv falsh_patch.
 */
void riscv_patch_init(riscv_cfg_t *patch_cfg);

#ifdef __cplusplus
#if __cplusplus
    }
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
