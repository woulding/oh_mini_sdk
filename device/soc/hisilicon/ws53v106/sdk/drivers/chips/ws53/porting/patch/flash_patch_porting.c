/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 *
 * Description: Provides flash_patch port template \n
 *
 * History: \n
 * 2023-07-26， Create file. \n
 */

#include "flash_patch_porting.h"

#define PATCH_REMAP_ENTRY_SIZE  2
#define PATCH_CMP_HEADER_SIZE   3

#define MAP_TBL __attribute__((section(".patch_remap")))
#define CMP_TBL __attribute__((section(".patch_cmp")))

static uint32_t MAP_TBL patch_remap[RISCV31_PATCH_NUM * PATCH_REMAP_ENTRY_SIZE] = { 0 };
static uint32_t CMP_TBL patch_cmp[RISCV31_PATCH_NUM + PATCH_CMP_HEADER_SIZE] = { 0 };

void patch_init(void)
{
    riscv_cfg_t patch_cfg;
    patch_cfg.cmp_start_addr = (uint32_t *)patch_cmp;
    patch_cfg.remap_addr = (uint32_t *)patch_remap;
    patch_cfg.off_region = true;
    riscv_patch_init(&patch_cfg);
}
