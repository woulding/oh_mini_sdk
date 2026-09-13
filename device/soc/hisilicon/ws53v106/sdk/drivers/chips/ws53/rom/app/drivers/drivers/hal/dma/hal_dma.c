/**
 * Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved. \n
 *
 * Description: Provides hal dma \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2022-10-16， Create file. \n
 */

#include "hal_dma.h"

#if defined(CONFIG_DMA_SUPPORT_SMDMA)
uintptr_t g_sdma_regs = NULL;
#endif /* CONFIG_DMA_SUPPORT_SMDMA */
void set_dma_regs_addr(uintptr_t addr);
static hal_dma_funcs_t *g_hal_dma_funcs = NULL;

#if defined(CONFIG_DMA_SUPPORT_SMDMA)
static uintptr_t sdma_base_addr_get(void)
{
    return g_sdma_base_addr;
}
#endif

errcode_t hal_dma_register_funcs(hal_dma_funcs_t *funcs)
{
    if (funcs == NULL) {
        return ERRCODE_INVALID_PARAM;
    }

    g_hal_dma_funcs = funcs;

    return ERRCODE_SUCC;
}

void hal_dma_unregister_funcs(void)
{
    g_hal_dma_funcs = NULL;
}

hal_dma_funcs_t *hal_dma_get_funcs(void)
{
    return g_hal_dma_funcs;
}

errcode_t hal_dma_regs_init(void)
{
    uintptr_t dma_regs = 0;
    if (dma_porting_base_addr_get() == 0) {
        return ERRCODE_DMA_REG_ADDR_INVALID;
    }
    dma_regs = dma_porting_base_addr_get();
    set_dma_regs_addr(dma_regs);
#if defined(CONFIG_DMA_SUPPORT_SMDMA)
    if (sdma_base_addr_get() == 0) {
        return ERRCODE_DMA_REG_ADDR_INVALID;
    }
    g_sdma_regs = sdma_base_addr_get();
#endif /* CONFIG_DMA_SUPPORT_SMDMA */

    return ERRCODE_SUCC;
}

void hal_dma_regs_deinit(void)
{
    set_dma_regs_addr((uintptr_t)NULL);
#if defined(CONFIG_DMA_SUPPORT_SMDMA)
    g_sdma_regs = NULL;
#endif /* CONFIG_DMA_SUPPORT_SMDMA */
}