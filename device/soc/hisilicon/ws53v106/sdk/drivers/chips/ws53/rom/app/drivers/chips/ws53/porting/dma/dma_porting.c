/**
 * Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved. \n
 *
 * Description: Provides dma port \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2022-10-16， Create file. \n
 */

#include "common_def.h"
#include "interrupt/osal_interrupt.h"
#include "chip_core_irq.h"
#include "platform_core.h"
#include "hal_dmac_v151.h"
#include "pm_veto.h"
#include "pm_veto_porting.h"
#include "dma_porting.h"

uintptr_t g_dma_base_addr = (uintptr_t)DMA_BASE_ADDR;
void irq_dma_handler(void);

uintptr_t dma_porting_base_addr_get(void)
{
    return g_dma_base_addr;
}

void dma_port_register_hal_funcs(void)
{
    hal_dma_register_funcs(hal_dmac_v151_funcs_get());
}

void dma_port_unregister_hal_funcs(void)
{
    hal_dma_unregister_funcs();
}

void dma_port_register_irq(void)
{
    osal_irq_request(M_DMA_IRQN, (osal_irq_handler)irq_dma_handler, NULL, NULL, NULL);
    osal_irq_enable(M_DMA_IRQN);
}

void dma_port_unregister_irq(void)
{
    osal_irq_disable(M_DMA_IRQN);
    osal_irq_free(M_DMA_IRQN, NULL);
}

static hal_dma_mux_handshaking_status_t dma_port_get_handshaking_channel_status(hal_dma_handshaking_source_t channel)
{
    unused(channel);
    return HAL_DMA_MUX_HANDSHAKING_IDLE;
}

void dma_port_set_handshaking_channel_status(hal_dma_handshaking_source_t channel, bool on)
{
    unused(channel);
    unused(on);
}

static void dma_port_switch_hardware_channel(hal_dma_handshaking_source_t channel)
{
    unused(channel);
}

static hal_dma_handshaking_source_t dma_port_set_mux_get_real_ch(hal_dma_handshaking_source_t ch)
{
    return ch;
}

errcode_t dma_port_set_mux_channel(dma_channel_t ch, hal_dma_transfer_peri_config_t *per_cfg)
{
    unused(ch);
    if ((dma_port_get_handshaking_channel_status(per_cfg->hs_source) == HAL_DMA_MUX_HANDSHAKING_USING) &&
        (dma_port_get_handshaking_channel_status(per_cfg->hs_dest) == HAL_DMA_MUX_HANDSHAKING_USING)) {
        return ERRCODE_DMA_RET_HANDSHAKING_USING;
    }
    dma_port_switch_hardware_channel(per_cfg->hs_source);
    dma_port_switch_hardware_channel(per_cfg->hs_dest);

    per_cfg->hs_source = dma_port_set_mux_get_real_ch(per_cfg->hs_source);
    per_cfg->hs_dest = dma_port_set_mux_get_real_ch(per_cfg->hs_dest);

    dma_port_set_handshaking_channel_status(per_cfg->hs_source, true);
    dma_port_set_handshaking_channel_status(per_cfg->hs_dest, true);

    return ERRCODE_SUCC;
}

PLAT_TCM_TEXT void dma_port_add_sleep_veto(void)
{
    uapi_pm_add_sleep_veto(PM_DMA_VETO_ID);
}

PLAT_TCM_TEXT void dma_port_remove_sleep_veto(void)
{
    uapi_pm_remove_sleep_veto(PM_DMA_VETO_ID);
}

PLAT_TCM_TEXT uint32_t dma_porting_lock(void)
{
    uint32_t irq_sts = osal_irq_lock();
    return irq_sts;
}

PLAT_TCM_TEXT void dma_porting_unlock(uint32_t irq_sts)
{
    osal_irq_restore(irq_sts);
}