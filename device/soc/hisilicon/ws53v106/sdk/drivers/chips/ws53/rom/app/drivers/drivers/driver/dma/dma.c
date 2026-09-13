/**
 * Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved. \n
 *
 * Description: Provides dma driver source \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2022-10-16， Create file. \n
 */

#include "common_def.h"
#include "hal_dma.h"
#include "dma_porting.h"
#include "dma.h"

void dma_hal_funcs_set(hal_dma_funcs_t *funcs);

static bool g_dma_is_initialised = false;

void dma_reset_channel_interrupt(dma_channel_t channel);

errcode_t uapi_dma_init(void)
{
    if (g_dma_is_initialised) {
        return ERRCODE_SUCC;
    }

    dma_port_register_hal_funcs();
    hal_dma_funcs_t *tmp_hal_dma_funcs = hal_dma_get_funcs();
    if (tmp_hal_dma_funcs == NULL) {
        return ERRCODE_DMA_NOT_INIT;
    }
    errcode_t ret = tmp_hal_dma_funcs->init();
    if (ret != ERRCODE_SUCC) {
        return ret;
    }
    dma_hal_funcs_set(tmp_hal_dma_funcs);
    g_dma_is_initialised = true;

    return ret;
}

void uapi_dma_deinit(void)
{
    if (!g_dma_is_initialised) {
        return;
    }
    hal_dma_funcs_t *tmp_hal_dma_funcs = hal_dma_get_funcs();
    tmp_hal_dma_funcs->deinit();

    dma_port_unregister_hal_funcs();

    g_dma_is_initialised = false;
}

errcode_t uapi_dma_open(void)
{
    if (unlikely(!g_dma_is_initialised)) {
        return ERRCODE_DMA_NOT_INIT;
    }
    hal_dma_funcs_t *tmp_hal_dma_funcs = hal_dma_get_funcs();
    tmp_hal_dma_funcs->open();

    dma_port_register_irq();

    return ERRCODE_SUCC;
}

void uapi_dma_close(void)
{
    hal_dma_funcs_t *tmp_hal_dma_funcs = hal_dma_get_funcs();
    if (tmp_hal_dma_funcs != NULL) {
        tmp_hal_dma_funcs->close();
    }

    dma_port_unregister_irq();
}

static bool dma_peripheral_cfg_param_check(const dma_ch_user_peripheral_config_t *user_cfg)
{
    if (unlikely(user_cfg == NULL)) {
        return false;
    }

    if (unlikely(user_cfg->src_handshaking >= HAL_DMA_HANDSHAKING_MAX_NUM) ||
        unlikely(user_cfg->dest_handshaking >= HAL_DMA_HANDSHAKING_MAX_NUM)) {
        return false;
    }

    if (unlikely(user_cfg->trans_type > HAL_DMA_TRANS_PERIPHERAL_TO_PERIPHERAL_DST)) {
        return false;
    }

    if (unlikely(user_cfg->trans_dir > HAL_DMA_TRANSFER_DIR_PERIPHERAL_TO_PERIPHERAL)) {
        return false;
    }

    if (unlikely(user_cfg->priority > HAL_DMA_CH_PRIORITY_3)) {
        return false;
    }

    if (unlikely((user_cfg->src_width > HAL_DMA_TRANSFER_WIDTH_256) ||
                 (user_cfg->dest_width > HAL_DMA_TRANSFER_WIDTH_256))) {
        return false;
    }

    if (unlikely(user_cfg->burst_length > HAL_DMA_BURST_TRANSACTION_LENGTH_256)) {
        return false;
    }

    if (unlikely((user_cfg->src_increment >= HAL_DMA_ADDRESS_INC_TYPES) ||
                 (user_cfg->dest_increment >= HAL_DMA_ADDRESS_INC_TYPES))) {
        return false;
    }

    if (unlikely(user_cfg->protection > HAL_DMA_PROTECTION_CONTROL_ALL)) {
        return false;
    }

    return true;
}

static void dma_peripheral_transfer_param_configure(hal_dma_transfer_base_config_t *transfer_config,
                                                    hal_dma_transfer_peri_config_t *peripheral_config,
                                                    const dma_ch_user_peripheral_config_t *user_cfg)
{
    transfer_config->src = user_cfg->src;
    transfer_config->dest = user_cfg->dest;
    transfer_config->transfer_num = user_cfg->transfer_num;
    transfer_config->src_width = user_cfg->src_width;
    transfer_config->dest_width = user_cfg->dest_width;
    transfer_config->src_burst_trans_length = user_cfg->burst_length;
    transfer_config->dest_burst_trans_length = user_cfg->burst_length;
    transfer_config->priority = user_cfg->priority;
    transfer_config->src_inc = user_cfg->src_increment;
    transfer_config->dest_inc = user_cfg->dest_increment;

    peripheral_config->trans_type = user_cfg->trans_type;
    peripheral_config->hs_source = user_cfg->src_handshaking;
    peripheral_config->hs_dest = user_cfg->dest_handshaking;
    peripheral_config->protection = user_cfg->protection;
    peripheral_config->trans_dir = user_cfg->trans_dir;
}

errcode_t uapi_dma_configure_peripheral_transfer_single(const dma_ch_user_peripheral_config_t *user_cfg,
                                                        uint8_t *channel, dma_transfer_cb_t callback, uintptr_t arg)
{
    hal_dma_transfer_base_config_t transfer_config;
    hal_dma_transfer_peri_config_t peripheral_config;
    hal_dma_funcs_t *tmp_hal_dma_funcs = hal_dma_get_funcs();
    if (unlikely(!g_dma_is_initialised)) {
        return ERRCODE_DMA_NOT_INIT;
    }

    if (!dma_peripheral_cfg_param_check(user_cfg)) {
        return ERRCODE_DMA_INVALID_PARAMETER;
    }
    if (user_cfg->trans_dir == HAL_DMA_TRANSFER_DIR_MEM_TO_PERIPHERAL) {
        *channel = tmp_hal_dma_funcs->get_idle(user_cfg->dest_handshaking, user_cfg->burst_length);
    } else {
        *channel = tmp_hal_dma_funcs->get_idle(user_cfg->src_handshaking, user_cfg->burst_length);
    }

    if (*channel == DMA_CHANNEL_NONE) { return ERRCODE_DMA_RET_NO_AVAIL_CH; }

    dma_reset_channel_interrupt(*channel);
    transfer_config.callback = callback;
    transfer_config.priv_arg = arg;
    dma_peripheral_transfer_param_configure(&transfer_config, &peripheral_config, user_cfg);

    return tmp_hal_dma_funcs->cfg_single(*channel, &transfer_config, &peripheral_config);
}

#if defined(CONFIG_DMA_SUPPORT_LLI)
errcode_t uapi_dma_configure_peripheral_transfer_lli(uint8_t channel, const dma_ch_user_peripheral_config_t *user_cfg,
                                                     dma_transfer_cb_t callback)
{
    hal_dma_funcs_t *tmp_hal_dma_funcs = hal_dma_get_funcs();
    if (unlikely(channel >= DMA_CHANNEL_MAX_NUM)) {
        return ERRCODE_DMA_INVALID_PARAMETER;
    }
    if (unlikely(!g_dma_is_initialised)) {
        return ERRCODE_DMA_NOT_INIT;
    }
    hal_dma_transfer_base_config_t transfer_config;
    hal_dma_transfer_peri_config_t peripheral_config;

    if (!dma_peripheral_cfg_param_check(user_cfg)) {
        return ERRCODE_DMA_INVALID_PARAMETER;
    }

    transfer_config.callback = callback;

    dma_peripheral_transfer_param_configure(&transfer_config, &peripheral_config, user_cfg);

    return tmp_hal_dma_funcs->add_lli(channel, &transfer_config, &peripheral_config);
}
#endif /* CONFIG_DMA_SUPPORT_LLI */

#ifdef CONFIG_DMA_SUPPORT_LPM
errcode_t uapi_dma_suspend(uintptr_t arg)
{
    unused(arg);
    return ERRCODE_SUCC;
}

errcode_t uapi_dma_resume(uintptr_t arg)
{
    if (unlikely(!g_dma_is_initialised)) {
        return ERRCODE_DMA_NOT_INIT;
    }

    hal_dma_funcs_t *tmp_hal_dma_funcs = hal_dma_get_funcs();
    unused(arg);
    tmp_hal_dma_funcs->close();
    tmp_hal_dma_funcs->open();
    return ERRCODE_SUCC;
}
#endif
