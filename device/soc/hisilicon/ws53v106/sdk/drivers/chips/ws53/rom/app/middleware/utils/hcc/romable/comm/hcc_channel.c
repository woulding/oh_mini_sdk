/*
 * Copyright (c) CompanyNameMagicTag 2021-2023. All rights reserved.
 * Description: hcc channel.
 * Author: CompanyName
 * Create: 2021-09-11
 */

#include "hcc_channel.h"
#include "hcc_bus.h"
#include "hcc_if.h"
#include "osal_def.h"
#include "common_def.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_HCC_COMM_HCC_CHANNEL_C

#undef THIS_MOD_ID
#define THIS_MOD_ID LOG_PFMODULE
#ifndef CONFIG_HCC_SUPPORT_MULTI_CHANNEL
td_s32 hcc_add_handler(hcc_handler *hcc)
{
    if (hcc_channel_list_head_get()->handler != TD_NULL) {
        return EXT_ERR_HCC_HANDLER_REPEAT;
    }
    hcc_channel_list_head_get()->handler = hcc;
    return EXT_ERR_SUCCESS;
}

td_void hcc_delete_handler(td_u8 chl)
{
    uapi_unused(chl);
    osal_kfree(hcc_channel_list_head_get()->handler);
    hcc_channel_list_head_get()->handler = TD_NULL;
}

#else
td_s32 hcc_add_handler(hcc_handler *hcc)
{
    hcc_handler_list *new = TD_NULL;
    if (hcc_get_handler(hcc->channel_id) != TD_NULL) {
        return EXT_ERR_HCC_HANDLER_REPEAT;
    }

    new = (hcc_handler_list *)osal_kmalloc(sizeof(hcc_handler_list), OSAL_GFP_KERNEL);
    if (new == TD_NULL) {
        return EXT_ERR_MALLOC_FAILUE;
    }

    new->handler_list.next = new->handler_list.prev = &new->handler_list;
    new->handler = hcc;
    osal_list_add_tail(&new->handler_list, &(hcc_channel_list_head_get()->handler_list));
    return EXT_ERR_SUCCESS;
}

td_void hcc_delete_handler(td_u8 chl)
{
    hcc_handler_list *handler_list =
        (hcc_handler_list *)hcc_traverse_handler_list(chl, hcc_traverse_func_get_handler_list);
    if (handler_list == TD_NULL) {
        return;
    }
    osal_list_del(&handler_list->handler_list);
    osal_kfree(handler_list->handler);
    handler_list->handler = TD_NULL;
    osal_kfree(handler_list);
}
#endif

td_bool hcc_chan_is_busy(td_u8 chl)
{
    hcc_handler *hcc = hcc_get_handler(chl);
    if (hcc == TD_NULL) {
        return TD_FALSE;
    }

    if (hcc_bus_is_busy(hcc->bus, HCC_DIR_TX) || hcc_bus_is_busy(hcc->bus, HCC_DIR_RX)) {
        return TD_TRUE;
    }

    return TD_FALSE;
}

osal_module_export(hcc_chan_is_busy);
osal_module_export(hcc_get_state);
osal_module_export(hcc_get_handler);
