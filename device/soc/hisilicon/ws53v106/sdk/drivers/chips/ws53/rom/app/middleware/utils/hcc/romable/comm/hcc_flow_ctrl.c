/*
 * Copyright (c) CompanyNameMagicTag 2021-2023. All rights reserved.
 * Description: hcc flow ctrl module completion.
 * Author: CompanyName
 * Create: 2021-06-30
 */

#include "hcc_flow_ctrl.h"
#include "soc_osal.h"
#include "osal_def.h"
#include "common_def.h"

#include "hcc_comm.h"
#include "hcc_service.h"
#include "hcc_list.h"
#include "hcc.h"
#include "hcc_adapt.h"
#include "hcc_bus.h"
#include "hcc_dfx.h"
#include "hcc_channel.h"
#include "hcc_if.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_HCC_COMM_HCC_FLOW_CTRL_C

#undef THIS_MOD_ID
#define THIS_MOD_ID LOG_PFMODULE

#define HCC_FLOWCTRL_DEFAULT_CREDIT_VALUE 20

#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL_ACTIVE
td_void fc_msg_init(td_u8 chl)
{
    hcc_message_register(chl, 0, FC_MSG_FLOWCTRL_ON, hcc_flowctrl_on_proc, (td_u8 *)hcc_get_handler(chl));
    hcc_message_register(chl, 0, FC_MSG_FLOWCTRL_OFF, hcc_flowctrl_off_proc, (td_u8 *)hcc_get_handler(chl));
    hcc_message_register(chl, 0, FC_MSG_FLOWCTRL_CHECK, hcc_flowctrl_check_proc, (td_u8 *)hcc_get_handler(chl));
}

td_u32 hcc_flowctrl_on_proc(td_u8 *data)
{
    hcc_handler *hcc = (hcc_handler *)data;
    td_u32 dir;
    td_u8 q_id;
    hcc_trans_queue *hcc_queue;
    unsigned long flags;
    hcc_printf("rx msg flow on\r\n");
    for (dir = 0; dir < HCC_DIR_COUNT; dir++) {
        for (q_id = 0; q_id < hcc->que_max_cnt; q_id++) {
            hcc_queue = &hcc->hcc_resource.hcc_queues[dir][q_id];
            if (hcc_queue->queue_ctrl->flow_type != HCC_FLOWCTRL_DATA ||
                (hcc_queue->queue_ctrl->fc_enable == 0)) {
                continue;
            }
            if (hcc_queue->fc_para.fc_back_para.flow_ctrl_open == 0) {
                osal_spin_lock_irqsave(&hcc_queue->queue_info.data_queue_lock, &flags);
                hcc_queue->fc_para.fc_back_para.flow_ctrl_open = TD_TRUE;
                hcc_queue->fc_para.fc_back_para.fc_off_cnt++;
                osal_spin_unlock_irqrestore(&hcc_queue->queue_info.data_queue_lock, &flags);
                hcc_printf("flowctrl_flag on -> off, can't send\r\n");
            }
        }
    }
    return EXT_ERR_SUCCESS;
}

td_u32 hcc_flowctrl_off_proc(td_u8 *data)
{
    hcc_handler *hcc = (hcc_handler *)data;
    td_u32 dir;
    td_u8 q_id;
    hcc_trans_queue *hcc_queue;
    unsigned long flags;
    hcc_printf("rx msg flow off\r\n");
    for (dir = 0; dir < HCC_DIR_COUNT; dir++) {
        for (q_id = 0; q_id < hcc->que_max_cnt; q_id++) {
            hcc_queue = &hcc->hcc_resource.hcc_queues[dir][q_id];
            if (hcc_queue->queue_ctrl->flow_type != HCC_FLOWCTRL_DATA ||
                (hcc_queue->queue_ctrl->fc_enable == 0)) {
                continue;
            }
            if (hcc_queue->fc_para.fc_back_para.flow_ctrl_open != 0) {
                osal_spin_lock_irqsave(&hcc_queue->queue_info.data_queue_lock, &flags);
                hcc_queue->fc_para.fc_back_para.flow_ctrl_open = TD_FALSE;
                hcc_queue->fc_para.fc_back_para.fc_on_cnt++;
                osal_spin_unlock_irqrestore(&hcc_queue->queue_info.data_queue_lock, &flags);
                hcc_printf("flowctrl_flag off -> on, start send\r\n");
                hcc_sched_transfer(hcc);
            }
        }
    }
    return EXT_ERR_SUCCESS;
}

td_u32 hcc_flowctrl_check_proc(td_u8 *data)
{
    hcc_handler *hcc = (hcc_handler *)data;
    if (hcc->bus->bus_ops->flow_off != TD_NULL) {
        hcc->bus->bus_ops->flow_off(hcc->bus, TD_TRUE);
    }
    return EXT_ERR_SUCCESS;
}
#endif

ext_errno hcc_flow_ctrl_module_init(hcc_handler *hcc)
{
    td_u8 dir;
    td_u8 q_id;
    hcc_trans_queue *queue;
    if (hcc == TD_NULL) {
        return EXT_ERR_FAILURE;
    }

    for (dir = 0; dir < HCC_DIR_COUNT; dir++) {
        for (q_id = 0; q_id < hcc->que_max_cnt; q_id++) {
            queue = &hcc->hcc_resource.hcc_queues[dir][q_id];
            queue->fc_para.fc_back_para.is_stopped = TD_FALSE;
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL_ACTIVE
            if (queue->queue_ctrl->flow_type == HCC_FLOWCTRL_DATA) {
                queue->fc_para.fc_back_para.flow_ctrl_open = TD_FALSE;
            }
            if (queue->queue_ctrl->flow_type == HCC_FLOWCTRL_CREDIT) {
                queue->fc_para.credit = HCC_FLOWCTRL_DEFAULT_CREDIT_VALUE;
            }
#endif
        }
    }

#ifndef CONFIG_HCC_SUPPORT_NON_OS
    if (osal_wait_init(&hcc->hcc_resource.hcc_fc_wq) != EXT_ERR_SUCCESS) {
        hcc_printf_err_log("hcc fc init wait err\r\n");
        return EXT_ERR_FAILURE;
    }
#endif
    return EXT_ERR_SUCCESS;
}

td_void hcc_flow_ctrl_module_deinit(hcc_handler *hcc)
{
#ifdef CONFIG_HCC_SUPPORT_NON_OS
    uapi_unused(hcc);
#else
    osal_wait_destroy(&hcc->hcc_resource.hcc_fc_wq);
#endif
}

ext_errno hcc_flow_ctrl_set_water_line(td_u8 chl, hcc_queue_dir direction, td_u8 q_id,
    td_u8 low_line, td_u8 high_line)
{
    td_ulong flags;
    hcc_handler *hcc = hcc_get_handler(chl);
    if (hcc == TD_NULL) {
        return EXT_ERR_HCC_HANDLER_ERR;
    }

    if (direction >= HCC_DIR_COUNT || q_id >= hcc->que_max_cnt) {
        return EXT_ERR_HCC_PARAM_ERR;
    }

    flags = 0;
    osal_spin_lock_irqsave(&hcc->hcc_resource.hcc_queues[direction][q_id].queue_info.data_queue_lock, &flags);
    hcc->hcc_resource.hcc_queues[direction][q_id].queue_ctrl->low_waterline  = low_line;
    hcc->hcc_resource.hcc_queues[direction][q_id].queue_ctrl->high_waterline = high_line;
    osal_spin_unlock_irqrestore(&hcc->hcc_resource.hcc_queues[direction][q_id].queue_info.data_queue_lock, &flags);
    return EXT_ERR_SUCCESS;
}

ext_errno hcc_flow_ctrl_get_water_line(td_u8 chl, hcc_queue_dir direction, td_u8 q_id,
    td_u8 *low_line, td_u8 *high_line)
{
    hcc_handler *hcc = hcc_get_handler(chl);
    if (hcc == TD_NULL) {
        return EXT_ERR_HCC_HANDLER_ERR;
    }

    if (direction >= HCC_DIR_COUNT || q_id >= hcc->que_max_cnt || low_line == TD_NULL || high_line == TD_NULL) {
        return EXT_ERR_HCC_PARAM_ERR;
    }
    *low_line = hcc->hcc_resource.hcc_queues[direction][q_id].queue_ctrl->low_waterline;
    *high_line = hcc->hcc_resource.hcc_queues[direction][q_id].queue_ctrl->high_waterline;
    return EXT_ERR_SUCCESS;
}

osal_module_export(hcc_flow_ctrl_set_water_line);
osal_module_export(hcc_flow_ctrl_get_water_line);
#endif

td_u32 hcc_flowctrl_check_with_off(td_u8 *data)
{
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL_ACTIVE
    hcc_handler *hcc = (hcc_handler *)data;
    if (hcc == TD_NULL || hcc->bus == TD_NULL || hcc->bus->bus_ops == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    if (hcc->bus->bus_ops->flow_off != TD_NULL) {
        hcc->bus->bus_ops->flow_off(hcc->bus, TD_FALSE);
    }
#endif
#endif
    unused(data);
    return EXT_ERR_SUCCESS;
}
