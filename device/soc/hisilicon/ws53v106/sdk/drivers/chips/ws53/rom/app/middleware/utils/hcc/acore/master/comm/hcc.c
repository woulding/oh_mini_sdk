/*
 * Copyright (c) CompanyNameMagicTag 2021-2023. All rights reserved.
 * Description: hcc module completion.
 * Author: CompanyName
 * Create: 2021-05-13
 */

#include "securec.h"
#include "soc_osal.h"
#include "osal_def.h"
#include "soc_errno.h"
#include "common_def.h"
#include "hcc_if.h"
#include "hcc_list.h"
#include "hcc_adapt.h"
#include "hcc_cfg_comm.h"
#include "hcc_comm.h"
#include "hcc_bus.h"
#include "hcc_bus_types.h"
#include "hcc_flow_ctrl.h"
#include "hcc_channel.h"
#include "hcc_service.h"
#include "hcc_test.h"
#include "hcc_dfx.h"
#include "hcc_ipc_adapt.h"
#include "hcc_rom_callback.h"
#include "hcc.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_HCC_COMM_HCC_C

#undef THIS_MOD_ID
#define THIS_MOD_ID LOG_PFMODULE

/* 消除Wmissing-prototypes编译选项引起的告警 */
STATIC td_void hcc_queue_process(hcc_handler *hcc);
STATIC hcc_queue_ctrl *hcc_get_queue_ctrl_from_cfg(hcc_handler *hcc, hcc_queue_dir dir, hcc_queue_type q_id);
STATIC td_bool hcc_check_queue_cfg(TD_CONST hcc_queue_cfg *queue_cfg, td_u32 queue_len);
STATIC td_s32 hcc_transfer_queue_init(hcc_handler *hcc, hcc_queue_cfg *queue_cfg, td_u32 queue_len);
STATIC td_void hcc_transfer_queue_deinit(hcc_handler *hcc);
STATIC td_void hcc_service_resource_init(hcc_handler *hcc);
#ifdef CONFIG_HCC_SUPPORT_UNC_POOL
STATIC ext_errno hcc_set_unc_pool(hcc_data_queue *unc_pool, td_u32 unc_pool_size);
STATIC td_void hcc_release_unc_pool(hcc_data_queue *unc_pool);
#endif
STATIC ext_errno hcc_task_init(hcc_handler *hcc, td_char *task_name, td_u8 task_pri);
STATIC td_void hcc_task_exit(hcc_handler *hcc);
STATIC td_void hcc_module_exit(hcc_handler *hcc);
STATIC hcc_handler *hcc_module_init_error(hcc_handler *hcc, hcc_module_init_errno num);
STATIC hcc_handler *hcc_module_mem_alloc(td_u32 unc_pool_size, td_u8 bus_type);
STATIC hcc_handler *hcc_module_init(hcc_channel_param *init);
STATIC ext_errno hcc_bt_tx_proc(hcc_handler *hcc, td_u8 *buf, td_u16 buf_size,
    hcc_transfer_param *param);

td_void hcc_enable_rx_thread(td_u8 chl, td_bool enable)
{
    if (hcc_get_handler(chl) != TD_NULL) {
        hcc_printf("enable/disable rx thread: %d\r\n", enable);
        hcc_get_handler(chl)->hcc_resource.rx_thread_enable = enable;
    }
}

td_void hcc_enable_tx_thread(td_u8 chl, td_bool enable)
{
    if (hcc_get_handler(chl) != TD_NULL) {
        hcc_printf("enable/disable tx thread: %d\r\n", enable);
        hcc_get_handler(chl)->hcc_resource.tx_thread_enable = enable;
    }
}

td_s32 hcc_stop_xfer(td_u8 chl)
{
    hcc_handler *hcc = hcc_get_handler(chl);

    if (hcc == TD_NULL) {
        return EXT_ERR_FAILURE;
    }

    if (hcc->bus && hcc->bus->bus_ops && hcc->bus->bus_ops->stop_xfer) {
        hcc->bus->bus_ops->stop_xfer();
    }
    hcc_enable_switch(chl, TD_FALSE);

    return EXT_ERR_SUCCESS;
}

td_u32 hcc_get_transfer_packet_num(hcc_handler *hcc)
{
    if (hcc == TD_NULL) {
        return 0;
    }
    return hcc->hcc_resource.cur_trans_pkts;
}

td_u16 hcc_tx_queue_proc(hcc_handler *hcc, hcc_trans_queue *queue)
{
    hcc_data_queue *head = TD_NULL;
    hcc_bus *bus = TD_NULL;
    td_u16 max_send_pkt_nums;
    td_u16 remain_pkt_nums;

    head = &queue->queue_info;
    if (hcc_is_list_empty(head)) {
        return 0;
    }
    bus = hcc->bus;
    hcc_printf("txproc list len:%d - burst limit:%d\r\n", hcc_list_len(head), queue->queue_ctrl->burst_limit);
    max_send_pkt_nums = (td_u16)osal_min(hcc_list_len(head), (td_u32)queue->queue_ctrl->burst_limit);
    remain_pkt_nums = max_send_pkt_nums;

    hcc_printf("txproc remain pkt nums: %d\r\n", remain_pkt_nums);
    while (remain_pkt_nums > 0) {
#if defined(CONFIG_HCC_SUPPORT_FLOW_CONTRL) && defined(CONFIG_HCC_SUPPORT_FLOW_CONTRL_ACTIVE)
        if (hcc_flow_ctrl_process(hcc, queue) != EXT_ERR_HCC_FC_PROC_UNBLOCK) {
            break;
        }
#endif
        if (hcc_bus_tx_proc(bus, queue, &remain_pkt_nums) != EXT_ERR_SUCCESS) {
            hcc->hcc_resource.tx_fail_cnt++;
            break;
        }
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL
        hcc_adapt_tx_start_subq(hcc, queue);
#endif
    }
    hcc_dfx_queue_total_pkt_increase(hcc, hcc_fuzzy_trans_queue_2_service(hcc, queue->queue_id), HCC_DIR_TX,
        queue->queue_id, (td_u8)(max_send_pkt_nums - remain_pkt_nums));
    return max_send_pkt_nums - remain_pkt_nums;
}

td_u16 hcc_rx_queue_proc(hcc_handler *hcc, hcc_trans_queue *queue)
{
    td_s32 ret = EXT_ERR_SUCCESS;
    hcc_unc_struc *unc_buf = TD_NULL;
    hcc_header *hcc_head = TD_NULL;
    hcc_serv_info *serv_info = TD_NULL;
    hcc_data_queue *head = &queue->queue_info;
    td_u16 rx_queue_cnt = 0;
    hcc_rx_data_cb rx_data_cb = TD_NULL;

    if (hcc_is_list_empty(head)) {
        return 0;
    }
    rx_data_cb = (hcc_rx_data_cb)hcc_get_rom_cb(HCC_CB_RX_DATA);
    if (rx_data_cb != TD_NULL) {
        if (rx_data_cb(hcc, queue, &rx_queue_cnt) != EXT_ERR_HCC_ROMBLE_HOOK_CONTINUE) {
            return rx_queue_cnt;
        }
    }

    unc_buf = hcc_list_dequeue(head);
    /* 依次处理队列中每个netbuf */
    while (unc_buf != TD_NULL) {
        hcc_head = (hcc_header *)unc_buf->buf;
        serv_info = hcc_get_serv_info(hcc, hcc_head->service_type);
        ret = EXT_ERR_FAILURE;
        if (serv_info == TD_NULL || serv_info->adapt == TD_NULL || !hcc_check_header_vaild(hcc, hcc_head)) {
            hcc_printf_err_log("hcc queue rx srv[%d] null\r\n", hcc_head->service_type);
            break;
        }

        ret = EXT_ERR_SUCCESS;
        hcc_dfx_service_exp_rx_cnt_increase(hcc, hcc_head->service_type);
        hcc_printf("[HCC]Rx Que-%d, srv-%d, len-%d\r\n", queue->queue_id, hcc_head->service_type, hcc_head->pay_len);
        if (serv_info->adapt->rx_proc != TD_NULL) {
            hcc_rx_proc(hcc, hcc_head, unc_buf->buf, unc_buf->user_param, serv_info->adapt->rx_proc);
            hcc_free_unc_buf(hcc, unc_buf);
        } else {
            hcc_adapt_mem_free(hcc, unc_buf);
            hcc_dfx_service_rx_err_cnt_increase(hcc, hcc_head->service_type);
            hcc_dfx_queue_loss_pkt_increase(hcc, HCC_DIR_RX, queue->queue_id);
        }
        if (rx_queue_cnt++ >= queue->queue_ctrl->burst_limit) {
            break;
        }
        unc_buf = hcc_list_dequeue(head);
    }

    if (ret != EXT_ERR_SUCCESS) {
        hcc_adapt_mem_free(hcc, unc_buf);
        hcc_dfx_queue_loss_pkt_increase(hcc, HCC_DIR_RX, queue->queue_id);
    }
    return rx_queue_cnt;
}

td_void hcc_change_state(osal_atomic *atomic, td_u32 state)
{
    td_s32 old_state;
    td_s32 new_state;
    if (atomic == TD_NULL) {
        return;
    }
    old_state = osal_atomic_read(atomic);
    osal_atomic_set(atomic, (td_s32)state);
    new_state = osal_atomic_read(atomic);
    if (old_state != new_state) {
        hcc_printf("state [%d]=>[%d]\r\n", old_state, new_state);
    }
}

td_u32 hcc_check_overrun(hcc_handler *hcc)
{
#if defined CONFIG_HCC_SUPPORT_NON_OS
    if (hcc->hcc_resource.cur_trans_pkts >= hcc->hcc_resource.max_proc_packets_per_loop) {
        hcc_proc_overnum_inc((td_void*)hcc);
        return EXT_ERR_FAILURE;
    }
#else
    uapi_unused(hcc);
#endif
    return EXT_ERR_SUCCESS;
}

STATIC td_void hcc_queue_process(hcc_handler *hcc)
{
    td_u8 i;
    hcc_trans_queue *queue = TD_NULL;
    hcc_queue_cfg *q_cfg = hcc->que_cfg;
    td_u16 pkt_proc = 0;

    for (i = 0; i < (hcc->que_max_cnt << 1); i++) {
        if (q_cfg[i].queue_id >= hcc->que_max_cnt) {
            hcc_printf_err_log("hcc thread err qid:%d\r\n", q_cfg[i].queue_id);
            continue;
        }

        queue = &hcc->hcc_resource.hcc_queues[q_cfg[i].dir][q_cfg[i].queue_id];
        hcc_printf("proc: dir - %d, qID - %d\r\n", q_cfg[i].dir, q_cfg[i].queue_id);
        switch (q_cfg[i].dir) {
            case HCC_DIR_TX:
                pkt_proc = hcc_tx_queue_proc(hcc, queue);
                break;

            case HCC_DIR_RX:
                pkt_proc = hcc_rx_queue_proc(hcc, queue);
                break;

            default:
                pkt_proc = 0;
                hcc_printf_err_log("hcc thread dir err qid:%d\r\n", q_cfg[i].dir);
                break;
        }
        hcc->hcc_resource.cur_trans_pkts += pkt_proc;
    }
}

td_s32 hcc_resume_xfer(td_u8 chl)
{
    hcc_handler *hcc = hcc_get_handler(chl);

    if (hcc->bus && hcc->bus->bus_ops && hcc->bus->bus_ops->resume_xfer) {
        hcc->bus->bus_ops->resume_xfer();
    }
    hcc_enable_switch(chl, TD_TRUE);
    return EXT_ERR_SUCCESS;
}

#if defined CONFIG_HCC_SUPPORT_NON_OS
td_void hcc_handle_tx_fail(hcc_handler *hcc)
{
    if (hcc->hcc_resource.tx_fail_cnt > hcc->hcc_resource.tx_fail_num_limit) {
        hcc_tx_fail_inc((td_void*)hcc);
    }
}
#endif

td_s32 hcc_transfer_thread(td_void *data)
{
    hcc_handler *hcc = (hcc_handler *)data;
    hcc_thread_watchdog watchdog = hcc_get_rom_cb(HCC_CB_WATCHDOG);
    if (hcc == TD_NULL) {
        hcc_printf_err_log("hcc thread null\r\n");
        return EXT_ERR_FAILURE;
    }
    hcc->hcc_resource.tx_fail_cnt = 0;
    hcc->hcc_resource.cur_trans_pkts = 0;
    while (hcc->hcc_resource.task_run != HCC_TASK_EXIT) {
        hcc->hcc_resource.task_run = HCC_TASK_WAIT;
        if (watchdog != TD_NULL) {
            watchdog();
        }
#if defined CONFIG_HCC_SUPPORT_NON_OS
        if (hcc_thread_wait_queue_cond(hcc) == TD_FALSE) {
            hcc_handle_tx_fail(hcc);
            return 0;
        }
#else
        osal_wait_interruptible(&hcc->hcc_resource.hcc_transfer_wq, hcc_thread_wait_queue_cond, hcc);
#endif

        hcc_printf("[INFO] - %s, evt wait success\r\n", __FUNCTION__);
        hcc->hcc_resource.task_run = HCC_TASK_RUN;
        hcc_queue_process(hcc);
        if (hcc_check_overrun(hcc) != EXT_ERR_SUCCESS) {
            return 0;
        }
    }
    hcc_printf("hcc transfer thread done!\r\n");
    return EXT_ERR_SUCCESS;
}

ext_errno hcc_message_register(td_u8 chl, td_u8 rsv, hcc_rx_msg_type msg_id, hcc_msg_rx cb, td_u8 *cb_data)
{
    hcc_bus *bus = hcc_get_channel_bus(chl);
    struct bus_msg_stru *message = TD_NULL;
    if (bus == TD_NULL || msg_id >= HCC_RX_MAX_MESSAGE || cb == TD_NULL) {
        return EXT_ERR_HCC_PARAM_ERR;
    }
    uapi_unused(rsv);
    message = &bus->msg[msg_id];
    message->msg_rx = cb;
    message->data = cb_data;
    hcc_printf("[success] hcc_message_register - %d\r\n", msg_id);
    osal_atomic_set(&message->count, 0);
    return EXT_ERR_SUCCESS;
}

ext_errno hcc_message_unregister(td_u8 chl, td_u8 rsv, hcc_rx_msg_type msg_id)
{
    hcc_bus *bus = hcc_get_channel_bus(chl);
    struct bus_msg_stru *message = TD_NULL;
    if (bus == TD_NULL || msg_id >= HCC_RX_MAX_MESSAGE) {
        return EXT_ERR_HCC_PARAM_ERR;
    }
    uapi_unused(rsv);
    message = &bus->msg[msg_id];
    message->msg_rx = TD_NULL;
    message->data = TD_NULL;
    return EXT_ERR_SUCCESS;
}

STATIC hcc_queue_ctrl *hcc_get_queue_ctrl_from_cfg(hcc_handler *hcc, hcc_queue_dir dir, hcc_queue_type q_id)
{
    td_u8 index;
    hcc_queue_cfg *que_cfg = hcc->que_cfg;
    for (index = 0; index < (hcc->que_max_cnt << 1); index++) {
        if (que_cfg[index].dir != dir || que_cfg[index].queue_id != q_id) {
            continue;
        }

        return &que_cfg[index].queue_ctrl;
    }
    return TD_NULL;
}

STATIC td_bool hcc_check_queue_cfg(TD_CONST hcc_queue_cfg *queue_cfg, td_u32 queue_len)
{
    td_u32 que_cnt[HCC_DIR_COUNT] = {0};
    td_u32 i;

    for (i = 0; i < queue_len; i++) {
        if (queue_cfg[i].dir < HCC_DIR_COUNT) {
            que_cnt[queue_cfg[i].dir]++;
        } else {
            return TD_FALSE;
        }
    }
    return (que_cnt[HCC_DIR_TX] == que_cnt[HCC_DIR_RX]);
}

STATIC td_s32 hcc_transfer_queue_init(hcc_handler *hcc, hcc_queue_cfg *queue_cfg, td_u32 queue_len)
{
    td_u8 dir;
    td_u8 q_id;
    hcc_trans_queue *hcc_queue = TD_NULL;
    td_u32 queue_size;

    hcc->que_cfg = queue_cfg;
    hcc->que_max_cnt = (td_u8)(queue_len >> 1);
    queue_size = (td_u32)(sizeof(hcc_trans_queue) * hcc->que_max_cnt);
    if (!hcc_check_queue_cfg(queue_cfg, queue_len)) {
        return EXT_ERR_FAILURE;
    }
    hcc->hcc_resource.hcc_queues[HCC_DIR_TX] = osal_kmalloc(queue_size, OSAL_GFP_KERNEL);
    hcc->hcc_resource.hcc_queues[HCC_DIR_RX] = osal_kmalloc(queue_size, OSAL_GFP_KERNEL);
    if ((hcc->hcc_resource.hcc_queues[HCC_DIR_TX] == TD_NULL) || hcc->hcc_resource.hcc_queues[HCC_DIR_RX] == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    (td_void)memset_s(hcc->hcc_resource.hcc_queues[HCC_DIR_TX], queue_size, 0, queue_size);
    (td_void)memset_s(hcc->hcc_resource.hcc_queues[HCC_DIR_RX], queue_size, 0, queue_size);
    for (dir = 0; dir < HCC_DIR_COUNT; dir++) {
        for (q_id = 0; q_id < hcc->que_max_cnt; q_id++) {
            hcc_queue = &hcc->hcc_resource.hcc_queues[dir][q_id];
            hcc_list_head_init(&hcc_queue->queue_info);
            hcc_queue->queue_id = q_id;
            hcc_queue->queue_ctrl = hcc_get_queue_ctrl_from_cfg(hcc, dir, q_id);
            if (hcc_queue->queue_ctrl == TD_NULL) {
                return EXT_ERR_FAILURE;
            }

            if (hcc_list_head_init(&hcc_queue->send_head) != EXT_ERR_SUCCESS) {
                return EXT_ERR_FAILURE;
            }
        }
    }
    return EXT_ERR_SUCCESS;
}

STATIC td_void hcc_transfer_queue_deinit(hcc_handler *hcc)
{
    td_u8 dir;
    td_u8 q_id;
    hcc_trans_queue *hcc_queue = TD_NULL;

    if ((hcc->hcc_resource.hcc_queues[HCC_DIR_TX] != TD_NULL) && hcc->hcc_resource.hcc_queues[HCC_DIR_RX] == TD_NULL) {
        for (dir = 0; dir < HCC_DIR_COUNT; dir++) {
            for (q_id = 0; q_id < hcc->que_max_cnt; q_id++) {
                hcc_queue = &hcc->hcc_resource.hcc_queues[dir][q_id];
                hcc_list_head_deinit(&hcc_queue->queue_info);
                hcc_list_head_deinit(&hcc_queue->send_head);
            }
        }
    } else {
        if (hcc->hcc_resource.hcc_queues[HCC_DIR_TX] != TD_NULL) {
            osal_kfree(hcc->hcc_resource.hcc_queues[HCC_DIR_TX]);
            hcc->hcc_resource.hcc_queues[HCC_DIR_TX] = TD_NULL;
        }
        if (hcc->hcc_resource.hcc_queues[HCC_DIR_RX] != TD_NULL) {
            osal_kfree(hcc->hcc_resource.hcc_queues[HCC_DIR_TX]);
            hcc->hcc_resource.hcc_queues[HCC_DIR_RX] = TD_NULL;
        }
    }
}

STATIC td_void hcc_service_resource_init(hcc_handler *hcc)
{
    OSAL_INIT_LIST_HEAD(&hcc->hcc_serv.service_list);
    hcc->hcc_serv.service_info = TD_NULL;
}

td_void hcc_enable_switch(td_u8 chl, td_bool enable)
{
    hcc_handler *hcc = hcc_get_handler(chl);
    if (hcc != TD_NULL) {
        hcc->hcc_state = (td_u8)enable;
    }
}

#ifdef CONFIG_HCC_SUPPORT_UNC_POOL
STATIC ext_errno hcc_set_unc_pool(hcc_data_queue *unc_pool, td_u32 unc_pool_size)
{
    td_u32 i;
    hcc_unc_struc *unc;

    hcc_list_head_init(unc_pool);
    unc = (hcc_unc_struc *)(unc_pool + 1);

    for (i = 0; i < unc_pool_size; i++) {
        hcc_list_add_tail(unc_pool, &unc[i]);
    }
    hcc_printf("%s success\r\n", __FUNCTION__);
    return EXT_ERR_SUCCESS;
}

STATIC td_void hcc_release_unc_pool(hcc_data_queue *unc_pool)
{
    if (unc_pool == TD_NULL) {
        return;
    }
    osal_spin_lock_destroy(&unc_pool->data_queue_lock);
}
#endif

STATIC ext_errno hcc_task_init(hcc_handler *hcc, td_char *task_name, td_u8 task_pri)
{
#ifdef CONFIG_HCC_SUPPORT_NON_OS
    /* non os 不需要创建task */
    hcc->hcc_resource.rx_thread_enable = TD_FALSE;
    hcc->hcc_resource.tx_thread_enable = TD_FALSE;
    hcc->hcc_resource.task_run = HCC_TASK_INIT;
    uapi_unused(task_name);
    uapi_unused(task_pri);
#else
    td_char *hcc_task_name;
    if (task_name == TD_NULL || strlen(task_name) > HCC_TASK_NAME_MAX_LEN) {
        hcc_task_name = "hcc_task";
    } else {
        hcc_task_name = task_name;
    }
    if (osal_wait_init(&hcc->hcc_resource.hcc_transfer_wq) != EXT_ERR_SUCCESS) {
        hcc_printf_err_log("hcc task wait err\r\n");
        return EXT_ERR_FAILURE;
    }

    /* 在任务创建之前赋值 */
    hcc->hcc_resource.task_run = HCC_TASK_INIT;
    hcc->hcc_resource.hcc_transfer_thread_handler = osal_kthread_create(
        hcc_transfer_thread, (td_void *)hcc, hcc_task_name, HCC_TRANS_THREAD_TASK_STACK_SIZE);
    if (hcc->hcc_resource.hcc_transfer_thread_handler == TD_NULL) {
        hcc_printf_err_log("hcc thread create failed!\r\n");
        return EXT_ERR_FAILURE;
    }
    osal_kthread_set_priority(hcc->hcc_resource.hcc_transfer_thread_handler, task_pri);
    /* 默认使用hcc task处理队列中的数据 */
    hcc->hcc_resource.rx_thread_enable = TD_TRUE;
    hcc->hcc_resource.tx_thread_enable = TD_TRUE;
#endif
    return EXT_ERR_SUCCESS;
}

STATIC td_void hcc_task_exit(hcc_handler *hcc)
{
    hcc->hcc_resource.task_run = HCC_TASK_EXIT;
#ifdef CONFIG_HCC_SUPPORT_NON_OS
    return;
#else
    osal_kthread_destroy(hcc->hcc_resource.hcc_transfer_thread_handler, TD_TRUE);
    osal_wait_destroy(&hcc->hcc_resource.hcc_transfer_wq);
#endif
}

STATIC td_void hcc_module_exit(hcc_handler *hcc)
{
    hcc_task_exit(hcc);
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL
    hcc_flow_ctrl_module_deinit(hcc);
#endif
    hcc_transfer_queue_deinit(hcc);
#ifdef CONFIG_HCC_SUPPORT_UNC_POOL
    hcc_release_unc_pool(hcc->unc_pool_head);
#endif
    hcc_delete_handler(hcc->channel_id);
}

STATIC hcc_handler *hcc_module_init_error(hcc_handler *hcc, hcc_module_init_errno num)
{
    // 初始化过程导致函数过长，使用errno替换goto标签，并记录错误码
    switch (num) {
        case HCC_MODULE_INIT_FAILED_ADD_HANDLER:
            hcc_task_exit(hcc);
            break;
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL
        case HCC_MODULE_INIT_FAILED_INIT_TASK:
            hcc_flow_ctrl_module_deinit(hcc);
            break;
#endif
        case HCC_MODULE_INIT_FAILED_INIT_FLOW_CTRL:
            hcc_transfer_queue_deinit(hcc);
            break;
#ifdef CONFIG_HCC_SUPPORT_UNC_POOL
        case HCC_MODULE_INIT_FAILED_INIT_QUEUE:
            hcc_release_unc_pool(hcc->unc_pool_head);
            break;
#endif
        case HCC_MODULE_INIT_FAILED_INIT_UNC_POOL:
            break;
        case HCC_MODULE_INIT_FAILED_SET_STATE:
            break;
        case HCC_MODULE_INIT_FAILED_INIT_STATE:
            break;
        default:
            break;
    }
    hcc_printf_err_log("hcc module init err:%d\r\n", num);
    osal_kfree((td_u8 *)hcc);
    return TD_NULL;
}

STATIC hcc_handler *hcc_module_mem_alloc(td_u32 unc_pool_size, td_u8 bus_type)
{
    hcc_handler *hcc;
    size_t total_len = 0;
#ifdef CONFIG_HCC_SUPPORT_UNC_POOL
    total_len = (td_u32)(sizeof(hcc_unc_struc) * unc_pool_size +
        sizeof(hcc_data_queue) + sizeof(hcc_handler));
    hcc = (hcc_handler *)osal_kmalloc(total_len, OSAL_GFP_KERNEL);
    if (hcc == TD_NULL) {
        hcc_printf_err_log("hcc module malloc err\r\n");
        return hcc;
    }
    (td_void)memset_s(hcc, total_len, 0, total_len);
    hcc->unc_pool_head = (hcc_data_queue *)(hcc + 1);
#else
    uapi_unused(unc_pool_size);
    total_len = sizeof(hcc_handler);
    hcc = (hcc_handler *)osal_kmalloc(sizeof(hcc_handler), OSAL_GFP_KERNEL);
    if (hcc == TD_NULL) {
        hcc_printf_err_log("hcc module malloc err\r\n");
        return hcc;
    }
    (td_void)memset_s(hcc, total_len, 0, total_len);
#endif

    hcc->channel_id = bus_type;
    return hcc;
}

STATIC hcc_handler *hcc_module_init(hcc_channel_param *init)
{
    hcc_handler *hcc = hcc_module_mem_alloc(init->unc_pool_size, init->bus_type);
    if (hcc == TD_NULL) {
        return hcc;
    }

    hcc->hcc_state = HCC_OFF;
#ifdef CONFIG_HCC_SUPPORT_UNC_POOL
    if (hcc_set_unc_pool(hcc->unc_pool_head, init->unc_pool_size) != EXT_ERR_SUCCESS) {
        return hcc_module_init_error(hcc, HCC_MODULE_INIT_FAILED_INIT_UNC_POOL);
    }
    hcc->unc_low_limit = init->unc_pool_low_limit;
#endif
    if (hcc_transfer_queue_init(hcc, init->queue_cfg, init->queue_len) != EXT_ERR_SUCCESS) {
        return hcc_module_init_error(hcc, HCC_MODULE_INIT_FAILED_INIT_QUEUE);
    }

#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL
    if (hcc_flow_ctrl_module_init(hcc) != EXT_ERR_SUCCESS) {
        return hcc_module_init_error(hcc, HCC_MODULE_INIT_FAILED_INIT_FLOW_CTRL);
    }
#endif
    hcc_service_resource_init(hcc);
    if (hcc_task_init(hcc, init->task_name, init->task_pri) != EXT_ERR_SUCCESS) {
        return hcc_module_init_error(hcc, HCC_MODULE_INIT_FAILED_INIT_TASK);
    }

    if (hcc_add_handler(hcc) != EXT_ERR_SUCCESS) {
        return hcc_module_init_error(hcc, HCC_MODULE_INIT_FAILED_ADD_HANDLER);
    }
    hcc->hcc_state = HCC_ON;
    hcc->srv_max_cnt = init->service_max_cnt;
    hcc->hcc_resource.max_proc_packets_per_loop = init->max_proc_packets_per_loop;
    hcc->hcc_resource.tx_fail_num_limit = init->tx_fail_num_limit;
    hcc_printf("[success] - %s\r\n", __FUNCTION__);
    return hcc;
}

td_void hcc_deinit(td_u8 chl)
{
    hcc_handler *hcc = hcc_get_handler(chl);
    if (hcc == TD_NULL) {
        return;
    }
    hcc_bus_unload(hcc->bus);
    hcc_module_exit(hcc);
}

td_u8 hcc_init(hcc_channel_param *init)
{
    td_u32 ret = EXT_ERR_SUCCESS;
    hcc_handler *hcc;

    if (init == TD_NULL) {
        return HCC_CHANNEL_INVALID;
    }
    hcc = hcc_get_bus_handler(init->bus_type);
    if ((hcc != TD_NULL) || (init->queue_cfg == TD_NULL) || (init->queue_len == 0)) {
        hcc_printf_err_log("hcc init param err\r\n");
        return HCC_CHANNEL_INVALID;
    }
    hcc = hcc_module_init(init);
    if (hcc == TD_NULL) {
        hcc_printf_err_log("hcc init module init err\r\n");
        return HCC_CHANNEL_INVALID;
    }
#ifdef CONFIG_HCC_SUPPORT_DFX
    ret = hcc_dfx_init(hcc);
    if (ret != EXT_ERR_SUCCESS) {
        hcc_printf_err_log("hcc init dfx init, ret %x\r\n", ret);
        return HCC_CHANNEL_INVALID;
    }
#endif
    ret = hcc_bus_load(init->bus_type, hcc);
    if (ret != EXT_ERR_SUCCESS) {
        hcc_module_exit(hcc);
        hcc_printf_err_log("hcc init bus load fail\r\n");
        return HCC_CHANNEL_INVALID;
    }
#ifdef CONFIG_HCC_SUPPORT_TEST
    hcc_test_msg_init();
#endif
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL_ACTIVE
    fc_msg_init(hcc->channel_id);
#endif
    hcc_debug("hcc init succ\r\n");
    return hcc->channel_id;
}

STATIC ext_errno hcc_bt_tx_proc(hcc_handler *hcc, td_u8 *buf, td_u16 buf_size,
    hcc_transfer_param *param)
{
    hcc_trans_queue *queue;
    if (hcc->hcc_state != HCC_ON) {
        hcc_printf_err_log("hcc bt tx proc state:%d\r\n", hcc->hcc_state);
        return EXT_ERR_HCC_STATE_OFF;
    }

    if (hcc_adapt_tx_param_check(hcc, buf, buf_size, param) != EXT_ERR_SUCCESS) {
        return EXT_ERR_HCC_PARAM_ERR;
    }
    queue = &hcc->hcc_resource.hcc_queues[HCC_DIR_TX][param->queue_id];
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL
    if (hcc_flow_ctrl_pre_proc(hcc, param, queue) != EXT_ERR_SUCCESS) {
        return EXT_ERR_HCC_FC_PRE_PROC_ERR;
    }
#endif

    return hcc_tx_proc(hcc, queue, param, buf, buf_size);
}

ext_errno hcc_bt_tx_data(td_u8 chl, td_u8 *data_buf, td_u16 len, hcc_transfer_param *param)
{
    ext_errno ret;
    hcc_handler *hcc = hcc_get_handler(chl);
    size_t buf_size;
    td_u8 *buf = TD_NULL;
    td_u8 *user_param = TD_NULL;
    hcc_serv_info *serv_info = TD_NULL;
    hcc_tx_data_cb tx_data_func = TD_NULL;

    if (hcc == TD_NULL || data_buf == TD_NULL || param == TD_NULL) {
        hcc_printf_err_log("hcc bt tx params null!\r\n");
        return EXT_ERR_HCC_PARAM_ERR;
    }
    tx_data_func = (hcc_tx_data_cb)hcc_get_rom_cb(HCC_CB_BT_TX);
    if (tx_data_func != TD_NULL) {
        ret = tx_data_func(chl, buf, len, param);
        if (ret != EXT_ERR_HCC_ROMBLE_HOOK_CONTINUE) {
            return ret;
        }
    }

    buf_size = align_next((len + sizeof(hcc_header)), hcc->bus->len_align);
    serv_info = hcc_get_serv_info(hcc, param->service_type);
    if (serv_info == TD_NULL || serv_info->adapt == TD_NULL) {
        hcc_printf_err_log("hcc bt tx srv err q-%d, serv-%d\r\n", param->queue_id, param->service_type);
        return EXT_ERR_FAILURE;
    }

    if (serv_info->adapt->alloc == TD_NULL || serv_info->adapt->free == TD_NULL) {
        hcc_printf_err_log("hcc bt tx srv-%d alloc or free  null\r\n", param->service_type);
        return EXT_ERR_FAILURE;
    }

    ret = serv_info->adapt->alloc(param->queue_id, buf_size, &buf, &user_param);
    if (ret != EXT_ERR_SUCCESS) {
        hcc_printf_err_log("hcc bt tx srv alloc fail\r\n");
        return ret;
    }
    (td_void)memset_s(buf, buf_size, 0, buf_size);
    /* hcc header init */
    hcc_header_init((hcc_header *)buf, len, param);
    ret = memcpy_s(buf + sizeof(hcc_header), len, data_buf, len);
    if (ret != EXT_ERR_SUCCESS) {
        return ret;
    }

    ret = hcc_bt_tx_proc(hcc, buf, (td_u16)buf_size, param);
    if (ret == EXT_ERR_SUCCESS) {
        return ret;
    }
    serv_info->adapt->free(param->queue_id, buf, user_param);
    return ret;
}

STATIC td_u32 hcc_get_tx_queue_len(td_u8 channel_name, td_u32 queue_id)
{
    hcc_handler *hcc = hcc_get_handler(channel_name);
    hcc_trans_queue *queue = TD_NULL;
    if (hcc == TD_NULL || queue_id >= hcc->que_max_cnt) {
        return 0;
    }

    queue = &hcc->hcc_resource.hcc_queues[HCC_DIR_TX][queue_id];
    return queue->queue_info.qlen;
}

STATIC td_u32 hcc_get_tx_sched_len(td_u8 channel_name, td_u32 queue_id)
{
    hcc_handler *hcc = hcc_get_handler(channel_name);
    hcc_trans_queue *queue = TD_NULL;
    if (hcc == TD_NULL || queue_id >= hcc->que_max_cnt) {
        return 0;
    }

    queue = &hcc->hcc_resource.hcc_queues[HCC_DIR_TX][queue_id];
    return queue->queue_ctrl->high_waterline;  // high 8 low 4 tid最多給hcc送8個包，hcc低於4個就喚醒
}

td_u32 hcc_get_tx_sched_num(osal_void)
{
    td_u32 total_num = 0;
    td_u32 allow_num = 0;

    total_num = hcc_get_tx_queue_len(HCC_CHANNEL_AP, DATA_LO_QUEUE);
    allow_num = hcc_get_tx_sched_len(HCC_CHANNEL_AP, DATA_LO_QUEUE);
    return (allow_num > total_num) ? (allow_num - total_num) : 0;
}

td_void hcc_tx_sched_wait(osal_wait_condition_func func, const void *param, unsigned long wait_time)
{
    td_s32 ret;
    hcc_handler *hcc = hcc_get_handler(HCC_CHANNEL_AP);

    if (hcc == TD_NULL) {
        return;
    }
    ret = osal_wait_timeout_interruptible(&hcc->hcc_resource.hcc_fc_wq, func, param, wait_time);
    if (ret == 0) {
        hcc_printf("[WARN]hcc flow control wait event timeout! too much time locked\r\n");
    }
}

osal_module_export(hcc_message_register);
osal_module_export(hcc_message_unregister);
osal_module_export(hcc_get_head_len);
osal_module_export(hcc_init);
osal_module_export(hcc_deinit);
osal_module_export(hcc_enable_switch);
osal_module_export(hcc_enable_rx_thread);
osal_module_export(hcc_enable_tx_thread);
osal_module_export(hcc_tx_data);
osal_module_export(hcc_bt_tx_data);
osal_module_export(hcc_get_tx_sched_num);
osal_module_export(hcc_tx_sched_wait);
