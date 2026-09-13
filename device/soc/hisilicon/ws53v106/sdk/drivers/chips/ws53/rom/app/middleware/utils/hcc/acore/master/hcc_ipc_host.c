/*
 * Copyright (c) CompanyNameMagicTag 2023-2023. All rights reserved.
 * Description: hcc ipc adapt layer.
 * Author: CompanyName
 * Create: 2023-02-24
 */
#ifdef CONFIG_HCC_SUPPORT_IPC
#include "hcc_cfg.h"
#include "hcc_ipc_host_rom.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_HCC_IPC_HOST_C

#undef THIS_MOD_ID
#define THIS_MOD_ID LOG_PFMODULE

#define CONFIG_SUPPORT_IPC_DMA
#define IPC_CRAM_OFFSET 0x10000000
#define HCC_RX_RSV_BUF_LEN  HCC_DATA_QUEUE_BUF_LEN

static hcc_ipc_bus_drv_t *g_hcc_ipc_drv;
td_void hcc_ipc_drv_set(hcc_ipc_bus_drv_t *drv);
#ifdef HCC_PRINT_PERFORM
td_u64 g_test_time[TEST_TIME_MAX] = {0};
#endif

#ifdef CONFIG_SUPPORT_IPC_DMA
static hcc_ipc_dma_intr_param_t g_dma_intr_param[HCC_IPC_DMA_MAX] = {0};
#endif

STATIC td_void hcc_set_test_timestamp(td_u8 id)
{
#ifdef HCC_PRINT_PERFORM
    g_test_time[id] = hcc_test_get_us();
#else
    uapi_unused(id);
#endif
}

hcc_ipc_bus_drv_t* hcc_ipc_drv_get(td_void)
{
    return g_hcc_ipc_drv;
}

STATIC td_bool hcc_ipc_rx_queue_is_busy(hcc_handler *hcc)
{
    td_u8 i;
    for (i = 0; i < hcc->que_max_cnt; i++) {
        hcc_trans_queue *queue = &hcc->hcc_resource.hcc_queues[HCC_DIR_RX][i];
        hcc_ipc_rx_queue_info_t *rx_queue_info = &g_hcc_ipc_drv->rx_queue_info[i];
        if (!hcc_is_list_empty(&queue->queue_info) || !hcc_is_list_empty(&rx_queue_info->rx_buf_head)) {
            return TD_TRUE;
        }
    }
    return TD_FALSE;
}

static td_u32 g_premem_addr_add_cnt = 0;
STATIC td_bool hcc_ipc_tx_queue_is_busy(hcc_handler *hcc)
{
    td_u8 i;
    for (i = 0; i < hcc->que_max_cnt; i++) {
        hcc_trans_queue *queue = &hcc->hcc_resource.hcc_queues[HCC_DIR_TX][i];
        hcc_data_queue *tx_buf_head = &g_hcc_ipc_drv->tx_buf_head[i];
        if (!hcc_is_list_empty(&queue->queue_info)) {
            return TD_TRUE;
        }
        if (!hcc_check_pre_req_queue(queue) && (!hcc_is_list_empty(tx_buf_head) ||
            !hcc_is_list_empty(&queue->send_head))) {
            return TD_TRUE;
        } else if (hcc_list_len(tx_buf_head) + hcc_list_len(&queue->send_head) > g_premem_addr_add_cnt) {
            return TD_TRUE;
        }
    }
    return TD_FALSE;
}

STATIC td_bool hcc_ipc_is_busy(hcc_queue_dir dir)
{
    hcc_handler *hcc = (hcc_handler *)g_hcc_ipc_drv->bus->hcc;
    if (dir == HCC_DIR_RX) {
        return hcc_ipc_rx_queue_is_busy(hcc);
    }
    return hcc_ipc_tx_queue_is_busy(hcc);
}

STATIC td_void hcc_ipc_mem_reply_addr(hcc_handler *hcc, hcc_trans_queue *queue,
    hcc_ipc_mem_reply_t *reply_info)
{
    td_u32 i;
    hcc_unc_struc *unc_buf;

    for (i = 0; i < reply_info->cnt; i++) {
        if (reply_info->addr[i] == TD_NULL) {
            hcc_printf_err_log("hcc ipc reply addr err\r\n");
            break;
        }
        unc_buf = hcc_ipc_mem_send_match_len(hcc, &queue->send_head, reply_info->data_len[i]);
        if (unc_buf != TD_NULL) {
            unc_buf->addr = reply_info->addr[i];
            hcc_list_unlock_add_tail(&g_hcc_ipc_drv->tx_buf_head[queue->queue_id], unc_buf);
        }
    }
}

STATIC td_void hcc_ipc_premem_reply_addr(hcc_trans_queue *queue, hcc_ipc_mem_reply_t *reply_info)
{
    td_u32 i;
    hcc_unc_struc *unc_buf;
    hcc_handler *hcc = (hcc_handler *)g_hcc_ipc_drv->bus->hcc;

    for (i = 0; i < reply_info->cnt; i++) {
        if (reply_info->addr[i] == TD_NULL) {
            hcc_printf_err_log("hcc ipc reply addr err\r\n");
            break;
        }

        unc_buf = hcc_list_unlock_dequeue(&queue->send_head);
        if (unc_buf == TD_NULL) {
            g_premem_addr_add_cnt++;
            unc_buf = hcc_alloc_unc_buf(hcc);
        }
        if (unc_buf != TD_NULL) {
            unc_buf->addr = reply_info->addr[i];
            hcc_list_unlock_add_tail(&g_hcc_ipc_drv->tx_buf_head[queue->queue_id], unc_buf);
        } else {
            hcc_printf_err_log("hcc_ipc_premem_reply_addr[%u] fail\r\n", queue->queue_id);
        }
    }
}

STATIC td_void hcc_ipc_mem_reply_msg(td_u8 *payload_addr, td_u32 payload_len)
{
    hcc_ipc_mem_reply_t *reply_info = (hcc_ipc_mem_reply_t *)payload_addr;
    hcc_handler *hcc = TD_NULL;
    hcc_trans_queue *queue = TD_NULL;

    if (g_hcc_ipc_drv == TD_NULL || g_hcc_ipc_drv->bus == TD_NULL || g_hcc_ipc_drv->bus->hcc == TD_NULL) {
        hcc_printf_err_log("host ipc dev's hcc handler is null\r\n");
        return;
    }

    if (payload_len != sizeof(hcc_ipc_mem_reply_t) ||
        reply_info->hcc_queue_id >= g_hcc_ipc_drv->que_len ||
        reply_info->cnt > IPC_MEM_MSG_MAX) {
        hcc_printf_err_log("hcc ipc reply param[%u] que_id[%u] cnt[%u] err\r\n",
            payload_len, reply_info->hcc_queue_id, reply_info->cnt);
        return;
    }
    hcc = (hcc_handler *)g_hcc_ipc_drv->bus->hcc;
    queue = &hcc->hcc_resource.hcc_queues[HCC_DIR_TX][reply_info->hcc_queue_id];
    /* 非预申请队列要去发送任务发包 */
    if (!hcc_check_pre_req_queue(queue)) {
        hcc_ipc_mem_reply_addr(hcc, queue, reply_info);
        osal_wait_wakeup(&g_hcc_ipc_drv->data_transfer_wait);
    } else {
        hcc_ipc_premem_reply_addr(queue, reply_info);
        hcc_sched_transfer(hcc);
    }
}

td_void hcc_ipc_mem_rx_start_msg(td_u8 *payload_addr, td_u32 payload_len)
{
    hcc_ipc_mem_reply_t *ack_info = (hcc_ipc_mem_reply_t *)payload_addr;
    hcc_ipc_rx_queue_info_t *rx_queue_info;

    if (g_hcc_ipc_drv == TD_NULL || g_hcc_ipc_drv->bus == TD_NULL || g_hcc_ipc_drv->bus->hcc == TD_NULL) {
        hcc_printf_err_log("host ipc dev's hcc handler is null\r\n");
        return;
    }
    if (payload_len != sizeof(hcc_ipc_mem_reply_t) ||
        ack_info->hcc_queue_id >= g_hcc_ipc_drv->que_len ||
        ack_info->cnt > IPC_MEM_MSG_MAX) {
        hcc_printf_err_log("hcc ipc rxmsg param[%u] que_id[%u] cnt[%u] err\r\n",
            payload_len, ack_info->hcc_queue_id, ack_info->cnt);
        return;
    }

    rx_queue_info = &g_hcc_ipc_drv->rx_queue_info[ack_info->hcc_queue_id];
    hcc_ipc_mem_handle_rx_unc((hcc_handler *)g_hcc_ipc_drv->bus->hcc, rx_queue_info, ack_info);
    osal_wait_wakeup(&g_hcc_ipc_drv->data_transfer_wait);
}

STATIC td_void hcc_ipc_print_result(td_u32 dma_cnt, td_u64 t1, td_u64 t2, td_u64 t3, td_u64 t4)
{
#ifdef HCC_PRINT_PERFORM
    hcc_debug("dma[%u]: T2:%llu[DEQ-%llu,trans-%llu], T4:%llu[end-%llu msg-%llu-%llu]\r\n",
        dma_cnt, hcc_calc_time_us(g_test_time[TEST_TIME_START], g_test_time[TEST_TIME_END]),
        hcc_calc_time_us(g_test_time[TEST_TIME_START], g_test_time[TEST_TIME_TRANS_START]),
        hcc_calc_time_us(g_test_time[TEST_TIME_TRANS_START], g_test_time[TEST_TIME_TRANS_END]),
        hcc_calc_time_us(t1, t4),
        hcc_calc_time_us(t1, t2), hcc_calc_time_us(t2, t3), hcc_calc_time_us(t3, t4));
#else
    uapi_unused(dma_cnt);
    uapi_unused(t1);
    uapi_unused(t2);
    uapi_unused(t3);
    uapi_unused(t4);
#endif
}

STATIC td_void hcc_ipc_wakeup_sched(osal_wait *transfer_wait)
{
#ifdef CONFIG_SUPPORT_IPC_DMA
    osal_wait_wakeup(transfer_wait);
#else
    uapi_unused(transfer_wait);
#endif
}

STATIC td_void hcc_ipc_complete_callback(td_u8 intr, td_u8 channel, uintptr_t arg)
{
    td_u8 cur_queue_id;
    td_u8 dma_cnt;
    td_u8 dir;
    td_u64 t1, t2, t3, t4;
    hcc_trans_queue *queue;
    hcc_handler *hcc = (hcc_handler *)g_hcc_ipc_drv->bus->hcc;
    t1 = hcc_test_get_us();

#ifndef CONFIG_SUPPORT_IPC_DMA
    cur_queue_id = channel;
    dma_cnt = intr;
    dir = (td_u8)arg;
#else
    hcc_ipc_dma_intr_param_t *dma_intr_param_t = (hcc_ipc_dma_intr_param_t *)arg;
    uapi_unused(intr);
    uapi_unused(channel);
    if (arg == 0) {
        return;
    }
    cur_queue_id = dma_intr_param_t->queue_id;
    dma_cnt = dma_intr_param_t->dma_cnt;
    dir = dma_intr_param_t->dir;
    uapi_dma_end_transfer(channel);
#endif
    t2 = hcc_test_get_us();
    if (cur_queue_id > g_hcc_ipc_drv->que_len || (dma_cnt == 0) || (dma_cnt > HCC_DMA_TRANS_MAX)) {
        return;
    }
    hcc_ipc_complete_dfx_stats(hcc, dir, cur_queue_id, dma_cnt);
    queue = &hcc->hcc_resource.hcc_queues[dir][cur_queue_id];
    if (dir == HCC_DIR_TX) {
        hcc_ipc_handle_complete_msg(&g_hcc_ipc_drv->tx_buf_head[cur_queue_id], hcc,
            HCC_IPC_MEM_TX_COMPLETE, cur_queue_id, dma_cnt);
        hcc_ipc_clr_dma_status(dir, cur_queue_id);
        t3 = hcc_test_get_us();
        if (!hcc_check_pre_req_queue(queue)) {
            hcc_ipc_wakeup_sched(&g_hcc_ipc_drv->data_transfer_wait);
        } else {
            hcc_ipc_wakeup_sched(&hcc->hcc_resource.hcc_transfer_wq);
        }
    } else {
        hcc_ipc_handle_complete_msg(&g_hcc_ipc_drv->rx_queue_info[cur_queue_id].rx_buf_head, hcc,
            HCC_IPC_MEM_RX_COMPLETE, cur_queue_id, dma_cnt);
        hcc_ipc_clr_dma_status(dir, cur_queue_id);
        hcc_ipc_wakeup_sched(&g_hcc_ipc_drv->data_transfer_wait);
        t3 = hcc_test_get_us();
    }
    t4 = hcc_test_get_us();
    hcc_ipc_print_result(dma_cnt, t1, t2, t3, t4);
}

#ifndef CONFIG_SUPPORT_IPC_DMA
STATIC td_u32 hcc_ipc_mem_cpu(hcc_ipc_dma_info_t *dma_info, td_u32 trans_nums, td_u8 dir, td_u8 que_id)
{
    td_u32 i;

    hcc_set_test_timestamp(TEST_TIME_TRANS_START);
    hcc_printf("transf num-%u, dir-%u, q-%u\r\n", trans_nums, dir, que_id);
    for (i = 0; i < trans_nums; i++) {
        hcc_printf("trans addr 0x%x -> 0x%x, len:%d\r\n",
            dma_info[i].src_addr, dma_info[i].dst_addr, dma_info[i].data_len);
        if (dir == HCC_DIR_TX) {
            memcpy_s(dma_info[i].dst_addr + IPC_CRAM_OFFSET, dma_info[i].data_len,
                dma_info[i].src_addr, dma_info[i].data_len);
        } else {
            memcpy_s(dma_info[i].dst_addr, dma_info[i].data_len,
                dma_info[i].src_addr + IPC_CRAM_OFFSET, dma_info[i].data_len);
        }
    }
    hcc_set_test_timestamp(TEST_TIME_TRANS_END);
    /* hcc_ipc_complete_callback为无锁函数，不在中断中调用需要加锁保护 */
    uint32_t status = osal_irq_lock();
    hcc_ipc_complete_callback((td_u8)trans_nums, que_id, dir);
    osal_irq_restore(status);
    return EXT_ERR_SUCCESS;
}
#else
STATIC td_u32 hcc_ipc_mem_dma_lli(hcc_ipc_dma_info_t *dma_info, hcc_ipc_dma_intr_param_t *dma_intr_param,
    td_u32 saddr_offset, td_u32 daddr_offset)
{
    td_u32 i;
    dma_channel_t dma_channel;
    dma_ch_user_memory_config_t user_cfg = {0};
    ext_errno ret;

    dma_channel = uapi_dma_get_lli_channel(0, 0);
    if (dma_channel == DMA_CHANNEL_NONE) {
        hcc_printf_err_log("hcc dma get_lli_channel D-%u Q-%u err\r\n", dma_intr_param->dir, dma_intr_param->queue_id);
        return EXT_ERR_FAILURE;
    }

    for (i = 0; i < dma_intr_param->dma_cnt; i++) {
        hcc_printf("dma trans addr 0x%x -> 0x%x, len:%d\r\n",
            dma_info[i].src_addr, dma_info[i].dst_addr, dma_info[i].data_len);
        user_cfg.dest = (td_u32)(uintptr_t)dma_info[i].dst_addr + daddr_offset;
        user_cfg.src = (td_u32)(uintptr_t)dma_info[i].src_addr + saddr_offset;
        user_cfg.transfer_num = dma_info[i].data_len >> HCC_DMA_WIDTH_DWORD;
        user_cfg.width = HCC_DMA_WIDTH_DWORD;
        ret = uapi_dma_transfer_memory_lli(dma_channel, &user_cfg, hcc_ipc_complete_callback);
        if (ret != ERRCODE_SUCC) {
            hcc_printf_err_log("hcc dma transfer_memory_lli D-%u Q-%u ret=0x%x\r\n",
                dma_intr_param->dir, dma_intr_param->queue_id, ret);
            return EXT_ERR_FAILURE;
        }
    }

    ret = uapi_dma_enable_lli(dma_channel, hcc_ipc_complete_callback, (uintptr_t)dma_intr_param);
    if (ret != ERRCODE_SUCC) {
        hcc_printf_err_log("hcc dma enable_lli D-%u Q-%u ret=0x%x\r\n",
            dma_intr_param->dir, dma_intr_param->queue_id, ret);
        return EXT_ERR_FAILURE;
    }
    return EXT_ERR_SUCCESS;
}

STATIC hcc_ipc_dma_intr_param_t *hcc_ipc_get_dma_param(td_u8 dir, td_u8 que_id)
{
    td_u8 pos = hcc_ipc_get_dma_param_index(dir, que_id);
    return &g_dma_intr_param[pos];
}

STATIC td_u32 hcc_ipc_mem_dma(hcc_ipc_dma_info_t *dma_info, td_u32 trans_nums, td_u8 dir, td_u8 que_id)
{
    dma_ch_user_memory_config_t user_cfg = {0};
    td_u32 saddr_offset = 0;
    td_u32 daddr_offset = 0;
    hcc_ipc_dma_intr_param_t *dma_intr_param;
    ext_errno ret;

    dma_intr_param = hcc_ipc_get_dma_param(dir, que_id);
    dma_intr_param->dir = dir;
    dma_intr_param->dma_cnt = (td_u8)trans_nums;
    dma_intr_param->queue_id = que_id;
    hcc_printf("dma transf num-%u, dir-%u, q-%u\r\n", trans_nums, dir, que_id);

    if (dir == HCC_DIR_TX) {
        daddr_offset = IPC_CRAM_OFFSET;
    } else {
        saddr_offset = IPC_CRAM_OFFSET;
    }
    hcc_set_test_timestamp(TEST_TIME_TRANS_START);
    if (trans_nums == 1) {
        user_cfg.dest = (td_u32)(uintptr_t)dma_info[0].dst_addr + daddr_offset;
        user_cfg.src = (td_u32)(uintptr_t)dma_info[0].src_addr + saddr_offset;
        user_cfg.transfer_num = dma_info[0].data_len >> HCC_DMA_WIDTH_DWORD;
        user_cfg.width = HCC_DMA_WIDTH_DWORD;
        hcc_printf("dma trans addr 0x%x -> 0x%x, len:%d\r\n",
            dma_info[0].src_addr, dma_info[0].dst_addr, dma_info[0].data_len);
        ret = uapi_dma_transfer_memory_single(&user_cfg, hcc_ipc_complete_callback, (uintptr_t)dma_intr_param);
        if (ret != ERRCODE_SUCC) {
            hcc_printf_err_log("hcc dma transfer single Q-%d,D-%d ret=0x%x\r\n", que_id, dir, ret);
            return EXT_ERR_FAILURE;
        }
    } else {
        if (hcc_ipc_mem_dma_lli(dma_info, dma_intr_param, saddr_offset, daddr_offset) != EXT_ERR_SUCCESS) {
            return EXT_ERR_FAILURE;
        }
    }
    hcc_set_test_timestamp(TEST_TIME_TRANS_END);
    return EXT_ERR_SUCCESS;
}
#endif

td_void hcc_ipc_queue_clear_dma_status(hcc_queue_dir dir, hcc_trans_queue *queue)
{
#ifdef CONFIG_SUPPORT_IPC_DMA
    td_u32 irq_status = osal_irq_lock();
    hcc_ipc_clr_dma_status(dir, queue->queue_id);
    osal_irq_restore(irq_status);
#else
    uapi_unused(dir);
    uapi_unused(queue);
#endif
}

td_bool hcc_ipc_queue_dma_is_busy(hcc_queue_dir dir, hcc_trans_queue *queue)
{
#ifdef CONFIG_SUPPORT_IPC_DMA
    return hcc_ipc_get_dma_status(dir, queue->queue_id);
#else
    uapi_unused(dir);
    uapi_unused(queue);
    return TD_FALSE;
#endif
}

td_bool hcc_ipc_queue_unlock_set_dma_busy(hcc_queue_dir dir, hcc_trans_queue *queue)
{
#ifdef CONFIG_SUPPORT_IPC_DMA
    td_bool res;
    td_u8 pos = hcc_ipc_get_dma_param_index(dir, queue->queue_id);
    if ((g_hcc_ipc_drv->dma_state & (1 << pos)) != 0) {
        res = TD_TRUE;
    } else {
        g_hcc_ipc_drv->dma_state |= 1 << pos;
        res = TD_FALSE;
    }
    return res;
#else
    uapi_unused(dir);
    uapi_unused(queue);
    return TD_FALSE;
#endif
}

td_bool hcc_ipc_tx_dma_is_busy(hcc_queue_dir dir, hcc_trans_queue *queue)
{
#ifdef CONFIG_SUPPORT_IPC_DMA
    td_bool ret = TD_FALSE;
    if ((dir == HCC_DIR_TX) && hcc_check_pre_req_queue(queue)) {
        if (hcc_ipc_get_dma_status(dir, queue->queue_id) ||
            hcc_is_list_empty(&g_hcc_ipc_drv->tx_buf_head[queue->queue_id])) {
            ret = TD_TRUE;
        }
    }
    return ret;
#else
    uapi_unused(dir);
    uapi_unused(queue);
    return TD_FALSE;
#endif
}

td_u32 hcc_ipc_data_transfer(hcc_ipc_dma_info_t *dma_info, td_u32 trans_nums, td_u8 que_id, td_u8 dir)
{
    td_u32 ret;
#ifndef CONFIG_SUPPORT_IPC_DMA
    ret = hcc_ipc_mem_cpu(dma_info, trans_nums, dir, que_id);
#else
    td_u32 retry_times = 0;
    ret = hcc_ipc_mem_dma(dma_info, trans_nums, dir, que_id);
    while ((ret != EXT_ERR_SUCCESS) && (retry_times < HCC_DMA_TRY_CNT)) {
        hcc_printf_err_log("hcc ipc Q[%d] dma transfer err\r\n", que_id);
        ret = hcc_ipc_mem_dma(dma_info, trans_nums, dir, que_id);
        osal_mdelay(1);
        retry_times++;
    }
#endif
    return ret;
}

STATIC td_void hcc_ipc_thread_rcv_alloc_data(hcc_handler *hcc, hcc_ipc_rx_queue_info_t *rx_queue_info,
    hcc_trans_queue *queue)
{
    td_u32 i;
    hcc_unc_struc *unc_buf;
    hcc_data_queue *rx_buf_head = &rx_queue_info->rx_buf_head;
    td_u32 need_alloc_cnt;
    struct osal_list_head *list_tmp;
    unsigned long flags;

    osal_spin_lock_irqsave(&rx_buf_head->data_queue_lock, &flags);
    need_alloc_cnt = rx_buf_head->qlen - rx_queue_info->alloc_cnt;
    list_tmp = rx_queue_info->alloc_list_head;
    osal_spin_unlock_irqrestore(&rx_buf_head->data_queue_lock, &flags);
    for (i = 0; i < need_alloc_cnt; i++) {
        osal_spin_lock_irqsave(&rx_buf_head->data_queue_lock, &flags);
        unc_buf = hcc_ipc_list_unlock_get_node(rx_buf_head, &list_tmp);
        if (unc_buf == TD_NULL) {
            osal_spin_unlock_irqrestore(&rx_buf_head->data_queue_lock, &flags);
            break;
        }
        if (hcc_ipc_alloc_unc_data(hcc, queue, unc_buf) == EXT_ERR_SUCCESS) {
            rx_queue_info->alloc_list_head = list_tmp;
            rx_queue_info->alloc_cnt++;
        } else {
            osal_spin_unlock_irqrestore(&rx_buf_head->data_queue_lock, &flags);
            break;
        }
        osal_spin_unlock_irqrestore(&rx_buf_head->data_queue_lock, &flags);
    }
}

STATIC td_void hcc_ipc_thread_rcv_data(hcc_handler *hcc, hcc_trans_queue *queue)
{
    td_u32 i;
    hcc_ipc_dma_info_t dma_info[HCC_DMA_TRANS_MAX] = {0};
    td_u32 total = 0;
    struct osal_list_head *list_tmp;
    hcc_ipc_rx_queue_info_t *rx_queue_info = &g_hcc_ipc_drv->rx_queue_info[queue->queue_id];
    hcc_data_queue *rx_buf_head = &rx_queue_info->rx_buf_head;
    unsigned long flags;

    if (hcc_is_list_empty(rx_buf_head)) {
        return;
    }
    if (rx_queue_info->alloc_cnt < HCC_DMA_TRANS_MAX) {
        hcc_ipc_thread_rcv_alloc_data(hcc, rx_queue_info, queue);
    }
    if (rx_queue_info->alloc_cnt == 0) {
        return;
    }
    hcc_set_test_timestamp(TEST_TIME_START);
    osal_spin_lock_irqsave(&rx_buf_head->data_queue_lock, &flags);
    /* 下面判断和dma status操作需要在锁保护中 */
    if (hcc_ipc_queue_unlock_set_dma_busy(HCC_DIR_RX, queue)) {
        osal_spin_unlock_irqrestore(&rx_buf_head->data_queue_lock, &flags);
        return;
    }

    list_tmp = rx_buf_head->data_queue.next;
    for (i = 0; i < HCC_DMA_TRANS_MAX; i++) {
        hcc_unc_struc *unc_buf = TD_NULL;
        if ((list_tmp != TD_NULL) && (list_tmp != rx_queue_info->alloc_list_head)) {
            unc_buf = (hcc_unc_struc *)osal_list_entry(list_tmp, hcc_unc_struc, list);
            list_tmp = list_tmp->next;
        }
        if (unc_buf == TD_NULL) {
            break;
        }
        hcc_ipc_set_dma_info(&dma_info[i], unc_buf->addr, unc_buf->buf, unc_buf->length);
        total++;
    }
    osal_spin_unlock_irqrestore(&rx_buf_head->data_queue_lock, &flags);

    if (total > 0) {
        if (hcc_ipc_data_transfer(dma_info, total, queue->queue_id, HCC_DIR_RX) != EXT_ERR_SUCCESS) {
            hcc_ipc_free_unclist(hcc, rx_buf_head, total);
            hcc_ipc_queue_clear_dma_status(HCC_DIR_RX, queue);
        } else if (hcc_check_pre_req_queue(queue)) {
            g_hcc_ipc_drv->stats[HCC_DIR_RX][total - 1]++;
        }
    } else {
        hcc_ipc_queue_clear_dma_status(HCC_DIR_RX, queue);
    }
    hcc_set_test_timestamp(TEST_TIME_END);
}

STATIC td_void hcc_ipc_thread_send_data(hcc_handler *hcc, hcc_trans_queue *queue)
{
    td_u32 i;
    hcc_ipc_dma_info_t dma_info[HCC_DMA_TRANS_MAX];
    td_u32 total = 0;
    struct osal_list_head *list_tmp;
    hcc_data_queue *tx_buf_head = &g_hcc_ipc_drv->tx_buf_head[queue->queue_id];
    unsigned long flags;

    if (hcc_is_list_empty(tx_buf_head)) {
        return;
    }

    hcc_set_test_timestamp(TEST_TIME_START);
    osal_spin_lock_irqsave(&tx_buf_head->data_queue_lock, &flags);
    /* 下面dma status操作需要在锁保护中 */
    if (hcc_ipc_queue_unlock_set_dma_busy(HCC_DIR_TX, queue)) {
        osal_spin_unlock_irqrestore(&tx_buf_head->data_queue_lock, &flags);
        return;
    }

    list_tmp = tx_buf_head->data_queue.next;
    for (i = 0; i < HCC_DMA_TRANS_MAX; i++) {
        hcc_unc_struc *unc_buf = hcc_ipc_list_unlock_get_node(tx_buf_head, &list_tmp);
        if (unc_buf == TD_NULL) {
            break;
        }
        hcc_ipc_set_dma_info(&dma_info[i], unc_buf->buf, unc_buf->addr, unc_buf->length);
        total++;
    }
    osal_spin_unlock_irqrestore(&tx_buf_head->data_queue_lock, &flags);

    if (total > 0) {
        if (hcc_ipc_data_transfer(dma_info, total, queue->queue_id, HCC_DIR_TX) != EXT_ERR_SUCCESS) {
            hcc_ipc_free_unclist(hcc, &queue->send_head, total);
            hcc_ipc_queue_clear_dma_status(HCC_DIR_TX, queue);
        }
    } else {
        hcc_ipc_queue_clear_dma_status(HCC_DIR_TX, queue);
    }
    hcc_set_test_timestamp(TEST_TIME_END);
}

STATIC td_void hcc_ipc_thread_handle_queue(hcc_handler *hcc, TD_CONST hcc_queue_cfg *q_cfg, td_u8 cfg_id)
{
    hcc_trans_queue *queue = &hcc->hcc_resource.hcc_queues[q_cfg[cfg_id].dir][q_cfg[cfg_id].queue_id];
    if ((q_cfg[cfg_id].dir == HCC_DIR_TX) &&  (!hcc_check_pre_req_queue(queue))) {
        hcc_ipc_thread_send_data(hcc, queue);
    } else if (q_cfg[cfg_id].dir == HCC_DIR_RX) {
        hcc_ipc_thread_rcv_data(hcc, queue);
    }
}

STATIC td_s32 hcc_ipc_data_thread(td_void *data)
{
    td_u8 i;
    hcc_handler *hcc = (hcc_handler *)data;
    hcc_queue_cfg *q_cfg = hcc->que_cfg;

    while (1) {
        td_s32 ret = osal_wait_interruptible(&g_hcc_ipc_drv->data_transfer_wait, hcc_ipc_thread_wait_cond, TD_NULL);
        if (ret < 0) {
            break;
        }
        for (i = 0; i < (hcc->que_max_cnt << 1); i++) {
            if (q_cfg[i].queue_id >= hcc->que_max_cnt) {
                hcc_printf_err_log("hcc_ipc_data err qid:%d\n", q_cfg[i].queue_id);
                continue;
            }
            hcc_ipc_thread_handle_queue(hcc, q_cfg, i);
        }
    }
    return 0;
}

STATIC td_u32 hcc_ipc_tx_proc(hcc_bus *bus, hcc_trans_queue *queue, td_u16 *remain_pkt_nums)
{
    td_u32 total_send = 0;
    td_u16 send_cnt;
    hcc_handler *hcc = (hcc_handler *)(bus->hcc);
    if (hcc == TD_NULL || g_hcc_ipc_drv == TD_NULL || g_hcc_ipc_drv->bus == TD_NULL ||
        g_hcc_ipc_drv->bus->hcc == TD_NULL) {
        hcc_printf_err_log("host ipc dev's hcc handler is null!\r\n");
        return EXT_ERR_FAILURE;
    }
    if (hcc_check_pre_req_queue(queue)) {
        hcc_set_test_timestamp(TEST_TIME_START);
        send_cnt = (*remain_pkt_nums > HCC_DMA_TRANS_MAX) ? HCC_DMA_TRANS_MAX : *remain_pkt_nums;
        total_send = hcc_ipc_send_pre_req_data(queue, send_cnt);
        hcc_set_test_timestamp(TEST_TIME_END);
    } else {
        total_send = *remain_pkt_nums > IPC_MEM_MSG_MAX ? IPC_MEM_MSG_MAX : *remain_pkt_nums;
        total_send = hcc_ipc_send_request_mem(queue, total_send);
    }
    if (total_send > 0) {
        *remain_pkt_nums = (*remain_pkt_nums > total_send) ? (*remain_pkt_nums - total_send) : 0;
        return EXT_ERR_SUCCESS;
    } else {
        hcc_printf("hcc_ipc_tx_proc fail Q[%u] Len[info-%u, send-%u, tx-%u], stat:0x%x, unc:%u\r\n",
            queue->queue_id, queue->queue_info.qlen, queue->send_head.qlen,
            g_hcc_ipc_drv->tx_buf_head[queue->queue_id].qlen,
            g_hcc_ipc_drv->dma_state, hcc->unc_pool_head->qlen);
        return EXT_ERR_FAILURE;
    }
}

td_void hcc_ipc_msg_rx_callback(td_u8 *payload_addr, td_u32 payload_len)
{
    td_u32 msg;

    if (payload_addr == TD_NULL || payload_len != sizeof(td_u32)) {
        return;
    }
    msg = ((td_u32 *)payload_addr)[0];
    if (msg < HCC_RX_MAX_MESSAGE) {
        hcc_bus_call_rx_message(g_hcc_ipc_drv->bus, (h2d_msg_type)msg);
    }
}

STATIC td_void hcc_ipc_data_rx_callback(td_u8 *payload_addr, td_u32 payload_len)
{
    td_u8 type;
#ifdef HCC_PRINT_PERFORM
    td_u64 t1, t2;
    t1 = hcc_test_get_us();
#endif
    if (payload_addr == TD_NULL) {
        return;
    }
    type = payload_addr[0];
    if (type == HCC_IPC_MEM_REPLY) {
        hcc_ipc_mem_reply_msg(payload_addr, payload_len);
    } else if (type == HCC_IPC_MEM_RX_START) {
        hcc_ipc_mem_rx_start_msg(payload_addr, payload_len);
    }
#ifdef HCC_PRINT_PERFORM
    t2 = hcc_test_get_us();
    hcc_debug("T5:%llu\r\n", hcc_calc_time_us(t1, t2));
#endif
}

STATIC td_s32 hcc_ipc_rx_info_init(hcc_ipc_rx_queue_info_t *rx_queue_info, td_u8 que_cnt)
{
    td_u8 i;
    for (i = 0; i < que_cnt; i++) {
        if (hcc_list_head_init(&rx_queue_info[i].rx_buf_head) != EXT_ERR_SUCCESS) {
            return EXT_ERR_FAILURE;
        }
        rx_queue_info[i].alloc_cnt = 0;
        rx_queue_info[i].alloc_list_head = &rx_queue_info[i].rx_buf_head.data_queue;
    }
    return EXT_ERR_SUCCESS;
}

STATIC td_s32 hcc_ipc_queue_init(hcc_data_queue *data_queue, td_u8 que_cnt)
{
    td_u8 i;
    for (i = 0; i < que_cnt; i++) {
        if (hcc_list_head_init(&data_queue[i]) != EXT_ERR_SUCCESS) {
            return EXT_ERR_FAILURE;
        }
    }
    return EXT_ERR_SUCCESS;
}

STATIC td_void hcc_ipc_queue_destroy(hcc_data_queue *data_queue, td_u8 que_cnt)
{
    td_u8 i;
    for (i = 0; i < que_cnt; i++) {
        osal_spin_lock_destroy(&data_queue[i].data_queue_lock);
    }
}

STATIC td_void hcc_ipc_rx_info_destroy(hcc_ipc_rx_queue_info_t *rx_queue_info, td_u8 que_cnt)
{
    td_u8 i;
    for (i = 0; i < que_cnt; i++) {
        osal_spin_lock_destroy(&rx_queue_info[i].rx_buf_head.data_queue_lock);
        rx_queue_info[i].alloc_cnt = 0;
        rx_queue_info[i].alloc_list_head = &rx_queue_info[i].rx_buf_head.data_queue;
    }
}

STATIC td_void hcc_ipc_drv_register(td_void)
{
    ipc_rx_handler_info_t data_handle;
    ipc_rx_handler_info_t msg_handle;

    data_handle.msg_id = IPC_MSG_CORE1_0_CMD;
    data_handle.cb = hcc_ipc_data_rx_callback;
    uapi_ipc_register_rx_handler(&data_handle);

    msg_handle.msg_id = IPC_MSG_CORE1_2_CMD;
    msg_handle.cb = hcc_ipc_msg_rx_callback;
    uapi_ipc_register_rx_handler(&msg_handle);
}

STATIC td_void hcc_ipc_res_deinit(td_void)
{
    if (g_hcc_ipc_drv != TD_NULL) {
        hcc_ipc_queue_destroy(g_hcc_ipc_drv->tx_buf_head, g_hcc_ipc_drv->que_len);
        hcc_ipc_rx_info_destroy(g_hcc_ipc_drv->rx_queue_info, g_hcc_ipc_drv->que_len);
        osal_wait_destroy(&g_hcc_ipc_drv->data_transfer_wait);
        osal_kthread_destroy(g_hcc_ipc_drv->data_transfer_task, 1);
        if (g_hcc_ipc_drv->rsv_buf != TD_NULL) {
            osal_kfree(g_hcc_ipc_drv->rsv_buf);
        }
        osal_kfree(g_hcc_ipc_drv);
    }
}

STATIC td_void hcc_ipc_free_tx_list(hcc_handler *hcc, hcc_trans_queue *queue)
{
    hcc_unc_struc *unc_buf;
    unc_buf = hcc_list_dequeue(&g_hcc_ipc_drv->tx_buf_head[queue->queue_id]);
    while (unc_buf != TD_NULL) {
        hcc_free_unc_buf(hcc, unc_buf);
        unc_buf = hcc_list_dequeue(&g_hcc_ipc_drv->tx_buf_head[queue->queue_id]);
    }

    unc_buf = hcc_list_dequeue(&queue->send_head);
    while (unc_buf != TD_NULL) {
        hcc_free_unc_buf(hcc, unc_buf);
        unc_buf = hcc_list_dequeue(&queue->send_head);
    }
}

td_void hcc_ipc_clear_premem(td_void)
{
    td_u8 i;
    hcc_handler *hcc = (hcc_handler *)g_hcc_ipc_drv->bus->hcc;
    hcc_queue_cfg *q_cfg = hcc->que_cfg;

    hcc_ipc_send_msg(hcc->bus, HCC_IPC_MEM_CLEAR_PREMEM);
    for (i = 0; i < (hcc->que_max_cnt << 1); i++) {
        hcc_trans_queue *queue = &hcc->hcc_resource.hcc_queues[q_cfg[i].dir][q_cfg[i].queue_id];
        if (hcc_check_pre_req_queue(queue)) {
            queue->queue_ctrl->transfer_mode = HCC_IPC_TRANS_POSTMEM;
            if (q_cfg[i].dir == HCC_DIR_TX) {
                hcc_ipc_free_tx_list(hcc, queue);
            }
        }
    }
}

STATIC hcc_ipc_bus_drv_t *hcc_ipc_res_init(hcc_handler *hcc)
{
    hcc_ipc_bus_drv_t *ipc_drv;
    size_t alloc_len;

    alloc_len = sizeof(hcc_ipc_bus_drv_t) +
        ((sizeof(hcc_data_queue) + sizeof(hcc_ipc_rx_queue_info_t)) * hcc->que_max_cnt);
    ipc_drv = osal_kmalloc(alloc_len, OSAL_GFP_KERNEL);
    if (ipc_drv == TD_NULL) {
        hcc_printf_err_log("hcc host ipc alloc err\r\n");
        return TD_NULL;
    }
    (td_void)memset_s(ipc_drv, alloc_len, 0, alloc_len);
    g_hcc_ipc_drv = ipc_drv;
    hcc_ipc_drv_set(ipc_drv);
    ipc_drv->que_len = hcc->que_max_cnt;
    /* 队列保存发送内存地址 */
    ipc_drv->tx_buf_head = (hcc_data_queue *)(ipc_drv + 1);
    /* 队列保存接收内存地址 */
    ipc_drv->rx_queue_info = (hcc_ipc_rx_queue_info_t *)(ipc_drv->tx_buf_head + ipc_drv->que_len);
    if (hcc_ipc_queue_init(ipc_drv->tx_buf_head, ipc_drv->que_len) != EXT_ERR_SUCCESS) {
        osal_kfree(ipc_drv);
        hcc_printf_err_log("hcc host ipc tx queue err\r\n");
        return TD_NULL;
    }
    if (hcc_ipc_rx_info_init(ipc_drv->rx_queue_info, ipc_drv->que_len) != EXT_ERR_SUCCESS) {
        osal_kfree(ipc_drv);
        hcc_printf_err_log("hcc host ipc rx queue err\r\n");
        return TD_NULL;
    }

    osal_wait_init(&ipc_drv->data_transfer_wait);
    ipc_drv->data_transfer_task = osal_kthread_create(hcc_ipc_data_thread, hcc, "hcc ipc",
        HCC_IPC_THREAD_STACK_SIZE);
    if (ipc_drv->data_transfer_task == TD_NULL) {
        hcc_ipc_res_deinit();
        hcc_printf_err_log("hcc host ipc task err\r\n");
        return TD_NULL;
    }

    ipc_drv->rsv_buf = osal_kmalloc(HCC_RX_RSV_BUF_LEN, OSAL_GFP_KERNEL);
    if (ipc_drv->rsv_buf == TD_NULL) {
        hcc_ipc_res_deinit();
    }
    OSAL_INIT_LIST_HEAD(&ipc_drv->addr_list);
    osal_kthread_set_priority(ipc_drv->data_transfer_task, HCC_IPC_TASK_PRIORITY);
    return ipc_drv;
}

STATIC bus_dev_ops g_ipc_opt_ops = {
    .tx_proc = hcc_ipc_tx_proc,
    .send_and_clear_msg = hcc_ipc_send_msg,
    .is_busy = hcc_ipc_is_busy,
    .flow_off = hcc_ipc_flowctrl_off,
    .flow_on = hcc_ipc_flowctrl_on,
};

STATIC td_void hcc_ipc_drv_dfx(td_void)
{
    td_u32 i;
    hcc_handler *hcc;
    hcc_queue_cfg *q_cfg;
    hcc_ipc_bus_drv_t *ipc_drv = g_hcc_ipc_drv;
    if (ipc_drv == TD_NULL) {
        return;
    }

    hcc = (hcc_handler *)ipc_drv->bus->hcc;
    q_cfg = hcc->que_cfg;
    hcc_dfx_print("\r\ndma_state:0x%x, rsv_drop:%u, flow ctrl:%d, addrlist:%u, addr_list_times:%u, premem:%u\r\n",
        ipc_drv->dma_state, ipc_drv->rsv_drop, ipc_drv->flow_on,
        ipc_drv->addr_list_len, ipc_drv->addr_list_times, g_premem_addr_add_cnt);

    for (i = 0; i < HCC_DMA_TRANS_MAX; i++) {
        hcc_dfx_print("premem[%u] tx:%u-%u, rx:%u-%u\r\n", i,
            ipc_drv->stats[HCC_DIR_TX][i], ipc_drv->cmplt_stats[HCC_DIR_TX][i],
            ipc_drv->stats[HCC_DIR_RX][i], ipc_drv->cmplt_stats[HCC_DIR_RX][i]);
    }
    for (i = 0; i < HCC_DMA_TRANS_MAX; i++) {
        hcc_dfx_print("postmem[%u] tx:%u, rx:%u\r\n", i,
            ipc_drv->msg_stats[HCC_DIR_TX][i], ipc_drv->msg_stats[HCC_DIR_RX][i]);
    }

    for (i = 0; i < ipc_drv->que_len; i++) {
        td_u8 queue_id = q_cfg[i << 1].queue_id;
        if (queue_id >= ipc_drv->que_len) {
            hcc_printf_err_log("hcc ipc dfx q:%d\r\n", queue_id);
            continue;
        }

        hcc_dfx_print("queue[%u] len[tx-%u, rx-%u], alloc_cnt:%u\r\n", queue_id, ipc_drv->tx_buf_head[queue_id].qlen,
            ipc_drv->rx_queue_info[queue_id].rx_buf_head.qlen, ipc_drv->rx_queue_info[queue_id].alloc_cnt);
    }
    hcc_dfx_print("\r\n");
}

hcc_bus *hcc_adapt_ipc_load(hcc_handler *hcc)
{
    hcc_bus *bus;

    if (hcc_ipc_res_init(hcc) == TD_NULL) {
        hcc_printf_err_log("hcc host ipc res fail\r\n");
        return TD_NULL;
    }

    bus = hcc_alloc_bus();
    if (bus == TD_NULL) {
        hcc_ipc_res_deinit();
        hcc_printf_err_log("hcc host ipc bus fail\r\n");
        return TD_NULL;
    }
    hcc_set_bus_ops(bus, &g_ipc_opt_ops);
    bus->bus_type = HCC_BUS_IPC;
    bus->data = g_hcc_ipc_drv;
    bus->max_trans_size = IPC_MAX_XFER_LEN;
    bus->addr_align = HCC_ADDR_ALIGN_WORD;
    bus->len_align = HCC_DATA_LEN_ALIGN_WORD;
    bus->max_assemble_cnt = HCC_ADAPT_BUS_ASSEMBLE_CNT_MIN;
    bus->descr_align_bit = HCC_ADAPT_BUS_DESCR_ALIGN_BIT_MIN;
    bus->state = 1;
    bus->hcc_bus_dfx = hcc_ipc_drv_dfx;

    g_hcc_ipc_drv->bus = bus;
    /* handler初始化完成后注册中断回调 */
    hcc_ipc_drv_register();
    return bus;
}

td_void hcc_adapt_ipc_unload(td_void)
{
    hcc_free_bus(g_hcc_ipc_drv->bus);
    hcc_ipc_res_deinit();
}
#endif
