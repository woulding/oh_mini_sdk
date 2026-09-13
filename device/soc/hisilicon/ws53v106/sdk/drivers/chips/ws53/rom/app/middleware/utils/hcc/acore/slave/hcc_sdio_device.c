/*
 * Copyright (c) CompanyNameMagicTag 2022-2023. All rights reserved.
 * Description: sdio device driver
 * Author: CompanyName
 * Create: 2022-10-27
 */

#ifdef CONFIG_HCC_SUPPORT_SDIO
#include "hcc_sdio_device_rom.h"
#include "hcc_comm.h"
#include "hcc_list.h"
#include "hcc_cfg.h"
#include "hcc_adapt.h"
#include "hal_sdio.h"
#include "sdio_slave.h"
#include "hcc_bus.h"
#include "securec.h"
#include "tcxo.h"
#ifdef BOARD_ASIC
#include "clock_recover.h"
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_HCC_SDIO_DEVICE_C

#undef THIS_MOD_ID
#define THIS_MOD_ID LOG_PFMODULE

enum {
    SDIO_RST_INIT,
    SDIO_RST_REINIT,
};
void sdio_patch_modify_hal_init(void);

#define HCC_SDIO_TX_BUSY_WAIT_INTERVAL 100
#define SDIO_RESET_WAIT_US 5

STATIC void hcc_sdio_reset_tx_status(sdio_bus_t bus)
{
    sdio_status_info_t status_info = {0};

    if (bus >= SDIO_BUS_MAX_NUM) {
        return;
    }

    (td_void)uapi_sdio_slave_get_status(bus, &status_info);
    status_info.tx_status = 0;
    (td_void)uapi_sdio_slave_set_status(bus, &status_info);
}

STATIC td_u32 hcc_sdio_tx_proc(hcc_bus *bus, hcc_trans_queue *queue, td_u16 *remain_pkt_nums)
{
    td_u32 ret;
    hcc_handler *hcc = (hcc_handler *)bus->hcc;
    if (get_sdio_data_ctl()->sdio_bus.state == 0) {
        hcc_list_free(hcc, &queue->queue_info);
        hcc_list_free(hcc, &queue->send_head);
        return EXT_ERR_FAILURE;
    }
    ret = sdio_tx_proc(bus, queue, remain_pkt_nums, sdio_wifi_tx_queue_sched, hcc_list_restore);
    if (ret == EXT_ERR_SUCCESS) {
        hcc->hcc_resource.tx_fail_cnt = 0;
    } else {
        hcc->hcc_resource.tx_fail_cnt++;
        if (hcc->hcc_resource.tx_fail_cnt >= hcc->hcc_resource.tx_fail_num_limit) {
            hcc_debug("sdio tx drop:t[%u],Q[%u],S[%u],QID[%u]\r\n", hcc->hcc_resource.tx_fail_num_limit,
                queue->queue_info.qlen, queue->send_head.qlen, queue->queue_id);
            hcc->hcc_resource.tx_fail_cnt = 0;
            osal_msleep(HCC_SDIO_TX_BUSY_WAIT_INTERVAL);
        }
    }
    return ret;
}

osal_void hcc_sdio_stop_xfer(osal_void)
{
    get_sdio_data_ctl()->sdio_bus.state = 0;
}

osal_void hcc_sdio_clear_xfer(const hcc_bus *hcc_bus)
{
    td_u8 i;
    hcc_trans_queue *queue = TD_NULL;
    hcc_queue_cfg *q_cfg;

    hcc_handler *hcc = (hcc_handler *)hcc_bus->hcc;
    if (hcc == TD_NULL) {
        return;
    }

    hcc_sdio_readover_callback();
    hcc_sdio_writeover_callback();

    q_cfg = hcc->que_cfg;

    for (i = 0; i < (hcc->que_max_cnt << 1); i++) {
        if (q_cfg[i].queue_id >= hcc->que_max_cnt) {
            continue;
        }
        queue = &hcc->hcc_resource.hcc_queues[q_cfg[i].dir][q_cfg[i].queue_id];
        hcc_list_free(hcc, &queue->queue_info);
        hcc_list_free(hcc, &queue->send_head);
    }
}

static td_u32 g_sdio_rst_status = SDIO_RST_INIT;
STATIC td_s32 hcc_sdio_resume_xfer(osal_void)
{
    get_sdio_data_ctl()->sdio_bus.state = 1;
    /* 业务恢复之后允许响应RST中断处理 */
    g_sdio_rst_status = SDIO_RST_INIT;
    return EXT_ERR_SUCCESS;
}

STATIC td_void hcc_sdio_soft_rst_callback(td_void)
{
    hcc_debug("sdio rst:%d, sts:%u\r\n", get_sdio_data_ctl()->sdio_bus.state, g_sdio_rst_status);
    uapi_sdio_slave_soft_reset(SDIO_BUS_0);
    uapi_tcxo_delay_us(SDIO_RESET_WAIT_US);
    uapi_sdio_slave_reinit(SDIO_BUS_0);
    hcc_sdio_reset_tx_status(SDIO_BUS_0);
    hcc_debug("sdio rst:%d\r\n", get_sdio_data_ctl()->sdio_bus.state);
}

static errcode_t hcc_sdio_slave_init(sdio_bus_t bus)
{
#ifdef BOARD_ASIC
    sdio_clock_set(true);
#endif
    return uapi_sdio_slave_init(bus);
}

STATIC td_s32 hcc_sdio_reinit(const hcc_bus *hcc_bus)
{
    errcode_t ret;
    uapi_unused(hcc_bus);
    hcc_debug("wait card\r\n");
    g_sdio_rst_status = SDIO_RST_REINIT;
    uapi_sdio_slave_soft_reset(SDIO_BUS_0);
    hcc_sdio_clear_xfer(hcc_bus);
    uapi_sdio_slave_memory_init(SDIO_BUS_0);
    hcc_sdio_rx_assem_info_reset();
    hcc_sdio_reset_tx_status(SDIO_BUS_0);
    ret = hcc_sdio_slave_init(SDIO_BUS_0);
    hcc_debug("wait card ret=%d\r\n", ret);
    return (td_s32)ret;
}

td_u32 hcc_sdio_writeover_callback_patch(td_void)
{
    sdio_data_ctl_stru *sdio_ctl = get_sdio_data_ctl();
    if (sdio_ctl == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    if (sdio_ctl->rx_aggr_info.trans_len == HISDIO_HOST2DEV_SCATT_SIZE) {
        /* receive ctrl pkt, clear aggr num */
        hcc_sdio_rx_assem_info_reset();
    }
    return hcc_sdio_writeover_callback();
}

/* 系统启动与HOST交互 */
hcc_bus *hcc_sdio_device_init(sdio_bus_t bus)
{
    td_s32 ret;
    sdio_callback_func_t funs = {0};
    sdio_data_ctl_stru *sdio_data_ctl;
    bus_dev_ops sdio_bus_ops = {0};

    sdio_bus_ops.tx_proc = hcc_sdio_tx_proc;
    sdio_bus_ops.send_and_clear_msg = hcc_sdio_send_message;
    sdio_bus_ops.is_busy = hcc_sdio_is_busy;
    sdio_bus_ops.update_credit = hcc_sdio_update_credit;
    sdio_bus_ops.stop_xfer = hcc_sdio_stop_xfer;
    sdio_bus_ops.resume_xfer = hcc_sdio_resume_xfer;
    sdio_bus_ops.reinit = hcc_sdio_reinit;

    ret = hcc_sdio_soft_res_init(&sdio_bus_ops);
    if (ret != EXT_ERR_SUCCESS) {
        return (hcc_bus *)TD_NULL;
    }
    sdio_data_ctl = get_sdio_data_ctl();
    sdio_data_ctl->dev_bus = bus;

    funs.read_start_callback = hcc_sdio_readstart_callback;
    funs.read_over_callback = hcc_sdio_readover_callback;
    funs.read_err_callback = hcc_sdio_readerr_callback;
    funs.write_start_callback = hcc_sdio_writestart_callback;
    funs.write_over_callback = hcc_sdio_writeover_callback_patch;
    funs.process_msg_callback = hcc_sdio_msg_callback;
    funs.soft_rst_callback = hcc_sdio_soft_rst_callback;
    if (uapi_sdio_slave_register_callback(bus, &funs) == ERRCODE_SUCC) {
        hcc_printf("hcc_sdio_device_init succ ret=%d\r\n", ret);
        return &(sdio_data_ctl->sdio_bus);
    } else {
        osal_kfree(sdio_data_ctl);
        return TD_NULL;
    }
}

td_void hcc_unc_buf_enqueue_cb(hcc_handler *hcc, hcc_queue_type queue_id, hcc_unc_struc *unc_buf)
{
    hcc_trans_queue *queue = TD_NULL;
    if (hcc->hcc_state != HCC_ON) {
        hcc_adapt_mem_free(hcc, unc_buf);
        return;
    }
    queue = &hcc->hcc_resource.hcc_queues[HCC_DIR_RX][queue_id];
    hcc_list_add_tail(&queue->queue_info, unc_buf);
#ifndef CONFIG_HCC_SUPPORT_NON_OS
    if (hcc->hcc_resource.rx_thread_enable == 0) {
        hcc_rx_queue_proc(hcc, queue);
    }
#endif
}

hcc_bus *hcc_adapt_sdio_load(hcc_handler *hcc)
{
    uapi_unused(hcc);

    sdio_patch_modify_hal_init();

    /* register hal func */
    sdio_port_register_hal_funcs(SDIO_BUS_0);
    hcc_bus *hcc_bus = hcc_sdio_device_init(SDIO_BUS_0);
    if (hcc_bus == TD_NULL) {
        hcc_printf_err_log("hcc_sdio_device_init fail\r\n");
    }
    return hcc_bus;
}

osal_void hcc_adapt_sdio_init(td_void)
{
    hcc_debug("wait card\r\n");

    if (hcc_sdio_slave_init(SDIO_BUS_0) == ERRCODE_SUCC) {
        hcc_debug("wait card ok\r\n");
    } else {
        hcc_printf_err_log("sdio slave init fail\r\n");
    }
}

osal_void hcc_adapt_sdio_unload(osal_void)
{
    sdio_data_ctl_stru *sdio_data_ctl = get_sdio_data_ctl();

    if (sdio_data_ctl != TD_NULL) {
        uapi_sdio_slave_deinit(sdio_data_ctl->dev_bus);
        osal_kfree(sdio_data_ctl);
        set_sdio_data_ctl(TD_NULL);
    }
    return;
}

#ifdef HCC_SDIO_DEBUG
td_void hcc_sdio_device_info_dump(td_void)
{
    td_u16 i;
    sdio_data_ctl_stru *sdio_ctl = get_sdio_data_ctl();
    if (sdio_ctl == TD_NULL) {
        return;
    }

    hcc_dfx_print("rx_pkt_miss: %d\r\n", sdio_ctl->sdio_device_stats.sdio_rx_pkt_miss);
    hcc_dfx_print("send_data_cnt: %d\r\n", sdio_ctl->sdio_device_stats.sdio_send_data_cnt);
    hcc_dfx_print("rd_start_cnt: %d\r\n", sdio_ctl->sdio_device_stats.sdio_rd_start_cnt);
    hcc_dfx_print("rd_over_cnt: %d\r\n", sdio_ctl->sdio_device_stats.sdio_rd_over_cnt);
    hcc_dfx_print("wr_start_cnt: %d\r\n", sdio_ctl->sdio_device_stats.sdio_wr_start_cnt);
    hcc_dfx_print("wr_over_cnt: %d\r\n", sdio_ctl->sdio_device_stats.sdio_wr_over_cnt);
    hcc_dfx_print("h2d_pkt_cnt: %d\r\n", sdio_ctl->sdio_device_stats.sdio_h2d_pkt_cnt);
    hcc_dfx_print("d2h_pkt_cnt: %d\r\n", sdio_ctl->sdio_device_stats.sdio_d2h_pkt_cnt);
    hcc_dfx_print("rx_buf_cnt:%d\r\n", sdio_ctl->sdio_device_stats.sdio_rx_buf_cnt);

    hcc_dfx_print("RX num:%d total_len:%d trans_len:%d\r\n", sdio_ctl->rx_aggr_info.aggr_rx_num,
        sdio_ctl->rx_aggr_info.rx_aggr_total_len, sdio_ctl->rx_aggr_info.trans_len);
    for (i = 0; i < sdio_ctl->rx_aggr_info.aggr_rx_num; i++) {
        hcc_debug("rx idx:%d len:%d\r\n", i, sdio_ctl->rx_aggr_info.sdio_rx_aggr[i].rx_pkt_bytes);
    }

    hcc_dfx_print("TX num:%d total_len:%d\r\n", sdio_ctl->tx_aggr_info.aggr_tx_num,
        sdio_ctl->tx_aggr_info.tx_aggr_total_len);
    for (i = 0; i < sdio_ctl->tx_aggr_info.aggr_tx_num; i++) {
        hcc_debug("tx idx:%d len:%d\r\n", i, sdio_ctl->tx_aggr_info.sdio_tx_aggr[i].tx_pkt_bytes);
    }
    hcc_dfx_print("panic_addr 0x%x\r\n", sdio_ctl->sdio_panic_addr);
}
#endif

td_void hcc_sdio_msg_callback(td_u32 msg)
{
    td_u32 i;
    td_u32 tmp_msg = msg;
    sdio_data_ctl_stru *sdio_ctl = get_sdio_data_ctl();
    /* 遍历 bit 0~15 */
    for (i = 0; i < HCC_RX_MAX_MESSAGE; i++) {
        if (tmp_msg == 0) {
            break;
        }
        if ((tmp_msg & ((td_u32)(1U << i))) != 0) {
            tmp_msg &= ~((td_u32)(1U << i));
            hcc_bus_call_rx_message(&(sdio_ctl->sdio_bus), (h2d_msg_type)i);
        }
    }
}

td_void hcc_sdio_readerr_callback(td_void)
{
    sdio_data_ctl_stru *sdio_data_ctl = get_sdio_data_ctl();
    sdio_data_ctl->sdio_device_stats.sdio_rd_error_cnt++;
}

STATIC td_bool hcc_sdio_rx_queue_is_busy(hcc_handler *hcc)
{
    td_u8 i;
    for (i = 0; i < hcc->que_max_cnt; i++) {
        hcc_trans_queue *queue = &hcc->hcc_resource.hcc_queues[HCC_DIR_RX][i];
        if (!hcc_is_list_empty(&queue->queue_info)) {
            return TD_TRUE;
        }
    }
    return TD_FALSE;
}

STATIC td_bool hcc_sdio_tx_queue_is_busy(hcc_handler *hcc)
{
    td_u8 i;
    for (i = 0; i < hcc->que_max_cnt; i++) {
        hcc_trans_queue *queue = &hcc->hcc_resource.hcc_queues[HCC_DIR_TX][i];
        if (!hcc_is_list_empty(&queue->queue_info) || !hcc_is_list_empty(&queue->send_head)) {
            return TD_TRUE;
        }
    }
    return TD_FALSE;
}

td_bool hcc_sdio_is_busy(hcc_queue_dir chan)
{
    sdio_data_ctl_stru *sdio_data_ctl = get_sdio_data_ctl();
    hcc_handler *hcc = (hcc_handler *)sdio_data_ctl->sdio_bus.hcc;
    if (chan == HCC_DIR_RX) {
        return hcc_sdio_rx_queue_is_busy(hcc);
    }
    return hcc_sdio_tx_queue_is_busy(hcc);
}

td_void hcc_sdio_dump_reg_and_panic(td_void)
{
#ifdef HCC_SDIO_DEBUG
    hcc_sdio_device_info_dump();
#endif
}

td_s32 hcc_sdio_soft_res_init(bus_dev_ops *sdio_bus_ops)
{
    sdio_data_ctl_stru *sdio_ctl = (sdio_data_ctl_stru *)osal_kmalloc(sizeof(sdio_data_ctl_stru), OSAL_GFP_KERNEL);
    if (sdio_ctl == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    memset_s(sdio_ctl, sizeof(sdio_data_ctl_stru), 0, sizeof(sdio_data_ctl_stru));

    sdio_ctl->sdio_bus_ops.tx_proc = sdio_bus_ops->tx_proc;
    sdio_ctl->sdio_bus_ops.send_and_clear_msg = sdio_bus_ops->send_and_clear_msg;
    sdio_ctl->sdio_bus_ops.is_busy = sdio_bus_ops->is_busy;
    sdio_ctl->sdio_bus_ops.update_credit = sdio_bus_ops->update_credit;
    sdio_ctl->sdio_bus_ops.flow_on = sdio_bus_ops->flow_on;
    sdio_ctl->sdio_bus_ops.flow_off = sdio_bus_ops->flow_off;
    sdio_ctl->sdio_bus_ops.reinit = sdio_bus_ops->reinit;
    sdio_ctl->sdio_bus_ops.stop_xfer = sdio_bus_ops->stop_xfer;
    sdio_ctl->sdio_bus_ops.resume_xfer = sdio_bus_ops->resume_xfer;

    sdio_ctl->descr_control_func[HCC_DESCR_ASSEM_RESET] = hcc_sdio_rx_assem_info_reset;
    sdio_ctl->sdio_bus.rsv_buf = &(sdio_ctl->sdio_hcc_unc_rsv_buf);
    sdio_ctl->sdio_bus.rsv_buf->buf = sdio_ctl->rsv_data_buf;
    sdio_ctl->sdio_bus.rsv_buf->length = BUS_RESERVE_BUFF;
    sdio_ctl->sdio_bus.tx_sched_count = HISDIO_DEV2HOST_SCATT_MAX;
    sdio_ctl->sdio_bus.bus_type = HCC_BUS_SDIO;
    sdio_ctl->sdio_bus.max_trans_size = 0xFFF;
    sdio_ctl->sdio_bus.addr_align = HISDIO_D2H_SCATT_BUFFADDR_ALIGN;
    sdio_ctl->sdio_bus.len_align = HISDIO_D2H_SCATT_BUFFLEN_ALIGN;
    sdio_ctl->sdio_bus.max_assemble_cnt = HISDIO_DEV2HOST_SCATT_MAX;
    sdio_ctl->sdio_bus.descr_align_bit = HISDIO_D2H_SCATT_BUFFLEN_ALIGN_BITS;
    sdio_ctl->current_queue_id = HCC_QUEUE_COUNT;
    sdio_ctl->sdio_bus.state = 1;
    sdio_ctl->sdio_bus.hcc_bus_dfx = hcc_sdio_dump_reg_and_panic;
    hcc_set_bus_ops(&sdio_ctl->sdio_bus, &(sdio_ctl->sdio_bus_ops));
    set_sdio_data_ctl(sdio_ctl);
    return EXT_ERR_SUCCESS;
}
#endif // CONFIG_HCC_SUPPORT_SDIO

