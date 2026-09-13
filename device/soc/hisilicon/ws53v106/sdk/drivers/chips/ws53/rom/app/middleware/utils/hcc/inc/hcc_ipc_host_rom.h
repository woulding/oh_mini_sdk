/*
 * Copyright (c) CompanyNameMagicTag 2023-2023. All rights reserved.
 * Description: hcc ipc host rom header
 * Author: CompanyName
 * Create: 2023-06-30
 */

#ifndef __HCC_IPC_HOST_ROM_H__
#define __HCC_IPC_HOST_ROM_H__
#include "hcc_ipc_adapt.h"
#include "soc_osal.h"
#include "hcc.h"
#include "hcc_if.h"
#include "hcc_list.h"
#include "hcc_bus.h"
#include "hcc_bus_types.h"
#include "hcc_adapt.h"
#include "hcc_comm.h"
#include "hcc_dfx.h"
#include "securec.h"
#include "ipc.h"
#include "ipc_porting.h"
#include "dma.h"
#include "dma_porting.h"

#define HCC_IPC_TASK_PRIORITY 6
#define HCC_IPC_SYN_FORCE_CNT 10
#define HCC_DMA_TRY_CNT 10
#define HCC_DMA_TRANS_MAX IPC_MEM_MSG_MAX
#define HCC_DMA_TRANS_MAX_LIMIT 8 /* HCC_DMA_TRANS_MAX 应小于HCC_DMA_TRANS_MAX_LIMIT */
#define HCC_IPC_THREAD_STACK_SIZE 4096

enum {
    HCC_IPC_DMA_TX1 = 0,
    HCC_IPC_DMA_RX1,
    HCC_IPC_DMA_TX2,
    HCC_IPC_DMA_RX2,
    HCC_IPC_DMA_MAX,
};

enum {
    HCC_DMA_WIDTH_BYTE = 0,
    HCC_DMA_WIDTH_HWORD = 1,
    HCC_DMA_WIDTH_DWORD = 2,
};

typedef struct hcc_ipc_dma_info {
    td_u8 *src_addr;
    td_u8 *dst_addr;
    td_u16 data_len;
} hcc_ipc_dma_info_t;

typedef struct hcc_ipc_dma_intr_param {
    td_u8 dir;
    td_u8 queue_id;
    td_u8 dma_cnt;
    td_u8 rsv;
} hcc_ipc_dma_intr_param_t;

typedef struct hcc_ipc_mem_rx_drop_addr {
    td_u8 queue_id;
    td_u8 rsv;
    td_u16 len;
    td_u8 *addr;
    struct osal_list_head list;
} hcc_ipc_mem_rx_drop_addr_t;

typedef struct hcc_ipc_rx_queue_info {
    hcc_data_queue rx_buf_head;
    struct osal_list_head *alloc_list_head;
    td_u32 alloc_cnt;
} hcc_ipc_rx_queue_info_t;

typedef struct hcc_ipc_bus_drv {
    hcc_bus *bus;
    td_u8 que_len;
    td_u8 dma_state;
    td_bool flow_on;
    osal_task *data_transfer_task;
    osal_wait data_transfer_wait;
    hcc_data_queue *tx_buf_head;
    hcc_ipc_rx_queue_info_t *rx_queue_info;
    td_u32 stats[HCC_DIR_COUNT][HCC_DMA_TRANS_MAX_LIMIT];
    td_u32 cmplt_stats[HCC_DIR_COUNT][HCC_DMA_TRANS_MAX_LIMIT];
    td_u32 msg_stats[HCC_DIR_COUNT][HCC_DMA_TRANS_MAX_LIMIT];
    td_u8 *rsv_buf;
    td_u32 rsv_drop;
    struct osal_list_head addr_list;
    td_u16 addr_list_len;
    td_u16 addr_list_times;
} hcc_ipc_bus_drv_t;

enum {
    TEST_TIME_START = 0,
    TEST_TIME_TRANS_START,
    TEST_TIME_TRANS_END,
    TEST_TIME_END,
    TEST_TIME_MAX,
};

td_s32 hcc_ipc_send_data_msg(td_u8 *buf, td_u32 len, td_u8 que_id);
ext_errno hcc_ipc_send_msg(TD_CONST hcc_bus *bus, td_u32 msg);
td_bool hcc_ipc_mem_reply_handle(td_u8 *payload_addr, td_u32 payload_len, td_u8 dir, td_char *print);
td_void hcc_ipc_mem_handle_rx_unc(hcc_handler *hcc, hcc_ipc_rx_queue_info_t *rx_queue_info,
                                  hcc_ipc_mem_reply_t *ack_info);
td_void hcc_ipc_mem_rx_start_msg(td_u8 *payload_addr, td_u32 payload_len);
td_void hcc_ipc_handle_complete_msg(hcc_data_queue *src_head, hcc_handler *hcc, td_u8 msg, td_u8 que_id, td_u8 cnt);
td_void hcc_ipc_complete_dfx_stats(hcc_handler *hcc, td_u8 dir, td_u8 queue_id, td_u8 dma_cnt);
td_u8 hcc_ipc_get_dma_param_index(td_u8 dir, td_u8 que_id);
td_void hcc_ipc_clr_dma_status(td_u8 dir, td_u8 que_id);
td_bool hcc_ipc_get_dma_status(td_u8 dir, td_u8 que_id);
td_void hcc_ipc_dma_info_copy(hcc_ipc_dma_info_t *dma_info, hcc_unc_struc *unc_buf_src, hcc_unc_struc *unc_buf_dst);
td_void hcc_ipc_free_unclist(hcc_handler *hcc, hcc_data_queue *head, td_u32 cnt);
hcc_unc_struc *hcc_ipc_mem_send_match_len(hcc_handler *hcc, hcc_data_queue *send_head, td_u16 len);
td_s32 hcc_ipc_thread_wait_cond(TD_CONST td_void *param);
td_u32 hcc_ipc_send_pre_req_data(hcc_trans_queue *queue, td_u16 send_nums);
td_void hcc_list_restore_cnt(hcc_data_queue *dst_queue,
                             hcc_data_queue *src_queue, td_u32 cnt);
td_u32 hcc_ipc_send_request_mem(hcc_trans_queue *queue, td_u16 send_nums);
td_void hcc_ipc_msg_rx_callback(td_u8 *payload_addr, td_u32 payload_len);
td_bool hcc_ipc_queue_dma_is_busy(hcc_queue_dir dir, hcc_trans_queue *queue);
td_bool hcc_ipc_queue_set_dma_busy(hcc_queue_dir dir, hcc_trans_queue *queue);
td_void hcc_ipc_queue_clear_dma_status(hcc_queue_dir dir, hcc_trans_queue *queue);
td_u32 hcc_ipc_data_transfer(hcc_ipc_dma_info_t *dma_info, td_u32 trans_nums, td_u8 que_id, td_u8 dir);
td_void hcc_ipc_free_unclist(hcc_handler *hcc, hcc_data_queue *head, td_u32 cnt);
td_void hcc_ipc_set_dma_info(hcc_ipc_dma_info_t *dma_info, td_u8 *src_addr, td_u8 *dst_addr, td_u32 len);
hcc_unc_struc *hcc_ipc_list_unlock_get_node(TD_CONST hcc_data_queue *data_queue_head,
                                            struct osal_list_head **list_node);
td_u32 hcc_ipc_alloc_unc_data(hcc_handler *hcc, hcc_trans_queue *queue, hcc_unc_struc *unc_buf);
#endif