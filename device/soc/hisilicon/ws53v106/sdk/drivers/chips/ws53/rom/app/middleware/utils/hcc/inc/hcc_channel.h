/*
 * Copyright (c) CompanyNameMagicTag 2021-2023. All rights reserved.
 * Description: hcc channel.
 * Author: CompanyName
 * Create: 2021-09-23
 */

#ifndef HCC_CHANNEL_HEADER
#define HCC_CHANNEL_HEADER

#include "td_type.h"
#include "hcc.h"
#include "hcc_cfg_comm.h"

typedef struct _hcc_handler_list_ {
    struct osal_list_head  handler_list;
    hcc_handler *handler;
} hcc_handler_list;
td_s32 hcc_add_handler(hcc_handler *hcc);
td_void hcc_delete_handler(td_u8 chl);
hcc_handler *hcc_get_bus_handler(td_u8 bus_type);
typedef td_void *(hcc_traverse_func)(hcc_handler_list *handler_list, td_u8 data);
td_void *hcc_traverse_handler_list(td_u8 data, hcc_traverse_func func);
td_void *hcc_traverse_func_get_handler_list(hcc_handler_list *handler_list, td_u8 chl);
td_void *hcc_traverse_func_get_bus_list(hcc_handler_list *handler_list, td_u8 bus_type);
hcc_handler *hcc_get_handler(td_u8 chl);
td_bool hcc_get_state(td_u8 chl);
td_bool hcc_chan_is_busy(td_u8 chl);
hcc_handler_list *hcc_channel_list_head_get(td_void);
#endif /* HCC_CHANNEL_HEADER */