/*
 * Copyright (c) @CompanyNameMagicTag 2024-2024. All rights reserved.
 *
 * Description: btc hcc msg
 *
 * Author: BGTP
 *
 * Create: 2024-04-09
 */

#ifndef BTC_HCC_MSG_H
#define BTC_HCC_MSG_H

#include "stdint.h"
#include "errcode.h"

typedef enum {
    BSLE_MSG_HCC_TYPE_CUSTOMIZE_DATA_REQ,
    BSLE_MSG_HCC_TYPE_CUSTOMIZE_DATA_RSP,
    BSLE_MSG_HCC_TYPE_CUSTOMIZE_DATA_ACK,
    BSLE_MSG_HCC_TYPE_DATA_BUTT
} bsle_msg_hcc_type;

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t data[0];
} bsle_msg_t;

typedef struct {
    uint16_t msg_type;
    errcode_t (*handler)(const uint16_t length, const uint8_t *data);
} bsle_msg_handle_t;

void btc_hcc_msg_init(void);
void btc_hcc_msg_deinit(void);
void btc_hcc_msg_send_to_btc(bsle_msg_hcc_type msg_type, uint16_t data_len, uint8_t *data);
#endif
