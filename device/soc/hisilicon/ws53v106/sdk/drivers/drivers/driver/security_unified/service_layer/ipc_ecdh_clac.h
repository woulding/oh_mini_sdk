/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: BT BR/EDR Simple Secure Paring App core clac ecdh
 *
 * Author: BGTP
 *
 * Create: 2024-05-08
 */
#ifndef IPC_ECDH_CLAC_H
#define IPC_ECDH_CLAC_H

#include "ipc.h"

#define KE_P256_KEY_LEN 32

enum {
    ECC_GEN_KEY = 0x00,
    ECC_GEN_ECDH_KEY,
    CHECK_DOT_ON_CURVE,
    GET_SEC_RAND,
};

typedef struct {
    uint8_t val[KE_P256_KEY_LEN];
} key_exchange_private_key_t;

typedef struct {
    uint8_t x[KE_P256_KEY_LEN];
    uint8_t y[KE_P256_KEY_LEN];
} key_exchange_public_key_t;

typedef struct {
    uint8_t val[KE_P256_KEY_LEN];
} key_exchange_dh_key_t;

typedef struct {
    uint8_t  ecdh_type;
    uint8_t  curve_length;
    uint8_t  curve_type;
    bool     on_curve;
    uint32_t rand;
    key_exchange_private_key_t  priv_key;
    key_exchange_public_key_t   public_key;
    key_exchange_dh_key_t       dh_key;
} ipc_ecdh_payload_t;  // 4字节对齐

bool ipc_app_callback(ipc_action_t message, const volatile ipc_payload *payload_p, cores_t src, uint32_t id);

void ipc_acce_ecdh_init(void);

#endif // IPC_ECDH_CLAC_H
