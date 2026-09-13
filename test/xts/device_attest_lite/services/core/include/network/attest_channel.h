/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef ATTEST_CHANNEL_H
#define ATTEST_CHANNEL_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_HOST_NAME_LEN       64
#define MAX_PORT_LEN            5
#define MAX_SEED_LEN            16

typedef struct {
    mbedtls_entropy_context   entropyCtx;
    mbedtls_ctr_drbg_context  ctrDrbgCtx;
    mbedtls_net_context       netCtx;
    mbedtls_ssl_context       sslCtx;
    mbedtls_ssl_config        sslConf;
    mbedtls_x509_crt          caCert;
} TLSConfig;

typedef struct {
    char        hostName[MAX_HOST_NAME_LEN + 1];
    char        port[MAX_PORT_LEN + 1];
} ServerInfo;

typedef struct {
    TLSConfig   tlsConfig;                   // TLSConfig配置
    ServerInfo  serverInfo;                  // 服务器信息
    char        entropySeed[MAX_SEED_LEN];   // mbedtls熵源seed, 可用CERTMGR_ID作为seed值
} TLSSession;

int32_t TLSConnect(TLSSession* session);

int32_t TLSWrite(const TLSSession* session, const uint8_t* buf, size_t len);

int32_t TLSRead(const TLSSession* session, uint8_t* buf, size_t len);

int32_t TLSClose(TLSSession* session);

#ifdef __cplusplus
}
#endif
#endif
