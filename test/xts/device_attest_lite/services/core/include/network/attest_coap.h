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

#ifndef __ATTEST_COAP_H__
#define __ATTEST_COAP_H__

#include <stdint.h>
#include <stdlib.h>
#include <attest_coap_def.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define OVER_TCP
#ifdef OVER_TCP
#define COAP_TCP_SHIM_HEADER_LEN      (2U)

#ifdef COAP_CONF_MAX_TCP_PDU_SIZE
#define COAP_MAX_TCP_PDU_SIZE         (COAP_CONF_MAX_TCP_PDU_SIZE)
#else
#define COAP_MAX_TCP_PDU_SIZE         (512)
#endif
#endif // OVER_TCP

#define COAP_MAX_SEGMENTS             4
#define HEADER_LEN                    2
#define CODE_LEN                      1
#define LENTKL_LEN                    1
#define MARKER_LEN                    1
#define PKT_TOKEN_LEN                 2
#define DEFAULT_TOK_LEN               0
#define MAX_TOK_LEN                   8
#define COAP_OPT_QUERY_LEN            64

#define BITS_PER_BYTE                 8

/* used for generation of custom response codes */
#define COAP_RESPONSE_CODE(N)         ((N) / 100 << 5 | (N) % 100)
#define COAP_VERSION                  (0x01)

#define MAX_MESSAGE_LEN               1024 // kitFWK 2048

typedef struct {
    size_t buffer;
    size_t len;
} CoapExtendedLength;

typedef struct {
    uint8_t len : 4;
    uint8_t tkl : 4;
    CoapExtendedLength extendedLength;
    uint8_t code;
} CoapHead;

typedef struct {
    const uint8_t* buffer;
    size_t len;
} CoapBuffer;

typedef struct {
    uint16_t       num;
    const uint8_t* optionBuffer;
    size_t         len;
} CoapOption;

typedef struct {
    uint32_t    transType;
    size_t      len;  /* needed buffer length if serializing to a buffer */
    CoapHead    hdr;
    CoapBuffer  tok;
    uint8_t     optsCnt;
    CoapOption  opts[COAP_MAX_OPTION];
    CoapBuffer  payload;
} CoapPacket;

typedef struct {
    char* rwBuffer; /* raw buffer for sending out the packet in serialized wag */
    size_t len;     /* len indicates the size of filled data */
    size_t size;    /* size indicates the Max PDU length */
} CoapRWBuffer;

typedef struct {
    uint32_t    transType;
    uint8_t     code;
    CoapOption* opts;
    uint8_t     optsCnt;
} CoapPacketParam;

int32_t CoapBuildMessage(CoapPacket* coapPacket, CoapPacketParam* coapPacketParam, CoapBuffer* payload,
                         char* buff, uint32_t* len);

int32_t CoapDecode(CoapPacket* pkt, const uint8_t* buf, size_t bufLen);

int32_t CoapGetExtensionLen(uint8_t param, size_t *length);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif