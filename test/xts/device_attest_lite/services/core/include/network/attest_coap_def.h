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

#ifndef __ATTEST_COAP_DEF_H__
#define __ATTEST_COAP_DEF_H__

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define COAP_MAX_OPTION                     16
#define COAP_MSGLEN_LEN                     2
#define MAX_VALUE_ONE_BYTE                  255
#define MAX_VALUE_TWO_BYTES                 65535
#define COAP_MESSAGE_OFFSET_ONE_BYTE        13
#define COAP_MESSAGE_OFFSET_TWO_BYTES       14
#define COAP_MESSAGE_OFFSET_FOUR_BYTES      15
#define COAP_MESSAGE_DIFF_VALUE_BYTE        13
#define COAP_MESSAGE_DIFF_VALUE_TWO_BYTES   269
#define COAP_MESSAGE_LENGTH_ONE_BYTE        1
#define COAP_MESSAGE_LENGTH_TWO_BYTES       2
#define COAP_OPTION_EXTENSION_LEN           2
#define COAP_BITS_OPTION_DELTA              4
#define COAP_BITS_HEADER_LEN                4 // the key Len of header is 4 bits
#define MAKE_RSPCODE(clas, det)     ((uint8_t)((clas) << 5) | ((det) & 0x1F))
#define BUILD_COAP_MESSAGE_ERR (-0X99)

enum COAP_PROTOCOL_TYPE_ENUM {
    COAP_UDP = 0,
    COAP_TCP
};

enum COAP_METHOD_TYPE_ENUM {
    COAP_METHOD_GET    = 1,
    COAP_METHOD_POST   = 2,
    COAP_METHOD_PUT    = 3,
    COAP_METHOD_DELETE = 4
};

enum COAP_MSG_TYPE_ENUM {
    COAP_TYPE_CON      = 0,
    COAP_TYPE_NONCON   = 1,
    COAP_TYPE_ACK      = 2,
    COAP_TYPE_RESET    = 3,
};

enum COAP_OPT_NUM_TYPE_ENUM {
    COAP_OPT_IF_MATCH         = 1,
    COAP_OPT_URI_HOST         = 3,
    COAP_OPT_ETAG             = 4,
    COAP_OPT_IF_NONE_MATCH    = 5,
    COAP_OPT_OBSERVE          = 6,
    COAP_OPT_URI_PORT         = 7,
    COAP_OPT_LOCATION_PATH    = 8,
    COAP_OPT_URI_PATH         = 11,
    COAP_OPT_CONTENT_FORMAT   = 12,
    COAP_OPT_MAX_AGE          = 14,
    COAP_OPT_URI_QUERY        = 15,
    COAP_OPT_ACCEPT           = 17,
    COAP_OPT_LOCATION_QUERY   = 20,
    COAP_OPT_PROXY_URI        = 35,
    COAP_OPT_PROXY_SCHEME     = 39,
    COAP_OPT_SESSION_ID       = 2048,
    COAP_OPT_ACCESS_TOKEN_ID  = 2049,
    COAP_OPT_REQ_ID           = 2050,
    COAP_OPT_DEV_ID           = 2051,
    COAP_OPT_USER_ID          = 2052,
    COAP_OPT_SEQ_NUM_ID       = 2053,
    COAP_OPT_PUUID            = 2056,
    COAP_OPT_PLUGIN           = 2057,
    COAP_OPT_LOCAL_ERR        = 2058,
    COAP_OPT_CLIENT_ID        = 3000,
    COAP_OPT_APP_ID           = 3001,
    COAP_OPT_MAX,
};

enum COAP_RESPONSECODE_TYPE_ENUM {
    COAP_RSCODE_CONTENT = MAKE_RSPCODE(2, 5),
    COAP_RSCODE_CREATED = MAKE_RSPCODE(2, 1),
    COAP_RSCODE_FORBIDDEN = MAKE_RSPCODE(4, 3),
    COAP_RSCODE_NOT_FOUND = MAKE_RSPCODE(4, 4),
    COAP_RSCODE_METHOD_NOT_ALLOWED = MAKE_RSPCODE(4, 5),
    COAP_RSCODE_BAD_REQUEST = MAKE_RSPCODE(4, 0),
    COAP_RSCODE_CHANGE = MAKE_RSPCODE(2, 4),
};

enum COAP_ERROR_TYPE_ENUM {
    COAP_ERR_CODE_NONE                             = 0,
    COAP_ERR_CODE_HEADER_TOO_SHORT                 = 1,
    COAP_ERR_CODE_VERSION_NOT_1                    = 2,
    COAP_ERR_CODE_TOKEN_TOO_SHORT                  = 3,
    COAP_ERR_CODE_OPTION_TOO_SHORT_FOR_HEADER      = 4,
    COAP_ERR_CODE_OPTION_TOO_SHORT                 = 5,
    COAP_ERR_CODE_OPTION_OVERRUNS_PACKET           = 6,
    COAP_ERR_CODE_OPTION_TOO_BIG                   = 7,
    COAP_ERR_CODE_OPTION_LEN_INVALID               = 8,
    COAP_ERR_CODE_BUFFER_TOO_SMALL                 = 9,
    COAP_ERR_CODE_UNSUPPORTED                      = 10,
    COAP_ERR_CODE_OPTION_DELTA_INVALID             = 11,
    COAP_ERR_CODE_PACKET_EXCEED_MAX_PDU            = 12,
    COAP_ERR_CODE_TCP_TYPE_NOT_NON                 = 13,
    COAP_ERR_CODE_UNKNOWN_MSG_TYPE                 = 14,
    COAP_ERR_CODE_INVALID_PACKET                   = 15,
    COAP_ERR_CODE_INVALID_TOKEN_LEN                = 16,
    COAP_ERR_CODE_INVALID_ARGUMENT                 = 17,
    COAP_ERR_CODE_TRANSPORT_NOT_UDP_OR_TCP         = 18,
    COAP_ERR_CODE_INVALID_EMPTY_MESSAGE            = 19,
    COAP_ERR_CODE_SERVER_ERROR                     = 20,
    COAP_ERR_CODE_BAD_REQUEST                      = 21,
    COAP_ERR_CODE_UNKNOWN_METHOD                   = 22,
    COAP_ERR_CODE_BLOCK_NO_PAYLOAD                 = 23,
    COAP_ERR_CODE_EXTENDED_LENGTH_INVALID          = 24,
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif