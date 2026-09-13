/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <pthread.h>
#include "securec.h"
#include "attest_channel.h"
#include "attest_tls.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_tdd_mock_config.h"
#include "attest_tdd_data_transfer.h"

int32_t g_netType = 0;

#define MAX_INVOKE_TIME    3
#define MAX_NO_EXTEND_TIME 2
#define INTERFACE_COUNT    4

// can't change network
#define ATTEST_RESET_CHAP_FIRST_MSG   "210,0"
#define ATTEST_RESET_CHAP_SECOND_MSG  "227,49"
#define ATTEST_RESET_CHAP_THIRD_MSG "69,166,93,255,123,34,99,104,97,108,108,101,110,103,101,34,58,34,51,57,\
97,57,100,48,52,100,52,49,54,49,55,49,54,50,56,57,51,99,51,51,49,50,99,101,98,48,51,48,97,99,97,99,56,100,56,\
98,100,48,99,99,57,102,99,101,98,99,97,98,53,52,48,50,97,52,51,56,57,49,51,52,49,100,34,44,34,99,117,114,114,\
101,110,116,84,105,109,101,34,58,49,54,56,48,55,56,49,54,55,49,50,50,54,44,34,101,114,114,99,111,100,101,34,58,\
48,44,34,115,101,114,118,101,114,73,110,102,111,34,58,123,34,97,99,116,105,118,101,83,105,116,101,34,58,34,119,\
105,115,101,100,101,118,105,99,101,45,108,105,116,101,45,100,114,99,110,46,111,112,101,110,104,97,114,109,111,\
110,121,46,99,110,34,44,34,115,116,97,110,100,98,121,83,105,116,101,34,58,34,119,105,115,101,100,101,118,105,99,\
101,45,108,105,116,101,45,100,114,99,110,46,111,112,101,110,104,97,114,109,111,110,121,46,99,110,34,125,125,0"

#define ATTEST_REST_ERROR_FIRST_MSG     "210,0"
#define ATTEST_REST_ERROR_SECOND_MSG    "5,49"
#define ATTEST_REST_ERROR_THIRD_MSG     "69,128,194,255,123,34,101,114,114,99,111,100,101,34,58,49,53,48,48,51,125,0"

#define ATTEST_AUTH_FIRST_MSG           "226,0"
#define ATTEST_AUTH_SECOND_MSG          "1,185,54"
#define ATTEST_AUTH_THIRD_MSG           "69,184,100,255,123,34,99,104,97,108,108,101,110,103,101,34,58,34,97,56,49,52,\
52,49,101,51,99,48,100,56,100,54,97,55,56,57,48,55,102,97,48,56,56,56,102,57,50,52,49,98,101,57,53,57,49,99,52,100,54,\
98,55,97,53,51,51,51,49,56,98,48,49,48,102,98,50,99,51,100,57,98,56,48,34,44,34,99,117,114,114,101,110,116,84,105,109,\
101,34,58,49,54,56,48,55,56,49,54,55,49,52,53,53,44,34,101,114,114,99,111,100,101,34,58,48,125,108"

#define ATTEST_ACTIVE_FIRST_MSG   "210,0"
#define ATTEST_ACTIVE_SECOND_MSG  "1,49"
#define ATTEST_ACTIVE_THIRD_MSG   "69,254,246,255,123,34,101,114,114,99,111,100,101,34,58,48,125,0"

static const char *mockTlsData[MAX_INVOKE_TIME][INTERFACE_COUNT] = {
    {ATTEST_RESET_CHAP_FIRST_MSG, ATTEST_REST_ERROR_FIRST_MSG, ATTEST_ACTIVE_FIRST_MSG, ATTEST_AUTH_FIRST_MSG},
    {ATTEST_RESET_CHAP_SECOND_MSG, ATTEST_REST_ERROR_SECOND_MSG, ATTEST_ACTIVE_SECOND_MSG, ATTEST_AUTH_SECOND_MSG},
    {ATTEST_RESET_CHAP_THIRD_MSG, ATTEST_REST_ERROR_THIRD_MSG, ATTEST_ACTIVE_THIRD_MSG, ATTEST_AUTH_THIRD_MSG}
};
bool isHasExtend[4] = {true, true, true, true};
int g_cout = 0;

int32_t TLSConnect(TLSSession* session)
{
    ATTEST_LOG_INFO("[TLSConnect mock] Begin.");
    if (session == NULL) {
        return ERR_NET_INVALID_ARG;
    }
    return ATTEST_OK;
}

int32_t TLSWrite(const TLSSession* session, const uint8_t* buf, size_t len)
{
    (void)session;
    (void)buf;
    (void)len;
    return ATTEST_OK;
}

int32_t TLSRead(const TLSSession* session, uint8_t* buf, size_t len)
{
    (void)session;
    (void)len;
    ATTEST_LOG_INFO("[TLSRead mock] g_cout:%d, g_netType:%d", g_cout, g_netType);
    if (g_cout > MAX_INVOKE_TIME || (g_netType < 0 || g_netType > INTERFACE_COUNT - 1)) {
        return ATTEST_ERR;
    }
    int32_t ret = AttestSeriaToBinary(mockTlsData[g_cout][g_netType], &buf, len);
    g_cout++;
    int32_t maxInvokeTime = isHasExtend[g_netType] ? MAX_INVOKE_TIME : MAX_NO_EXTEND_TIME;
    if (g_cout == maxInvokeTime) {
        g_cout = 0;
    }
    return ret;
}

int32_t TLSClose(TLSSession* session)
{
    (void)session;
    return ATTEST_OK;
}
