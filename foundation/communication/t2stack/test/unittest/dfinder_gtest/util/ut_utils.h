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

#ifndef UT_UTILS_H
#define UT_UTILS_H

#include "nstackx_timer.h"
#include "nstackx_device.h"
#include "nstackx_error.h"

#ifdef __cplusplus
extern "C" {
#endif

struct LocalIface {
    List node;

    uint8_t type;
    uint8_t state;
    uint8_t createCount;
    uint8_t af;
    char ifname[NSTACKX_MAX_INTERFACE_NAME_LEN];
    char ipStr[NSTACKX_MAX_IP_STRING_LEN];
    union InetAddr addr;
    char serviceData[NSTACKX_MAX_SERVICE_DATA_LEN];
    struct timespec updateTime;

    Timer *timer;
    CoapCtxType *ctx;
};

LocalIface *CreateLocalIface();
void FreeLocalIface(LocalIface *localInterface);
coap_context_t *CreateCoapContext();
void FreeCoapContext(coap_context_t *context);
CoapCtxType *CreateCoapCtxType();
void FreeCoapCtxType(CoapCtxType *coapCtxType);
CoapCtxType *InsertDevice(void);
void RemoveDevice(CoapCtxType *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // UT_UTILS_H
