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

#ifndef __ATTEST_NETWORK_H__
#define __ATTEST_NETWORK_H__

#include <stdint.h>
#include <stddef.h>
#include "attest_channel.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define NETWORK_CONFIG_SIZE 256
#define NETWORK_CONFIG_SERVER_INFO_NAME "serverInfo"
#define HOST_PATTERN "[a-zA-Z0-9-_.]"
#define PORT_PATTERN "[0-9]"
#define PARAM_ONE 1
#define PARAM_TWO 2
#define ISSUE_REGION_KEY "issueRegion"
#define ISSUE_REGION_VAL "CN"
#define ACTIVE_SITE_KEY "activeSiteKey"
#define STANDBY_SITE_KEY "standbySiteKey"
#define ACTIVE_SITE_VAL_COAP "CoAP_ActiveSiteKey"
#define STANDBY_SITE_VAL_COAP "CoAP_StandbySiteKey"
#define CONNECTOR ":"
#define UPDATE_OK 1
#define UPDATE_NO 0

typedef enum {
    COAP_URI_PATH   = 11,
    COAP_APP_ID     = 3001,
} COAP_OPT_TYPE_ENUM;

typedef struct CoapOptList {
    struct CoapOptList* next;
    COAP_OPT_TYPE_ENUM optType;
    size_t length;
    uint8_t* data;
} CoapOptList;

int32_t D2CConnect(void);

void D2CClose(void);

DevicePacket* CreateDevicePacket(void);

void DestroyDevicePacket(DevicePacket** devicePacket);

#define FREE_DEVICE_PACKET(devicePacket) DestroyDevicePacket((DevicePacket**)&(devicePacket))

int32_t SendAttestMsg(const DevicePacket *devValue, ATTEST_ACTION_TYPE actionType, char **respBodyData);

typedef char* (*BuildBodyFunc)(const DevicePacket *);

char* BuildCoapChallBody(const DevicePacket *devPacket);

char* BuildCoapResetBody(const DevicePacket *devPacket);

char* BuildCoapAuthBody(const DevicePacket *devPacket);

char* BuildCoapActiveBody(const DevicePacket *devPacket);

int32_t InitNetworkServerInfo(void);

int32_t UpdateNetConfig(char* activeSite, char* standbySite, int32_t* updateFlag);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif