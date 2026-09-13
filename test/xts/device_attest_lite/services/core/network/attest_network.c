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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <securec.h>
#include "cJSON.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_utils_list.h"
#include "attest_utils_json.h"
#include "attest_service_device.h"
#include "attest_coap.h"
#include "attest_coap_def.h"
#include "attest_channel.h"
#include "attest_adapter.h"
#include "attest_network.h"

#define MSG_LENGTH_BIT 0XFF
#define MSG_LEFT_SHIFT_BIT 8

#define UDID_SHA256_OUTPUT_SIZE    64
#define UDID_HEX_OUTPUT_SIZE       64
#define COAP_MSGLEN_LEN            2
#define COAP_LENTKL_LEN            1
#define MAX_OPTION_VAL_LEN         64
#define MAX_NETWORK_CFG_LIST_SIZE  2

TLSSession* g_attestSession = NULL;

List g_attestNetworkList;

typedef struct {
    uint16_t  optionType;
    char      optionValue[MAX_OPTION_VAL_LEN + 1];
    size_t    optionLength;
} Option;

const char DEFAULT_VER[] = "1.0.1";

BuildBodyFunc g_buildBodyFunc[ATTEST_ACTION_MAX] = {
    BuildCoapChallBody,
    BuildCoapResetBody,
    BuildCoapAuthBody,
    BuildCoapActiveBody,
};

char *g_uriPath[ATTEST_ACTION_MAX] = {
    "device/v3/challenge",
    "device/v3/reset",
    "device/v3/auth",
    "device/v3/token/activate",
};

DevicePacket* CreateDevicePacket(void)
{
    DevicePacket* devicePacket = (DevicePacket *)ATTEST_MEM_MALLOC(sizeof(DevicePacket));
    if (devicePacket == NULL) {
        ATTEST_LOG_ERROR("[CreateDevicePacket] devicePacket malloc memory failed");
        return NULL;
    }
    devicePacket->appId = NULL;
    devicePacket->tenantId = NULL;
    devicePacket->udid = NULL;
    devicePacket->ticket = NULL;
    devicePacket->randomUuid = NULL;
    devicePacket->tokenInfo.uuid = NULL;
    devicePacket->tokenInfo.token = NULL;
    devicePacket->productInfo.prodId = NULL;
    devicePacket->productInfo.model = NULL;
    devicePacket->productInfo.brand = NULL;
    devicePacket->productInfo.manu = NULL;
    devicePacket->productInfo.versionId = NULL;
    devicePacket->productInfo.displayVersion = NULL;
    devicePacket->productInfo.rootHash = NULL;
    devicePacket->productInfo.patchTag = NULL;
    devicePacket->kitinfo = NULL;
    devicePacket->pcid = NULL;
    return devicePacket;
}

void DestroyDevicePacket(DevicePacket** devPacket)
{
    if (devPacket == NULL || *devPacket == NULL) {
        ATTEST_LOG_ERROR("[DestroyDevicePacket] Invalid parameter");
        return;
    }
    DevicePacket* devicePacket = *devPacket;
    ATTEST_MEM_FREE(devicePacket->appId);
    ATTEST_MEM_FREE(devicePacket->tenantId);
    ATTEST_MEM_FREE(devicePacket->udid);
    ATTEST_MEM_FREE(devicePacket->ticket);
    ATTEST_MEM_FREE(devicePacket->randomUuid);
    ATTEST_MEM_FREE(devicePacket->tokenInfo.uuid);
    ATTEST_MEM_FREE(devicePacket->tokenInfo.token);
    ATTEST_MEM_FREE(devicePacket->productInfo.prodId);
    ATTEST_MEM_FREE(devicePacket->productInfo.model);
    ATTEST_MEM_FREE(devicePacket->productInfo.brand);
    ATTEST_MEM_FREE(devicePacket->productInfo.manu);
    ATTEST_MEM_FREE(devicePacket->productInfo.versionId);
    ATTEST_MEM_FREE(devicePacket->productInfo.displayVersion);
    ATTEST_MEM_FREE(devicePacket->productInfo.rootHash);
    ATTEST_MEM_FREE(devicePacket->productInfo.patchTag);
    ATTEST_MEM_FREE(devicePacket->kitinfo);
    ATTEST_MEM_FREE(devicePacket->pcid);
    ATTEST_MEM_FREE(*devPacket);
}

static int32_t BuildCoapMsg(List *optionList, CoapBuffer *payload, char *outputBuf, size_t *outputLen)
{
    ATTEST_LOG_DEBUG("[BuildCoapMsg] Start");
    if (optionList == NULL || payload == NULL || outputBuf == NULL || outputLen == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapMsg] Invalid parameter");
        return ERR_NET_INVALID_ARG;
    }
    CoapPacket coapPacket;
    CoapPacketParam coapPacketParam;
    (void)memset_s(&coapPacket, sizeof(CoapPacket), 0, sizeof(CoapPacket));
    (void)memset_s(&coapPacketParam, sizeof(CoapPacketParam), 0, sizeof(CoapPacketParam));
    coapPacketParam.code = COAP_METHOD_POST;
    coapPacketParam.opts = coapPacket.opts;
    coapPacketParam.optsCnt = GetListSize(optionList);
    ListNode* head = optionList->head;
    uint32_t index = 0;
    while ((head != NULL) && (index < COAP_MAX_OPTION)) {
        Option* option = (Option*)head->data;
        coapPacketParam.opts[index].num = option->optionType;
        coapPacketParam.opts[index].optionBuffer = (const unsigned char *)&option->optionValue[0];
        coapPacketParam.opts[index].len = option->optionLength;
        head = head->next;
        index++;
    }

    if (CoapBuildMessage(&coapPacket, &coapPacketParam, payload, outputBuf, (uint32_t *)outputLen) != 0) {
        ATTEST_LOG_ERROR("[BuildCoapMsg] Build coap msg failed");
        return ATTEST_ERR;
    }
    ATTEST_LOG_DEBUG("[BuildCoapMsg] End");
    return ATTEST_OK;
}

// 用户自定义配置接口
static TLSSession* CustomConfig(const char* seed, ServerInfo* networkInfo)
{
    ATTEST_LOG_DEBUG("[CustomConfig] Begin.");
    if (seed == NULL || networkInfo == NULL) {
        ATTEST_LOG_ERROR("[CustomConfig] config or seed is NULL.");
        return NULL;
    }

    TLSSession* session = (TLSSession*)ATTEST_MEM_MALLOC(sizeof(TLSSession));
    if (session == NULL) {
        ATTEST_LOG_ERROR("[CustomConfig] session malloc failed");
        return NULL;
    }

    if (memcpy_s(session->entropySeed, MAX_SEED_LEN, seed, strlen(seed)) != 0 ||
        memcpy_s(session->serverInfo.hostName, MAX_HOST_NAME_LEN, networkInfo->hostName,
                 strlen(networkInfo->hostName)) != 0 ||
        memcpy_s(session->serverInfo.port, MAX_PORT_LEN, networkInfo->port,
                 strlen(networkInfo->port)) != 0) {
        ATTEST_LOG_ERROR("[CustomConfig] Memcpy failed.");
        ATTEST_MEM_FREE(session);
        return NULL;
    }
    ATTEST_LOG_DEBUG("[CustomConfig] End.");
    return session;
}

static int32_t CloseNetwork(TLSSession* session)
{
    if (session == NULL) {
        return ATTEST_ERR;
    }
    int32_t ret = TLSClose(session);
    ATTEST_MEM_FREE(session);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[CloseNetwork] TLSClose failed, ret = %d.", ret);
    }
    return ret;
}

static int32_t ConnectNetWork(TLSSession **session, void* reserved)
{
    ATTEST_LOG_DEBUG("[ConnectNetWork] Begin.");
    const char* seed = NULL;
    if (reserved == NULL) {
        seed = DEFAULT_VER;
    } else {
        seed = (const char*)reserved;
    }
    TLSSession* tmpSession = NULL;
    ListNode* head = g_attestNetworkList.head;
    int32_t currentIndex = 0;
    int32_t ret = ATTEST_OK;
    while (head != NULL && currentIndex < MAX_NETWORK_CFG_LIST_SIZE) {
        currentIndex++;
        ServerInfo* networkInfo = (ServerInfo*)head->data;
        head = head->next;
        tmpSession = CustomConfig(seed, networkInfo);
        if (tmpSession == NULL) {
            ATTEST_LOG_ERROR("[ConnectNetWork] Session is NULL.");
            ret = ATTEST_ERR;
            continue;
        }
        ret = TLSConnect(tmpSession);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ConnectNetWork] TLSConnect fail, ret = %d.", ret);
            CloseNetwork(tmpSession);
            continue;
        } else {
            ATTEST_LOG_INFO("[ConnectNetWork] connect successfully.");
            break;
        }
    }
    if (currentIndex == 0 || currentIndex > MAX_NETWORK_CFG_LIST_SIZE) {
        ATTEST_LOG_ERROR("[ConnectNetWork] listSize wrong.");
    }

    if (ret != ATTEST_OK) {
        return ret;
    }

    *session = tmpSession;
    ATTEST_LOG_DEBUG("[ConnectNetWork] End.");
    return ATTEST_OK;
}

int32_t D2CConnect(void)
{
    ATTEST_LOG_DEBUG("[D2CConnect] Begin.");
    if (g_attestSession != NULL) {
        ATTEST_LOG_ERROR("[D2CConnect] g_attestSession is not null.");
        return ATTEST_ERR;
    }
    int32_t ret = ConnectNetWork(&g_attestSession, DEVATTEST_ID);
    if (ret != ATTEST_OK) {
        ATTEST_MEM_FREE(g_attestSession);
        g_attestSession = NULL;
        return ret;
    }
    ATTEST_LOG_DEBUG("[D2CConnect] End.");
    return ATTEST_OK;
}

void D2CClose(void)
{
    int32_t ret = CloseNetwork(g_attestSession);
    g_attestSession = NULL;
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[D2CClose] TLSClose failed, ret = %d.", ret);
    }
}

#ifndef __ATTEST_DISABLE_SITE__
static int32_t BuildCoapChallServerInfo(cJSON **postData)
{
    if (postData == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapChallServerInfo] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON *serverInfo = cJSON_CreateObject();
    if (serverInfo == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapChallServerInfo] postData CreateObject fail");
        return ATTEST_ERR;
    }
    if (!cJSON_AddItemToObject(*postData, "serverInfo", serverInfo)) {
        ATTEST_LOG_ERROR("[BuildCoapChallServerInfo] add serverInfo to postData fail");
        cJSON_Delete(serverInfo);
        return ATTEST_ERR;
    }
    int32_t ret = ATTEST_ERR;
    do {
        if (cJSON_AddStringToObject(serverInfo, ISSUE_REGION_KEY, ISSUE_REGION_VAL) == NULL) {
            ATTEST_LOG_ERROR("[BuildCoapChallServerInfo] build issueRegion fail");
            break;
        }
        if (cJSON_AddStringToObject(serverInfo, ACTIVE_SITE_KEY, ACTIVE_SITE_VAL_COAP) == NULL) {
            ATTEST_LOG_ERROR("[BuildCoapChallServerInfo] build activeSiteKey fail");
            break;
        }
        if (cJSON_AddStringToObject(serverInfo, STANDBY_SITE_KEY, STANDBY_SITE_VAL_COAP) == NULL) {
            ATTEST_LOG_ERROR("[BuildCoapChallServerInfo] build standbySiteKey fail");
            break;
        }
        ret = ATTEST_OK;
    } while (0);
    if (ret != ATTEST_OK) {
        cJSON_Delete(serverInfo);
        ATTEST_LOG_ERROR("[BuildCoapChallServerInfo] generate serverInfo fail");
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}
#endif

char* BuildCoapChallBody(const DevicePacket *postValue)
{
    ATTEST_LOG_DEBUG("[BuildCoapChallBody] Begin.");
    if (postValue == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapChallBody] Invalid parameter postValue");
        return NULL;
    }
    cJSON *postData = cJSON_CreateObject();
    if (postData == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapChallBody] postData CreateObject fail");
        return NULL;
    }
    int32_t ret = ATTEST_ERR;
    do {
        if (cJSON_AddStringToObject(postData, "uniqueId", postValue->udid) == NULL) {
            ATTEST_LOG_ERROR("[BuildCoapChallBody] postData  AddStringToObject fail");
            break;
        }
#ifndef __ATTEST_DISABLE_SITE__
        ret = BuildCoapChallServerInfo(&postData);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[BuildCoapChallBody] BuildCoapChallServerInfo fail");
            break;
        }
#endif
        ret = ATTEST_OK;
    } while (0);
    if (ret != ATTEST_OK) {
        cJSON_Delete(postData);
        return NULL;
    }
    char *bodyData = cJSON_Print(postData);
    cJSON_Delete(postData);
    ATTEST_LOG_DEBUG("[BuildCoapChallBody] End.");
    return bodyData;
}

char* BuildCoapResetBody(const DevicePacket *postValue)
{
    ATTEST_LOG_DEBUG("[BuildCoapResetBody] Begin.");
    if (postValue == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapResetBody] Invalid parameter");
        return NULL;
    }
    cJSON *postData = cJSON_CreateObject();
    if (postData == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapResetBody] postData CreateObject fail");
        return NULL;
    }
    int32_t ret = ATTEST_OK;
    do {
        if (cJSON_AddStringToObject(postData, "udid", postValue->udid) == NULL) {
            ret = ATTEST_ERR;
            break;
        }
        cJSON *postObj = cJSON_CreateObject();
        if (postObj == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapResetBody] postObj Create Object fail");
            break;
        }
        if (!cJSON_AddItemToObject(postData, "tokenInfo", postObj)) {
            cJSON_Delete(postObj);
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapResetBody] postData add Item To Object fail");
            break;
        }
        if (cJSON_AddStringToObject(postObj, "uuid", postValue->tokenInfo.uuid) == NULL ||
            cJSON_AddStringToObject(postObj, "token", postValue->tokenInfo.token) == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapResetBody] postObj  add uuid or token fail");
            break;
        }
    } while (0);
    if (ret == ATTEST_ERR) {
        cJSON_Delete(postData);
        ATTEST_LOG_ERROR("[BuildCoapResetBody] postObj  add value fail");
        return NULL;
    }
    char *bodyData = cJSON_Print(postData);
    cJSON_Delete(postData);
    ATTEST_LOG_DEBUG("[BuildCoapResetBody] End.");
    return bodyData;
}

static int32_t BuildCoapAuthBodySoftware(const DevicePacket *postValue, cJSON *outData)
{
    if (postValue == NULL || outData == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapAuthBodySoftware] Invalid parameter");
        return ATTEST_ERR;
    }

    cJSON *software = cJSON_CreateObject();
    if (software == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapAuthBodySoftware] software Create Object fail");
        return ATTEST_ERR;
    }

    if (!cJSON_AddItemToObject(outData, "software", software)) {
        cJSON_Delete(software);
        ATTEST_LOG_ERROR("[BuildCoapAuthBodySoftware] postData Add Item To Object fail");
        return ATTEST_ERR;
    }

    if (cJSON_AddStringToObject(software, "versionId", postValue->productInfo.versionId) == NULL ||
        cJSON_AddStringToObject(software, "manufacture", postValue->productInfo.manu) == NULL ||
        cJSON_AddStringToObject(software, "model", postValue->productInfo.model) == NULL ||
        cJSON_AddStringToObject(software, "brand", postValue->productInfo.brand) == NULL ||
        cJSON_AddStringToObject(software, "rootHash", postValue->productInfo.rootHash) == NULL ||
        cJSON_AddStringToObject(software, "version", postValue->productInfo.displayVersion) == NULL ||
#ifndef __LITEOS_M__
        cJSON_AddStringToObject(software, "pcid", postValue->pcid) == NULL ||
#endif
        cJSON_AddStringToObject(software, "patchLevel", postValue->productInfo.patchTag) == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapAuthBodySoftware] software Add productInfo values fail");
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

char* BuildCoapAuthBody(const DevicePacket *postValue)
{
    ATTEST_LOG_DEBUG("[BuildCoapAuthBody] Begin.");
    if (postValue == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapAuthBody] Invalid parameter");
        return NULL;
    }
    cJSON *postData = cJSON_CreateObject();
    if (postData == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapAuthBody] postData CreateObject fail");
        return NULL;
    }
    int32_t ret = ATTEST_OK;
    do {
        if (cJSON_AddStringToObject(postData, "udid", postValue->udid) == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapAuthBody] udid Add String To Object fail");
            break;
        }
        cJSON *tokenInfo = cJSON_CreateObject();
        if (tokenInfo == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapAuthBody] tokenInfo Create Object fail");
            break;
        }
        if (!cJSON_AddItemToObject(postData, "tokenInfo", tokenInfo)) {
            cJSON_Delete(tokenInfo);
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapAuthBody] tokenInfo Add Item To Object fail");
            break;
        }
        if (cJSON_AddStringToObject(tokenInfo, "uuid", postValue->tokenInfo.uuid) == NULL ||
            cJSON_AddStringToObject(tokenInfo, "token", postValue->tokenInfo.token) == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapAuthBody] tokenInfo Add uuid or token fail");
            break;
        }
        ret = BuildCoapAuthBodySoftware(postValue, postData);
    } while (0);
    if (ret == ATTEST_ERR) {
        cJSON_Delete(postData);
        ATTEST_LOG_ERROR("[BuildCoapAuthBody] postData extract values fail");
        return NULL;
    }
    char *bodyData = cJSON_Print(postData);
    cJSON_Delete(postData);
    ATTEST_LOG_DEBUG("[BuildCoapAuthBody] End.");
    return bodyData;
}

char* BuildCoapActiveBody(const DevicePacket *postValue)
{
    ATTEST_LOG_DEBUG("[BuildCoapActiveBody] Begin.");
    if (postValue == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapActiveBody] Invalid parameter");
        return NULL;
    }
    cJSON *postData = cJSON_CreateObject();
    if (postData == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapActiveBody] postData CreateObject fail");
        return NULL;
    }
    int32_t ret = ATTEST_OK;
    do {
        if (cJSON_AddStringToObject(postData, "ticket", postValue->ticket) == NULL ||
            cJSON_AddStringToObject(postData, "udid", postValue->udid) == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapActiveBody] postData Add ticket or udid fail");
            break;
        }

        cJSON *postObj = cJSON_CreateObject();
        if (postObj == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapActiveBody] postObj CreateObject fail");
            break;
        }
        if (!cJSON_AddItemToObject(postData, "tokenInfo", postObj)) {
            cJSON_Delete(postObj);
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapActiveBody] postObj AddItemToObject fail");
            break;
        }
        if (cJSON_AddStringToObject(postObj, "uuid", postValue->tokenInfo.uuid) == NULL ||
            cJSON_AddStringToObject(postObj, "token", postValue->tokenInfo.token) == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildCoapActiveBody] postObj add uuid or token fail");
            break;
        }
    } while (0);
    if (ret == ATTEST_ERR) {
        cJSON_Delete(postData);
        ATTEST_LOG_ERROR("[BuildCoapActiveBody] postData extract values by postValue fail");
        return NULL;
    }
    char *bodyData = cJSON_Print(postData);
    cJSON_Delete(postData);
    ATTEST_LOG_DEBUG("[BuildCoapActiveBody] End.");
    return bodyData;
}

static int32_t BuildCoapBody(const DevicePacket *devData, ATTEST_ACTION_TYPE actionType, char **outBody)
{
    if (actionType >= ATTEST_ACTION_MAX) {
        ATTEST_LOG_ERROR("[BuildCoapBody] actionType out of range");
        return ATTEST_ERR;
    }
    
    BuildBodyFunc buildBodyFunc = g_buildBodyFunc[actionType];
    if (buildBodyFunc == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapBody] g_buildBodyFunc fail");
        return ATTEST_ERR;
    }
    char *postBody = buildBodyFunc(devData);
    if (postBody == NULL) {
        ATTEST_LOG_ERROR("[BuildCoapBody] buildBodyFunc fail");
        return ATTEST_ERR;
    }
    *outBody = postBody;
    ATTEST_LOG_DEBUG("[BuildCoapBody] end");
    return ATTEST_OK;
}

static int32_t GenCoapMsg(const DevicePacket *devPacket, ATTEST_ACTION_TYPE actionType, char **reqMsg)
{
    ATTEST_LOG_DEBUG("[GenCoapMsg] start");
    if (devPacket == NULL || reqMsg == NULL || actionType >= ATTEST_ACTION_MAX) {
        ATTEST_LOG_ERROR("[GenCoapMsg] Invalid parameter");
        return ATTEST_ERR;
    }

    char *msg = NULL;
    int32_t ret = BuildCoapBody(devPacket, actionType, &msg);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GenCoapMsg] Build coap body fail");
        ATTEST_MEM_FREE(msg);
        return ATTEST_ERR;
    }
    *reqMsg = msg;
    return ATTEST_OK;
}

static int32_t SplitBySymbol(const char* src, size_t srcLen, const char* separator, List* list)
{
    if (src == NULL || srcLen == 0 || list == NULL || separator == NULL || strlen(separator) == 0) {
        ATTEST_LOG_ERROR("[SplitBySymbol] Invalid parameter.");
        return ATTEST_ERR;
    }
    char *tempSrc = (char *)ATTEST_MEM_MALLOC(srcLen + 1);
    if (tempSrc == NULL) {
        return ATTEST_ERR;
    }
    if (strncpy_s(tempSrc, srcLen + 1, src, srcLen) != 0) {
        ATTEST_MEM_FREE(tempSrc);
        return ATTEST_ERR;
    }
    int32_t ret = ATTEST_OK;
    char* next = NULL;
    char* pNext = (char*)strtok_s(tempSrc, separator, &next);
    if (pNext == NULL) {
        ATTEST_LOG_ERROR("[SplitBySymbol] No separator found.");
        return ATTEST_ERR;
    }
    while (pNext != NULL) {
        uint32_t pNextLen = strlen(pNext);
        if (pNextLen == 0 || pNextLen > MAX_MESSAGE_LEN) {
            ATTEST_LOG_ERROR("[SplitBySymbol] pNextLen wrong");
            ret = ATTEST_ERR;
            break;
        }
        uint32_t tempLen = pNextLen + 1;
        char* tempStr = (char*)ATTEST_MEM_MALLOC(tempLen);
        if (tempStr == NULL) {
            ATTEST_LOG_ERROR("[SplitBySymbol] Malloc mem failed");
            ret = ATTEST_ERR;
            break;
        }
        if (memcpy_s(tempStr, tempLen, pNext, pNextLen) != 0) {
            ATTEST_LOG_ERROR("[SplitBySymbol] Mem copy failed");
            ATTEST_MEM_FREE(tempStr);
            ret = ATTEST_ERR;
            break;
        }
        AddListNode(list, tempStr);
        pNext = (char*)strtok_s(NULL, separator, &next);
    }
    ATTEST_MEM_FREE(tempSrc);
    if (ret != ATTEST_OK) {
        ReleaseList(list);
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

static int32_t BuildOption(List* optionList, uint16_t optionType, size_t optionLength, const char* optionValue)
{
    if (optionList == NULL || optionType > COAP_OPT_MAX || optionValue == NULL || optionLength == 0) {
        ATTEST_LOG_ERROR("[BuildOption] Invalid parameter.");
        return ATTEST_ERR;
    }
    Option* tempOpt = (Option *)ATTEST_MEM_MALLOC(sizeof(Option));
    if (tempOpt == NULL) {
        ATTEST_LOG_ERROR("[BuildOption] Malloc tempOpt failed");
        return ERR_NET_MEM_MALLOC;
    }
    tempOpt->optionType = optionType;
    tempOpt->optionLength = optionLength;
    if (memcpy_s(tempOpt->optionValue, sizeof(tempOpt->optionValue), optionValue, optionLength) != 0) {
        ATTEST_LOG_ERROR("[BuildOption] Memcpy failed.");
        ATTEST_MEM_FREE(tempOpt);
        return ERR_NET_MEM_MEMCPY;
    }
    if (AddListNode(optionList, tempOpt) != ATTEST_OK) {
        ATTEST_LOG_ERROR("[BuildOption] Add list node failed.");
        ATTEST_MEM_FREE(tempOpt);
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

static int32_t BuildUriOption(const char* uriPath, uint32_t uriPathLen, List* optionList)
{
    List uriList;
    (void)CreateList(&uriList);
    int32_t ret = SplitBySymbol(uriPath, uriPathLen, "/", &uriList);
    if (ret != 0) {
        ATTEST_LOG_ERROR("[BuildUriOption] Split URI failed");
        return ATTEST_ERR;
    }
    ListNode* head = uriList.head;
    while (head != NULL) {
        if (BuildOption(optionList, COAP_OPT_URI_PATH, strlen((char*)head->data), (char*)head->data) != 0) {
            ReleaseList(&uriList);
            return ATTEST_ERR;
        }
        head = head->next;
    }
    ReleaseList(&uriList);
    return ATTEST_OK;
}

static int32_t GenUdidSHA256HEX(char* udid, char** udidSHA256Hex)
{
    if (udid == NULL || udidSHA256Hex == NULL) {
        ATTEST_LOG_ERROR("[GenUdidSHA256HEX] Invalid parameter.");
        return ATTEST_ERR;
    }

    int32_t ret = ToLowerStr(udid, UDID_STRING_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GenUdidSHA256HEX] To lower string failed.");
        return ATTEST_ERR;
    }
    char* udidAfterSHA256 = (char*)ATTEST_MEM_MALLOC(UDID_SHA256_OUTPUT_SIZE + 1);
    if (udidAfterSHA256 == NULL) {
        return ATTEST_ERR;
    }
    ret = Sha256Value((const unsigned char *)udid, UDID_STRING_LEN, udidAfterSHA256, UDID_SHA256_OUTPUT_SIZE + 1);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GenUdidSHA256HEX] Sha256 value failed.");
        ATTEST_MEM_FREE(udidAfterSHA256);
        return ATTEST_ERR;
    }
    *udidSHA256Hex = udidAfterSHA256;
    return ATTEST_OK;
}

static int32_t BuildClientIdOption(const DevicePacket *devPacket, List* optionList)
{
    char* udidSHA256HEX = NULL;
    int32_t ret = GenUdidSHA256HEX(devPacket->udid, &udidSHA256HEX);
    if (ret != 0) {
        ATTEST_LOG_ERROR("[BuildClientIdOption] Generate udid sha256 hex failed.");
        return ATTEST_ERR;
    }
    ret = ToLowerStr(udidSHA256HEX, UDID_HEX_OUTPUT_SIZE);
    if (ret != 0) {
        return ATTEST_ERR;
    }
    if (BuildOption(optionList, COAP_OPT_CLIENT_ID, UDID_HEX_OUTPUT_SIZE, udidSHA256HEX) != 0) {
        ATTEST_MEM_FREE(udidSHA256HEX);
        return ATTEST_ERR;
    }
    ATTEST_MEM_FREE(udidSHA256HEX);
    return ATTEST_OK;
}

static int32_t BuildAppIdOption(const DevicePacket *devPacket, List* optionList)
{
    char *appId = devPacket->appId;
    if (BuildOption(optionList, COAP_OPT_APP_ID, strlen(appId), appId) != 0) {
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

static int32_t TransOptions(const TLSSession* session, const DevicePacket *devPacket, ATTEST_ACTION_TYPE actionType,
                            List* optionList)
{
    ATTEST_LOG_DEBUG("[TransOptions] Start.");
    if (optionList == NULL) {
        ATTEST_LOG_ERROR("[TransOptions] Invalid parameter.");
        return ATTEST_ERR;
    }
    if (BuildOption(optionList, COAP_OPT_URI_HOST, sizeof(session->serverInfo.hostName),
        session->serverInfo.hostName) != 0) {
        ATTEST_LOG_ERROR("[TransOptions] Build Coap host option failed.");
        return ATTEST_ERR;
    }
    if (BuildUriOption(g_uriPath[actionType], strlen(g_uriPath[actionType]), optionList) != 0) {
        ATTEST_LOG_ERROR("[TransOptions] Build coap uri_path option failed.");
        return ATTEST_ERR;
    }

    // Add traceId option
    if (BuildOption(optionList, COAP_OPT_REQ_ID, strlen(devPacket->randomUuid), devPacket->randomUuid) != 0) {
        ATTEST_LOG_ERROR("[TransOptions] Build Coap req_id option failed.");
        return ATTEST_ERR;
    }
    if (BuildClientIdOption(devPacket, optionList) != 0) {
        ATTEST_LOG_ERROR("[TransOptions] Build coap client_id option failed.");
        return ATTEST_ERR;
    }
    if (BuildAppIdOption(devPacket, optionList) != 0) {
        ATTEST_LOG_ERROR("[TransOptions] Build coap app_id option failed.");
        return ATTEST_ERR;
    }
    ATTEST_LOG_DEBUG("[TransOptions] End.");
    return ATTEST_OK;
}

static int32_t SendTLSMsg(const TLSSession* session, char *coapMessage, size_t coapMessageLen)
{
    if (session == NULL || coapMessage == NULL || coapMessageLen > MAX_MESSAGE_LEN) {
        return ERR_NET_INVALID_ARG;
    }
    int32_t ret = ATTEST_ERR;
    int32_t i = 0;
    for (; i <= WISE_RETRY_CNT; i++) {
        ret = TLSWrite(session, (unsigned char*)coapMessage, coapMessageLen);
        if (ret == ATTEST_OK) {
            ATTEST_LOG_INFO("[SendTLSMsg] Send msg succ.");
            break;
        }
    }
    if (ret != ATTEST_OK && i > WISE_RETRY_CNT) {
        ATTEST_LOG_ERROR("[SendTLSMsg] Send msg failed, exceed retry limit.");
        return ret;
    }
    return ATTEST_OK;
}

static int32_t SendCoapMsg(const TLSSession* session, const DevicePacket* devPacket,
                           const ATTEST_ACTION_TYPE actionType, CoapBuffer* payload)
{
    ATTEST_LOG_DEBUG("[SendCoapMsg] Start.");
    if (devPacket == NULL || session == NULL || payload == NULL) {
        ATTEST_LOG_ERROR("[SendCoapMsg] Invalid parameter.");
        return ATTEST_ERR;
    }
    int32_t ret = ATTEST_OK;
    size_t coapMessageLen = MAX_MESSAGE_LEN;
    char* coapMessage = (char*)ATTEST_MEM_MALLOC(sizeof(char) * MAX_MESSAGE_LEN);
    if (coapMessage  == NULL) {
        return ERR_NET_MEM_MALLOC;
    }
    List optionList;
    (void)CreateList(&optionList);
    do {
        if (TransOptions(session, devPacket, actionType, &optionList) != ATTEST_OK) {
            ret = ATTEST_ERR;
            break;
        }
        if (BuildCoapMsg(&optionList, payload, coapMessage, &coapMessageLen) != 0) {
            ret = ATTEST_ERR;
            break;
        }
        if (SendTLSMsg(session, coapMessage, coapMessageLen) != 0) {
            ret = ATTEST_ERR;
            break;
        }
    } while (0);
    ReleaseList(&optionList);
    ATTEST_MEM_FREE(coapMessage);
    return ret;
}

static int32_t DecodeCoapMessage(CoapPacket* coapPkt, const char *input, size_t inputLen,
                                 char **output, size_t *outputLen)
{
    ATTEST_LOG_DEBUG("[DecodeCoapMessage] Start.");
    if (CoapDecode(coapPkt, (const uint8_t*)input, inputLen) != 0) {
        ATTEST_LOG_ERROR("[DecodeCoapMessage] Decode coap msg failed.");
        return ATTEST_ERR;
    }
    if (coapPkt->payload.len == 0) {
        return ATTEST_ERR;
    }
    *outputLen = coapPkt->payload.len;
    char *tempOutput = (char *)ATTEST_MEM_MALLOC((*outputLen + 1) * sizeof(char));
    if (tempOutput == NULL) {
        return ERR_NET_MEM_MALLOC;
    }
    if (memcpy_s(tempOutput, *outputLen + 1, coapPkt->payload.buffer, *outputLen + 1) != 0) {
        ATTEST_MEM_FREE(tempOutput);
        return ERR_NET_MEM_MEMCPY;
    }
    *output = tempOutput;
    ATTEST_LOG_DEBUG("[DecodeCoapMessage] End.");
    return ATTEST_OK;
}

static int32_t DecodeExtendedLength(const TLSSession* session, size_t messageLen, size_t extendedLen,
                                    size_t *extendedLength)
{
    if (extendedLen == 0 || extendedLength == NULL) {
        return ATTEST_ERR;
    }
    char* messageExtendedLength = (char*)ATTEST_MEM_MALLOC(sizeof(char) * extendedLen);
    if (messageExtendedLength == NULL) {
        return ERR_NET_MEM_MALLOC;
    }
    if (TLSRead(session, (unsigned char*)messageExtendedLength, extendedLen) != 0) {
        ATTEST_MEM_FREE(messageExtendedLength);
        return ATTEST_ERR;
    }
    
    if (messageLen == COAP_MESSAGE_OFFSET_ONE_BYTE) {
        *extendedLength = (((size_t)messageExtendedLength[0] & 0xFF) + COAP_MESSAGE_DIFF_VALUE_BYTE);
    } else if (messageLen == COAP_MESSAGE_OFFSET_TWO_BYTES) {
        size_t tempLength = (size_t)(((messageExtendedLength[0] & 0xFF) << BITS_PER_BYTE) |
                            (messageExtendedLength[1] & 0xFF));
        if (tempLength > (MAX_VALUE_TWO_BYTES - COAP_MESSAGE_DIFF_VALUE_TWO_BYTES)) {
            return COAP_ERR_CODE_BAD_REQUEST;
        }
        *extendedLength = tempLength + COAP_MESSAGE_DIFF_VALUE_TWO_BYTES;
    } else if (messageLen == COAP_MESSAGE_OFFSET_FOUR_BYTES) {
        ATTEST_MEM_FREE(messageExtendedLength);
        return COAP_ERR_CODE_EXTENDED_LENGTH_INVALID;
    }
    ATTEST_MEM_FREE(messageExtendedLength);
    return ATTEST_OK;
}

static int32_t DecodeLenTkl(const TLSSession* session, CoapPacket* coapPkt)
{
    uint8_t msgLenTkl[COAP_LENTKL_LEN] = {0};
    int32_t ret = TLSRead(session, &msgLenTkl[0], COAP_LENTKL_LEN);
    if (ret != 0) {
        ATTEST_LOG_ERROR("[DecodeLenTkl] Receive message LenTkl fail, ret = %d.", ret);
        return ATTEST_ERR;
    }
    uint8_t msgLen = ((msgLenTkl[0] & 0xF0) >> COAP_BITS_HEADER_LEN);
    uint8_t msgTkl = msgLenTkl[0] & 0x0F;
    coapPkt->hdr.len = msgLen;
    coapPkt->hdr.tkl = msgTkl;
    size_t extendedLengthSize = 0;
    size_t extendedLength = 0;

    if ((ret = CoapGetExtensionLen(msgLen, &extendedLengthSize)) != 0) {
        return ret;
    }
    if ((ret = DecodeExtendedLength(session, msgLen, extendedLengthSize, &extendedLength)) != 0) {
        ATTEST_LOG_ERROR("[DecodeLenTkl] Decode extended length fail, ret = %d, extendedLength = %d.",
            ret, extendedLength);
        return ret;
    }
    coapPkt->hdr.extendedLength.buffer = extendedLength;
    coapPkt->hdr.extendedLength.len = extendedLengthSize;
    return ATTEST_OK;
}

static int32_t RecvCoapMsg(const TLSSession* session, char **respData, size_t *respDataLen)
{
    if (session == NULL || respData == NULL || respDataLen == NULL) {
        ATTEST_LOG_ERROR("[RecvCoapMsg] Invalid parameter.");
        return ATTEST_ERR;
    }
    CoapPacket coapPkt;
    (void)memset_s(&coapPkt, sizeof(CoapPacket), 0, sizeof(CoapPacket));
    int32_t ret = DecodeLenTkl(session, &coapPkt);
    if (ret != ATTEST_OK) {
        return ret;
    }
    // coapMessageLen include: code + tokens + options + payload
    if ((LENTKL_LEN + coapPkt.hdr.extendedLength.len + CODE_LEN +
         coapPkt.hdr.tkl + coapPkt.hdr.extendedLength.buffer) > MAX_MESSAGE_LEN) {
        ATTEST_LOG_ERROR("[RecvCoapMsg] Receive message overruns the buffer size");
        return COAP_ERR_CODE_PACKET_EXCEED_MAX_PDU;
    }
    size_t coapMessageLen = CODE_LEN + coapPkt.hdr.tkl + coapPkt.hdr.extendedLength.buffer;
    coapPkt.len = coapMessageLen + coapPkt.hdr.extendedLength.len + LENTKL_LEN;
    char *coapMessage = (char *)ATTEST_MEM_MALLOC(coapMessageLen * sizeof(char));
    if (coapMessage == NULL) {
        ATTEST_LOG_ERROR("[RecvCoapMsg] Mem malloc failed.");
        return ERR_NET_MEM_MALLOC;
    }
    do {
        if (TLSRead(session, (unsigned char*)coapMessage, coapMessageLen) != 0) {
            ATTEST_LOG_ERROR("[RecvCoapMsg] Receive message fail, ret = %d.", ret);
            ret = ATTEST_ERR;
            break;
        }
        if (DecodeCoapMessage(&coapPkt, coapMessage, coapMessageLen, respData, respDataLen) != 0) {
            ATTEST_LOG_ERROR("[RecvCoapMsg] Decode coap message fail.");
            ret = ATTEST_ERR;
            break;
        }
    } while (0);
    ATTEST_MEM_FREE(coapMessage);
    return ret;
}

int32_t SendAttestMsg(const DevicePacket *devPacket, ATTEST_ACTION_TYPE actionType, char **respBody)
{
    ATTEST_LOG_DEBUG("[SendAttestMsg] Begin.");
    
    char *reqData = NULL;
    char *respData = NULL;
    int32_t retCode;
    CoapBuffer payload;
    (void)memset_s(&payload, sizeof(CoapBuffer), 0, sizeof(CoapBuffer));
    if (devPacket == NULL || respBody == NULL || actionType >= ATTEST_ACTION_MAX) {
        ATTEST_LOG_ERROR("[SendAttestMsg] Input Parameter is null.");
        return ATTEST_ERR;
    }
    do {
        retCode = GenCoapMsg(devPacket, actionType, &reqData);
        if (retCode != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendAttestMsg] Generate coap msg fail, retCode = %d.", retCode);
            break;
        }

        payload.buffer = (unsigned char *)reqData;
        payload.len = strlen(reqData);
        retCode = SendCoapMsg(g_attestSession, devPacket, actionType, &payload);
        if (retCode != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendAttestMsg] Send https msg failed, retCode = %d.", retCode);
            break;
        }
        size_t respDataLen = 0;
        retCode = RecvCoapMsg(g_attestSession, &respData, &respDataLen);
        if (retCode != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendAttestMsg] Parse response failed, retCode = %d.", retCode);
            break;
        }
    } while (0);
    ATTEST_MEM_FREE(reqData);
    if (retCode != ATTEST_OK) {
        ATTEST_MEM_FREE(respData);
        return retCode;
    }
    *respBody = respData;
    ATTEST_LOG_DEBUG("[SendAttestMsg] End.");
    return retCode;
}

static int32_t SplitNetworkInfoSymbol(char *inputData, List *list)
{
    if (inputData == NULL || list == NULL) {
        ATTEST_LOG_ERROR("[SplitNetworkInfoSymbol] paramter wrong.");
        return ATTEST_ERR;
    }

    ServerInfo* networkServerInfo = (ServerInfo*)ATTEST_MEM_MALLOC(sizeof(ServerInfo));
    if (networkServerInfo == NULL) {
        ATTEST_LOG_ERROR("[SplitNetworkInfoSymbol] network infomation malloc failed.");
        return ATTEST_ERR;
    }

    int32_t ret = sscanf_s(inputData, "%" HOST_PATTERN ":%" PORT_PATTERN,
        networkServerInfo->hostName, MAX_HOST_NAME_LEN,
        networkServerInfo->port, MAX_PORT_LEN);

    if (ret != PARAM_TWO) {
        ATTEST_LOG_ERROR("[SplitNetworkInfoSymbol] failed to split NetworkInfo, host[%s] port[%s]",
            networkServerInfo->hostName, networkServerInfo->port);
        ATTEST_MEM_FREE(networkServerInfo);
        return ATTEST_ERR;
    }
    ret = AddListNode(list, (char *)networkServerInfo);
    return ret;
}

#ifdef __LITEOS_M__
static int32_t ParseNetworkInfosConfig(char *inputData, List *list)
{
    if (inputData == NULL || list == NULL) {
        ATTEST_LOG_ERROR("[ParseNetworkInfosConfig] paramter wrong.");
        return ATTEST_ERR;
    }
    int32_t ret = ATTEST_OK;
    char *next = NULL;
    char *pNext = strtok_s(inputData, ";", &next);
    if (pNext == NULL) {
        ATTEST_LOG_ERROR("[ParseNetworkInfosConfig] inputData or strtok_s wrong");
        return ATTEST_ERR;
    }
    while (pNext != NULL) {
        ret = SplitNetworkInfoSymbol(pNext, list);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseNetworkInfosConfig] failed to split network info.");
            break;
        }
        pNext = strtok_s(NULL, ";", &next);
    }
    return ret;
}
#else
static int32_t ParseNetworkInfosConfig(char *inputData, List *list)
{
    if (inputData == NULL || list == NULL) {
        ATTEST_LOG_ERROR("[ParseNetworkInfoConfig] parameter wrong.");
        return ATTEST_ERR;
    }

    cJSON* root = cJSON_Parse(inputData);
    if (root == NULL) {
        ATTEST_LOG_ERROR("[ParseNetworkInfoConfig] failed to parse json.");
        return ATTEST_ERR;
    }

    int32_t ret = ATTEST_OK;
    do {
        cJSON* array = cJSON_GetObjectItem(root, NETWORK_CONFIG_SERVER_INFO_NAME);
        if (array == NULL) {
            ATTEST_LOG_ERROR("[ParseNetworkInfosConfig] failed to get ObjectItem");
            ret = ATTEST_ERR;
            break;
        }
        if (!cJSON_IsArray(array)) {
            ret = ATTEST_ERR;
            break;
        }
        int32_t arraySize = cJSON_GetArraySize(array);
        for (int32_t i = 0; i < arraySize; i++) {
            char *valueString = cJSON_GetStringValue(cJSON_GetArrayItem(array, i));
            if (valueString == NULL) {
                ATTEST_LOG_ERROR("[ParseNetworkInfosConfig] failed to get string");
                ret = ATTEST_ERR;
                break;
            }

            ret = SplitNetworkInfoSymbol(valueString, list);
            if (ret != ATTEST_OK) {
                ATTEST_LOG_ERROR("[ParseNetworkInfosConfig] failed to get SplitNetworkInfo");
                break;
            }
        }
        if (ret != ATTEST_OK) {
            break;
        }
    } while (0);

    cJSON_Delete(root);
    return ret;
}
#endif

static int32_t NetworkInfoConfig(List* list)
{
    if (list == NULL) {
        ATTEST_LOG_ERROR("[NetworkInfoConfig] paramter wrong");
        return ATTEST_ERR;
    }

    // No need to initialize
    if (GetListSize(list) != 0) {
        ATTEST_LOG_WARN("[NetworkInfoConfig] already configed network list");
        return ATTEST_OK;
    }

    int32_t ret = CreateList(list);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[NetworkInfoConfig] create network list failed");
        return ATTEST_ERR;
    }

    // For reading network_config.json
    char *buffer = (char *)ATTEST_MEM_MALLOC(NETWORK_CONFIG_SIZE + 1);
    if (buffer == NULL) {
        ATTEST_LOG_ERROR("[NetworkInfoConfig] buffer malloc failed.");
        ReleaseList(list);
        return ATTEST_ERR;
    }
    do {
        ret = AttestReadNetworkConfig(buffer, NETWORK_CONFIG_SIZE);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[NetworkInfoConfig] read networkconfig failed.");
            break;
        }

        ret = ParseNetworkInfosConfig(buffer, list);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[NetworkInfoConfig] parse networkconfig failed.");
            break;
        }
    } while (0);
    if (ret != ATTEST_OK) {
        ReleaseList(list);
    }
    ATTEST_MEM_FREE(buffer);
    return ret;
}

int32_t InitNetworkServerInfo(void)
{
    if (g_attestNetworkList.head != NULL) {
        ATTEST_LOG_WARN("[InitNetworkServerInfo] already init g_attestNetworkList");
        return ATTEST_OK;
    }
    int32_t ret = NetworkInfoConfig(&g_attestNetworkList);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_INFO("[InitNetworkServerInfo] init g_attestNetworkList failed");
        return ret;
    }
    return ATTEST_OK;
}

static int32_t MergeDomain(char* hostName, char* port, char** resultDomain)
{
    if (hostName == NULL || port == NULL || resultDomain == NULL) {
        ATTEST_LOG_ERROR("[MergeDomain] invalid parameter");
        return ATTEST_ERR;
    }
    int32_t ret = ATTEST_OK;
    char* newDomain = NULL;
    do {
        int newDomainSize = strlen(hostName) + strlen(port) + strlen(CONNECTOR) + 1;
        newDomain = (char *)ATTEST_MEM_MALLOC(newDomainSize);
        if (newDomain == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[MergeDomain] failed to mem malloc new domain");
            break;
        }
        if (strcat_s(newDomain, newDomainSize, hostName) != 0 ||
            strcat_s(newDomain, newDomainSize, CONNECTOR) != 0 ||
            strcat_s(newDomain, newDomainSize, port) != 0) {
            ATTEST_MEM_FREE(newDomain);
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[MergeDomain] failed to copy domain info");
            break;
        }
    } while (0);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[MergeDomain] cat host port failed");
        return ATTEST_ERR;
    }
    *resultDomain = newDomain;
    return ret;
}

static int32_t TestConnection(char* newDomain, char* curDomain)
{
    int32_t ret = TLSClose(g_attestSession);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[TestConnection] close connection failed");
        return ATTEST_ERR;
    }
    do {
        ReleaseList(&g_attestNetworkList);
        ret = SplitNetworkInfoSymbol(newDomain, &g_attestNetworkList);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[TestConnection] update g_attestNetworkList failed");
            break;
        }
        ret = ConnectNetWork(&g_attestSession, DEVATTEST_ID);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[TestConnection] connect to new domain failed");
            break;
        }
    } while (0);
    if (ret != ATTEST_OK) {
        ReleaseList(&g_attestNetworkList);
        (void)SplitNetworkInfoSymbol(curDomain, &g_attestNetworkList);
        return ATTEST_ERR;
    }
    ATTEST_LOG_DEBUG("[TestConnection] connect to new domain[%s] success", newDomain);
    return ATTEST_OK;
}

static int32_t CheckDomain(char* inputData, char** outData)
{
    if (inputData == NULL || outData == NULL) {
        ATTEST_LOG_ERROR("[CheckDomain] Invalid parameter");
        return ATTEST_ERR;
    }
    if (g_attestNetworkList.head == NULL) {
        ATTEST_LOG_ERROR("[CheckDomain] no init g_attestNetworkList ");
        return ATTEST_ERR;
    }
    ServerInfo* serverInfo = (ServerInfo*)g_attestNetworkList.head->data;
    char newHost[MAX_HOST_NAME_LEN];
    int32_t ret = sscanf_s(inputData, "%*[^:]:%*[/]%[a-zA-Z_.-]", newHost, MAX_HOST_NAME_LEN);
    if (ret != PARAM_ONE) {
        ATTEST_LOG_ERROR("[CheckDomain] split domain from HTTP addr failed");
        return ATTEST_ERR;
    }
    if (strcmp(serverInfo->hostName, newHost) == 0) {
        ATTEST_LOG_ERROR("[CheckDomain] same domain");
        return ATTEST_ERR;
    }
    char* newDomain = NULL;
    char* curDomain = NULL;
    if (MergeDomain(serverInfo->hostName, serverInfo->port, &curDomain) != ATTEST_OK ||
        MergeDomain(newHost, serverInfo->port, &newDomain) != ATTEST_OK) {
        ATTEST_LOG_ERROR("[CheckDomain] generate domain failed");
        return ATTEST_ERR;
    }
    ret = TestConnection(newDomain, curDomain);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[CheckDomain] connect to new domain[%s] failed", newDomain);
        TLSClose(g_attestSession);
        (void)InitNetworkServerInfo();
        ConnectNetWork(&g_attestSession, DEVATTEST_ID);
        return ATTEST_ERR;
    }
    *outData = newDomain;
    ATTEST_LOG_DEBUG("[CheckDomain] check domain success");
    return ATTEST_OK;
}

#ifdef __LITEOS_M__
static int32_t DumpDomain(const char* newDomain)
{
    uint32_t len = strlen(newDomain) * sizeof(char);
    int32_t ret = AttestWriteNetworkConfig(newDomain, len);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DumpDomain] dump networkconfig failed.");
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}
#else
static int32_t DumpDomain(const char* newDomain)
{
    cJSON* newConfig = cJSON_CreateObject();
    cJSON* newArr = cJSON_AddArrayToObject(newConfig, NETWORK_CONFIG_SERVER_INFO_NAME);
    cJSON_AddItemToArray(newArr, cJSON_CreateString(newDomain));
    char* jsonData = cJSON_Print(newConfig);
    cJSON_Delete(newConfig);
    uint32_t len = strlen(jsonData) * sizeof(char);
    int32_t ret = AttestWriteNetworkConfig(jsonData, len);
    ATTEST_MEM_FREE(jsonData);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DumpDomain] dump networkconfig failed.");
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}
#endif

int32_t UpdateNetConfig(char* activeSite, char* standbySite, int32_t* updateFlag)
{
    if (activeSite == NULL || standbySite == NULL || updateFlag == NULL) {
        ATTEST_LOG_ERROR("[UpdateNetConfig] Invalid parameter");
        return ATTEST_ERR;
    }
    char* newDomain = NULL;
    *updateFlag = UPDATE_NO;
    int32_t ret = CheckDomain(activeSite, &newDomain);
    if (ret != ATTEST_OK && strcmp(activeSite, standbySite) != 0) {
        ret = CheckDomain(standbySite, &newDomain);
    }
    if (ret != ATTEST_OK) {
        (void)InitNetworkServerInfo();
        ATTEST_LOG_WARN("[UpdateNetConfig] update new domain failed");
        return ATTEST_ERR;
    }
    *updateFlag = UPDATE_OK;
    ret = DumpDomain(newDomain);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[UpdateNetConfig] dump new domain failed");
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}