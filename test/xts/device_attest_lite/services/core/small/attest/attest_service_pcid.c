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

#ifndef __LITEOS_M__
#include <securec.h>
#include "syscap_interface.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_service_device.h"

#define PCID_STRING_LEN 64

static int32_t MergePcid(char *osPcid, int32_t osPcidLen, char *privatePcid, int32_t privatePcidLen, char **output)
{
    if (output == NULL || osPcid == NULL || osPcidLen == 0) {
        ATTEST_LOG_ERROR("[MergePcid] Invalid parameter.");
        return ATTEST_ERR;
    }

    int32_t pcidLen = osPcidLen + privatePcidLen;
    char *pcidBuff = (char *)ATTEST_MEM_MALLOC(pcidLen);
    if (pcidBuff == NULL) {
        ATTEST_LOG_ERROR("[MergePcid] Failed to malloc.");
        return ATTEST_ERR;
    }

    if (memcpy_s(pcidBuff, pcidLen, osPcid, osPcidLen) != 0) {
        ATTEST_LOG_ERROR("[MergePcid] Failed to memcpy osSyscaps.");
        ATTEST_MEM_FREE(pcidBuff);
        return ATTEST_ERR;
    }

    if ((privatePcidLen > 0 && privatePcid != NULL) &&
        (memcpy_s(pcidBuff, pcidLen, privatePcid, privatePcidLen) != 0)) {
        ATTEST_LOG_ERROR("[MergePcid] Failed to memcpy privateSyscaps.");
        ATTEST_MEM_FREE(pcidBuff);
        return ATTEST_ERR;
    }

    *output = pcidBuff;
    return ATTEST_OK;
}

static int32_t EncodePcid(char *buff, int32_t bufLen, char **output)
{
    if (output == NULL || buff == NULL || bufLen == 0) {
        ATTEST_LOG_ERROR("[EncodePcid] Invalid parameter.");
        return ATTEST_ERR;
    }

    char *pcidSha256 = (char *)ATTEST_MEM_MALLOC(PCID_STRING_LEN + 1);
    if (pcidSha256 == NULL) {
        ATTEST_LOG_ERROR("[EncodePcid] Failed to malloc.");
        return ATTEST_ERR;
    }

    int32_t ret = Sha256Value((const uint8_t *)buff, bufLen, pcidSha256, PCID_STRING_LEN + 1);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncodePcid] Failed to encode.");
        ATTEST_MEM_FREE(pcidSha256);
        return ATTEST_ERR;
    }

    *output = pcidSha256;
    return ATTEST_OK;
}

char* GetPcid(void)
{
    char osSyscaps[PCID_MAIN_BYTES] = {0};
    if (!EncodeOsSyscap(osSyscaps, PCID_MAIN_BYTES)) {
        ATTEST_LOG_ERROR("[GetPcid] EncodeOsSyscap failed");
        return NULL;
    }

    char *privateSyscaps = NULL;
    int32_t privatePcidLen = 0;
    if (!EncodePrivateSyscap(&privateSyscaps, &privatePcidLen)) {
        ATTEST_LOG_ERROR("[GetPcid] EncodePrivateSyscap failed");
        return NULL;
    }

    // Merge OsSyscap and PrivateSyscap
    char *pcidBuff = NULL;
    int32_t ret = MergePcid(osSyscaps, PCID_MAIN_BYTES, privateSyscaps, privatePcidLen, &pcidBuff);
    if (ret != ATTEST_OK || pcidBuff == NULL) {
        ATTEST_LOG_ERROR("[GetPcid] Failed to merge Pcid.");
        return NULL;
    }

    // SHA256转换
    char *pcidSha256 = NULL;
    ret = EncodePcid(pcidBuff, PCID_MAIN_BYTES + privatePcidLen, &pcidSha256);
    if (ret != ATTEST_OK || pcidSha256 == NULL) {
        ATTEST_LOG_ERROR("[GetPcid] Failed to SHA256.");
        ATTEST_MEM_FREE(pcidBuff);
        return NULL;
    }

    ATTEST_MEM_FREE(pcidBuff);
    return pcidSha256;
}
#endif
