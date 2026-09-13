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

#ifdef __LITEOS_M__

#include "attest_utils_log.h"
#include "attest_adapter.h"

#if defined(CHIP_VER_Hi3861)
#include <hi_mdm.h>

#define HI_NV_XTS_DEV_ATTEST_NET 0x60
#define HI_NV_NET_SIZE 164

typedef struct {
    uint8_t nv_dev_attest_net[HI_NV_NET_SIZE];
} hi_nv_xts_dev_attest_net_cfg;

static int32_t CopyNVData(char *dst, int32_t dstLen, unsigned char *src, int32_t srcLen)
{
    if (dst == NULL || src == NULL) {
        ATTEST_LOG_ERROR("[CopyNVData] input paramter wrong");
        return ATTEST_ERR;
    }
    int32_t dataLen = (dstLen < srcLen) ? dstLen : srcLen;
    for (int32_t i = 0; i < dataLen; i++) {
        dst[i] = (char)src[i];
    }
    return ATTEST_OK;
}

// 读取网络配置信息
int32_t AttestReadNetworkConfig(char* buffer, uint32_t bufferLen)
{
    hi_nv_xts_dev_attest_net_cfg nv_net = { 0 };
    int32_t ret = hi_nv_read(HI_NV_XTS_DEV_ATTEST_NET, (void*)&nv_net, sizeof(nv_net), 0);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestReadNetworkConfig] hi_nv_read failed");
        return ATTEST_ERR;
    }
    return CopyNVData(buffer, bufferLen, nv_net.nv_dev_attest_net, sizeof(hi_nv_xts_dev_attest_net_cfg));
}

// 写入网络配置信息
int32_t AttestWriteNetworkConfig(const char* data, uint32_t len)
{
    if (data == NULL || len > HI_NV_NET_SIZE) {
        ATTEST_LOG_ERROR("[AttestWriteNetworkConfig] invalid parameter");
        return ATTEST_ERR;
    }
    hi_nv_xts_dev_attest_net_cfg nv_net = { 0 };
    int32_t ret = CopyNVData(nv_net.nv_dev_attest_net, sizeof(hi_nv_xts_dev_attest_net_cfg), data, len);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestWriteNetworkConfig] copy data to NV failed");
        return ATTEST_ERR;
    }
    ret = hi_nv_write(HI_NV_XTS_DEV_ATTEST_NET, (void*)&nv_net, sizeof(nv_net), 0);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestWriteNetworkConfig] nv write failed");
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

#else

int32_t AttestReadNetworkConfig(char* buffer, uint32_t bufferLen)
{
    (void)buffer;
    (void)bufferLen;
    ATTEST_LOG_ERROR("[AttestReadNetworkConfig] Need to implement interface AttestReadNetworkConfig!");
    return ATTEST_ERR;
}

int32_t AttestWriteNetworkConfig(const char* data, uint32_t bufferLen)
{
    (void)data;
    (void)bufferLen;
    ATTEST_LOG_ERROR("[AttestWriteNetworkConfig] Need to implement interface AttestWriteNetworkConfig!");
    return ATTEST_ERR;
}

#endif // defined(CHIP_VER_Hi3861)

#endif // __LITEOS_M__
