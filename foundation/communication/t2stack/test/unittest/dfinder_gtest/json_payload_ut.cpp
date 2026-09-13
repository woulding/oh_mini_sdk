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

#include "json_payload.h"
#include <securec.h>

#include "cJSON.h"
#ifndef DFINDER_USE_MINI_NSTACKX
#include "coap_client.h"
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
#include "nstackx_dfinder_log.h"
#include "nstackx_dfinder_mgt_msg_log.h"
#include "nstackx_error.h"
#include "nstackx_device.h"
#include "nstackx_statistics.h"
#include "nstackx_device_local.h"

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"

class Dfinder : public testing::Test {
public:
    void SetUp()
    {
        Dfinderinit();
    }
    void TearDown()
    {
        DfinderDestroy();
    }
};

TEST(Dfinder, TestPrepareServiceDiscover)
{
    DeviceInfo *deviceInfo = (DeviceInfo *)calloc(1, sizeof(DeviceInfo));
    char deviceName[11] = "deviceName";
    strcpy_s(deviceInfo->deviceName, sizeof(deviceInfo->deviceName), deviceName);
    deviceInfo->deviceType = UINT8_MAX + 1;
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM] = {1};
    memcpy_s(deviceInfo->capabilityBitmap, sizeof(deviceInfo->capabilityBitmap), capabilityBitmap,
        sizeof(deviceInfo->capabilityBitmap));
    MOCKER(GetLocalDeviceInfo).stubs().will(returnValue(deviceInfo));
    char localIpStr[NSTACKX_MAX_IP_STRING_LEN] = "127.1.1.1";
    char serviceData[512] =
        "{"
        "\"deviceId\":\"{\\\"UDID\\\":\\\"FE73EE0BA926F5A5B149B1567AD2D32BC5443A9FE05FE812CE623283EAE5CEDD\\\"}\","
        "\"devicename\":\"Mate 50\",\"type\":0,\"seqNo\":1,\"mode\":1,"
        "\"deviceHash\":\"0\",\"serviceData\":\"\",\"extendServiceData\":\"\",\"wlanIp\":\"127.0.0.1\","
        "\"capabilityBitmap\":[71],"
        "\"bType\":0,\"bData\":\"\", \"coapUri\":\"coap://127.0.0.1/device_discover\""
        "}";
    char *ret = PrepareServiceDiscover(AF_INET, localIpStr, NSTACKX_TRUE, NSTACKX_BUSINESS_TYPE_SOFTBUS, serviceData);
    ASSERT_NE(ret, (char *)NULL);
    cJSON_free(ret);

    // deviceInfo->deviceType <= UINT8_MAX
    deviceInfo->deviceType = UINT8_MAX;
    ret = PrepareServiceDiscover(AF_INET, localIpStr, NSTACKX_TRUE, NSTACKX_BUSINESS_TYPE_SOFTBUS, serviceData);
    ASSERT_NE(ret, (char *)NULL);
    cJSON_free(ret);

    GlobalMockObject::verify();

    // cJSON_CreateString == NULL
    MOCKER(GetLocalDeviceInfo).stubs().will(returnValue(deviceInfo));
    MOCKER(cJSON_CreateString).stubs().will(returnValue((cJSON *)NULL));
    ret = PrepareServiceDiscover(AF_INET, localIpStr, NSTACKX_TRUE, NSTACKX_BUSINESS_TYPE_SOFTBUS, serviceData);
    ASSERT_EQ(ret, (char *)NULL);
    GlobalMockObject::verify();

    // cJSON_CreateNumber == NULL
    MOCKER(GetLocalDeviceInfo).stubs().will(returnValue(deviceInfo));
    MOCKER(cJSON_CreateNumber).stubs().will(returnValue((cJSON *)NULL));
    ret = PrepareServiceDiscover(AF_INET, localIpStr, NSTACKX_TRUE, NSTACKX_BUSINESS_TYPE_SOFTBUS, serviceData);
    ASSERT_EQ(ret, (char *)NULL);
    GlobalMockObject::verify();

    // cJSON_CreateObject == NULL
    MOCKER(cJSON_CreateObject).stubs().will(returnValue((cJSON *)NULL));
    ret = PrepareServiceDiscover(AF_INET, localIpStr, NSTACKX_TRUE, NSTACKX_BUSINESS_TYPE_SOFTBUS, serviceData);
    ASSERT_EQ(ret, (char *)NULL);
    GlobalMockObject::verify();

    free(deviceInfo);
}

TEST(Dfinder, TestParseServiceDiscover)
{
    char buf[512] =
        "{"
        "\"deviceId\":\"{\\\"UDID\\\":\\\"FE73EE0BA926F5A5B149B1567AD2D32BC5443A9FE05FE812CE623283EAE5CEDD\\\"}\","
        "\"devicename\":\"Mate 50\",\"type\":0,\"seqNo\":1,\"mode\":1,"
        "\"deviceHash\":\"0\",\"serviceData\":\"\",\"extendServiceData\":\"\",\"wlanIp\":\"127.0.0.1\","
        "\"capabilityBitmap\":[71],"
        "\"bType\":0,\"bData\":\"\", \"coapUri\":\"coap://127.0.0.1/device_discover\""
        "}";
    DeviceInfo *deviceInfo = (DeviceInfo *)calloc(1, sizeof(DeviceInfo));
    char *remoteUrl = NULL;
    int32_t ret = ParseServiceDiscover((uint8_t *)buf, deviceInfo, &remoteUrl);
    free(remoteUrl);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // strdup is error
    MOCKER(strdup).stubs().will(returnValue((char *)NULL));
    ret = ParseServiceDiscover((uint8_t *)buf, deviceInfo, &remoteUrl);
    GlobalMockObject::verify();
    ASSERT_EQ(ret, NSTACKX_ENOMEM);

    // cJSON_IsString is false, 0 is false
    MOCKER(cJSON_IsString).stubs().will(returnValue(0));
    ret = ParseServiceDiscover((uint8_t *)buf, deviceInfo, &remoteUrl);
    GlobalMockObject::verify();
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // strcpy_s != EOK
    MOCKER(strcpy_s).stubs().will(returnValue(-1));
    ret = ParseServiceDiscover((uint8_t *)buf, deviceInfo, &remoteUrl);
    GlobalMockObject::verify();
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // cJSON_IsNumber is false, 0 is false
    MOCKER(cJSON_IsNumber).stubs().will(returnValue(0));
    ret = ParseServiceDiscover((uint8_t *)buf, deviceInfo, &remoteUrl);
    GlobalMockObject::verify();
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    free(deviceInfo);
}

TEST(Dfinder, TestParseServiceDiscover_RecvMsgWithHicomVersion)
{
    char recvedMsg[512] =
        "{"
        "\"deviceId\":\"{\\\"UDID\\\":\\\"FE73EE0BA926F5A5B149B1567AD2D32BC5443A9FE05FE812CE623283EAE5CEDD\\\"}\","
        "\"devicename\":\"Mate 50\",\"type\":0,\"seqNo\":1,\"hicomversion\":\"3.1.0.0\",\"mode\":1,"
        "\"deviceHash\":\"0\",\"serviceData\":\"\",\"extendServiceData\":\"\",\"wlanIp\":\"127.0.0.1\","
        "\"capabilityBitmap\":[71],"
        "\"bType\":0,\"bData\":\"\", \"coapUri\":\"coap://127.0.0.1/device_discover\""
        "}";

    DeviceInfo *deviceInfo = (DeviceInfo *)calloc(1, sizeof(DeviceInfo));
    ASSERT_NE(deviceInfo, nullptr);

    char *remoteUrl = NULL;
    int32_t ret = ParseServiceDiscover((uint8_t *)recvedMsg, deviceInfo, &remoteUrl);
    free(deviceInfo);
    free(remoteUrl);
    ASSERT_EQ(ret, NSTACKX_EOK);
}

TEST(Dfinder, TestParseServiceNotification)
{
    char buf[] =
        "{\"notify\":\"{\\\"UDID\\\":\\\"FE73EE0BA926F5A5B149B1567AD2D32BC5443A9FE05FE812CE623283EAE5CEDD\\\"}\"}";
    // buf NULL
    int32_t ret = ParseServiceNotification(NULL, NULL);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "input buf null";

    char tmpMsg[NSTACKX_MAX_NOTIFICATION_DATA_LEN] = {0};
    NSTACKX_NotificationConfig config = {
        msg : tmpMsg,
        msgLen : 0,
        intervalsMs : NULL,
        intervalLen : 0,
        businessType : NSTACKX_BUSINESS_TYPE_NULL
    };

    // cJSON_Parse fail
    MOCKER(cJSON_Parse).stubs().will(returnValue((cJSON *)NULL));
    ret = ParseServiceNotification((const uint8_t *)buf, &config);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case cJSON_Parse fail";
    GlobalMockObject::verify();

    // cJSON_GetObjectItemCaseSensitive fail
    MOCKER(cJSON_GetObjectItemCaseSensitive).stubs().will(returnValue((cJSON *)NULL));
    ret = ParseServiceNotification((const uint8_t *)buf, &config);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case cJSON_GetObjectItemCaseSensitive fail";
    GlobalMockObject::verify();

    // cJSON_IsString fail
    MOCKER(cJSON_IsString).stubs().will(returnValue((cJSON_bool)false));
    ret = ParseServiceNotification((const uint8_t *)buf, &config);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case cJSON_IsString fail";
    GlobalMockObject::verify();

    // strcpy_s fail
    MOCKER(strcpy_s).stubs().will(returnValue(EINVAL));
    ret = ParseServiceNotification((const uint8_t *)buf, &config);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case strcpy_s fail";
    GlobalMockObject::verify();
}

TEST(Dfinder, TestPrepareServiceNotification)
{
    // cJSON_CreateObject fail
    MOCKER(cJSON_CreateObject).stubs().will(returnValue((cJSON *)NULL));
    char *ret = PrepareServiceNotification();
    EXPECT_EQ(ret, (char *)NULL) << "case cJSON_CreateObject fail";
    GlobalMockObject::verify();

    // JsonAddStr fail
    DeviceInfo tmpDeviceInfo = {0};
    MOCKER(GetLocalDeviceInfo).stubs().will(returnValue(&tmpDeviceInfo));
    MOCKER(cJSON_CreateString).stubs().will(returnValue((cJSON *)NULL));
    ret = PrepareServiceNotification();
    EXPECT_EQ(ret, (char *)NULL) << "JsonAddStr fail";
    GlobalMockObject::verify();

    // all ok
    tmpDeviceInfo = {0};
    MOCKER(GetLocalDeviceInfo).stubs().will(returnValue(&tmpDeviceInfo));
    ret = PrepareServiceNotification();
    EXPECT_NE(ret, (char *)NULL) << "case cJSON_PrintUnformatted fail";
    if (ret != NULL) {
        free(ret);
    }
    GlobalMockObject::verify();
}