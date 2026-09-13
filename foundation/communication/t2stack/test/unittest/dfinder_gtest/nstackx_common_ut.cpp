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

#include "nstackx_common.h"
#include "nstackx_error.h"
#include "nstackx_event.h"
#include "nstackx_timer.h"
#include "nstackx_util.h"
#include "json_payload.h"
#include "nstackx_device_remote.h"
#include "nstackx_dfinder_hievent.h"

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"

static void DeviceListChanged(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
}

static void DeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
}

static void MsgReceived(const char *moduleName, const char *deviceId,
                        const uint8_t *data, uint32_t len, const char *srcIp)
{
}

static DFinderMsgType mType = DFINDER_ON_INNER_ERROR;

static void DFinderMsgReceived(DFinderMsgType msgType)
{
    mType = msgType;
}

void DFinderOnNotificationReceived(const NSTACKX_NotificationConfig *notification)
{
    (void)notification;
}

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

TEST(Dfinder, TestGetIsNotifyPerDevice)
{
    bool ret = GetIsNotifyPerDevice();
    ASSERT_EQ(ret, false);
}

TEST(Dfinder, TestGetEventNodeChain)
{
    List *ret = GetEventNodeChain();
    ASSERT_NE(ret, nullptr);
}

TEST(Dfinder, TestGetEpollFD)
{
    EpollDesc ret = GetEpollFD();
    ASSERT_EQ(ret, INVALID_EPOLL_DESC);
}

TEST(Dfinder, TestNotifyDFinderMsgRecver)
{
    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    NotifyDFinderMsgRecver(DFINDER_ON_TOO_BUSY);
    ASSERT_EQ(mType, DFINDER_ON_TOO_BUSY);
    NSTACKX_Deinit();
}

TEST(Dfinder, TestShouldAutoReplyUnicast)
{
    int32_t ret = ShouldAutoReplyUnicast(NSTACKX_BUSINESS_TYPE_NULL);
    ASSERT_EQ(ret, NSTACKX_TRUE);
    ret = ShouldAutoReplyUnicast(NSTACKX_BUSINESS_TYPE_HICOM);
    ASSERT_EQ(ret, NSTACKX_TRUE);
    ret = ShouldAutoReplyUnicast(NSTACKX_BUSINESS_TYPE_SOFTBUS);
    ASSERT_EQ(ret, NSTACKX_FALSE);
    ret = ShouldAutoReplyUnicast(NSTACKX_BUSINESS_TYPE_NEARBY);
    ASSERT_EQ(ret, NSTACKX_TRUE);
    ret = ShouldAutoReplyUnicast(-1);
    ASSERT_EQ(ret, NSTACKX_TRUE);
}

TEST(Dfinder, TestGetDefaultDiscoverInterval)
{
    uint32_t ret = GetDefaultDiscoverInterval(0);
    ASSERT_EQ(ret, (uint32_t)COAP_FIRST_DISCOVER_INTERVAL);
    ret = GetDefaultDiscoverInterval(COAP_FIRST_DISCOVER_COUNT_RANGE);
    ASSERT_EQ(ret, (uint32_t)COAP_SECOND_DISCOVER_INTERVAL);
    ret = GetDefaultDiscoverInterval(COAP_SECOND_DISCOVER_COUNT_RANGE);
    ASSERT_EQ(ret, (uint32_t)COAP_LAST_DISCOVER_INTERVAL);
}

TEST(Dfinder, TestGetServiceDiscoverInfo)
{
    const uint8_t *buf =(uint8_t *)
        "{\"deviceId\":\"{\\\"UDID\\\":\\\"FE73EE0BA926F5A5B149B1567AD2D32BC5443A9FE05FE812CE623283EAE5CEDD\\\"}\","
        "\"devicename\":\"Mate 50\",\"type\":14,\"mode\":1,\"deviceHash\":\"0\","
        "\"serviceData\":\"\",\"extendServiceData\":\"\",\"wlanIp\":\"127.0.0.1\",\"capabilityBitmap\":[71],"
        "\"bType\":0,\"bData\":\"\", \"coapUri\":\"coap://127.0.0.1/device_discover\"}";
    DeviceInfo deviceInfo = {0};
    char *remoteUrl = NULL;
    //deviceInfo->discoveryType = (*remoteUrl != NULL) ? NSTACKX_DISCOVERY_TYPE_PASSIVE : NSTACKX_DISCOVERY_TYPE_ACTIVE;
    deviceInfo.discoveryType = NSTACKX_DISCOVERY_TYPE_ACTIVE;

    // size <= 0
    int32_t ret = GetServiceDiscoverInfo(buf, 0, &deviceInfo, &remoteUrl);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    ret = GetServiceDiscoverInfo(buf, sizeof(buf)-1, &deviceInfo, &remoteUrl);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    // memcpy_s is error
    MOCKER(memcpy_s).stubs().will(returnValue(-1));
    ret = GetServiceDiscoverInfo(buf, sizeof(buf)-1, &deviceInfo, &remoteUrl);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = GetServiceDiscoverInfo(buf, sizeof(buf)-1, &deviceInfo, &remoteUrl);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // ParseServiceDiscover == NSTACKX_EOK
    MOCKER(ParseServiceDiscover).stubs().will(returnValue(NSTACKX_EOK));
    ret = GetServiceDiscoverInfo(buf, sizeof(buf)-1, &deviceInfo, &remoteUrl);
    ASSERT_EQ(ret, NSTACKX_EOK);
    GlobalMockObject::verify();
}

TEST(Dfinder, TestGetMainLoopEpollFd)
{
    EpollDesc ret = GetMainLoopEpollFd();
    ASSERT_EQ(ret, INVALID_EPOLL_DESC);
}

TEST(Dfinder, TestGetMainLoopEvendChain)
{
    List *ret = GetMainLoopEvendChain();
    ASSERT_NE(ret, nullptr);
}

TEST(Dfinder, TestNSTACKX_InitAndDeinit)
{
    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    // GetTimeDiffMs > EVENT_COUNT_RATE_INTERVAL
    MOCKER(GetTimeDiffMs).stubs().will(returnValue(2001));
    int32_t ret = NSTACKX_Init(&parameter);
    ASSERT_EQ(ret, NSTACKX_EOK);
    // init again
    ret = NSTACKX_InitV2(&parameter, true);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(1100000); // 因为每隔1秒，主线程会轮询执行一遍，所以睡眠1.1s，保证主线程轮询的时候mock还生效
    GlobalMockObject::verify();
    NSTACKX_Deinit();
    // deInit again
    NSTACKX_Deinit();

    // CoapDiscoverInit error
    MOCKER(CoapDiscoverInit).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_Init(&parameter);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // DeviceModuleInit error
    MOCKER(DeviceModuleInit).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_Init(&parameter);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // EventModuleInit error
    MOCKER(EventModuleInit).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_Init(&parameter);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // IsEpollDescValid error
    MOCKER(CreateEpollDesc).stubs().will(returnValue(-1));
    ret = NSTACKX_Init(&parameter);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_StartDeviceFind)
{
    // not init
    int32_t ret = NSTACKX_StartDeviceFind();
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDeviceFound = DeviceFound;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // all is ok
    MOCKER(IsCoapContextReady).stubs().will(returnValue(true));
    ret = NSTACKX_StartDeviceFind();
    ASSERT_EQ(ret, NSTACKX_EOK);
    NSTACKX_Deinit();
    usleep(50000); // post event is async operation
    GlobalMockObject::verify();

    // onDeviceFound == NULL
    parameter.onDeviceFound = NULL;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();
    ret = NSTACKX_StartDeviceFind();
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation

    // PostEvent error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_StartDeviceFind();
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_StartDeviceFindAn)
{
    // not init
    int32_t ret = NSTACKX_StartDeviceFindAn(DISCOVER_MODE);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // all is ok
    ret = NSTACKX_StartDeviceFindAn(DISCOVER_MODE);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation

    // PostEvent error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_StartDeviceFindAn(DISCOVER_MODE);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_StopDeviceFind)
{
    // not init
    int32_t ret = NSTACKX_StopDeviceFind();
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // all is ok
    ret = NSTACKX_StopDeviceFind();
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation

    // PostEvent error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_StopDeviceFind();
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_StartDeviceDiscovery)
{
    // not init
    NSTACKX_DiscoverySettings settings = {0};
    int32_t ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();
    
    // *settings * is null
    NSTACKX_DiscoverySettings *setting = nullptr;
    ret = NSTACKX_StartDeviceDiscovery(setting);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // businessData == null and length != 0
    settings.businessData = nullptr;
    settings.length = 1;
    ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // length is NSTACKX_MAX_BUSINESS_DATA_LEN
    settings.businessData = (char *)"businessData";
    settings.length = NSTACKX_MAX_BUSINESS_DATA_LEN;
    ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // advertiseCount is 0 and advertiseDuration is 0
    settings.length = NSTACKX_MAX_BUSINESS_DATA_LEN - 1;
    settings.advertiseCount = 0;
    settings.advertiseDuration = 0;
    ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // advertiseCount is NSTACKX_MIN_ADVERTISE_COUNT and advertiseDuration is NSTACKX_MAX_ADVERTISE_DURATION + 1
    settings.advertiseCount = NSTACKX_MIN_ADVERTISE_COUNT;
    settings.advertiseDuration = NSTACKX_MAX_ADVERTISE_DURATION + 1;
    ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // all is ok
    settings.advertiseDuration = NSTACKX_MAX_ADVERTISE_DURATION;
    settings.businessType = 0;
    ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation

    // businessType != businessTypeLocal
    settings.businessType = 1;
    ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // strncpy_s is error
    MOCKER(strncpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_StartDeviceDiscovery(&settings);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_StartDeviceDiscoveryWithConfig)
{
    DFinderDiscConfig config = {0};
    uint32_t array[] = {NSTACKX_MAX_ADVERTISE_INTERVAL};
    config.bcastInterval = array;
    config.intervalArrLen = 1;
    config.businessData = (char *)"businessData";
    config.businessDataLen = NSTACKX_MAX_BUSINESS_DATA_LEN - 1;
    // not init
    int32_t ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // param is NULL
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(NULL);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // intervalArrLen is 0
    config.intervalArrLen = 0;
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    config.intervalArrLen = 1;

    // bcastInterval is illegal
    uint32_t array1[] = {NSTACKX_MAX_ADVERTISE_INTERVAL + 1};
    config.bcastInterval = array1;
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    uint32_t array2[] = {NSTACKX_MAX_ADVERTISE_INTERVAL};
    config.bcastInterval = array2;

    // businessData is NULL and businessDataLen != 0
    config.businessData = (char *)NULL;
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    config.businessData = (char *)"businessData";

    // businessDataLen is NSTACKX_MAX_BUSINESS_DATA_LEN
    config.businessDataLen = NSTACKX_MAX_BUSINESS_DATA_LEN;
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    config.businessDataLen = NSTACKX_MAX_BUSINESS_DATA_LEN - 1;

    // all is ok
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation
    // businessType != businessTypeLocal
    config.businessType = 1;
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation

    // calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // strncpy_s is error
    MOCKER(strncpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    //  PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_StartDeviceDiscoveryWithConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_Deinit();
    NSTACKX_ThreadDeinit();
}

TEST(Dfinder, TestNSTACKX_SubscribeModule)
{
    // not init
    int32_t ret = NSTACKX_SubscribeModule();
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);

    // all is ok
    ret = NSTACKX_SubscribeModule();
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_UnsubscribeModule)
{
    // not init
    int32_t ret = NSTACKX_UnsubscribeModule();
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);

    // all is ok
    ret = NSTACKX_UnsubscribeModule();
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation
    GlobalMockObject::verify();

    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_RegisterDevice)
{
    NSTACKX_LocalDeviceInfo *deviceInfo = (NSTACKX_LocalDeviceInfo *)calloc(1, sizeof(NSTACKX_LocalDeviceInfo));
    // not init
    int32_t ret = NSTACKX_RegisterDevice(deviceInfo);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);

    // param is NULL
    ret = NSTACKX_RegisterDevice(NULL);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // ifNums is error
    memset_s(deviceInfo, sizeof(deviceInfo), 0, sizeof(deviceInfo));
    deviceInfo->ifNums = NSTACKX_MAX_LISTENED_NIF_NUM + 1;
    ret = NSTACKX_RegisterDevice(deviceInfo);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // StringHasEOF(networkIpAddr) is error or invalid ip addr
    // StringHasEOF(networkIpAddr) is error
    deviceInfo->ifNums = 0;
    for (int i = 0; i < NSTACKX_MAX_IP_STRING_LEN; i++) {
        deviceInfo->networkIpAddr[i] = 'a';
    }
    ret = NSTACKX_RegisterDevice(deviceInfo);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    // invalid ip addr
    deviceInfo->networkIpAddr[NSTACKX_MAX_IP_STRING_LEN - 1] = '\0';
    ret = NSTACKX_RegisterDevice(deviceInfo);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // StringHasEOF(networkName) is error
    memset_s(deviceInfo, sizeof(deviceInfo), 0, sizeof(deviceInfo));
    for (int i = 0; i < NSTACKX_MAX_INTERFACE_NAME_LEN; i++) {
        deviceInfo->networkName[i] = 'a';
    }
    ret = NSTACKX_RegisterDevice(deviceInfo);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // all is ok
    memset_s(deviceInfo, sizeof(deviceInfo), 0, sizeof(deviceInfo));
    memset_s(deviceInfo->networkIpAddr, sizeof(deviceInfo->networkIpAddr), 0, sizeof(deviceInfo->networkIpAddr));
    memset_s(deviceInfo->networkName, sizeof(deviceInfo->networkName), 0, sizeof(deviceInfo->networkName));
    deviceInfo->ifNums = 0;
    deviceInfo->deviceId[NSTACKX_MAX_DEVICE_ID_LEN - 1] = '\0';
    deviceInfo->name[NSTACKX_MAX_DEVICE_NAME_LEN] = '\0';
    deviceInfo->networkName[NSTACKX_MAX_INTERFACE_NAME_LEN - 1] = '\0';
    deviceInfo->networkIpAddr[0] = '1';
    deviceInfo->networkIpAddr[1] = '2';
    deviceInfo->networkIpAddr[2] = '7';
    deviceInfo->networkIpAddr[3] = '.';
    deviceInfo->networkIpAddr[4] = '1';
    deviceInfo->networkIpAddr[5] = '0';
    deviceInfo->networkIpAddr[6] = '0';
    deviceInfo->networkIpAddr[7] = '.';
    deviceInfo->networkIpAddr[8] = '1';
    deviceInfo->networkIpAddr[9] = '0';
    deviceInfo->networkIpAddr[10] = '0';
    deviceInfo->networkIpAddr[11] = '.';
    deviceInfo->networkIpAddr[12] = '1';
    deviceInfo->networkIpAddr[13] = '0';
    deviceInfo->networkIpAddr[14] = '0';
    ret = NSTACKX_RegisterDevice(deviceInfo);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation

    // strcpy_s is error
    deviceInfo->ifNums = 0;
    MOCKER(strcpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterDevice(deviceInfo);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    GlobalMockObject::verify();

    NSTACKX_Deinit();
    free(deviceInfo);
}

// 其他分支在TestNSTACKX_RegisterDevice里已全部覆盖
TEST(Dfinder, TestNSTACKX_RegisterDeviceAn)
{
    NSTACKX_LocalDeviceInfo deviceInfo = {0};
    // not init
    int32_t ret = NSTACKX_RegisterDeviceAn(&deviceInfo, 0);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
}

// 其他分支在TestNSTACKX_RegisterDevice里已全部覆盖
TEST(Dfinder, TestNSTACKX_RegisterDeviceV2)
{
    NSTACKX_LocalDeviceInfoV2 deviceInfo = {0};
    // not init
    int32_t ret = NSTACKX_RegisterDeviceV2(&deviceInfo);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    ret = NSTACKX_RegisterDeviceV2(&deviceInfo);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    usleep(50000); // post event is async operation
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_RegisterDeviceName)
{
    char devName[NSTACKX_MAX_DEVICE_NAME_LEN - 1] = "A";
    // not init
    int32_t ret = NSTACKX_RegisterDeviceName(devName);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    ret = NSTACKX_RegisterDeviceName(NULL);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // strlen(devName) > NSTACKX_MAX_DEVICE_NAME_LEN - 1
    char devName1[NSTACKX_MAX_DEVICE_NAME_LEN + 1] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    ret = NSTACKX_RegisterDeviceName(devName1);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    (void)NSTACKX_ThreadInit();
    // PostEvent != NSTACKX_EOK
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterDeviceName(devName);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    ret = NSTACKX_RegisterDeviceName(devName);
    ASSERT_EQ(ret, NSTACKX_EOK);

    NSTACKX_ThreadDeinit();
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_RegisterCapability)
{
    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // capabilityBitmapNum != 0 && capabilityBitmap == NULL
    int32_t ret = NSTACKX_RegisterCapability(1, NULL);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    // capabilityBitmapNum > NSTACKX_MAX_CAPABILITY_NUM
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM];
    ret = NSTACKX_RegisterCapability(NSTACKX_MAX_CAPABILITY_NUM + 1, capabilityBitmap);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // all is ok
    ret = NSTACKX_RegisterCapability(NSTACKX_MAX_CAPABILITY_NUM, capabilityBitmap);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation

    // calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = NSTACKX_RegisterCapability(NSTACKX_MAX_CAPABILITY_NUM, capabilityBitmap);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // memcpy_s is error
    MOCKER(memcpy_s).stubs().will(returnValue(-1));
    ret = NSTACKX_RegisterCapability(NSTACKX_MAX_CAPABILITY_NUM, capabilityBitmap);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterCapability(NSTACKX_MAX_CAPABILITY_NUM, capabilityBitmap);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_Deinit();
    NSTACKX_ThreadDeinit();
}

// 其他分支在TestNSTACKX_RegisterCapability里已全部覆盖
TEST(Dfinder, TestNSTACKX_SetFilterCapability)
{
    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    int32_t ret = NSTACKX_SetFilterCapability(0, NULL);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_SetMaxDeviceNum)
{
    // not init
    int32_t ret = NSTACKX_SetMaxDeviceNum(0);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // SemInit is error
    MOCKER(SemInit).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SetMaxDeviceNum(0);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SetMaxDeviceNum(0);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_Deinit();
    NSTACKX_ThreadDeinit();
}

TEST(Dfinder, TestNSTACKX_SetDeviceListAgingTime)
{
    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);

    // all is ok
    int32_t ret = NSTACKX_SetDeviceListAgingTime(0);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_ScreenStatusChange)
{
    // not init
    int32_t ret = NSTACKX_ScreenStatusChange(false);
    ASSERT_EQ(ret, NSTACKX_EOK);
}

TEST(Dfinder, TestNSTACKX_RegisterServiceData)
{
    // param is NULL
    int32_t ret = NSTACKX_RegisterServiceData(NULL);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    const char serviceData[] = "serviceData,serviceData,serviceData,serviceData,serviceData,serviceData,";
    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    // strlen(serviceData) >= NSTACKX_MAX_SERVICE_DATA_LEN
    ret = NSTACKX_RegisterServiceData(serviceData);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    ret = NSTACKX_RegisterServiceData("data");
    ASSERT_EQ(ret, NSTACKX_EOK);

    (void)NSTACKX_ThreadInit();
    const char serviceData1[] = "serviceData";
    // calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = NSTACKX_RegisterServiceData(serviceData1);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // strncpy_s is error
    MOCKER(strncpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterServiceData(serviceData1);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    GlobalMockObject::verify();


    // all is ok
    ret = NSTACKX_RegisterServiceData(serviceData1);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterServiceData(serviceData1);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_ThreadDeinit();
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNNSTACKX_RegisterBusinessData)
{
    // param is NULL
    int32_t ret = NSTACKX_RegisterBusinessData(NULL);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // not init
    const char businessData[] = "A";
    ret = NSTACKX_RegisterBusinessData(businessData);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    char businessData1[NSTACKX_MAX_BUSINESS_DATA_LEN + 1] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    // strlen(businessData) >= NSTACKX_MAX_BUSINESS_DATA_LEN
    ret = NSTACKX_RegisterBusinessData(businessData1);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = NSTACKX_RegisterBusinessData(businessData);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // strncpy_s is error
    MOCKER(strncpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterBusinessData(businessData);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterBusinessData(businessData);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_Deinit();
    NSTACKX_ThreadDeinit();
}

TEST(Dfinder, TestNSTACKX_RegisterExtendServiceData)
{
    // param is NULL
    int32_t ret = NSTACKX_RegisterExtendServiceData(NULL);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    const char extendServiceData[] = "extendServiceData";

    // not init
    ret = NSTACKX_RegisterExtendServiceData(extendServiceData);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // strlen(extendServiceData) >= NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN
    const char extendServiceData1[] = "extendServiceData,extendServiceData,extendServiceData,extendServiceData,"
                                      "extendServiceData,extendServiceData,extendServiceData,extendServiceData,";
    ret = NSTACKX_RegisterExtendServiceData(extendServiceData1);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = NSTACKX_RegisterExtendServiceData(extendServiceData);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // strncpy_s is error
    MOCKER(strncpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterExtendServiceData(extendServiceData);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterExtendServiceData(extendServiceData);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_ThreadDeinit();
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_SendMsgDirect)
{
    // not init
    const char moduleName[] = "";
    const char deviceId[] = "";
    const uint8_t data[] = {0};
    const char ipaddr[] = "";

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // ipaddr == NULL
    int32_t ret = NSTACKX_SendMsgDirect(moduleName, deviceId, data, 1, NULL, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // type > SERVER_TYPE_USB
    ret = NSTACKX_SendMsgDirect(moduleName, deviceId, data, 1, ipaddr, SERVER_TYPE_USB + 1);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // moduleName == NULL
    ret = NSTACKX_SendMsgDirect(NULL, deviceId, data, 1, ipaddr, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // deviceId == NULL
    ret = NSTACKX_SendMsgDirect(moduleName, NULL, data, 1, ipaddr, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // data == NULL
    ret = NSTACKX_SendMsgDirect(moduleName, deviceId, NULL, 1, ipaddr, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // invalid ip addr
    ret = NSTACKX_SendMsgDirect(moduleName, deviceId, data, 1, ipaddr, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // all is ok
    MOCKER(inet_pton).stubs().will(returnValue(1)); // inet_pton is ok, == 1
    ret = NSTACKX_SendMsgDirect(moduleName, deviceId, data, 1, ipaddr, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    usleep(50000); // post event is async operation
    GlobalMockObject::verify();

    // SemInit is error
    MOCKER(inet_pton).stubs().will(returnValue(1)); // inet_pton is ok, == 1
    MOCKER(SemInit).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SendMsgDirect(moduleName, deviceId, data, 1, ipaddr, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(inet_pton).stubs().will(returnValue(1)); // inet_pton is ok, == 1
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SendMsgDirect(moduleName, deviceId, data, 1, ipaddr, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    NSTACKX_ThreadDeinit();
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_SendMsg)
{
    // not init
    const char moduleName[] = "";
    const char deviceId[] = "";
    const uint8_t data[] = {0};

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // moduleName == NULL
    int32_t ret = NSTACKX_SendMsg(NULL, deviceId, data, 1);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // SemInit is error
    MOCKER(SemInit).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SendMsg(moduleName, deviceId, data, 1);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SendMsg(moduleName, deviceId, data, 1);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // remoteIp == NULL
    ret = NSTACKX_SendMsg(moduleName, deviceId, data, 1);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // remoteIp != NULL && inet_ntop != NULL
    const struct in_addr remoteIp = {0};
    MOCKER(GetRemoteDeviceIp).stubs().will(returnValue(&remoteIp));
    ret = NSTACKX_SendMsg(moduleName, deviceId, data, 1);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // remoteIp != NULL && inet_ntop == NULL
    MOCKER(GetRemoteDeviceIp).stubs().will(returnValue(&remoteIp));
    MOCKER(inet_ntop).stubs().will(returnValue((char const*)NULL));
    ret = NSTACKX_SendMsg(moduleName, deviceId, data, 1);
    ASSERT_EQ(ret, NSTACKX_EOK);
    GlobalMockObject::verify();

    // all is ok
    MOCKER(GetRemoteDeviceIp).stubs().will(returnValue(&remoteIp));
    MOCKER(CoapSendServiceMsg).stubs().will(returnValue(NSTACKX_EOK));
    ret = NSTACKX_SendMsg(moduleName, deviceId, data, 1);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation
    GlobalMockObject::verify();

    NSTACKX_Deinit();
    NSTACKX_ThreadDeinit();
}

TEST(Dfinder, TestNSTACKX_SendDiscoveryRsp)
{
    NSTACKX_ResponseSettings settings = {0};
    // not init
    int32_t ret = NSTACKX_SendDiscoveryRsp(&settings);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // responseSettings == NULL
    ret = NSTACKX_SendDiscoveryRsp(NULL);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // (responseSettings->businessData == NULL) && (responseSettings->length != 0)
    settings.businessData = NULL;
    settings.length = NSTACKX_MAX_BUSINESS_DATA_LEN - 1;
    ret = NSTACKX_SendDiscoveryRsp(&settings);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // responseSettings->length >= NSTACKX_MAX_BUSINESS_DATA_LEN
    settings.businessData = (char *)"businessData";
    settings.length = NSTACKX_MAX_BUSINESS_DATA_LEN;
    ret = NSTACKX_SendDiscoveryRsp(&settings);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    settings.length = NSTACKX_MAX_BUSINESS_DATA_LEN - 1;

    // calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = NSTACKX_SendDiscoveryRsp(&settings);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // businessData != NULL && strncpy_s is error
    MOCKER(strncpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SendDiscoveryRsp(&settings);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    GlobalMockObject::verify();

    // businessData == NULL && strncpy_s is error
    settings.businessData = NULL;
    settings.length = 0;
    MOCKER(strncpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SendDiscoveryRsp(&settings);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    settings.businessData = (char *)"businessData";
    settings.length = NSTACKX_MAX_BUSINESS_DATA_LEN - 1;
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SendDiscoveryRsp(&settings);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // all is ok
    ret = NSTACKX_SendDiscoveryRsp(&settings);
    ASSERT_EQ(ret, NSTACKX_EOK);
    // businessType != localBusinessType
    settings.businessType = 2;
    ret = NSTACKX_SendDiscoveryRsp(&settings);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000);

    NSTACKX_Deinit();
    NSTACKX_ThreadDeinit();
    // because PostEvent is async, so lastly execute GlobalMockObject::verify()
    GlobalMockObject::verify();
}

TEST(Dfinder, TestNSTACKX_GetDeviceList)
{
    // not init
    NSTACKX_DeviceInfo deviceList = {0};
    uint32_t deviceCountPtr = 1;
    int32_t ret = NSTACKX_GetDeviceList(&deviceList, &deviceCountPtr);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // deviceCountPtr == NULL
    ret = NSTACKX_GetDeviceList(&deviceList, NULL);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // SemInit is error
    MOCKER(SemInit).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_GetDeviceList(&deviceList, &deviceCountPtr);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_GetDeviceList(&deviceList, &deviceCountPtr);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // all is ok
    ret = NSTACKX_GetDeviceList(&deviceList, &deviceCountPtr);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(50000); // post event is async operation

    NSTACKX_Deinit();
    NSTACKX_ThreadDeinit();
}

TEST(Dfinder, TestNSTACKX_InitRestart)
{
    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    int32_t ret = NSTACKX_InitRestart(&parameter);
    ASSERT_EQ(ret, NSTACKX_EOK);
    GlobalMockObject::verify();
    NSTACKX_Deinit();
}

void DFinderLogCb(const char *moduleName, uint32_t logLevel, const char *format, ...)
{
    (void)logLevel;
}

TEST(Dfinder, TestNSTACKX_DFinderRegisterLog)
{
    // userLogCallback == NULL
    int32_t ret = NSTACKX_DFinderRegisterLog(NULL);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    // all is ok
    ret = NSTACKX_DFinderRegisterLog(DFinderLogCb);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // logCb == g_nstackxLogCallBack
    ret = NSTACKX_DFinderRegisterLog(DFinderLogCb);
    ASSERT_EQ(ret, NSTACKX_EOK);
}

void DFinderDumpFuncCb(void *softObj, const char *data, uint32_t len)
{
    (void)softObj;
    (void)len;
    printf("[%s][%d] %s\n", __FUNCTION__, __LINE__, data);
}
TEST(Dfinder, TestNSTACKX_DFinderDump)
{
    const char* argv = (const char*)"argv";
    uint32_t argc = 1;
    int32_t softObj = 0;
    // not init
    int32_t ret = NSTACKX_DFinderDump((const char**)&argv, argc, (void *)&softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);

    // dump == NULL
    ret = NSTACKX_DFinderDump((const char**)&argv, argc, (void *)&softObj, NULL);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // argc > MAX_DUMP_ARGC
    argc = 10 + 1;
    ret = NSTACKX_DFinderDump((const char**)&argv, argc, (void *)&softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EINVAL);
    argc = 1;

    // argv == NULL
    ret = NSTACKX_DFinderDump(NULL, argc, (void *)&softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // argv[0] == NULL
    char *argv1 = (char *)"argv1";
    (&argv1)[0] = NULL;
    ret = NSTACKX_DFinderDump((const char**)&argv1, argc, (void *)&softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EINVAL);

    // all is ok
    ret = NSTACKX_DFinderDump((const char**)&argv, argc, (void *)&softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EOK);

    NSTACKX_Deinit();
}

static void DFinderEventFunCb(void *softObj, const DFinderEvent *info)
{
    (void)info;
}
TEST(Dfinder, TestNSTACKX_DFinderSetEventFunc)
{
    int32_t softObj = 0;
    // not init
    int ret = NSTACKX_DFinderSetEventFunc((void *)&softObj, DFinderEventFunCb);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    MOCKER(SetEventFunc).stubs().will(returnValue(NSTACKX_EOK));
    ret = NSTACKX_DFinderSetEventFunc((void *)&softObj, DFinderEventFunCb);
    ASSERT_EQ(ret, NSTACKX_EOK);
    NSTACKX_Deinit();

    GlobalMockObject::verify();
}

TEST(Dfinder, TestGetServiceNotificationInfo)
{
    const char *buf = "{\"notify\":\"{\\\"UDID\\\":\\\"FE73EE0BA926F5A5B149B1567AD2D32BC5443A9FE05FE812CE62\\\"}\"}";
    NSTACKX_NotificationConfig config = {0};

    // calloc fail
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    int32_t ret = GetServiceNotificationInfo((const uint8_t *)buf, strlen(buf), &config);
    EXPECT_EQ(ret, NSTACKX_ENOMEM) << "case calloc fail";
    GlobalMockObject::verify();

    // memcpy_s fail
    MOCKER(memcpy_s).stubs().will(returnValue(EINVAL));
    ret = GetServiceNotificationInfo((const uint8_t *)buf, strlen(buf), &config);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case memcpy_s fail";
    GlobalMockObject::verify();

    // ParseServiceNotification fail
    MOCKER(ParseServiceNotification).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = GetServiceNotificationInfo((const uint8_t *)buf, strlen(buf), &config);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case ParseServiceNotification fail";
    GlobalMockObject::verify();

    // all ok
    MOCKER(ParseServiceNotification).stubs().will(returnValue(NSTACKX_EOK));
    ret = GetServiceNotificationInfo((const uint8_t *)buf, strlen(buf), &config);
    EXPECT_EQ(ret, NSTACKX_EOK);
    GlobalMockObject::verify();
}

TEST(Dfinder, TestNotificationReceived)
{
    NSTACKX_Parameter param = {0};
    param.onNotificationReceived = DFinderOnNotificationReceived;
    int32_t ret = NSTACKX_Init(&param);
    ASSERT_EQ(ret, NSTACKX_EOK) << "case NULL init fail";

    // param NULL
    NotificationReceived(NULL);

    // param not NULL
    NSTACKX_NotificationConfig tmpConfig = {0};
    NotificationReceived(&tmpConfig);
    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_StopSendNotification)
{
    uint8_t businessType = NSTACKX_BUSINESS_TYPE_NULL;

    // dfinder not inited
    int32_t ret = NSTACKX_StopSendNotification(businessType);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case dfinder not inited fail";

    NSTACKX_Parameter param = {0};
    param.onNotificationReceived = DFinderOnNotificationReceived;
    ret = NSTACKX_Init(&param);
    ASSERT_EQ(ret, NSTACKX_EOK) << "init fail";

    ret = NSTACKX_ThreadInit();
    ASSERT_EQ(ret, NSTACKX_EOK) << "threadinit fail";

    // invalid business type
    ret = NSTACKX_StopSendNotification(NSTACKX_BUSINESS_TYPE_MAX);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case invalid business type fail";

    // PostEvent fail
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_StopSendNotification(businessType);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case PostEvent fail";
    GlobalMockObject::verify();
    
    // ThreadInit
    ret = NSTACKX_ThreadInit();
    ASSERT_EQ(ret, NSTACKX_EOK) << "thread init fail";

    // all ok
    ret = NSTACKX_StopSendNotification(businessType);
    EXPECT_EQ(ret, NSTACKX_EOK) << "case all ok fail";
    GlobalMockObject::verify();

    NSTACKX_Deinit();
    NSTACKX_ThreadDeinit();
}

TEST(Dfinder, TestNSTACKX_SendNotification)
{
    // dfinder not inited
    int32_t ret = NSTACKX_SendNotification(NULL);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case dfinder not inited fail";

    NSTACKX_Parameter param = {0};
    param.onNotificationReceived = DFinderOnNotificationReceived;
    ret = NSTACKX_Init(&param);
    ASSERT_EQ(ret, NSTACKX_EOK) << "init fail";

    ret = NSTACKX_ThreadInit();
    ASSERT_EQ(ret, NSTACKX_EOK) << "thread init fail";

    // config NULL
    ret = NSTACKX_SendNotification(NULL);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case config NULL fail";

    // invalid business type
    NSTACKX_NotificationConfig config = {0};
    config.businessType = NSTACKX_BUSINESS_TYPE_MAX;
    ret = NSTACKX_SendNotification(&config);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case invalid business type fail";

    // msg NULL
    config.businessType = NSTACKX_BUSINESS_TYPE_NULL;
    config.msg = NULL;
    ret = NSTACKX_SendNotification(&config);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case msg NULL fail";

    // invalid msg len
    std::string tmpMsg("hello");
    config.msg = const_cast<char *>(tmpMsg.c_str());
    config.msgLen = 0;
    ret = NSTACKX_SendNotification(&config);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case invalid msg len fail";

    // invalid interval len
    config.intervalLen = 0;
    ret = NSTACKX_SendNotification(&config);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case invalid interval len fail";

    // interval ms NULL
    config.intervalLen = 3;
    config.intervalsMs = NULL;
    ret = NSTACKX_SendNotification(&config);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case interval ms fail";

    // first interval not zero
    uint16_t intervalFirstNotZero[] = {100, 200, 300};
    config.intervalsMs = intervalFirstNotZero;
    config.intervalLen = 3;
    ret = NSTACKX_SendNotification(&config);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case first interval not zero fail";

    // interval too big
    uint16_t intervalTooBig[] = {0, NSTACKX_MAX_ADVERTISE_INTERVAL + 1};
    config.intervalsMs = intervalTooBig;
    config.intervalLen = 2;
    ret = NSTACKX_SendNotification(&config);
    EXPECT_EQ(ret, NSTACKX_EINVAL) << "case interval too big fail";

    std::string legalMsg("auv");
    uint16_t legalInterval[] = {0, 200, 200};
    NSTACKX_NotificationConfig legalConfig = {
        msg : const_cast<char *>(legalMsg.c_str()),
        msgLen : 3,
        intervalsMs : legalInterval,
        intervalLen : 3,
        businessType : NSTACKX_BUSINESS_TYPE_NULL
    };

    // calloc fail
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = NSTACKX_SendNotification(&legalConfig);
    EXPECT_EQ(ret, NSTACKX_ENOMEM) << "case calloc fail";
    GlobalMockObject::verify();

    // PostEvent fail
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_SendNotification(&legalConfig);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case PostEvent fail";
    GlobalMockObject::verify();

    // all ok
    ret = NSTACKX_SendNotification(&legalConfig);
    EXPECT_EQ(ret, NSTACKX_EOK) << "case all ok fail";

    NSTACKX_Deinit();
}

TEST(Dfinder, TestNSTACKX_RegisterServiceDataV2)
{
    NSTACKX_ServiceData testData = {0};
    strcpy_s(testData.ip, sizeof(testData.ip), "127.0.0.1");
    strcpy_s(testData.serviceData, sizeof(testData.serviceData), "testdata");
    const struct NSTACKX_ServiceData *param = &testData;

    // not inited
    int32_t ret = NSTACKX_RegisterServiceDataV2(param, 1);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case dfinder not inited fail";

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();

    // SemInit is error
    MOCKER(SemInit).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterServiceDataV2(param, 1);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // PostEvent fail
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterServiceDataV2(param, 1);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case PostEvent fail";
    GlobalMockObject::verify();

    NSTACKX_Deinit();
}


TEST(Dfinder, TestNSTACKX_RegisterDeviceHash)
{
    // dfinder not inited
    int32_t ret = NSTACKX_RegisterDeviceHash(0);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case dfinder not inited fail";

    NSTACKX_Parameter parameter;
    parameter.onDFinderMsgReceived = DFinderMsgReceived;
    (void)NSTACKX_Init(&parameter);
    (void)NSTACKX_ThreadInit();
    
    // PostEvent fail
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = NSTACKX_RegisterDeviceHash(0);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case PostEvent fail";
    GlobalMockObject::verify();

    NSTACKX_Deinit();
}
