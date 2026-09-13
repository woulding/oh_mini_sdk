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

#include "nstackx_device_remote.h"
#include "nstackx_error.h"
#include "nstackx_timer.h"

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

TEST(Dfinder, TestRemoteDeviceListInit)
{
    // all is ok
    int32_t ret = RemoteDeviceListInit();
    ASSERT_EQ(ret, NSTACKX_EOK);
}

TEST(Dfinder, TestGetRemoteNodeCount)
{
    uint32_t count = GetRemoteNodeCount();
    ASSERT_EQ(count, 0);
}

TEST(Dfinder, TestUpdateRemoteNodeByDeviceInfo)
{
    NSTACKX_InterfaceInfo ifaceInfo = {0};
    strcpy_s(ifaceInfo.networkName, sizeof(ifaceInfo.networkName), "eth");
    strcpy_s(ifaceInfo.networkIpAddr, sizeof(ifaceInfo.networkIpAddr), "127.0.0.1");

    NSTACKX_InterfaceInfo ifaceInfo1 = {0};
    strcpy_s(ifaceInfo1.networkName, sizeof(ifaceInfo1.networkName), "eth");
    strcpy_s(ifaceInfo1.networkIpAddr, sizeof(ifaceInfo1.networkIpAddr), "127.0.0.2");

    NSTACKX_InterfaceInfo ifaceInfo2 = {0};
    strcpy_s(ifaceInfo2.networkName, sizeof(ifaceInfo2.networkName), "eth");
    strcpy_s(ifaceInfo2.networkIpAddr, sizeof(ifaceInfo2.networkIpAddr), "127.0.0.3");

    NSTACKX_InterfaceInfo ifaceInfo3 = {0};
    strcpy_s(ifaceInfo3.networkName, sizeof(ifaceInfo3.networkName), "eth");
    strcpy_s(ifaceInfo3.networkIpAddr, sizeof(ifaceInfo3.networkIpAddr), "127.0.0.4");

    NSTACKX_InterfaceInfo ifaceInfo4 = {0};
    strcpy_s(ifaceInfo4.networkName, sizeof(ifaceInfo4.networkName), "eth");
    strcpy_s(ifaceInfo4.networkIpAddr, sizeof(ifaceInfo4.networkIpAddr), "127.0.0.5");

    BusinessDataAll businessData = { 0 };
    businessData.isBroadcast = NSTACKX_FALSE;
    strcpy_s(businessData.businessDataBroadcast, sizeof(businessData.businessDataBroadcast), "Broadcast");
    strcpy_s(businessData.businessDataUnicast, sizeof(businessData.businessDataUnicast), "Unicast");
    DeviceInfo deviceInfo = { 0 };

    deviceInfo.businessData = businessData;
    deviceInfo.netChannelInfo.wifiApInfo.af = AF_INET;
    deviceInfo.deviceType = NSTACKX_DISCOVERY_TYPE_PASSIVE;
    deviceInfo.capabilityBitmapNum = 1;
    uint8_t updated = NSTACKX_FALSE;

    // CreateRemoteDevice == NULL, (1)calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    int32_t ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // CreateRemoteDevice == NULL, (2)strcpy_s is error
    MOCKER(strcpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // g_remoteNodeCount == GetMaxDeviceNum() && CheckAndRemoveAgingNode() != NSTACKX_EOK
    MOCKER(GetMaxDeviceNum).stubs().will(returnValue(GetRemoteNodeCount()));
    SetDeviceListAgingTime(2);
    MOCKER(GetTimeDiffMs).stubs().will(returnValue(1001));
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // all is ok, add list node
    SetDeviceListAgingTime(1);
    SetMaxDeviceNum(10);
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);
    usleep(2000);

    // UpdateRemoteNode, isBroadcast == NSTACKX_TRUE
    BusinessDataAll businessData1 = {0};
    businessData1.isBroadcast = NSTACKX_TRUE;
    strcpy_s(businessData1.businessDataBroadcast, sizeof(businessData1.businessDataBroadcast), "Broadcast1");
    strcpy_s(businessData1.businessDataUnicast, sizeof(businessData1.businessDataUnicast), "Unicast1");
    DeviceInfo deviceInfo1 = {0};
    strcpy_s(deviceInfo1.deviceId, sizeof(deviceInfo1.deviceId), "deviceId");
    deviceInfo.netChannelInfo.wifiApInfo.af = AF_INET;
    deviceInfo.netChannelInfo.wifiApInfo.addr.in.s_addr = 778;
    deviceInfo1.businessData = businessData1;
    deviceInfo1.deviceType = NSTACKX_DISCOVERY_TYPE_PASSIVE;
    deviceInfo1.netChannelInfo.wifiApInfo.af = AF_INET;
    deviceInfo1.capabilityBitmapNum = 1;
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo1, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // UpdateRemoteNode, isBroadcast != NSTACKX_TRUE
    BusinessDataAll businessData2 = { 0 };
    businessData2.isBroadcast = NSTACKX_FALSE;
    strcpy_s(businessData2.businessDataBroadcast, sizeof(businessData2.businessDataBroadcast), "Broadcast2");
    strcpy_s(businessData2.businessDataUnicast, sizeof(businessData2.businessDataUnicast), "Unicast2");
    DeviceInfo deviceInfo2 = { 0 };
    strcpy_s(deviceInfo2.deviceId, sizeof(deviceInfo2.deviceId), "deviceId");
    deviceInfo2.deviceType = NSTACKX_DISCOVERY_TYPE_PASSIVE;
    deviceInfo2.businessData = businessData2;
    deviceInfo2.netChannelInfo.wifiApInfo.af = AF_INET;
    deviceInfo2.capabilityBitmapNum = 1;
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo2, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // UpdateRemoteNode, businessType != newInfo->businessType
    deviceInfo.businessType = 1;
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // UpdateRemoteNode, serviceData != newInfo->serviceData
    strcpy_s(deviceInfo.serviceData, sizeof(deviceInfo.serviceData), "serviceData");
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // UpdateRemoteNode, mode != newInfo->mode
    deviceInfo.mode = 1;
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // UpdateRemoteNode, deviceHash != newInfo->deviceHash
    strcpy_s(deviceInfo.deviceHash, sizeof(deviceInfo.deviceHash), "deviceHash");
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // UpdateRemoteNode, capabilityBitmapNum > 0
    deviceInfo.capabilityBitmapNum = 1;
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // UpdateRemoteNode, capabilityBitmapNum > 0, memcpy_s is error
    MOCKER(memcpy_s).stubs().will(returnValue(-1));
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // UpdateRemoteNode, deviceName != newInfo->deviceName
    strcpy_s(deviceInfo.deviceName, sizeof(deviceInfo.deviceName), "deviceName");
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // CheckAndUpdateRemoteNodeChangeState, discoveryType == NSTACKX_DISCOVERY_TYPE_PASSIVE
    deviceInfo.discoveryType = NSTACKX_DISCOVERY_TYPE_PASSIVE;
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // UpdateRemoteNode, deviceType != newInfo->deviceType
    deviceInfo.deviceType = NSTACKX_DISCOVERY_TYPE_ACTIVE;
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    // rxIface->remoteNodeCnt >= RX_IFACE_REMOTE_NODE_COUNT, 调用5次UpdateRemoteNodeByDeviceInfo，每次传的remoteIp不同
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    deviceInfo.deviceType = NSTACKX_DISCOVERY_TYPE_PASSIVE;
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo1, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo2, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo3, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo4, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // insert node into list
    /** eth */
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo1, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo2, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);
    /** wlan */
    NSTACKX_InterfaceInfo ifaceInfo5 = {0};
    strcpy_s(ifaceInfo5.networkName, sizeof(ifaceInfo5.networkName), "wlan");
    strcpy_s(ifaceInfo5.networkIpAddr, sizeof(ifaceInfo5.networkIpAddr), "127.0.0.1");
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo5, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);

    NSTACKX_InterfaceInfo ifaceInfo6 = {0};
    strcpy_s(ifaceInfo6.networkName, sizeof(ifaceInfo6.networkName), "wlan");
    strcpy_s(ifaceInfo6.networkIpAddr, sizeof(ifaceInfo6.networkIpAddr), "127.0.0.2");
    ret = UpdateRemoteNodeByDeviceInfo("deviceId", &ifaceInfo, &deviceInfo, &updated);
    ASSERT_EQ(ret, NSTACKX_EOK);
}

TEST(Dfinder, TestGetRemoteDeviceIp)
{
    const struct in_addr *remoteIp = GetRemoteDeviceIp("deviceId");
    ASSERT_NE(remoteIp, nullptr);

    remoteIp = GetRemoteDeviceIp("deviceId1");
    ASSERT_EQ(remoteIp, nullptr);
}

TEST(Dfinder, TestDumpRemoteDevice)
{
    char buf[2048];
    (void)memset_s(buf, 2048, 0, 2048);
    int32_t ret = DumpRemoteDevice(buf, 2048);
    ASSERT_EQ(ret, 571);
    ret = DumpRemoteDevice(buf, 0);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
}
