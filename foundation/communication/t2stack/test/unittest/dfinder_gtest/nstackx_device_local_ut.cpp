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

#include "nstackx_device_local.h"
#include "nstackx_device_remote.h"

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"
#include "ut_utils.h"

TEST(Dfinder, TestLocalDeviceInit)
{
    EpollDesc epollDesc = CreateEpollDesc();

    // g_localDevice.timer == NULL
    MOCKER(TimerStart).stubs().will(returnValue((Timer *)NULL));
    int ret = LocalDeviceInit(epollDesc);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // all is ok
    ret = LocalDeviceInit(epollDesc);
    ASSERT_EQ(ret, NSTACKX_EOK);

    LocalDeviceDeinit();
}

static Timer *g_timer;
static Timer *InvokeTimerStart(EpollDesc epollfd, uint32_t ms, uint8_t repeated, TimeoutHandle handle, void *data)
{
    handle(data);
    g_timer = (Timer *)malloc(1*sizeof(Timer));
    return g_timer;
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

TEST(Dfinder, TestAddLocalIface)
{
    (void)LocalDeviceInit(CreateEpollDesc());

    // iface->ctx == NULL
    union InetAddr addr;
    union InetAddr addr1;
    struct in_addr ipv4Addr;
    struct in_addr ipv4Addr1;
    inet_pton(AF_INET, "127.0.0.1", &ipv4Addr);
    addr.in = ipv4Addr;
    char serviceData[NSTACKX_MAX_SERVICE_DATA_LEN] = "data";
    int ret = AddLocalIface("eth0", serviceData, AF_INET, &addr);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    CoapCtxType *ctx = (CoapCtxType *)malloc(1 * sizeof(CoapCtxType));
    ctx->ctx = CreateCoapContext();
    MOCKER(CoapServerInit).stubs().will(returnValue(ctx));

    ret = AddLocalIface("eth", serviceData, AF_INET, &addr); // eth 127.0.0.1 添加到g_localDevice.readyList里
    ASSERT_EQ(ret, NSTACKX_EOK);

    ret = AddLocalIface("wlan", serviceData, AF_INET, &addr); /** wlan 127.0.0.1 添加到g_localDevice.readyList里 */
    ASSERT_EQ(ret, NSTACKX_EOK);

    // iface == NULL and then iface != NULL
    RemoveLocalIface(AF_INET, "eth"); // // eth 127.0.0.1 添加到g_localDevice.destroyList里
    ret = AddLocalIface("eth", serviceData, AF_INET, &addr); // eth 127.0.0.1 添加到g_localDevice.readyList里
    ASSERT_EQ(ret, NSTACKX_EOK);

    // ip.s_addr == ip->s_addr
    ret = AddLocalIface("eth", serviceData, AF_INET, &addr); // 没有添加到任何list里
    ASSERT_EQ(ret, NSTACKX_EOK);

    // ip.s_addr != ip->s_addr
    inet_pton(AF_INET, "127.0.0.2", &ipv4Addr1);
    addr1.in = ipv4Addr1;
    ret = AddLocalIface("eth", serviceData, AF_INET, &addr1); /** eth 127.0.0.2 添加到g_localDevice.destroyList里 */
    ASSERT_EQ(ret, NSTACKX_EOK);

    // inet_ntop(AF_INET, ip, ipStr, sizeof(ipStr)) == NULL
    MOCKER(inet_ntop).stubs().will(returnValue((char const*)NULL));
    ret = AddLocalIface("eth", serviceData, AF_INET, &addr); /** eth 127.0.0.1 添加到g_localDevice.destroyList里 */
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // !NeedCreateSynchronously(iface->type), 即GetIfaceType >= IFACE_TYPE_P2P
    MOCKER(GetIfaceType).stubs().will(returnValue(2));
    ret = AddLocalIface("p2p", serviceData, AF_INET, &addr); // 没有添加到任何list里
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // !NeedCreateSynchronously(iface->type), 即GetIfaceType >= IFACE_TYPE_P2P
    MOCKER(TimerStart).stubs().will(invoke(InvokeTimerStart));
    ret = AddLocalIface("p2p", serviceData, AF_INET, &addr);/** p2p 127.0.0.1 添加到g_localDevice.creatingList里 */
    ASSERT_EQ(ret, NSTACKX_EOK);
    GlobalMockObject::verify();

    free(g_timer);
    FreeCoapContext(ctx->ctx);
    free(ctx);
}

TEST(Dfinder, TestLocalIfaceDump)
{
    char buf[2048];
    // 与TestAddLocalIface方法挂钩，遍历g_localDevice3个列表：creatingList、readyList、destroyList
    int ret = LocalIfaceDump(buf, 2048);
    ASSERT_EQ(ret, 181);
}

TEST(Dfinder, TestLocalIfaceGetCoapCtx)
{
    // 与TestAddLocalIface方法挂钩，遍历g_localDevice.readyList列表
    CoapCtxType *coapCtxType = LocalIfaceGetCoapCtx(AF_INET, "eth");
    ASSERT_EQ(coapCtxType, nullptr);
}

bool mHasLocalIface = true;
int32_t InvokeGetTargetInterface(const struct sockaddr_in *dstAddr, struct ifreq *localDev)
{
    // 与TestAddLocalIface方法挂钩，LocalIfaceGetCoapCtxByRemoteIp会从g_localDevice.readyList里查找
    if (mHasLocalIface) {
        (void)strcpy_s(localDev->ifr_ifrn.ifrn_name, IFNAMSIZ, "wlan");
    } else {
        (void)strcpy_s(localDev->ifr_ifrn.ifrn_name, IFNAMSIZ, "eth");
    }
    return NSTACKX_EOK;
}
TEST(Dfinder, TestLocalIfaceGetCoapCtxByRemoteIp)
{
    char ipStr[INET_ADDRSTRLEN] = "127.0.0.1"; // host:port
    struct in_addr remoteIp;
    inet_pton(AF_INET, ipStr, &remoteIp);

    // GetTargetInterface != NSTACKX_EOK
    CoapCtxType *coapCtxType = LocalIfaceGetCoapCtxByRemoteIp(&remoteIp, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(coapCtxType, nullptr);

    // all is ok
    MOCKER(GetTargetInterface).stubs().will(invoke(InvokeGetTargetInterface));
    coapCtxType = LocalIfaceGetCoapCtxByRemoteIp(&remoteIp, SERVER_TYPE_WLANORETH);
    ASSERT_NE(coapCtxType, nullptr);

    // !IfaceTypeIsMatch
    coapCtxType = LocalIfaceGetCoapCtxByRemoteIp(&remoteIp, SERVER_TYPE_USB + 1);
    ASSERT_EQ(coapCtxType, nullptr);

    // iface == NULL
    mHasLocalIface = false;
    MOCKER(GetTargetInterface).stubs().will(invoke(InvokeGetTargetInterface));
    coapCtxType = LocalIfaceGetCoapCtxByRemoteIp(&remoteIp, SERVER_TYPE_WLANORETH);
    ASSERT_EQ(coapCtxType, nullptr);
    GlobalMockObject::verify();
}

uint8_t mBusinessType = 10;
const char mDeviceId[] = "deviceId";
char mNetworkName[NSTACKX_MAX_INTERFACE_NAME_LEN] = "eth";
TEST(Dfinder, TestRegisterLocalDeviceV2)
{
    NSTACKX_LocalDeviceInfoV2 devInfo = {0};
    // strcpy_s(devInfo->deviceId) != EOK
    int ret = RegisterLocalDeviceV2(&devInfo, REGISTER_TYPE_UPDATE_ALL);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    // name[0] == '\0'
    devInfo.deviceId = mDeviceId;
    devInfo.name = "";
    ret = RegisterLocalDeviceV2(&devInfo, REGISTER_TYPE_UPDATE_ALL);
    ASSERT_EQ(ret, NSTACKX_EOK);

    devInfo.name = "name";
    devInfo.ifNums = 1;
    devInfo.hasDeviceHash = true;
    devInfo.deviceHash = 1;
    devInfo.businessType = mBusinessType;
    NSTACKX_InterfaceInfo info = {0};
    devInfo.localIfInfo = &info;

    // ifInfo->networkName[0] == '\0'
    (void)strcpy_s(info.networkName, NSTACKX_MAX_INTERFACE_NAME_LEN, "");
    ret = RegisterLocalDeviceV2(&devInfo, REGISTER_TYPE_UPDATE_ALL);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // inet_pton(AF_INET, ifInfo[i].networkIpAddr, &ip) != 1
    (void)strcpy_s(info.networkName, NSTACKX_MAX_INTERFACE_NAME_LEN, mNetworkName);
    (void)strcpy_s(info.networkIpAddr, NSTACKX_MAX_IP_STRING_LEN, "127");
    ret = RegisterLocalDeviceV2(&devInfo, REGISTER_TYPE_UPDATE_ALL);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    // ip.s_addr == 0
    (void)strcpy_s(info.networkIpAddr, NSTACKX_MAX_IP_STRING_LEN, "0.0.0.0");
    ret = RegisterLocalDeviceV2(&devInfo, REGISTER_TYPE_UPDATE_ALL);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // all is ok
    (void)strcpy_s(info.networkName, NSTACKX_MAX_INTERFACE_NAME_LEN, mNetworkName);
    (void)strcpy_s(info.networkIpAddr, NSTACKX_MAX_IP_STRING_LEN, "127.0.0.1");
    ret = RegisterLocalDeviceV2(&devInfo, REGISTER_TYPE_UPDATE_ALL);
    ASSERT_EQ(ret, NSTACKX_EOK);

    ret = RegisterLocalDeviceV2(&devInfo, REGISTER_TYPE_UPDATE_SPECIFIED);
    ASSERT_EQ(ret, NSTACKX_EOK);
}

TEST(Dfinder, TestGetLocalDeviceBusinessType)
{
    uint8_t ret = GetLocalDeviceBusinessType();
    ASSERT_EQ(ret, mBusinessType);
}

TEST(Dfinder, TestGetLocalDeviceId)
{
    const char *ret = GetLocalDeviceId();
    ASSERT_EQ(*ret, *mDeviceId);
}

TEST(Dfinder, TestGetLocalDeviceInfo)
{
    DeviceInfo *deviceInfo = GetLocalDeviceInfo();
    ASSERT_EQ(*(deviceInfo->deviceId), *mDeviceId);
}

TEST(Dfinder, TestSetLocalDeviceCapability)
{
    // all is ok
    uint32_t bitmapNum=1;
    uint32_t bitmap[]={0};
    int ret = SetLocalDeviceCapability(bitmapNum, bitmap);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // memcpy_s is error
    MOCKER(memcpy_s).stubs().will(returnValue(-1));
    ret = SetLocalDeviceCapability(bitmapNum, bitmap);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();
}

TEST(Dfinder, TestSetLocalDeviceServiceData)
{
    // all is ok
    int32_t ret = SetLocalDeviceServiceData("serviceData");
    ASSERT_EQ(ret, NSTACKX_EOK);

    // strcpy_s is error
    MOCKER(strcpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = SetLocalDeviceServiceData("serviceData");
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();
}

TEST(Dfinder, TestSetLocalDeviceBusinessData)
{
    // all is ok
    int ret = SetLocalDeviceBusinessData("data", false);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // strcpy_s is error
    MOCKER(strcpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = SetLocalDeviceBusinessData("data", true);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();
}

TEST(Dfinder, TestLocalDeviceMode)
{
    uint8_t mode = 1;
    SetLocalDeviceMode(mode);
    uint8_t ret = GetLocalDeviceMode();
    ASSERT_EQ(ret, mode);
}

TEST(Dfinder, TestSetLocalDeviceExtendServiceData)
{
    // all is ok
    int32_t ret = SetLocalDeviceExtendServiceData("extendServiceData");
    ASSERT_EQ(ret, NSTACKX_EOK);

    // strcpy_s is error
    MOCKER(strcpy_s).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = SetLocalDeviceExtendServiceData("extendServiceData");
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();
}

TEST(Dfinder, TestGetLocalIfaceIpStr)
{
    LocalIface *localIface = CreateLocalIface();
    const char *ipStr = GetLocalIfaceIpStr(localIface);
    ASSERT_EQ(localIface->ipStr, ipStr);

    FreeLocalIface(localIface);
}

TEST(Dfinder, TestGetLocalIfaceName)
{
    LocalIface *localIface = CreateLocalIface();
    const char *name = GetLocalIfaceName(localIface);
    ASSERT_EQ(*localIface->ifname, *name);

    FreeLocalIface(localIface);
}

void InvokeDestroyRxIfaceByIfname(const char *ifName)
{
    return;
}

void InvokeCoapServerDestroy(CoapCtxType *ctx, bool moduleDeinit)
{
    return;
}

TEST(Dfinder, TestLocalizeNotificationMsg)
{
    const char *msg = "auv";

    // strcpy_s fail
    MOCKER(strcpy_s).stubs().will(returnValue(EINVAL));
    int32_t ret = LocalizeNotificationMsg(msg);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case strcpy_s fail";
    GlobalMockObject::verify();

    // all ok
    MOCKER(strcpy_s).stubs().will(returnValue(EOK));
    ret = LocalizeNotificationMsg(msg);
    EXPECT_EQ(ret, NSTACKX_EOK) << "case all ok fail";
    GlobalMockObject::verify();
}
