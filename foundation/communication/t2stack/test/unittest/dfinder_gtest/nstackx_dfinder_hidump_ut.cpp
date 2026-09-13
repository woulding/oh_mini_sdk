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

#include "nstackx_dfinder_hidump.h"
#include "nstackx_util.h"
#include "nstackx_getopt.h"
#include "nstackx_event.h"
#include "nstackx_device_local.h"
#include "nstackx_device_remote.h"

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"
#include "ut_utils.h"

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

TEST(Dfinder, TestDumpDeviceInfo)
{
    DeviceInfo deviceInfo = {0};
    (void)strcpy_s(deviceInfo.deviceId, NSTACKX_MAX_DEVICE_ID_LEN, "deviceId");
    char buf[2048];

    // all is ok
    int ret = DumpDeviceInfo(&deviceInfo, buf, 2048, 1);
    ASSERT_EQ(ret, 99);

    // memcpy_s is error
    MOCKER(memcpy_s).stubs().will(returnValue(-1));
    ret = DumpDeviceInfo(&deviceInfo, buf, 2048, 1);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();
}

TEST(Dfinder, TestDFinderDumpIface)
{
    char buf[2048];
    char ifname[] = "eth";
    LocalIface *localIface = CreateLocalIface();
    union InetAddr ipAddr;
    ipAddr.in = localIface->addr.in;
    struct DumpIfaceInfo info = {
        .ifname = "eth",
        .state = 1,
        .af = AF_INET,
        .addr = &ipAddr
    };


    // all is ok
    int ret = DFinderDumpIface(&info, buf, sizeof(buf));
    ASSERT_GT(ret, 0);

    // IpAddrAnonymousFormat < 0
    MOCKER(IpAddrAnonymousFormat).stubs().will(returnValue(-10));
    ret = DFinderDumpIface(&info, buf, sizeof(buf));
    ASSERT_EQ(ret, -10);
    GlobalMockObject::verify();

    // Test IPv6
    union InetAddr ipv6Addr;
    ipv6Addr.in6 = in6addr_any;
    struct DumpIfaceInfo ipv6Info = {
        .ifname = "eth6",
        .state = 1,
        .af = AF_INET6,
        .addr = &ipv6Addr
    };
    ret = DFinderDumpIface(&ipv6Info, buf, sizeof(buf));
    ASSERT_NE(ret, NSTACKX_EFAILED);

    FreeLocalIface(localIface);
}

static void DFinderDumpFuncCb(void *softObj, const char *data, uint32_t len)
{
    (void)softObj;
    (void)len;
}
int32_t InvokePostEvent(const List *eventNodeChain, EpollDesc epollfd, EventHandle handle, void *arg)
{
    handle(arg);
    return NSTACKX_EOK;
}
TEST(Dfinder, TestDFinderDump)
{
    const char *argv[] = {"", "-f", "-h", "-l", "-r", "-s", "-m", "0", ""};
    char softObj[2048];

    MOCKER(PostEvent).stubs().will(invoke(InvokePostEvent));
    MOCKER(LocalIfaceDump).stubs().will(returnValue(NSTACKX_EOK));
    MOCKER(DumpRemoteDevice).stubs().will(returnValue(NSTACKX_EOK));

    // EnableMgtMsgLog enable == 0
    int ret = DFinderDump(argv, sizeof(argv)/sizeof(argv[0]), (void *)softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // EnableMgtMsgLog enable == 1
    const char *argv1[] = {"", "-f", "-h", "-l", "-r", "-s", "-m", "1", ""};
    ret = DFinderDump(argv1, sizeof(argv1)/sizeof(argv1[0]), (void *)softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // EnableMgtMsgLog strlen(optMsg) != 1
    const char *argv2[] = {"", "-f", "-h", "-l", "-r", "-s", "-m", ""};
    ret = DFinderDump(argv2, sizeof(argv2)/sizeof(argv2[0]), (void *)softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EFAILED);

    // NstackGetOpt is default
    MOCKER(NstackGetOpt).stubs().will(returnValue(0));
    ret = DFinderDump(argv, sizeof(argv)/sizeof(argv[0]), (void *)softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // CreateDumpMsg == NULL, that is SemInit error
    MOCKER(SemInit).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = DFinderDump(argv, sizeof(argv)/sizeof(argv[0]), (void *)softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // PostEvent is error
    MOCKER(PostEvent).stubs().will(returnValue(NSTACKX_EFAILED));
    ret = DFinderDump(argv, sizeof(argv)/sizeof(argv[0]), (void *)softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // argc = 1
    ret = DFinderDump(nullptr, 1, (void *)&softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // argc = 1 and calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = DFinderDump(nullptr, 1, (void *)&softObj, DFinderDumpFuncCb);
    ASSERT_EQ(ret, NSTACKX_EOK);
    GlobalMockObject::verify();
}