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

#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "fillpadapt.h"
#include "fillpinc.h"
#include "socket_common.h"
#ifdef FILLP_LINUX
#include <sys/epoll.h>
#include <netinet/tcp.h>
#endif

using namespace testing::ext;

class NSTACK_DSTREAM_WITH_SETUP_AND : public testing::Test {
public:
    void SetUp()
    {
        Ftinit();
    }
    void TearDown()
    {
        FtDestroy();
    }
};

#ifndef DTFUZZ_TEST_TIMES
#define DTFUZZ_TEST_TIMES 30000000
#endif
#ifndef DTFUZZ_TEST_TIME_OUT
#define DTFUZZ_TEST_TIME_OUT 10800 // second, 3 hours max
#endif

#define LOOPBACK_IP "127.0.0.1"
char g_addr[32] = LOOPBACK_IP;
bool g_isServer = false;
bool g_isIpv6 = false;

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, create_socket_001, TestSize.Level1)
{
    int ret = 0;
    ret = FtSocket(*(int *)DT_SetGetS32(&g_Element[0], 0x01), *(int *)DT_SetGetS32(&g_Element[1], 0x01),
                       *(int *)DT_SetGetS32(&g_Element[2], 0x01));
    EXPECT_EQ(0, ret);
    ret = FtClose(ret);

    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_bind_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }

    int ret = FtBind(fd, g_addr, len);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);

    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_listen_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }

    int ret = FtBind(fd, g_addr, len);
    EXPECT_EQ(0, ret);

    FtListen(fd, 10);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_accept_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }

    int ret = FtBind(fd, g_addr, len);
    EXPECT_EQ(0, ret);

    FtListen(fd, 10);

    ret = FtAccept(fd, g_addr, &len);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_connect_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }

    ret = FtConnect(fd, g_addr, len);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftsend_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }

    ret = FtConnect(fd, g_addr, len);
    EXPECT_EQ(0, ret);

    char data[256];
    int datalen = 255;
    ret = FtSend(fd, data, datalen, 0);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftsendframe_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }

    ret = FtConnect(fd, g_addr, len);
    EXPECT_EQ(0, ret);

    char data[256];
    int datalen = 255;
    ret = FtSendFrame(fd, data, datalen, 0);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftsendframeext_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }

    ret = FtConnect(fd, g_addr, len);
    EXPECT_EQ(0, ret);

    char data[256];
    int datalen = 255;
    ret = FtSendFrameExt(fd, data, datalen, 0);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftsendframeext_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    FtEventCbkInfo evtInfo = {0};
    int ret = FtApiEventInfoGet(fd, &evtInfo);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftrecv_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }

    int ret = FtBind(fd, g_addr, len);
    EXPECT_EQ(0, ret);

    FtListen(fd, 10);

    ret = FtAccept(fd, g_addr, &len);
    EXPECT_EQ(0, ret);

    char data[255] = 0;
    int datalen = 255;
    ret = FtRecv(fd, data, datalen, 0);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftwritev_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    int iovCount = 10;
    struct iovec *iov = (struct iovec *)malloc(iovCount * sizeof(struct iovec));
    for (int i = 0; i < iovCount; i++) {
        iov[i].iov_len = *(int *)DT_SetGetNumberRange(&g_Element[2 + i], 0, 0, 100);
        if (iov[i].iov_len == 0) {
            iov[i].iov_base = NULL;
        } else {
            iov[i].iov_base = malloc(iov[i].iov_len);
        }
    }
    int ret = FtWritev(fd, iov, iovCount);
    EXPECT_EQ(0, ret);
    free(iov);
    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftgetsockname_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }
    char *addr = (char *)malloc(len);

    int ret = FtGetSockName(fd, addr, &len);
    EXPECT_EQ(0, ret);
    free(addr);
    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftgetpeerkname_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = sizeof(struct sockaddr_in);
    if (sizeof(struct sockaddr_in6) > len) {
        len = sizeof(struct sockaddr_in6);
    }
    char *addr = (char *)malloc(len);
    int ret = FtGetPeerName(fd, addr, &len);
    EXPECT_EQ(0, ret);

    free(addr);
    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftgetsockopt_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = 255;
    char *addr = (char *)malloc(len);
    int ret = FtGetSockOpt(fd, 0, 0, addr, &len);
    EXPECT_EQ(0, ret);
    free(addr);
    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}

HWTEST_F(NSTACK_DSTREAM_WITH_SETUP_AND, socket_ftsetsockopt_001, TestSize.Level1)
{
    int fd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    int flags = 1;
    FtIoctl(fd, FILLP_FIONBIO, &flags);

    size_t len = 255;
    char *addr = (char *)malloc(len);
    int ret = FtSetSockOpt(fd, 0, 0, addr, &len);
    EXPECT_EQ(0, ret);

    ret = FtClose(fd);
    EXPECT_EQ(0, ret);
}
