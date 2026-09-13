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

#include "coap_app.h"
#ifndef _WIN32
#include <netdb.h>
#endif
#include "coap_client.h"
#include "nstackx_device_local.h"

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"
#include "ut_utils.h"

TEST(Dfinder, TestGetCoapContextList)
{
    List *list = GetCoapContextList();
    ASSERT_NE(list, nullptr);
}

void Invoke_coap_register_response_handler(coap_context_t *context, coap_response_handler_t handler)
{
    (void)context;
    (void)handler;
}
TEST(Dfinder, TestCoapServerInit)
{
    coap_context_t *ctx = CreateCoapContext();
    LocalIface *localIface = CreateLocalIface();
    union InetAddr ipAddr;
    ipAddr.in = localIface->addr.in;

    // calloc is error
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    CoapCtxType *coapCtxType = CoapServerInit(AF_INET, &ipAddr, localIface);
    ASSERT_EQ(coapCtxType, nullptr);
    GlobalMockObject::verify();

    // CoapGetContext == NULL
    MOCKER(CoapGetContext).stubs().will(returnValue((coap_context_t *)NULL));
    coapCtxType = CoapServerInit(AF_INET, &ipAddr, localIface);
    ASSERT_EQ(coapCtxType, nullptr);
    GlobalMockObject::verify();

    // CoapInitResources(ctx->ctx) != NSTACKX_EOK, {@link ctx} is free
    MOCKER(CoapGetContext).stubs().will(returnValue(ctx));
    MOCKER(CoapInitResources).stubs().will(returnValue(NSTACKX_EFAILED));
    coapCtxType = CoapServerInit(AF_INET, &ipAddr, localIface);
    ASSERT_EQ(coapCtxType, nullptr);
    GlobalMockObject::verify();

    // all is ok
    MOCKER(CoapGetContext).stubs().will(returnValue(ctx));
    MOCKER(CoapInitResources).stubs().will(returnValue(NSTACKX_EOK));
    MOCKER(coap_register_response_handler).stubs().will(invoke(Invoke_coap_register_response_handler));
    coapCtxType = CoapServerInit(AF_INET, &ipAddr, localIface);
    ASSERT_NE(coapCtxType, nullptr);
    GlobalMockObject::verify();

    FreeLocalIface(localIface);
    ListRemoveNode(&coapCtxType->node);
    free(coapCtxType);
}

TEST(Dfinder, TestCoapGetCoapCtxType)
{
    CoapCtxType *ctx = InsertDevice();

    CoapCtxType *coapCtxType = CoapGetCoapCtxType(NULL);
    ASSERT_EQ(coapCtxType, nullptr);

    coapCtxType = CoapGetCoapCtxType(ctx->ctx);
    ASSERT_EQ(coapCtxType, ctx);

    RemoveDevice(ctx);
}

TEST(Dfinder, TestIsCoapContextReady)
{
    bool ret = IsCoapContextReady();
    ASSERT_EQ(ret, false);
}

static coap_socket_t *g_socket;
#define PREPARE_IO_RETURN_VALUE 1000
unsigned int Invoke_coap_io_prepare_io(coap_context_t *ctx, coap_socket_t *sockets[], unsigned int max_sockets,
    unsigned int *numSockets, coap_tick_t now)
{
    *numSockets = 1;
    g_socket = (coap_socket_t *)malloc(1*sizeof(coap_socket_t));
    g_socket->fd = 1;
    g_socket->flags = COAP_SOCKET_WANT_CONNECT;
    sockets[0] = g_socket;
    return PREPARE_IO_RETURN_VALUE;
}
TEST(Dfinder, TestRegisterCoAPEpollTask)
{
    CoapCtxType *ctx = InsertDevice();
    // all is ok
    ctx->socketNum = 1;
    EpollDesc epollfd = CreateEpollDesc();
    MOCKER(coap_io_prepare_io).stubs().will(invoke(Invoke_coap_io_prepare_io));
    uint32_t ret = RegisterCoAPEpollTask(epollfd);
    ASSERT_EQ(ret, (uint32_t)1000);
    GlobalMockObject::verify();

    free(g_socket);
    RemoveDevice(ctx);
}

TEST(Dfinder, TestCoAPEpollReadHandle)
{
    CoapCtxType *ctx = InsertDevice();
    // all is ok
    ctx->socketNum = 1;
    EpollDesc epollfd = CreateEpollDesc();
    MOCKER(coap_io_prepare_io).stubs().will(invoke(Invoke_coap_io_prepare_io));
    uint32_t ret = RegisterCoAPEpollTask(epollfd);
    ASSERT_EQ(ret, (uint32_t)1000);
    GlobalMockObject::verify();

    // data == null
    ctx->taskList[0].readHandle(NULL);

    EpollTask task = {0};
    // task->taskfd < 0
    task.taskfd = -1;
    ctx->taskList[0].readHandle(&task);

    // task->ptr == NULL
    task.taskfd = 0;
    task.ptr = (void *)NULL;
    ctx->taskList[0].readHandle(&task);

    coap_socket_t socket = {0};
    task.ptr = &socket;
    // socket->flags & COAP_SOCKET_WANT_READ
    socket.flags = COAP_SOCKET_WANT_READ;
    ctx->taskList[0].readHandle(&task);

    // socket->flags & COAP_SOCKET_WANT_ACCEPT
    socket.flags = COAP_SOCKET_WANT_ACCEPT;
    ctx->taskList[0].readHandle(&task);

    free(g_socket);
    RemoveDevice(ctx);
}

TEST(Dfinder, TestCoAPEpollWriteHandle)
{
    CoapCtxType *ctx = InsertDevice();
    // all is ok
    ctx->socketNum = 1;
    EpollDesc epollfd = CreateEpollDesc();
    MOCKER(coap_io_prepare_io).stubs().will(invoke(Invoke_coap_io_prepare_io));
    uint32_t ret = RegisterCoAPEpollTask(epollfd);
    ASSERT_EQ(ret, (uint32_t)1000);
    GlobalMockObject::verify();

    // data == null
    ctx->taskList[0].writeHandle(NULL);

    EpollTask task = {0};
    // task->taskfd < 0
    task.taskfd = -1;
    ctx->taskList[0].writeHandle(&task);

    // task->ptr == NULL
    task.taskfd = 0;
    task.ptr = (void *)NULL;
    ctx->taskList[0].writeHandle(&task);

    coap_socket_t socket = {0};
    task.ptr = &socket;
    // socket->flags & COAP_SOCKET_WANT_WRITE
    socket.flags = COAP_SOCKET_WANT_WRITE;
    ctx->taskList[0].writeHandle(&task);

    // socket->flags & COAP_SOCKET_WANT_CONNECT
    socket.flags = COAP_SOCKET_WANT_CONNECT;
    ctx->taskList[0].writeHandle(&task);

    free(g_socket);
    RemoveDevice(ctx);
}

TEST(Dfinder, TestCoAPEpollErrorHandle)
{
    CoapCtxType *ctx = InsertDevice();
    // all is ok
    ctx->socketNum = 1;
    EpollDesc epollfd = CreateEpollDesc();
    MOCKER(coap_io_prepare_io).stubs().will(invoke(Invoke_coap_io_prepare_io));
    uint32_t ret = RegisterCoAPEpollTask(epollfd);
    ASSERT_EQ(ret, (uint32_t)1000);
    GlobalMockObject::verify();

    EpollTask task = {0};
    // task->taskfd < 0
    task.taskfd = -1;
    ctx->taskList[0].errorHandle(&task);

    // task->ptr == NULL
    task.taskfd = 0;
    task.ptr = (void *)NULL;
    ctx->taskList[0].errorHandle(&task);

    coap_socket_t socket = {0};
    task.ptr = &socket;

    // IsCoapCtxEndpointSocket is ok
    MOCKER(IsCoapCtxEndpointSocket).stubs().will(returnValue(1));
    ctx->taskList[0].errorHandle(&task);
    GlobalMockObject::verify();

    // IsCoapCtxEndpointSocket is error
    MOCKER(IsCoapCtxEndpointSocket).stubs().will(returnValue(0));
    ctx->taskList[0].errorHandle(&task);
    GlobalMockObject::verify();

    free(g_socket);
    RemoveDevice(ctx);
}
