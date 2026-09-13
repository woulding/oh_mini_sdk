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

#include "coap_discover.h"
#include "coap_client.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_util.h"
#include "json_payload.h"
#include "nstackx_device_local.h"

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"
#include "ut_utils.h"

#define BODY_LENGTH 331

void MockSetDefaultCoapDiscoverTargetCount()
{
    // IsCoapContextReady is ok
    MOCKER(IsCoapContextReady).stubs().will(returnValue(true));
    // g_coapDiscoverType = COAP_BROADCAST_TYPE_DEFAULT
    SetCoapDiscoverType(COAP_BROADCAST_TYPE_DEFAULT);
    CoapServiceDiscoverInnerConfigurable(1);
}

#define LOCAL_IP_LENGTH 9

void MockCoapGetSession(coap_context_t *ctx)
{
    // setsockopt is ok
    MOCKER(setsockopt).stubs().will(returnValue(0));
    // coap_session_get_by_peer is ok
    coap_address_t dst = {0};
    struct sockaddr_in inetAddr;
    inetAddr.sin_family = AF_INET;
    inetAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    inetAddr.sin_port = htons(COAP_DEFAULT_PORT);
    memcpy_s(&dst.addr.sa, sizeof(struct sockaddr), (struct sockaddr*)&inetAddr, LOCAL_IP_LENGTH);
    dst.size = (uint32_t)LOCAL_IP_LENGTH;
    dst.addr.sin.sin_port = htons(COAP_DEFAULT_PORT);
    dst.addr.sa.sa_family = AF_INET;
    coap_session_t *session = coap_new_client_session(ctx, NULL, &dst, COAP_PROTO_UDP);
    MOCKER(coap_session_get_by_peer).stubs().will(returnValue(session));
}

TEST(Dfinder, TestSetCoapDiscConfig)
{
    uint32_t bcastInterval[1] = {0};
    DFinderDiscConfig config;
    config.bcastInterval = bcastInterval;
    config.intervalArrLen = 1;

    // malloc is error, and g_coapIntervalArr == NULL
    MOCKER(malloc).stubs().will(returnValue((void *)NULL));
    int32_t ret = SetCoapDiscConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // all is ok
    ret = SetCoapDiscConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // g_coapIntervalArr != NULL
    ret = SetCoapDiscConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EOK);

    // malloc is error, and g_coapIntervalArr != NULL
    MOCKER(malloc).stubs().will(returnValue((void *)NULL));
    ret = SetCoapDiscConfig(&config);
    ASSERT_EQ(ret, NSTACKX_EOK);
    GlobalMockObject::verify();

    // free g_coapIntervalArr
    CoapDiscoverDeinit();
}

static Timer *InvokeTimerStart(EpollDesc epollfd, uint32_t ms, uint8_t repeated, TimeoutHandle handle, void *data)
{
    handle(data);
    return (Timer *)malloc(1 * sizeof(Timer));
}
static void TimerHandle(void *argument)
{
    (void)argument;
}
TEST(Dfinder, TestCoapDiscoverInit)
{
    EpollDesc epollfd = CreateEpollDesc();

    // g_recvRecountTimer == NULL
    MOCKER(TimerStart).stubs().will(returnValue((Timer *)NULL));
    int32_t ret = CoapDiscoverInit(epollfd);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // g_discoverTimer == NULL
    Timer *timer = TimerStart(epollfd, 1000, NSTACKX_TRUE, TimerHandle, NULL);
    MOCKER(TimerStart).stubs().will(returnValue(timer)).then(returnValue((Timer *)NULL));
    ret = CoapDiscoverInit(epollfd);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // g_notificationTimer == NULL
    Timer *tmpRecvTimer = TimerStart(epollfd, 1000, NSTACKX_TRUE, TimerHandle, NULL);
    EXPECT_NE(tmpRecvTimer, (Timer *)NULL) << "recv timer, case g_notificationTimer == NULL fail";
    Timer *tmpDiscTimer = TimerStart(epollfd, 1000, NSTACKX_TRUE, TimerHandle, NULL);
    EXPECT_NE(tmpDiscTimer, (Timer *)NULL) << "disc timer, case g_notificationTimer == NULL fail";
    MOCKER(TimerStart).stubs().will(returnValue(tmpRecvTimer)).
        then(returnValue(tmpDiscTimer)).then(returnValue((Timer *)NULL));
    ret = CoapDiscoverInit(epollfd);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "case g_notificationTimer == NULL fail";
    CoapDiscoverDeinit();
    GlobalMockObject::verify();

    // calloc is error
    MOCKER(TimerStart).stubs().will(invoke(InvokeTimerStart));
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = CoapDiscoverInit(epollfd);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
    GlobalMockObject::verify();

    // all is ok
    MOCKER(TimerStart).stubs().will(invoke(InvokeTimerStart));
    ret = CoapDiscoverInit(epollfd);
    ASSERT_EQ(ret, NSTACKX_EOK);
    GlobalMockObject::verify();
    CoapDiscoverDeinit();

    // g_discoverCount < g_coapDiscoverTargetCount && IsCoapContextReady is true
    MOCKER(IsCoapContextReady).stubs().will(returnValue(true));
    MOCKER(TimerStart).stubs().will(invoke(InvokeTimerStart));
    SetCoapDiscoverType(COAP_BROADCAST_TYPE_DEFAULT);
    CoapServiceDiscoverInnerAn(1);
    // CoapPostServiceDiscover
    CoapCtxType *ctx = InsertDevice();

    char serviceData[] = "service\0";
    NSTACKX_RegisterServiceData(serviceData);
    // GetBroadcastIp != NSTACKX_EOK
    ret = CoapDiscoverInit(epollfd);
    ASSERT_EQ(ret, NSTACKX_EOK);
    CoapDiscoverDeinit();

    // GetBroadcastIp == NSTACKX_EOK
    MOCKER(GetBroadcastIp).stubs().will(returnValue(NSTACKX_EOK));
    // CoapGetSession != NULL
    coap_session_t *session = (coap_session_t *)malloc(1 * sizeof(coap_session_t));
    MOCKER(CoapGetSession).stubs().will(returnValue(session));
    // coap_split_uri >= 0
    MOCKER(coap_split_uri).stubs().will(returnValue(0));
    // CoapResolveAddress >= 0
    MOCKER(CoapResolveAddress).stubs().will(returnValue(0));
    // coap_new_pdu != NULL
    coap_pdu_t *pdu = (coap_pdu_t *)malloc(1 * sizeof(coap_pdu_t));
    MOCKER(coap_new_pdu).stubs().will(returnValue(pdu));
    // coap_send != COAP_INVALID_TID(-1)
    MOCKER(coap_send).stubs().will(returnValue(1));

    ret = CoapDiscoverInit(epollfd);
    ASSERT_EQ(ret, NSTACKX_EOK);
    CoapDiscoverDeinit();
    GlobalMockObject::verify();

    CoapDiscoverDeinit();
    RemoveDevice(ctx);
    free(session);
    free(pdu);
}

TEST(Dfinder, TestCoapDiscoverRequestOngoing)
{
     // 调用 CoapSubscribeModuleInner，假设它会触发 CoapDiscoverRequestOngoing 返回 1
    CoapSubscribeModuleInner(1);
    uint8_t ret = CoapDiscoverRequestOngoing();
    ASSERT_EQ(ret, 1);
}

namespace ServiceMsgNs {
    static const uint8_t data[] = {0};
    static MsgCtx ctx = {
        .deviceId = "deviceId",
        .moduleName = "moduleName",
        .data = data,
        .len = 1,
        .type = SERVER_TYPE_WLANORETH,
        .err = NSTACKX_EOK
    };
    const char addr[INET_ADDRSTRLEN] = "127.0.0.1:8080";
    struct in_addr remoteIp;
}

TEST(Dfinder, TestCoapSendServiceMsg_NullCtx)
{
    (void)inet_pton(AF_INET, ServiceMsgNs::addr, &ServiceMsgNs::remoteIp);
    MOCKER(LocalIfaceGetCoapCtxByRemoteIp).stubs().will(returnValue((CoapCtxType *)NULL));
    int32_t ret = CoapSendServiceMsg(&ServiceMsgNs::ctx, ServiceMsgNs::addr, &ServiceMsgNs::remoteIp);
    GlobalMockObject::verify();
    ASSERT_EQ(ret, NSTACKX_EFAILED);
}

TEST(Dfinder, TestCoapSendServiceMsg_NullSession)
{
    CoapCtxType *coapCtxType = CreateCoapCtxType();
    MOCKER(LocalIfaceGetCoapCtxByRemoteIp).stubs().will(returnValue(coapCtxType));
    MOCKER(CoapGetSession).stubs().will(returnValue((coap_session_t *)NULL));
    int32_t ret = CoapSendServiceMsg(&ServiceMsgNs::ctx, ServiceMsgNs::addr, &ServiceMsgNs::remoteIp);
    GlobalMockObject::verify();
    FreeCoapCtxType(coapCtxType);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
}

TEST(Dfinder, TestCoapSendServiceMsg_MemcpysFail)
{
    MOCKER(memcpy_s).stubs().will(returnValue(EINVAL));
    int32_t ret = CoapSendServiceMsg(&ServiceMsgNs::ctx, ServiceMsgNs::addr, &ServiceMsgNs::remoteIp);
    ASSERT_EQ(ret, NSTACKX_EFAILED);
}

TEST(Dfinder, TestCoapSendServiceMsg_CallocFail)
{
    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    int32_t ret = CoapSendServiceMsg(&ServiceMsgNs::ctx, ServiceMsgNs::addr, &ServiceMsgNs::remoteIp);
    GlobalMockObject::verify();
    ASSERT_EQ(ret, NSTACKX_EFAILED);
}

static bool g_IsDiscoverMode = true;
static void Invoke_coap_register_handler(coap_resource_t *resource, coap_request_t method,
    coap_method_handler_t handler)
{
    coap_session_t *session = NULL;
    coap_pdu_t *request = (coap_pdu_t *)malloc(1 * sizeof(coap_pdu_t));
    coap_pdu_t *response = (coap_pdu_t *)malloc(1 * sizeof(coap_pdu_t));
    request->mid = 1; // Valid message ids are 0 to 2^16. Negative values are error codes.
    if (g_IsDiscoverMode) {
        request->body_data = (const uint8_t *)
            "{\"deviceId\":\"{\\\"UDID\\\":\\\"FE73EE0BA926F5A5B149B1567AD2D32BC5443A9FE05FE812CE623283EAE5CEDD\\\"}\","
            "\"devicename\":\"Mate 50\",\"type\":14,\"mode\":1,\"deviceHash\":\"0\","
            "\"serviceData\":\"\",\"extendServiceData\":\"\",\"wlanIp\":\"127.0.0.1\",\"capabilityBitmap\":[71],"
            "\"bType\":0,\"bData\":\"\", \"coapUri\":\"coap://127.0.0.1/device_discover\"}";
    } else {
        request->body_data = (const uint8_t *)
            "{\"deviceId\":\"{\\\"UDID\\\":\\\"FE73EE0BA926F5A5B149B1567AD2D32BC5443A9FE05FE812CE623283EAE5CEDD\\\"}\","
            "\"devicename\":\"Mate 50\",\"type\":14,\"mode\":2,\"deviceHash\":\"0\","
            "\"serviceData\":\"\",\"extendServiceData\":\"\",\"wlanIp\":\"127.0.0.1\",\"capabilityBitmap\":[71],"
            "\"bType\":0,\"bData\":\"\", \"coapUri\":\"coap://127.0.0.1/device_discover\"}";
    }
    request->body_length = (size_t)BODY_LENGTH;
    handler(resource, session, request, coap_get_query(request), response);

    free(request);
    free(response);
}
static void Invoke_coap_resource_set_get_observable(coap_resource_t *resource, int mode)
{
    return;
}
static void Invoke_coap_add_resource(coap_context_t *context, coap_resource_t *resource)
{
    return;
}
static int Invoke_coap_delete_resource(coap_context_t *context, coap_resource_t *resource)
{
    return 0;
}
static void Invoke_coap_pdu_set_code(coap_pdu_t *pdu, coap_pdu_code_t code)
{
    return;
}
TEST(Dfinder, TestCoapInitResources)
{
    // InsertDevice and CoapDiscoverInit
    CoapCtxType *ctx = InsertDevice();

    // r == NULL
    MOCKER(coap_resource_init).stubs().will(returnValue((coap_resource_t *)NULL));
    int32_t ret = CoapInitResources(ctx->ctx);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // msg == NULL
    MOCKER(coap_register_request_handler).stubs().will(invoke(Invoke_coap_register_handler));
    MOCKER(coap_resource_set_get_observable).stubs().will(invoke(Invoke_coap_resource_set_get_observable));
    MOCKER(coap_add_resource).stubs().will(invoke(Invoke_coap_add_resource));
    MOCKER(coap_delete_resource).stubs().will(invoke(Invoke_coap_delete_resource));
    coap_resource_t *res = (coap_resource_t *)malloc(1 * sizeof(coap_resource_t));
    MOCKER(coap_resource_init).stubs().will(returnValue(res)).then(returnValue((coap_resource_t *)NULL));
    ret = CoapInitResources(ctx->ctx);
    ASSERT_EQ(ret, NSTACKX_ENOMEM);
    GlobalMockObject::verify();

    // notification == NULL
    MOCKER(coap_register_request_handler).stubs().will(invoke(Invoke_coap_register_handler));
    MOCKER(coap_resource_set_get_observable).stubs().will(invoke(Invoke_coap_resource_set_get_observable));
    MOCKER(coap_add_resource).stubs().will(invoke(Invoke_coap_add_resource));
    MOCKER(coap_delete_resource).stubs().will(invoke(Invoke_coap_delete_resource));
    coap_resource_t *resDisc = (coap_resource_t *)malloc(1 * sizeof(coap_resource_t));
    EXPECT_NE(resDisc, (coap_resource_t *)NULL) << "malloc for disc testcase notification == NULL fail";
    coap_resource_t *resMsg = (coap_resource_t *)malloc(1 * sizeof(coap_resource_t));
    EXPECT_NE(resMsg, (coap_resource_t *)NULL) << "malloc for msg testcase notification == NULL fail";
    MOCKER(coap_resource_init).stubs().will(returnValue(resDisc)).
        then(returnValue(resMsg)).then(returnValue((coap_resource_t *)NULL));
    ret = CoapInitResources(ctx->ctx);
    if (resDisc) free(resDisc);
    if (resMsg) free(resMsg);
    EXPECT_EQ(ret, NSTACKX_ENOMEM) << "case notification == NULL fail";
    GlobalMockObject::verify();

    // all is ok
    MOCKER(coap_register_request_handler).stubs().will(invoke(Invoke_coap_register_handler));
    MOCKER(coap_resource_set_get_observable).stubs().will(invoke(Invoke_coap_resource_set_get_observable));
    MOCKER(coap_add_resource).stubs().will(invoke(Invoke_coap_add_resource));
    MOCKER(coap_delete_resource).stubs().will(invoke(Invoke_coap_delete_resource));
    MOCKER(coap_resource_init).stubs().will(returnValue(res));
    coap_context_t *context = CreateCoapContext();
    MOCKER(coap_session_get_context).stubs().will(returnValue(context));
    MOCKER(CoapGetCoapCtxType).stubs().will(returnValue(ctx));
    MOCKER(GetServiceDiscoverInfo).stubs().will(returnValue(NSTACKX_EOK));
    MOCKER(ReportDiscoveredDevice).stubs().will(returnValue(NSTACKX_EOK));
    MOCKER(coap_pdu_set_code).stubs().will(invoke(Invoke_coap_pdu_set_code));
    MOCKER(ntohs).stubs().will(returnValue(BODY_LENGTH));

    ret = CoapInitResources(ctx->ctx);
    ASSERT_EQ(ret, NSTACKX_EOK);
    GlobalMockObject::verify();

    CoapDiscoverDeinit();
    RemoveDevice(ctx);
    free(res);
    FreeCoapContext(context);
}

TEST(Dfinder, TestCoapServiceNotification)
{
    // coap context not ready
    CoapServiceNotification();

    // coap context ready, init, already running, run again: g_notificationRunCnt != 0
    MOCKER(IsCoapContextReady).stubs().will(returnValue(true));
    NSTACKX_Parameter params = {0};
    int32_t ret = NSTACKX_Init(&params);
    EXPECT_EQ(ret, NSTACKX_EOK) << "dfinder init fail";
    uint16_t tmpIntervals[3] = {0, 2000, 2000};
    std::string tmpMsg("hello");
    NSTACKX_NotificationConfig config = {
        msg : const_cast<char *>(tmpMsg.c_str()),
        msgLen : 5,
        intervalsMs : tmpIntervals,
        intervalLen : 3,
        businessType : NSTACKX_BUSINESS_TYPE_NULL
    };
    // ThreadInit
    ret = NSTACKX_ThreadInit();
    ASSERT_EQ(ret, NSTACKX_EOK) << "thread init fail";

    ret = NSTACKX_SendNotification(&config);
    EXPECT_EQ(ret, NSTACKX_EOK) << "send notification fail";
    CoapServiceNotification();
    NSTACKX_Deinit();
    GlobalMockObject::verify();
}

TEST(Dfinder, TestLocalizeNotificationInterval)
{
    const uint16_t tmpIntervals[3] = {0, 2000, 2000};
    const uint8_t intervalLen = 3;

    MOCKER(calloc)
            .stubs()
            .will(returnValue(static_cast<void*>(NULL)));
    int32_t ret = LocalizeNotificationInterval(tmpIntervals, intervalLen);
    EXPECT_EQ(ret, NSTACKX_EFAILED) << "malloc for notification interval fail";
    GlobalMockObject::verify();

    // all ok, first call to make g_notificationIntervals not NULL
    ret = LocalizeNotificationInterval(tmpIntervals, intervalLen);
    EXPECT_EQ(ret, NSTACKX_EOK) << "first localize interval fail";

    MOCKER(calloc)
        .stubs()
        .will(returnValue(static_cast<void*>(NULL)));
    ret = LocalizeNotificationInterval(tmpIntervals, intervalLen);
    EXPECT_EQ(ret, NSTACKX_EOK) << "second localize interval fail";
    GlobalMockObject::verify();
}

TEST(Dfinder, TestCoapServiceNotificationStop)
{
    // g_notificationIntervals == NULL
    CoapServiceNotificationStop();

    // g_notificationIntervals != NULL
    const uint16_t tmpIntervals[5] = {0, 1000, 2000, 3000, 4000};
    const uint8_t intervalLen = 5;
    int32_t ret = LocalizeNotificationInterval(tmpIntervals, intervalLen);
    EXPECT_EQ(ret, NSTACKX_EOK) << "first localize interval fail";
    CoapServiceNotificationStop();
}
