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

#include "coap_client.h"
#ifndef _WIN32
#include <netdb.h>
#endif

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"
#include "ut_utils.h"

TEST(Dfinder, TestCoapResolveAddress)
{
    // all is ok
    coap_str_const_t *server = coap_make_str_const("server");
    struct sockaddr_in inetAddr = {0};
    inetAddr.sin_family = AF_INET;
    inetAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    inetAddr.sin_port = htons(0);
    struct sockaddr *dst = (struct sockaddr*)&inetAddr;
    int32_t ret = CoapResolveAddress(server, dst);
    ASSERT_NE(ret, -1);

    // dst == NULL
    ret = CoapResolveAddress(server, NULL);
    ASSERT_EQ(ret, -2);

    // server->length > 0 and then memcpy_s is error
    MOCKER(memcpy_s).stubs().will(returnValue(-1));
    ret = CoapResolveAddress(server, dst);
    ASSERT_EQ(ret, -1);
    GlobalMockObject::verify();

    // server->length == 0 and then memcpy_s is error
    MOCKER(memcpy_s).stubs().will(returnValue(-1));
    int temp = server->length;
    server->length = 0;
    ret = CoapResolveAddress(server, dst);
    ASSERT_EQ(ret, -1);
    server->length = temp;
    GlobalMockObject::verify();

    // getaddrinfo return -2
    MOCKER(getaddrinfo).stubs().will(returnValue(-2));
    ret = CoapResolveAddress(server, dst);
    ASSERT_EQ(ret, -2);
    GlobalMockObject::verify();
}

namespace MessageHandlerNs {
    static coap_session_t *session = NULL;
    static coap_pdu_t sent;
    static coap_pdu_t recv;
    static coap_opt_t opt = {0};
}

TEST(Dfinder, TestCoapMessageHandler_NullReceivedPdu)
{
    coap_response_t ret = CoapMessageHandler(MessageHandlerNs::session, &MessageHandlerNs::sent, NULL, 1);
    ASSERT_EQ(ret, COAP_RESPONSE_FAIL);
}

TEST(Dfinder, TestCoapMessageHandler_ReceiveRstMsg)
{
    MOCKER(coap_pdu_get_type).stubs().will(returnValue(COAP_MESSAGE_RST));
    int32_t ret = CoapMessageHandler(MessageHandlerNs::session, &MessageHandlerNs::sent, &MessageHandlerNs::recv, 1);
    GlobalMockObject::verify();
    ASSERT_EQ(ret, COAP_RESPONSE_FAIL);
}

TEST(Dfinder, TestCoapMessageHandler_OptNotNull)
{
    MOCKER(coap_check_option).stubs().will(returnValue(&MessageHandlerNs::opt));
    MOCKER(coap_pdu_get_type).stubs().will(returnValue(COAP_MESSAGE_ACK));
    int32_t ret = CoapMessageHandler(MessageHandlerNs::session, &MessageHandlerNs::sent, &MessageHandlerNs::recv, 1);
    GlobalMockObject::verify();
    ASSERT_EQ(ret, COAP_RESPONSE_FAIL);
}

TEST(Dfinder, TestCoapMessageHandler_NullOptThenNotNullOpt)
{
    MOCKER(coap_check_option).stubs().will(returnValue((coap_opt_t *)NULL)).then(returnValue(&MessageHandlerNs::opt));
    MOCKER(coap_pdu_get_type).stubs().will(returnValue(COAP_MESSAGE_ACK));
    int32_t ret = CoapMessageHandler(MessageHandlerNs::session, &MessageHandlerNs::sent, &MessageHandlerNs::recv, 1);
    GlobalMockObject::verify();
    ASSERT_EQ(ret, COAP_RESPONSE_FAIL);
}

TEST(Dfinder, TestCoapMessageHandler_AllOk)
{
    // all is ok
    MOCKER(coap_check_option).stubs().will(returnValue((coap_opt_t *)NULL));
    MOCKER(coap_pdu_get_type).stubs().will(returnValue(COAP_MESSAGE_ACK));
    int32_t ret = CoapMessageHandler(MessageHandlerNs::session, &MessageHandlerNs::sent, &MessageHandlerNs::recv, 1);
    ASSERT_EQ(ret, COAP_RESPONSE_OK);
    GlobalMockObject::verify();
}

TEST(Dfinder, TestCoapGetContext)
{
    char addrStr[NI_MAXHOST] = COAP_SRV_DEFAULT_ADDR;
    char portStr[NI_MAXSERV] = COAP_SRV_DEFAULT_PORT;
    LocalIface *localIface = CreateLocalIface();
    union InetAddr ipAddr;
    ipAddr.in = localIface->addr.in;

    // getaddrinfo != 0
    MOCKER(getaddrinfo).stubs().will(returnValue(-1));
    coap_context_t *ctx = CoapGetContext(addrStr, portStr, AF_INET, &ipAddr);
    ASSERT_EQ(ctx, nullptr);
    GlobalMockObject::verify();

    // coap_new_endpoint == NULL
    MOCKER(coap_new_endpoint).stubs().will(returnValue((coap_endpoint_t *)NULL));
    ctx = CoapGetContext(addrStr, portStr, AF_INET, &ipAddr);
    ASSERT_EQ(ctx, nullptr);
    GlobalMockObject::verify();

    // BindToDevice(ep->sock.fd, sockIpPtr) != NSTACKX_EOK
    ctx = CoapGetContext(addrStr, portStr, AF_INET, &ipAddr);
    ASSERT_EQ(ctx, nullptr);

    FreeLocalIface(localIface);
    free(ctx);
}

TEST(Dfinder, TestCoapGetSession)
{
    coap_address_t dst = {0};
    struct sockaddr_in inetAddr;
    inetAddr.sin_family = AF_INET;
    inetAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    inetAddr.sin_port = htons(0);
    memcpy_s(&dst.addr.sa, sizeof(struct sockaddr), (struct sockaddr*)&inetAddr, 10);
    dst.size = (uint32_t)10;
    dst.addr.sin.sin_port = htons(COAP_DEFAULT_PORT);
    dst.addr.sa.sa_family = AF_INET;
    CoapServerParameter coapServerParameter = {
            .proto = COAP_PROTO_UDP,
            .dst = &dst
    };
    coap_context_t *ctx = CreateCoapContext();
    coap_session_t *session1 = (coap_session_t *)malloc(1*sizeof(coap_session_t *));
    // all is ok
    MOCKER(coap_new_client_session).stubs().will(returnValue(session1));
    coap_session_t *session = CoapGetSession(ctx, "127.0.0.1", COAP_SRV_DEFAULT_PORT, &coapServerParameter);
    ASSERT_EQ(session, session1);
    GlobalMockObject::verify();

    // localAddr == NULL
    session = CoapGetSession(ctx, NULL, COAP_SRV_DEFAULT_PORT, &coapServerParameter);
    ASSERT_EQ(session, nullptr);

    // getaddrinfo != 0
    MOCKER(getaddrinfo).stubs().will(returnValue(-1));
    session = CoapGetSession(ctx, "127.0.0.1", COAP_SRV_DEFAULT_PORT, &coapServerParameter);
    ASSERT_EQ(session, nullptr);
    GlobalMockObject::verify();

    // coap_session_get_by_peer != NULL
    MOCKER(coap_session_get_by_peer).stubs().will(returnValue(session1));
    session = CoapGetSession(ctx, "127.0.0.1", COAP_SRV_DEFAULT_PORT, &coapServerParameter);
    ASSERT_EQ(session, session1);
    GlobalMockObject::verify();

    // dst == NULL
    coapServerParameter.dst = NULL;
    session = CoapGetSession(ctx, "127.0.0.1", COAP_SRV_DEFAULT_PORT, &coapServerParameter);
    ASSERT_EQ(session, nullptr);

    // proto != COAP_PROTO_UDP
    coapServerParameter.proto = COAP_PROTO_NONE;
    session = CoapGetSession(ctx, "127.0.0.1", COAP_SRV_DEFAULT_PORT, &coapServerParameter);
    ASSERT_EQ(session, nullptr);

    // coapServerParameter == NULL
    session = CoapGetSession(ctx, "127.0.0.1", COAP_SRV_DEFAULT_PORT, NULL);
    ASSERT_EQ(session, nullptr);

    FreeCoapContext(ctx);
    free(session1);
}

TEST(Dfinder, TestIsCoapCtxEndpointSocket)
{
    coap_context_t *coapContext = CreateCoapContext();
    uint8_t ret = IsCoapCtxEndpointSocket(coapContext, 1);
    ASSERT_EQ(ret, NSTACKX_FALSE);

    // ctx == NULL
    ret = IsCoapCtxEndpointSocket(NULL, 1);
    ASSERT_EQ(ret, NSTACKX_FALSE);

    FreeCoapContext(coapContext);
}
