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
#include <securec.h>
#include <gtest/gtest.h>
#include <pthread.h>

#include "devattest_log.h"
#include "attest_entry.h"
#include "attest_result_info.h"
#include "attest_type.h"
#include "attest_service_active.h"
#include "attest_service_auth.h"
#include "attest_service_challenge.h"
#include "attest_service_device.h"
#include "attest_service.h"
#include "attest_service_device.h"
#include "attest_security_token.h"
#include "attest_service_reset.h"
#include "attest_network.h"
#include "attest_adapter.h"
#include "devattest_errno.h"
#include "attest_utils.h"
#include "attest_tdd_mock_property.h"
#include "attest_tdd_mock_hal.h"
#include "attest_tdd_test.h"
#include "attest_tdd_mock_config.h"

using namespace testing::ext;
namespace OHOS {
namespace DevAttest {

static const int32_t ATTEST_GET_CHANLLEGE = 0;
static const int32_t ATTEST_RESET = 1;
static const int32_t ATTEST_ACTIVE = 2;
static const int32_t ATTEST_AUTH = 3;

static const char* ATTEST_REST_ERROR_EXPECT_RESULT = "15003";
static const char* ATTEST_RESET_EXPECT_CHAP = "39a9d04d41617162893c3312ceb030acac8d8bd0cc9fcebcab5402a43891341d";

class AttestTddTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void AttestTddTest::SetUpTestCase(void)
{
}

void AttestTddTest::TearDownTestCase(void)
{
}

void AttestTddTest::SetUp()
{
}

void AttestTddTest::TearDown()
{
}

/*
 * @tc.name: TestInitSysData001
 * @tc.desc: Test init system data.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestInitSysData001, TestSize.Level1)
{
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    EXPECT_STREQ(StrdupDevInfo(VERSION_ID), ATTEST_MOCK_PROPERTY_VERSIONID);
    EXPECT_STREQ(StrdupDevInfo(ROOT_HASH), ATTEST_MOCK_PROPERTY_HASH);
    EXPECT_STREQ(StrdupDevInfo(DISPLAY_VERSION), ATTEST_MOCK_PROPERTY_SOFTWARE_VERSION);
    EXPECT_STREQ(StrdupDevInfo(MANU_FACTURE), ATTEST_MOCK_PROPERTY_MANU);
    EXPECT_STREQ(StrdupDevInfo(PRODUCT_MODEL), ATTEST_MOCK_PROPERTY_MODEL);
    EXPECT_STREQ(StrdupDevInfo(BRAND), ATTEST_MOCK_PROPERTY_BRAND);
    EXPECT_STREQ(StrdupDevInfo(SECURITY_PATCH_TAG), ATTEST_MOCK_PROPERTY_PATCH);
    EXPECT_STREQ(StrdupDevInfo(UDID), ATTEST_MOCK_PROPERTY_UDID);
    // 恢复环境
    DestroySysData();
    EXPECT_TRUE(StrdupDevInfo(VERSION_ID) == nullptr);
}

/*
 * @tc.name: TestInitNetWork001
 * @tc.desc: Test init network, result is success.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestInitNetWork001, TestSize.Level1)
{
    int ret = InitNetworkServerInfo();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    ServerInfo* serverInfo = (ServerInfo*)g_attestNetworkList.head->data;
    EXPECT_STREQ(serverInfo->hostName, ATTEST_MOCK_HAL_NETWORK_RESULT);
    ReleaseList(&g_attestNetworkList);
}

/*
 * @tc.name: TestInitNetWork002
 * @tc.desc: Test init network, result is fail.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestInitNetWork002, TestSize.Level1)
{
    int ret = InitNetworkServerInfo();
    EXPECT_TRUE(ret == DEVATTEST_FAIL);
    ReleaseList(&g_attestNetworkList);
}

/*
 * @tc.name: TestGetAuthStatus001
 * @tc.desc: Test get authStatus.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGetAuthStatus001, TestSize.Level1)
{
    int32_t ret = FlushAuthResult(ATTEST_MOCK_HAL_TICKET, ATTEST_MOCK_HAL_STATUS);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
    char *status = nullptr;
    ret = GetAuthStatus(&status);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
    EXPECT_TRUE((status != nullptr));
    if (status == nullptr) {
        return;
    }
    EXPECT_STREQ(ATTEST_MOCK_HAL_STATUS, status);
    free(status);
}

/*
 * @tc.name: TestDecodeAuthStatus001
 * @tc.desc: Test decode auth status.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestDecodeAuthStatus001, TestSize.Level1)
{
    char *status = nullptr;
    int32_t ret = GetAuthStatus(&status);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
    AuthStatus* outStatus = CreateAuthStatus();
    EXPECT_TRUE((outStatus != nullptr));
    if (outStatus == nullptr) {
        return;
    }
    ret = DecodeAuthStatus(status, outStatus);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    SoftwareResultDetail* detail = outStatus->softwareResultDetail;
    EXPECT_TRUE((outStatus->versionId != nullptr) && (outStatus->authType != nullptr) && (detail != nullptr));
    if ((outStatus->versionId == nullptr) || (outStatus->authType == nullptr) || (detail == nullptr)) {
        DestroyAuthStatus(&outStatus);
        return;
    }
    EXPECT_TRUE(outStatus->hardwareResult == ATTEST_HARDWARE_RESULT);
    EXPECT_STREQ(outStatus->authType, ATTEST_AUTH_TYPE);
    EXPECT_TRUE(outStatus->expireTime == ATTEST_EXPIRE_TIME);
    EXPECT_STREQ(outStatus->versionId, ATTEST_VERSION_ID);
    EXPECT_TRUE(outStatus->softwareResult == ATTEST_SOFTWARE_RESULT);
    DestroyAuthStatus(&outStatus);
}

/*
 * @tc.name: TestCheckExpireTime001
 * @tc.desc: Test check expire time.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestCheckExpireTime001, TestSize.Level1)
{
    AuthStatus* outStatus = CreateAuthStatus();
    EXPECT_TRUE(outStatus != nullptr);
    if (outStatus == nullptr) {
        return;
    }
    outStatus->expireTime = 19673222;
    uint64_t currentTime = 19673223;
    int32_t ret = CheckExpireTime(outStatus, currentTime);
    EXPECT_TRUE(ret != DEVATTEST_SUCCESS);
    outStatus->expireTime = 19673222;
    currentTime = 19673221;
    ret = CheckExpireTime(outStatus, currentTime);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    free(outStatus);
}

/*
 * @tc.name: TestCheckAuthResult001
 * @tc.desc: Test check auth result.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestCheckAuthResult001, TestSize.Level1)
{
    AuthStatus* outStatus = CreateAuthStatus();
    EXPECT_TRUE(outStatus != nullptr);
    if (outStatus == nullptr) {
        return;
    }
    outStatus->hardwareResult = 1;
    outStatus->softwareResult = 0;
    int32_t ret = CheckAuthResult(outStatus);
    EXPECT_TRUE(ret != DEVATTEST_SUCCESS);
    outStatus->hardwareResult = 0;
    ret = CheckAuthResult(outStatus);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    free(outStatus);
}

static AuthResult *GetAuthResult()
{
    AuthResult *authResult = CreateAuthResult();
    if (authResult == nullptr) {
        return nullptr;
    }
    int32_t ret = ParseAuthResultResp(ATTEST_AUTH_EXPECT_RESULT, authResult);
    if (ret != DEVATTEST_SUCCESS) {
        DestroyAuthResult(&authResult);
        return nullptr;
    }
    return authResult;
}

static DevicePacket* TddGenMsg(int input)
{
    DevicePacket* reqMsg = nullptr;
    int32_t ret = DEVATTEST_SUCCESS;
    ChallengeResult challenge;
    do {
        if (input == ATTEST_CASE_RESET) {
            challenge.challenge = (char*)ATTEST_RESET_CHAP;
            challenge.currentTime = ATTEST_RESET_CHAP_TIME;
            ret = GenResetMsg(&challenge, &reqMsg);
            break;
        }
        if (input == ATTEST_CASE_AUTH) {
            challenge.challenge = (char*)ATTEST_AUTH_CHAP;
            challenge.currentTime = ATTEST_AUTH_CHAP_TIME;
            ret = GenAuthMsg(&challenge, &reqMsg);
            break;
        }
        if (input == ATTEST_CASE_ACTIVE) {
            challenge.challenge = (char*)ATTEST_ACTIVE_CHAP;
            challenge.currentTime = ATTEST_ACTIVE_CHAP_TIME;
            AuthResult *authResult = GetAuthResult();
            ret = GenActiveMsg(authResult, &challenge, &reqMsg);
            break;
        }
    } while (0);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    if (ret != DEVATTEST_SUCCESS) {
        FREE_DEVICE_PACKET(reqMsg);
        return nullptr;
    }
    return reqMsg;
}

/*
 * @tc.name: TestGenResetMsg001
 * @tc.desc: Test gen reset msg with stored token.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenResetMsg001, TestSize.Level1)
{
    AttestSetMockReadTokenRet(ATTEST_OK);
    // 初始化参数
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);

    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_RESET);
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == nullptr) {
        DestroySysData();
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == nullptr) {
        FREE_DEVICE_PACKET(reqMsg);
        DestroySysData();
        return;
    }
    EXPECT_TRUE(strcmp(ATTEST_RESET_GEN_TOKEN, outToken) == 0);
    FREE_DEVICE_PACKET(reqMsg);
    // 恢复环境
    DestroySysData();
}

/*
 * @tc.name: TestGenResetMsg002
 * @tc.desc: Test gen reset msg without token.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenResetMsg002, TestSize.Level1)
{
    AttestSetMockReadTokenRet(TOKEN_UNPRESET);
    // 初始化参数
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);

    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_RESET);
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == nullptr) {
        DestroySysData();
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == nullptr) {
        FREE_DEVICE_PACKET(reqMsg);
        DestroySysData();
        return;
    }
#if defined(__ATTEST_ENABLE_PRESET_TOKEN__)
    EXPECT_TRUE(strcmp(ATTEST_RESET_GEN_ONLINE_TOKEN, outToken) == 0);

    outToken = reqMsg->tokenInfo.uuid;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == nullptr) {
        FREE_DEVICE_PACKET(reqMsg);
        DestroySysData();
        return;
    }
    EXPECT_TRUE(strcmp(ATTEST_RESET_GEN_ONLINE_TOKEN_ID, outToken) == 0);
#else
    EXPECT_TRUE(strcmp(ATTEST_RESET_GEN_PRODUCT_TOKEN, outToken) == 0);
#endif
    FREE_DEVICE_PACKET(reqMsg);
    // 恢复环境
    DestroySysData();
}

/*
 * @tc.name: TestParseResetResult001
 * @tc.desc: Test parse reset result，result is ok.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseResetResult001, TestSize.Level1)
{
    string input = "{\"errcode\":0}";
    int32_t ret = ParseResetResult(input.c_str());
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    input = "{\"errcode\":\"-32s\"}";
    ret = ParseResetResult(input.c_str());
    EXPECT_TRUE((ret != DEVATTEST_SUCCESS));
}

/*
 * @tc.name: TestGenAuthMsg001
 * @tc.desc: Test gen auth msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenAuthMsg001, TestSize.Level1)
{
    AttestSetMockReadTokenRet(ATTEST_OK);
    // 初始化参数
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);

    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_AUTH);
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == nullptr) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == nullptr) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
    EXPECT_TRUE(strcmp(outToken, ATTEST_AUTH_GEN_TOKEN) == 0);
    FREE_DEVICE_PACKET(reqMsg);
    // 恢复环境
    DestroySysData();
}

/*
 * @tc.name: TestGenAuthMsg002
 * @tc.desc: Test gen auth msg without token.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenAuthMsg002, TestSize.Level1)
{
    AttestSetMockReadTokenRet(TOKEN_UNPRESET);
    // 初始化参数
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);

    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_AUTH);
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == nullptr) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == nullptr) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
#if defined(__ATTEST_ENABLE_PRESET_TOKEN__)
    EXPECT_TRUE(strcmp(ATTEST_AUTH_GEN_ONLINE_TOKEN, outToken) == 0);
#else
    EXPECT_TRUE(strcmp(ATTEST_AUTH_GEN_PRODUCT_TOKEN, outToken) == 0);
#endif
    FREE_DEVICE_PACKET(reqMsg);
    // 恢复环境
    DestroySysData();
}

/*
 * @tc.name: TestParseAuthResultResp001
 * @tc.desc: Test parse auth result resp.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseAuthResultResp001, TestSize.Level1)
{
    AuthResult *authResult = GetAuthResult();
    EXPECT_TRUE(authResult != nullptr);
    if (authResult == nullptr) {
        return;
    }
    EXPECT_TRUE((authResult->ticket != nullptr) && (authResult->tokenValue != nullptr) &&
        (authResult->authStatus != nullptr));
    if (authResult->ticket != nullptr) {
        EXPECT_TRUE(strcmp(authResult->ticket, ATTEST_MOCK_HAL_TICKET) == 0);
    }
    DestroyAuthResult(&authResult);
}

/*
 * @tc.name: TestGenActiveMsg001
 * @tc.desc: Test gen active msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenActiveMsg001, TestSize.Level1)
{
    AttestSetMockReadTokenRet(ATTEST_OK);
    // 初始化参数
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);

    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_ACTIVE);
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == nullptr) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == nullptr) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
    EXPECT_TRUE(strcmp(outToken, ATTEST_ACTIVE_GEN_TOKEN) == 0);
    FREE_DEVICE_PACKET(reqMsg);
    // 恢复环境
    DestroySysData();
}

/*
 * @tc.name: TestGenActiveMsg002
 * @tc.desc: Test gen auth msg without token.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenActiveMsg002, TestSize.Level1)
{
    AttestSetMockReadTokenRet(TOKEN_UNPRESET);
    // 初始化参数
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);

    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_ACTIVE);
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == nullptr) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == nullptr) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
#if defined(__ATTEST_ENABLE_PRESET_TOKEN__)
    EXPECT_TRUE(strcmp(ATTEST_ACTIVE_GEN_ONLINE_TOKEN, outToken) == 0);
#else
    EXPECT_TRUE(strcmp(ATTEST_ACTIVE_GEN_PRODUCT_TOKEN, outToken) == 0);
#endif
    FREE_DEVICE_PACKET(reqMsg);
    // 恢复环境
    DestroySysData();
}

/*
 * @tc.name: TestParseActiveResult001
 * @tc.desc: Test parse active result，result is ok.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseActiveResult001, TestSize.Level1)
{
    string input = "{\"errcode\":0}";
    int32_t ret = ParseActiveResult(input.c_str());
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    input = "{\"errcode\":\"-32s\"}";
    ret = ParseActiveResult(input.c_str());
    EXPECT_TRUE((ret != DEVATTEST_SUCCESS));
}

/*
 * @tc.name: TestGetChallenge001
 * @tc.desc: Test get reset challenge.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGetChallenge001, TestSize.Level1)
{
    // 初始化环境
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    (void)InitNetworkServerInfo();
    (void)D2CConnect();

    g_netType = ATTEST_GET_CHANLLEGE;
    ChallengeResult* challenge = nullptr;
    ret = GetChallenge(&challenge, ATTEST_ACTION_RESET);
    EXPECT_TRUE(ret == ATTEST_OK);
    EXPECT_TRUE(challenge != nullptr);
    if (ret == ATTEST_OK && challenge != nullptr) {
        EXPECT_TRUE(strcmp(ATTEST_RESET_EXPECT_CHAP, challenge->challenge) == 0);
        FREE_CHALLENGE_RESULT(challenge);
    }
    // 恢复环境
    DestroySysData();
    EXPECT_TRUE(StrdupDevInfo(VERSION_ID) == nullptr);
}

/*
 * @tc.name: TestSendResetMsg001
 * @tc.desc: Test send reset msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestSendResetMsg001, TestSize.Level1)
{
    // 初始化环境
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    (void)InitNetworkServerInfo();
    (void)D2CConnect();

    g_netType = ATTEST_RESET;
    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_RESET);
    if (reqMsg == nullptr) {
        return;
    }
    char* respMsg = nullptr;
    ret = SendResetMsg(reqMsg, &respMsg);
    EXPECT_TRUE((ret == ATTEST_OK) && (respMsg != nullptr));
    FREE_DEVICE_PACKET(reqMsg);
    if ((ret == ATTEST_OK) && (respMsg != nullptr)) {
        EXPECT_TRUE(strstr(respMsg, ATTEST_REST_ERROR_EXPECT_RESULT) != nullptr);
        free(respMsg);
    }
    // 恢复环境
    DestroySysData();
    EXPECT_TRUE(StrdupDevInfo(VERSION_ID) == nullptr);
}

/*
 * @tc.name: TestSendActiveMsg001
 * @tc.desc: Test send active msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestSendActiveMsg001, TestSize.Level1)
{
    // 初始化环境
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);

    (void)InitNetworkServerInfo();
    (void)D2CConnect();

    g_netType = ATTEST_ACTIVE;
    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_ACTIVE);
    ASSERT_TRUE(reqMsg != nullptr);

    char* respMsg = nullptr;
    ret = SendActiveMsg(reqMsg, &respMsg);
    EXPECT_TRUE((ret == ATTEST_OK) && (respMsg != nullptr));
    FREE_DEVICE_PACKET(reqMsg);
    if ((ret == ATTEST_OK) && (respMsg != nullptr)) {
        const char* ATTEST_ACTIVE_EXPECT_RESULT = "{\"errcode\":0}";
        EXPECT_TRUE(strcmp(ATTEST_ACTIVE_EXPECT_RESULT, respMsg) == 0);
        free(respMsg);
    }
    // 恢复环境
    DestroySysData();
    EXPECT_TRUE(StrdupDevInfo(VERSION_ID) == nullptr);
}

/*
 * @tc.name: TestQueryAttestStatus001
 * @tc.desc: Test query attest status.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestQueryAttestStatus001, TestSize.Level1)
{
    AuthResult *authResult = GetAuthResult();
    if (authResult == nullptr) {
        return;
    }
    int32_t ret = FlushToken(authResult);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
    uint8_t authResultCode = ATTEST_RESULT_CODE;
    AttestWriteAuthResultCode((char*)&authResultCode, 1);
    AttestResultInfo attestResultInfo = { .softwareResultDetail = {-2, -2, -2, -2, -2} };
    attestResultInfo.ticket = nullptr;
    ret = EntryGetAttestStatus(&attestResultInfo);
    EXPECT_TRUE((ret == ATTEST_OK) && (attestResultInfo.authResult == ATTEST_OK));
    EXPECT_TRUE((attestResultInfo.ticket != nullptr));
    if (attestResultInfo.ticket == nullptr) {
        return;
    }
    EXPECT_TRUE(strcmp(attestResultInfo.ticket, ATTEST_MOCK_HAL_TICKET) == 0);
}
}
}