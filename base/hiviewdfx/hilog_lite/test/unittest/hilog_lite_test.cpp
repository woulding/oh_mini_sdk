/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "hilog_lite_test.h"

#include <cstdlib>
#include <malloc.h>

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace ACELite {
constexpr int32_t RET_OK = 0;
constexpr int32_t RET_SIZE = 0;
constexpr int32_t VECTOR_SIZE = 1;
constexpr size_t STRING_SIZE = 1;
constexpr size_t ARG_NUMBER = 3;
constexpr size_t ARG_NUMBER_ZERO = 0;
constexpr size_t ARG_NUMBER_ONE = 1;
constexpr size_t ARG_NUMBER_TWO = 2;
constexpr int32_t LOG_LEVEL_INVALID = 2;
constexpr int32_t LOG_LEVEL_DEBUG = 3;
constexpr int32_t LOG_LEVEL_INFO = 4;
constexpr int32_t LOG_LEVEL_WARN = 5;
constexpr int32_t LOG_LEVEL_ERROR = 6;
constexpr int32_t LOG_LEVEL_FATAL = 7;
constexpr int32_t LOG_ARG_NUMBER = 0;
constexpr size_t RELLOC_SIZE = 10;
const char RELLOC_STRING[] = "123456789";
const char PARSE_LOG_CASE_S[] = "TEST%{public}s";
const char PARSE_LOG_CASE_S_FINAL_VALUE[] = "TEST1";
const char PARSE_LOG_CASE_D[] = "TEST%{public}d";
const char PARSE_LOG_CASE_D_FINAL_VALUE[] = "TEST1";
const char PARSE_LOG_CASE_O1[] = "TEST%{public}O";
const char PARSE_LOG_CASE_O1_FINAL_VALUE[] = "TEST1";
const char PARSE_LOG_CASE_O2[] = "TEST%{public}o";
const char PARSE_LOG_CASE_O2_FINAL_VALUE[] = "TEST1";
const char PARSE_LOG_CASE_I[] = "TEST%{public}i";
const char PARSE_LOG_CASE_I_FINAL_VALUE[] = "TEST1";
const char PARSE_LOG_CASE_C[] = "TEST%{public}c";
const char PARSE_LOG_CASE_PRIVATE[] = "TEST%{private}s";
const char PARSE_LOG_CASE_PRIVATE_FINAL_VALUE[] = "TEST<private>";
const char PARSE_LOG_CASE_NONE[] = "TEST%s";
const char PARSE_LOG_CASE_NONE_FINAL_VALUE[] = "TEST<private>";
const char FMT_STRING[] = "TEST";
const char PARSE_LOG_CONTENT[] = "1";
const char HILOG_THIS_VAL[] = "1";
const char HILOG_CONTENT[] = "log";
const char HILOG_CONTENT_LENGTH_STRING[] = "l";
const char HILOG_CONTENT_LENGTH[] = "l";
const char ERROR_ARG[] = "";
const char TEST_CHAR = 'A';

// SetUpTestCase
void HilogLiteTest::SetUpTestCase(void) {}

// TearDownTestCase
void HilogLiteTest::TearDownTestCase(void) {}

void HilogLiteTest::SetUp(void) {}

// Tear down
void HilogLiteTest::TearDown(void) {}

/**
 * @tc.name: Hilog_Lite_ParseLogContent_001
 * @tc.desc: Call ParseLogContent with %{public}s to parse logs.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_ParseLogContent_001, Level1)
{
    const char *fmtString = PARSE_LOG_CASE_S;
    const char *finalValue = PARSE_LOG_CASE_S_FINAL_VALUE;
    ACELite::HilogString fmtStringBuffer;
    ACELite::HilogVector params;
    ACELite::HilogString logContent;

    ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    ACELite::HilogVector::Push(&params, PARSE_LOG_CONTENT, ACELite::STRING_TYPE);

    ACELite::HilogModule::ParseLogContent(&fmtStringBuffer, &params, &logContent);
    EXPECT_TRUE(strcmp(logContent.str, finalValue) == RET_OK);
}

/**
 * @tc.name: Hilog_Lite_ParseLogContent_003
 * @tc.desc: Call ParseLogContent with %{public}d to parse logs.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_ParseLogContent_003, Level1)
{
    const char *fmtString = PARSE_LOG_CASE_D;
    const char *finalValue = PARSE_LOG_CASE_D_FINAL_VALUE;
    ACELite::HilogString fmtStringBuffer;
    ACELite::HilogVector params;
    ACELite::HilogString logContent;

    ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    ACELite::HilogVector::Push(&params, PARSE_LOG_CONTENT, ACELite::INT_TYPE);

    ACELite::HilogModule::ParseLogContent(&fmtStringBuffer, &params, &logContent);
    EXPECT_TRUE(strcmp(logContent.str, finalValue) == RET_OK);
}

/**
 * @tc.name: Hilog_Lite_ParseLogContent_004
 * @tc.desc: Call ParseLogContent with %{public}O to parse logs.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_ParseLogContent_004, Level1)
{
    const char *fmtString = PARSE_LOG_CASE_O1;
    const char *finalValue = PARSE_LOG_CASE_O1_FINAL_VALUE;
    ACELite::HilogString fmtStringBuffer;
    ACELite::HilogVector params;
    ACELite::HilogString logContent;

    ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    ACELite::HilogVector::Push(&params, PARSE_LOG_CONTENT, ACELite::OBJECT_TYPE);

    ACELite::HilogModule::ParseLogContent(&fmtStringBuffer, &params, &logContent);
    EXPECT_TRUE(strcmp(logContent.str, finalValue) == RET_OK);
}

/**
 * @tc.name: Hilog_Lite_ParseLogContent_005
 * @tc.desc: Call ParseLogContent with %{public}o to parse logs.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_ParseLogContent_005, Level1)
{
    const char *fmtString = PARSE_LOG_CASE_O2;
    const char *finalValue = PARSE_LOG_CASE_O2_FINAL_VALUE;
    ACELite::HilogString fmtStringBuffer;
    ACELite::HilogVector params;
    ACELite::HilogString logContent;

    ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    ACELite::HilogVector::Push(&params, PARSE_LOG_CONTENT, ACELite::OBJECT_TYPE);

    ACELite::HilogModule::ParseLogContent(&fmtStringBuffer, &params, &logContent);
    EXPECT_TRUE(strcmp(logContent.str, finalValue) == RET_OK);
}

/**
 * @tc.name: Hilog_Lite_ParseLogContent_006
 * @tc.desc: Call ParseLogContent with %{public}i to parse logs.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_ParseLogContent_006, Level1)
{
    const char *fmtString = PARSE_LOG_CASE_I;
    const char *finalValue = PARSE_LOG_CASE_I_FINAL_VALUE;
    ACELite::HilogString fmtStringBuffer;
    ACELite::HilogVector params;
    ACELite::HilogString logContent;

    ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    ACELite::HilogVector::Push(&params, PARSE_LOG_CONTENT, ACELite::INT_TYPE);

    ACELite::HilogModule::ParseLogContent(&fmtStringBuffer, &params, &logContent);
    EXPECT_TRUE(strcmp(logContent.str, finalValue) == RET_OK);
}

/**
 * @tc.name: Hilog_Lite_ParseLogContent_007
 * @tc.desc: Call ParseLogContent with %{private}s to parse logs.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_ParseLogContent_007, Level1)
{
    const char *fmtString = PARSE_LOG_CASE_PRIVATE;
    const char *finalValue = PARSE_LOG_CASE_PRIVATE_FINAL_VALUE;
    ACELite::HilogString fmtStringBuffer;
    ACELite::HilogVector params;
    ACELite::HilogString logContent;

    ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    ACELite::HilogVector::Push(&params, PARSE_LOG_CONTENT, ACELite::STRING_TYPE);

    ACELite::HilogModule::ParseLogContent(&fmtStringBuffer, &params, &logContent);
    EXPECT_TRUE(strcmp(logContent.str, finalValue) == RET_OK);
}

/**
 * @tc.name: Hilog_Lite_ParseLogContent_008
 * @tc.desc: Call ParseLogContent with %{private}s to parse logs.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_ParseLogContent_008, Level1)
{
    const char *fmtString = PARSE_LOG_CASE_NONE;
    const char *finalValue = PARSE_LOG_CASE_NONE_FINAL_VALUE;
    ACELite::HilogString fmtStringBuffer;
    ACELite::HilogVector params;
    ACELite::HilogString logContent;

    ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    ACELite::HilogVector::Push(&params, PARSE_LOG_CONTENT, ACELite::STRING_TYPE);

    ACELite::HilogModule::ParseLogContent(&fmtStringBuffer, &params, &logContent);
    EXPECT_TRUE(strcmp(logContent.str, finalValue) == RET_OK);
}

/**
 * @tc.name: Hilog_Lite_Debug_001
 * @tc.desc: Call Debug.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_Debug_001, Level1)
{
    ACELite::JSIValue undefValue = ACELite::JSI::CreateUndefined();
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args = ACELite::JSI::CreateString(HILOG_CONTENT);
    ACELite::JSIValue resultValue = ACELite::HilogModule::Debug(thisVal, &args, LOG_ARG_NUMBER);
    EXPECT_TRUE(resultValue == undefValue);
}

/**
 * @tc.name: Hilog_Lite_Info_001
 * @tc.desc: Call Info.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_Info_001, Level1)
{
    ACELite::JSIValue undefValue = ACELite::JSI::CreateUndefined();
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args = ACELite::JSI::CreateString(HILOG_CONTENT);
    ACELite::JSIValue resultValue = ACELite::HilogModule::Info(thisVal, &args, LOG_ARG_NUMBER);
    EXPECT_TRUE(resultValue == undefValue);
}

/**
 * @tc.name: Hilog_Lite_Error_001
 * @tc.desc: Call Error.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_Error_001, Level1)
{
    ACELite::JSIValue undefValue = ACELite::JSI::CreateUndefined();
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args = ACELite::JSI::CreateString(HILOG_CONTENT);
    ACELite::JSIValue resultValue = ACELite::HilogModule::Error(thisVal, &args, LOG_ARG_NUMBER);
    EXPECT_TRUE(resultValue == undefValue);
}

/**
 * @tc.name: Hilog_Lite_Warn_001
 * @tc.desc: Call Warn.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_Warn_001, Level1)
{
    ACELite::JSIValue undefValue = ACELite::JSI::CreateUndefined();
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args = ACELite::JSI::CreateString(HILOG_CONTENT);
    ACELite::JSIValue resultValue = ACELite::HilogModule::Warn(thisVal, &args, LOG_ARG_NUMBER);
    EXPECT_TRUE(resultValue == undefValue);
}

/**
 * @tc.name: Hilog_Lite_Fatal_001
 * @tc.desc: Call Fatal.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_Fatal_001, Level1)
{
    ACELite::JSIValue undefValue = ACELite::JSI::CreateUndefined();
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args = ACELite::JSI::CreateString(HILOG_CONTENT);
    ACELite::JSIValue resultValue = ACELite::HilogModule::Fatal(thisVal, &args, LOG_ARG_NUMBER);
    EXPECT_TRUE(resultValue == undefValue);
}

/**
 * @tc.name: Hilog_Lite_IsLoggable_001
 * @tc.desc: Call IsLoggable with DEBUG level.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_IsLoggable_001, Level1)
{
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args[ARG_NUMBER];
    args[ARG_NUMBER_ZERO] = ACELite::JSI::CreateNumber(STRING_SIZE);
    args[ARG_NUMBER_ONE] = ACELite::JSI::CreateString(HILOG_CONTENT);
    args[ARG_NUMBER_TWO] = ACELite::JSI::CreateNumber(LOG_LEVEL_DEBUG);
    ACELite::JSIValue resultValue = ACELite::HilogModule::IsLoggable(thisVal, args, ARG_NUMBER);
    EXPECT_TRUE(ACELite::JSI::ValueToBoolean(resultValue) == true);
}

/**
 * @tc.name: Hilog_Lite_IsLoggable_002
 * @tc.desc: Call IsLoggable with INFO level.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_IsLoggable_002, Level1)
{
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args[ARG_NUMBER];
    args[ARG_NUMBER_ZERO] = ACELite::JSI::CreateNumber(STRING_SIZE);
    args[ARG_NUMBER_ONE] = ACELite::JSI::CreateString(HILOG_CONTENT);
    args[ARG_NUMBER_TWO] = ACELite::JSI::CreateNumber(LOG_LEVEL_INFO);
    ACELite::JSIValue resultValue = ACELite::HilogModule::IsLoggable(thisVal, args, ARG_NUMBER);
    EXPECT_TRUE(ACELite::JSI::ValueToBoolean(resultValue) == true);
}

/**
 * @tc.name: Hilog_Lite_IsLoggable_003
 * @tc.desc: Call IsLoggable with WARN level.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_IsLoggable_003, Level1)
{
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args[ARG_NUMBER];
    args[ARG_NUMBER_ZERO] = ACELite::JSI::CreateNumber(STRING_SIZE);
    args[ARG_NUMBER_ONE] = ACELite::JSI::CreateString(HILOG_CONTENT);
    args[ARG_NUMBER_TWO] = ACELite::JSI::CreateNumber(LOG_LEVEL_WARN);
    ACELite::JSIValue resultValue = ACELite::HilogModule::IsLoggable(thisVal, args, ARG_NUMBER);
    EXPECT_TRUE(ACELite::JSI::ValueToBoolean(resultValue) == true);
}

/**
 * @tc.name: Hilog_Lite_IsLoggable_004
 * @tc.desc: Call IsLoggable with ERROR level.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_IsLoggable_004, Level1)
{
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args[ARG_NUMBER];
    args[ARG_NUMBER_ZERO] = ACELite::JSI::CreateNumber(STRING_SIZE);
    args[ARG_NUMBER_ONE] = ACELite::JSI::CreateString(HILOG_CONTENT);
    args[ARG_NUMBER_TWO] = ACELite::JSI::CreateNumber(LOG_LEVEL_ERROR);
    ACELite::JSIValue resultValue = ACELite::HilogModule::IsLoggable(thisVal, args, ARG_NUMBER);
    EXPECT_TRUE(ACELite::JSI::ValueToBoolean(resultValue) == true);
}

/**
 * @tc.name: Hilog_Lite_IsLoggable_005
 * @tc.desc: Call IsLoggable with FATAL level.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_IsLoggable_005, Level1)
{
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args[ARG_NUMBER];
    args[ARG_NUMBER_ZERO] = ACELite::JSI::CreateNumber(STRING_SIZE);
    args[ARG_NUMBER_ONE] = ACELite::JSI::CreateString(HILOG_CONTENT);
    args[ARG_NUMBER_TWO] = ACELite::JSI::CreateNumber(LOG_LEVEL_FATAL);
    ACELite::JSIValue resultValue = ACELite::HilogModule::IsLoggable(thisVal, args, ARG_NUMBER);
    EXPECT_TRUE(ACELite::JSI::ValueToBoolean(resultValue) == true);
}

/**
 * @tc.name: Hilog_Lite_IsLoggable_006
 * @tc.desc: Call IsLoggable with invalid level.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_IsLoggable_006, Level1)
{
    ACELite::JSIValue thisVal = ACELite::JSI::CreateString(HILOG_THIS_VAL);
    ACELite::JSIValue args[ARG_NUMBER];
    args[ARG_NUMBER_ZERO] = ACELite::JSI::CreateNumber(STRING_SIZE);
    args[ARG_NUMBER_ONE] = ACELite::JSI::CreateString(HILOG_CONTENT);
    args[ARG_NUMBER_TWO] = ACELite::JSI::CreateNumber(LOG_LEVEL_INVALID);
    ACELite::JSIValue resultValue = ACELite::HilogModule::IsLoggable(thisVal, args, ARG_NUMBER);
    EXPECT_TRUE(ACELite::JSI::ValueToBoolean(resultValue) == false);
}

/**
 * @tc.name: Hilog_Lite_HilogString_Puts_001
 * @tc.desc: Call Puts with default length value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Puts_001, Level1)
{
    const char *fmtString = PARSE_LOG_CASE_C;
    const char *finalValue = PARSE_LOG_CASE_C;
    ACELite::HilogString fmtStringBuffer;

    size_t resultValue = ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    EXPECT_TRUE(strcmp(fmtStringBuffer.str, finalValue) == RET_OK);
    EXPECT_TRUE(resultValue == strlen(fmtString));
}

/**
 * @tc.name: Hilog_Lite_HilogString_Puts_002
 * @tc.desc: Call Puts with a length value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Puts_002, Level1)
{
    const char *fmtString = HILOG_CONTENT;
    const char *finalValue = HILOG_CONTENT_LENGTH_STRING;
    ACELite::HilogString fmtStringBuffer;

    size_t resultValue = ACELite::HilogString::Puts(fmtString, &fmtStringBuffer, STRING_SIZE);
    EXPECT_TRUE(strcmp(fmtStringBuffer.str, finalValue) == RET_OK);
    EXPECT_TRUE(resultValue == strlen(finalValue));
}

/**
 * @tc.name: Hilog_Lite_HilogString_Puts_003
 * @tc.desc: Call Puts with invalid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Puts_003, Level1)
{
    const char *fmtString = ERROR_ARG;
    ACELite::HilogString fmtStringBuffer;

    size_t resultValue = ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    EXPECT_TRUE(resultValue == strlen(fmtString));
}

/**
 * @tc.name: Hilog_Lite_HilogString_Puts_004
 * @tc.desc: Call Puts with null.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Puts_004, Level1)
{
    char *fmtString = nullptr;
    ACELite::HilogString fmtStringBuffer;

    size_t resultValue = ACELite::HilogString::Puts(fmtString, &fmtStringBuffer);
    EXPECT_TRUE(resultValue == RET_SIZE);
}

/**
 * @tc.name: Hilog_Lite_HilogString_Get_001
 * @tc.desc: Call Get.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Get_001, Level1)
{
    ACELite::HilogString fmtStringBuffer;

    char *resultValue = ACELite::HilogString::Get(&fmtStringBuffer);
    EXPECT_TRUE(resultValue == nullptr);
}

/**
 * @tc.name: Hilog_Lite_HilogString_Get_002
 * @tc.desc: Call Get with null.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Get_002, Level1)
{
    char *resultValue = ACELite::HilogString::Get(nullptr);
    EXPECT_TRUE(resultValue == nullptr);
}

/**
 * @tc.name: Hilog_Lite_HilogString_Length_001
 * @tc.desc: Call Length.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Length_001, Level1)
{
    ACELite::HilogString fmtStringBuffer;

    size_t resultValue = ACELite::HilogString::Length(&fmtStringBuffer);
    EXPECT_TRUE(resultValue == RET_SIZE);
}

/**
 * @tc.name: Hilog_Lite_HilogString_Length_002
 * @tc.desc: Call Length with null.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Length_002, Level1)
{
    size_t resultValue = ACELite::HilogString::Length(nullptr);
    EXPECT_TRUE(resultValue == RET_SIZE);
}

/**
 * @tc.name: Hilog_Lite_HilogString_Putc_001
 * @tc.desc: Call Putc.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Putc_001, Level1)
{
    ACELite::HilogString fmtStringBuffer;

    ACELite::HilogString::Putc(TEST_CHAR, &fmtStringBuffer);
    EXPECT_TRUE(fmtStringBuffer.str[LOG_ARG_NUMBER] == TEST_CHAR);
}

/**
 * @tc.name: Hilog_Lite_HilogString_Putc_002
 * @tc.desc: Call Putc.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogString_Putc_002, Level1)
{
    ACELite::HilogString fmtStringBuffer;
    char rChar = EOF;

    char resultValue = ACELite::HilogString::Putc('0', nullptr);
    EXPECT_TRUE(resultValue == rChar);
}

/**
 * @tc.name: Hilog_Lite_HilogVector_Push_001
 * @tc.desc: Call Push with valid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogVector_Push_001, Level1)
{
    ACELite::HilogVector params;

    ACELite::HilogVector::Push(&params, PARSE_LOG_CONTENT, ACELite::STRING_TYPE);
    EXPECT_TRUE(params.size == VECTOR_SIZE);
    EXPECT_TRUE(strcmp(params.str[params.size - VECTOR_SIZE], PARSE_LOG_CONTENT) == RET_OK);
}

/**
 * @tc.name: Hilog_Lite_HilogVector_Push_002
 * @tc.desc: Call Push with invalid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogVector_Push_002, Level1)
{
    ACELite::HilogVector params;

    ACELite::HilogVector::Push(&params, ERROR_ARG, ACELite::STRING_TYPE);
    EXPECT_TRUE(params.size == VECTOR_SIZE);
    EXPECT_TRUE(strcmp(params.str[params.size - VECTOR_SIZE], ERROR_ARG) == RET_OK);
}

/**
 * @tc.name: Hilog_Lite_HilogVector_Push_003
 * @tc.desc: Call Push with null value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogVector_Push_003, Level1)
{
    ACELite::HilogVector params;

    ACELite::HilogVector::Push(&params, nullptr, ACELite::STRING_TYPE);
    EXPECT_TRUE(params.size == RET_SIZE);
}

/**
 * @tc.name: Hilog_Lite_HilogVector_Size_001
 * @tc.desc: Call Size with valid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogVectorSize_001, Level1)
{
    ACELite::HilogVector params;

    size_t result = ACELite::HilogVector::Size(&params);
    EXPECT_TRUE(result == RET_SIZE);
}

/**
 * @tc.name: Hilog_Lite_HilogVector_Size_002
 * @tc.desc: Call Size with nullptr value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogVectorSize_002, Level1)
{
    ACELite::HilogVector params;

    size_t result = ACELite::HilogVector::Size(nullptr);
    EXPECT_TRUE(result == RET_SIZE);
}

/**
 * @tc.name: Hilog_Lite_HilogVector_GetStr_001
 * @tc.desc: Call GetStr with valid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogVectorGetStr_001, Level1)
{
    ACELite::HilogVector params;

    char *result = ACELite::HilogVector::GetStr(&params, RET_SIZE);
    EXPECT_TRUE(result == nullptr);
}

/**
 * @tc.name: Hilog_Lite_HilogVector_GetStr_002
 * @tc.desc: Call GetStr with valid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogVectorGetStr_002, Level1)
{
    ACELite::HilogVector params;

    char *result = ACELite::HilogVector::GetStr(&params, 0);
    EXPECT_TRUE(result == nullptr);
}

/**
 * @tc.name: Hilog_Lite_HilogRealloc_Realloc_001
 * @tc.desc: Call Realloc with invalid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogRealloc_Realloc_001, Level1)
{
    void *result = ACELite::HilogRealloc::Realloc(nullptr, 0, 0);
    EXPECT_TRUE(result == nullptr);
}

/**
 * @tc.name: Hilog_Lite_HilogRealloc_Realloc_002
 * @tc.desc: Call Realloc with invalid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogRealloc_Realloc_002, Level1)
{
    char *ptr = static_cast<char*>(malloc(1));
    ASSERT_NE(ptr, nullptr);
    char *result = static_cast<char*>(ACELite::HilogRealloc::Realloc(ptr, 0, 0));
    free(ptr);
    EXPECT_TRUE(result == nullptr);
}

/**
 * @tc.name: Hilog_Lite_HilogRealloc_Realloc_003
 * @tc.desc: Call Realloc with valid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogRealloc_Realloc_003, Level1)
{
    char *ptr = const_cast<char*>(RELLOC_STRING);
    ASSERT_NE(ptr, nullptr);
    char *result = static_cast<char*>(ACELite::HilogRealloc::Realloc(ptr, 1, RELLOC_SIZE));
    EXPECT_TRUE(strlen(result) == RELLOC_SIZE - 1);
}

/**
 * @tc.name: Hilog_Lite_HilogRealloc_Realloc_004
 * @tc.desc: Call Realloc with valid value.
 * @tc.type: FUNC
 * @tc.require: I5NCYY
 * @tc.author: Wutm
 */
HWTEST_F(HilogLiteTest, Test_HilogRealloc_Realloc_004, Level1)
{
    char *ptr = static_cast<char*>(malloc(RELLOC_SIZE - 1));
    ASSERT_NE(ptr, nullptr);
    size_t size = malloc_usable_size(ptr);
    char *result = static_cast<char*>(ACELite::HilogRealloc::Realloc(ptr, RELLOC_SIZE, RELLOC_SIZE - 1));
    free(result);
    EXPECT_TRUE(malloc_usable_size(result) >= RELLOC_SIZE);
    EXPECT_TRUE(malloc_usable_size(result) >= size);
}
}  // namespace ACELite
}  // namespace OHOS
