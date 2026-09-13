/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "nstackx_dfinder_hievent.h"
#include "nstackx_getopt.h"
#include "nstackx_event.h"

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"

static int g_eventCnt = 0;
static void TestDFinderEventFuncCb(void *softObj, const DFinderEvent *info)
{
    (void)softObj;
    (void)info;
    g_eventCnt++;
}

static int32_t InvokePostEvent(const List *eventNodeChain,
    EpollDesc epollfd, EventHandle handle, void *arg)
{
    handle(arg);
    return 0;
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

TEST(Dfinder, TestSetEventFunc)
{
    MOCKER(PostEvent).stubs().will(invoke(InvokePostEvent));
    ASSERT_EQ(SetEventFunc(NULL, TestDFinderEventFuncCb), 0);
    ASSERT_EQ(SetEventFunc(NULL, NULL), 0);
    GlobalMockObject::verify();

    MOCKER(PostEvent).stubs().will(returnValue(-1));
    ASSERT_NE(SetEventFunc(NULL, TestDFinderEventFuncCb), 0);
    GlobalMockObject::verify();
}

TEST(Dfinder, TestNotifyStatisticsEvent)
{
    MOCKER(PostEvent).stubs().will(invoke(InvokePostEvent));
    NotifyStatisticsEvent();
    ASSERT_EQ(g_eventCnt, 0);
    ASSERT_EQ(SetEventFunc(NULL, TestDFinderEventFuncCb), 0);
    GlobalMockObject::verify();
    NotifyStatisticsEvent();
    ASSERT_EQ(g_eventCnt, 1);
    ResetEventFunc();
    NotifyStatisticsEvent();
    ASSERT_EQ(g_eventCnt, 1);
}
