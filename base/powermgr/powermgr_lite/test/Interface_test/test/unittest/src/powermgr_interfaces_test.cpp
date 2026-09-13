/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "hilog/log.h"
#include "running_lock_framework.h"
#include "power_manage.h"
#include "power_screen_saver.h"

#undef LOG_TAG
#define LOG_TAG "POWERMGR_LITE"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class PowermgrInterfacesTest : public testing::Test {
protected:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: PowermgrInterfacesTest001
 * @tc.desc: Test the interface Powermgr::CreateRunningLock().
 * @tc.type: FUNC
 */
HWTEST_F(PowermgrInterfacesTest, PowermgrInterfacesTest001, TestSize.Level0)
{
    HILOG_INFO(HILOG_MODULE_APP, "PowermgrInterfacesTest001 called");
    const char* name = "test_lock";
    RunningLockType type = RUNNINGLOCK_SCREEN;
    RunningLockFlag flag = RUNNINGLOCK_FLAG_NONE;
    const RunningLock* lock = CreateRunningLock(name, type, flag);
    EXPECT_NE(lock, nullptr);
};

/**
 * @tc.name: PowermgrInterfacesTest002
 * @tc.desc: Test the interface Powermgr::AcquireRunningLock().
 * @tc.type: FUNC
 */
HWTEST_F(PowermgrInterfacesTest, PowermgrInterfacesTest002, TestSize.Level0)
{
    HILOG_INFO(HILOG_MODULE_APP, "PowermgrInterfacesTest002 called");
    const RunningLock* lock = CreateRunningLock("test_lock", RUNNINGLOCK_SCREEN, RUNNINGLOCK_FLAG_NONE);
    bool ret = AcquireRunningLock(lock);
    ret = ReleaseRunningLock(lock);
    EXPECT_TRUE(ret);
};

/**
 * @tc.name: PowermgrInterfacesTest003
 * @tc.desc: Test the interface Powermgr::ReleaseRunningLock().
 * @tc.type: FUNC
 */
HWTEST_F(PowermgrInterfacesTest, PowermgrInterfacesTest003, TestSize.Level0)
{
    HILOG_INFO(HILOG_MODULE_APP, "PowermgrInterfacesTest003 called");
    const RunningLock* lock = CreateRunningLock("test_lock", RUNNINGLOCK_SCREEN, RUNNINGLOCK_FLAG_NONE);
    bool ret = ReleaseRunningLock(lock);
    EXPECT_TRUE(ret);
};

/**
 * @tc.name: PowermgrInterfacesTest004
 * @tc.desc: Test the interface Powermgr::IsRunningLockHolding().
 * @tc.type: FUNC
 */
HWTEST_F(PowermgrInterfacesTest, PowermgrInterfacesTest004, TestSize.Level0)
{
    HILOG_INFO(HILOG_MODULE_APP, "PowermgrInterfacesTest004 called");
    const RunningLock* lock = CreateRunningLock("test_lock", RUNNINGLOCK_SCREEN, RUNNINGLOCK_FLAG_NONE);
    bool ret = AcquireRunningLock(lock);
    ret = ReleaseRunningLock(lock);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(IsRunningLockHolding(lock));
};

/**
 * @tc.name: PowermgrInterfacesTest005
 * @tc.desc: Test the interface Powermgr::DestroyRunningLock().
 * @tc.type: FUNC
 */
HWTEST_F(PowermgrInterfacesTest, PowermgrInterfacesTest005, TestSize.Level0)
{
    HILOG_INFO(HILOG_MODULE_APP, "PowermgrInterfacesTest005 called");
    const RunningLock* lock = CreateRunningLock("test_lock", RUNNINGLOCK_SCREEN, RUNNINGLOCK_FLAG_NONE);
    EXPECT_NE(lock, nullptr);
    DestroyRunningLock(lock);
    EXPECT_FALSE(IsRunningLockHolding(lock));
};

/**
 * @tc.name: PowermgrInterfacesTest006
 * @tc.desc: Test the interface Powermgr::SuspendDevice().
 * @tc.type: FUNC
 */
HWTEST_F(PowermgrInterfacesTest, PowermgrInterfacesTest006, TestSize.Level0)
{
    HILOG_INFO(HILOG_MODULE_APP, "PowermgrInterfacesTest006 called");
    BOOL suspendImmed = true;
    SuspendDevice(SUSPEND_DEVICE_REASON_TIMEOUT, suspendImmed);
    EXPECT_NE(suspendImmed, false);
    const char* details = "power_key";
    WakeupDevice(WAKEUP_DEVICE_POWER_BUTTON, details);
    EXPECT_NE(details, nullptr);
};

/**
 * @tc.name: PowermgrInterfacesTest007
 * @tc.desc: Test the interface Powermgr::SetScreenSaverState
 * @tc.type: FUNC
 */
HWTEST_F(PowermgrInterfacesTest, PowermgrInterfacesTest007, TestSize.Level0)
{
    HILOG_INFO(HILOG_MODULE_APP, "PowermgrInterfacesTest007 called");
    BOOL result = true;
    SetScreenSaverState(result);
    EXPECT_NE(result, false);
};
};