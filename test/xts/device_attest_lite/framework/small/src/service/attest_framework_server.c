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

#include <stdio.h>
#include <unistd.h>
#include <ohos_init.h>
#include <iunknown.h>
#include <samgr_lite.h>

#include "devattest_log.h"
#include "attest_framework_define.h"

typedef struct {
    INHERIT_SERVICE;
    Identity identity;
} AttestFrameworkService;

// 实现服务的生命周期函数
static const char *GetName(Service *service)
{
    (void)service;
    return ATTEST_SERVICE;
}

static BOOL Initialize(Service *service, Identity identity)
{
    AttestFrameworkService *attestService = (AttestFrameworkService *)service;
    attestService->identity = identity;
    return TRUE;
}

static BOOL MessageHandle(Service *service, Request *msg)
{
    (void)service;
    HILOGI("[SERVER MessageHandle] msg->msgId:%d", msg->msgId);
    return FALSE;
}

static TaskConfig GetTaskConfig(Service *service)
{
    (void)service;
    TaskConfig config = {LEVEL_HIGH, PRI_NORMAL, ATTEST_STACK_SIZE, ATTEST_QUEUE_SIZE, SINGLE_TASK};
    return config;
}

// 创建服务对象
static AttestFrameworkService g_attestService = {
    .GetName = GetName,
    .Initialize = Initialize,
    .MessageHandle = MessageHandle,
    .GetTaskConfig = GetTaskConfig,
    {-1, -1, NULL}
};

// 向SAMGR注册服务及接口
static void Init(void)
{
    SAMGR_GetInstance()->RegisterService((Service *)&g_attestService);
}

// 定义服务的初始化入口
SYS_SERVICE_INIT(Init);