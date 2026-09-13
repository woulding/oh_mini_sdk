/*
 * Copyright (C) 2026 HiHope Open Source Organization.
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

/* OHOS bs21e SLE server demo: 简单 SLE server，搭配星闪调试助手验证
 * OHOS 侧 APP_FEATURE_INIT -> SDK SLE 协议栈调用链路是否正常。
 * 数据通路：助手写 0x2323 -> write 回调 -> msg 队列 -> 任务回发 notify(echo)。
 */

#include <string.h>
#include "ohos_init.h"
#include "securec.h"
#include "soc_osal.h"
#include "common_def.h"
#include "errcode.h"
#include "sle_errcode.h"
#include "sle_device_discovery.h"
#include "sle_server_adv.h"
#include "sle_server.h"

#define SLE_SERVER_TASK_PRIO                 28
#define SLE_SERVER_TASK_STACK_SIZE           0x1200
#define SLE_SERVER_TASK_DURATION_MS          2000

#define SLE_SERVER_MSG_QUEUE_LEN             5
#define SLE_SERVER_MSG_QUEUE_MAX_SIZE        64
#define SLE_SERVER_QUEUE_DELAY               0xFFFFFFFF

#define SLE_SERVER_LOG "[sle server]"

#define SLE_ADV_HANDLE_DEFAULT               1

static unsigned long g_sle_server_msgqueue_id;
static uint8_t g_rx_buf[SLE_SERVER_MSG_QUEUE_MAX_SIZE] = {0};

static const uint8_t g_sle_dis_connect_msg[] = "sle_dis_connect";

static void sle_server_write_msgqueue(uint8_t *buffer_addr, uint16_t buffer_size)
{
    if (buffer_size > SLE_SERVER_MSG_QUEUE_MAX_SIZE) {
        buffer_size = SLE_SERVER_MSG_QUEUE_MAX_SIZE;
    }
    int msg_ret = osal_msg_queue_write_copy(g_sle_server_msgqueue_id, (void *)buffer_addr,
        buffer_size, 0);
    if (msg_ret != OSAL_SUCCESS) {
        osal_printk("%s msg queue write copy fail.\r\n", SLE_SERVER_LOG);
    }
}

static void sle_server_rx_buf_init(void)
{
    (void)memset_s(g_rx_buf, SLE_SERVER_MSG_QUEUE_MAX_SIZE, 0, SLE_SERVER_MSG_QUEUE_MAX_SIZE);
}

static void *sle_server_demo_task(const char *arg)
{
    unused(arg);
    uint32_t rx_length = 0;
    errcode_t ret;

    if (osal_msg_queue_create("sle_server_msgqueue", SLE_SERVER_MSG_QUEUE_LEN,
        &g_sle_server_msgqueue_id, 0, SLE_SERVER_MSG_QUEUE_MAX_SIZE) != OSAL_SUCCESS) {
        osal_printk("%s msg queue create failed!\r\n", SLE_SERVER_LOG);
        return NULL;
    }
    sle_server_register_msg(sle_server_write_msgqueue);

    /* 注册回调 → 使能 SLE → 等使能完成 → 加服务 → 启动广播，全部在任务上下文完成 */
    ret = sle_server_init();
    if (ret != ERRCODE_SLE_SUCCESS) {
        osal_printk("%s sle_server_init fail :0x%x\r\n", SLE_SERVER_LOG, ret);
        return NULL;
    }

    while (1) {
        sle_server_rx_buf_init();
        rx_length = SLE_SERVER_MSG_QUEUE_MAX_SIZE;
        if (osal_msg_queue_read_copy(g_sle_server_msgqueue_id, (void *)g_rx_buf,
            &rx_length, SLE_SERVER_QUEUE_DELAY) == OSAL_SUCCESS && rx_length > 0) {
            if ((rx_length == sizeof(g_sle_dis_connect_msg)) &&
                (memcmp(g_rx_buf, g_sle_dis_connect_msg, sizeof(g_sle_dis_connect_msg)) == 0)) {
                /* 断连：重启广播，等待助手重连 */
                ret = sle_start_announce(SLE_ADV_HANDLE_DEFAULT);
                if (ret != ERRCODE_SLE_SUCCESS) {
                    osal_printk("%s sle_start_announce fail :0x%x\r\n", SLE_SERVER_LOG, ret);
                }
            } else if (sle_server_is_connected()) {
                /* echo: 回发助手写入的数据 */
                ret = sle_server_send_report_by_handle(g_rx_buf, (uint16_t)rx_length);
                if (ret != ERRCODE_SLE_SUCCESS) {
                    osal_printk("%s send report fail :0x%x\r\n", SLE_SERVER_LOG, ret);
                } else {
                    osal_printk("%s echo %u bytes\r\n", SLE_SERVER_LOG, rx_length);
                }
            } else {
                osal_printk("%s not connected, drop %u bytes\r\n", SLE_SERVER_LOG, rx_length);
            }
        }
        osal_msleep(SLE_SERVER_TASK_DURATION_MS);
    }
    osal_msg_queue_delete(g_sle_server_msgqueue_id);
    return NULL;
}

static void Bs21eSleServerDemo(void)
{
    osal_task *task_handle = NULL;
    osal_printk("%s demo start\r\n", SLE_SERVER_LOG);
    osal_kthread_lock();
    task_handle = osal_kthread_create((osal_kthread_handler)sle_server_demo_task, 0, "SleServerTask",
        SLE_SERVER_TASK_STACK_SIZE);
    if (task_handle != NULL) {
        osal_kthread_set_priority(task_handle, SLE_SERVER_TASK_PRIO);
    }
    osal_kthread_unlock();
}

APP_FEATURE_INIT(Bs21eSleServerDemo);
