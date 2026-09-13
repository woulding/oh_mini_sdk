/**
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

#ifndef SLE_SERVER_DEMO_H
#define SLE_SERVER_DEMO_H

#include <stdint.h>
#include "errcode.h"
#include "sle_ssap_server.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/* Service UUID */
#define SLE_UUID_SERVER_SERVICE        0x2222

/* Property UUID */
#define SLE_UUID_SERVER_NTF_REPORT     0x2323

/* Property Permission */
#define SLE_UUID_TEST_PROPERTIES  (SSAP_PERMISSION_READ | SSAP_PERMISSION_WRITE)

/* Operation indication */
#define SLE_UUID_TEST_OPERATION_INDICATION  (SSAP_OPERATE_INDICATION_BIT_READ | \
                                             SSAP_OPERATE_INDICATION_BIT_WRITE | \
                                             SSAP_OPERATE_INDICATION_BIT_NOTIFY)

/* Descriptor Property */
#define SLE_UUID_TEST_DESCRIPTOR   (SSAP_PERMISSION_READ | SSAP_PERMISSION_WRITE)

/* Link qos state info */
typedef struct sle_link_state_info {
    uint16_t conn_id;               /* 链路Id */
    uint8_t link_state;             /* 链路状态 */
} sle_link_state_info_t;

/* Message queue callback registered by the demo task */
typedef void (*sle_server_msg_queue)(uint8_t *buffer_addr, uint16_t buffer_size);

errcode_t sle_server_init(void);

errcode_t sle_server_send_report_by_handle(const uint8_t *data, uint16_t len);

uint16_t sle_server_is_connected(void);

void sle_server_register_msg(sle_server_msg_queue msg_cb);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SLE_SERVER_DEMO_H */
