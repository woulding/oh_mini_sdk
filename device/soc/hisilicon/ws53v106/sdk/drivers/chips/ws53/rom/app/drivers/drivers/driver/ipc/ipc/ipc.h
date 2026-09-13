/**
 * Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved. \n
 *
 * Description: Provides driver ipc \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2022-11-14, Create file. \n
 */

#ifndef IPC_H
#define IPC_H

#include <stdint.h>
#include "errcode.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_driver_ipc IPC
 * @ingroup  drivers_driver
 * @{
 */

/**
 * @if Eng
 * @brief  Indicates the preprocessing callback type on the receiving side of the IPC.
 * @param  [in,out] buf_addr  Data storage buffer address set in the preprocessing phase.
 * @param  [in,out] buf_len  Data storage buffer length.
 * @retval 0        Success.
 * @retval Other    failure.
 * @else
 * @brief  表示IPC接收侧预处理回调类型。
 * @param  [in,out] buf_addr 预处理阶段设置的数据存储缓冲区地址。
 * @param  [in,out] buf_len  数据存储缓冲区长度。
 * @retval 0        成功。
 * @retval Other    失败。
 * @endif
 */
typedef int32_t (*ipc_rx_pre_callback_t)(uintptr_t *buf_addr, uint32_t *buf_len);

/**
 * @if Eng
 * @brief  Indicates the callback type on the receiving side of the IPC.
 * @param  [in] payload_addr IPC message address, the receiving side needs to obtain and process data from this address.
 * @param  [in] payload_len  IPC message length.
 * @else
 * @brief  表示IPC接收侧回调函数类型。
 * @param  [in] payload_addr IPC消息地址, 接收端需从该地址中取数据并处理。
 * @param  [in] payload_len  IPC消息长度。
 * @endif
 */
typedef void (*ipc_rx_callback_t)(uint8_t *payload_addr, uint32_t payload_len);

/**
 * @if Eng
 * @brief  Received information body of the IPC message.
 * @else
 * @brief  IPC接收消息描述。
 * @endif
 */
typedef struct ipc_rx_handler_info {
    uint8_t msg_id;                 /*!< @if Eng IPC message ID.
                                         @else   IPC消息ID。 @endif */
    uint8_t reserved[3];            /*!< @if Eng Reserved.
                                         @else   保留。 @endif */
    ipc_rx_pre_callback_t pre_cb;   /*!< @if Eng IPC receive preprocessing callback function.
                                         @else   IPC接收预处理回调处理函数。 @endif */
    ipc_rx_callback_t cb;           /*!< @if Eng IPC receive callback function.
                                         @else   IPC接收回调处理函数。 @endif */
} ipc_rx_handler_info_t;

/**
 * @if Eng
 * @brief  Sending information body of the IPC message.
 * @else
 * @brief  IPC发送消息描述。
 * @endif
 */
typedef struct ipc_msg_info {
    uint8_t  dst_core;          /*!< @if Eng IPC message destination core.
                                     @else   IPC消息目的核。 @endif */
    uint8_t  channel;           /*!< @if Eng IPC message interrupt channel.
                                     @else   IPC消息通道。 @endif */
    uint8_t  msg_id;            /*!< @if Eng IPC message ID.
                                     @else   IPC消息ID。 @endif */
    uint8_t  priority;          /*!< @if Eng IPC message priority.
                                     @else   IPC消息优先级。 @endif */
    uint8_t  *buf_addr;         /*!< @if Eng IPC message data buffer address.
                                     @else   IPC消息数据缓冲区地址。 @endif */
    uint32_t buf_len;           /*!< @if Eng IPC message data buffer length.
                                     @else   IPC消息数据缓冲长度。 @endif */
} ipc_msg_info_t;

/**
 * @if Eng
 * @brief  Initialize IPC.
 * @retval ERRCODE_SUCC Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  初始化IPC。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败。参考 @ref errcode_t
 * @endif
 */
errcode_t uapi_ipc_init(void);

/**
 * @if Eng
 * @brief  Deinitialize IPC.
 * @retval ERRCODE_SUCC Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  去初始化IPC。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败。参考 @ref errcode_t
 * @endif
 */
errcode_t uapi_ipc_deinit(void);

/**
 * @if Eng
 * @brief  IPC sends messages synchronously.
 * @param  [in]  msg_info Send message header.
 * @retval ERRCODE_SUCC Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  IPC同步发送消息。
 * @param  [in]  msg_info 发送信息头。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败。参考 @ref errcode_t
 * @endif
 */
errcode_t uapi_ipc_send_msg_sync(ipc_msg_info_t *msg_info);

/**
 * @if Eng
 * @brief  IPC sends messages asynchronously.
 * @param  [in]  msg_info Send message header.
 * @retval ERRCODE_SUCC Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  IPC异步发送消息。
 * @param  [in]  msg_info 发送信息头。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败。参考 @ref errcode_t
 * @endif
 */
errcode_t uapi_ipc_send_msg_async(ipc_msg_info_t *msg_info);

/**
 * @if Eng
 * @brief  IPC registers the RX interrupt handler.
 * @note   A handler needs to be registered for each message ID.
 * @param  [in]  handler_info RX interrupt handler information.
 * @retval ERRCODE_SUCC Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  IPC注册接收中断处理程序，每个消息ID都需要注册一个中断处理程序。
 * @param  [in]  handler_info RX中断处理程序信息。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败。参考 @ref errcode_t
 * @endif
 */
errcode_t uapi_ipc_register_rx_handler(ipc_rx_handler_info_t *handler_info);

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif