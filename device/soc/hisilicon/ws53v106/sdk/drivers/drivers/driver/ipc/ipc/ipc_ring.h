/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides driver ipc \n
 *
 * History: \n
 * 2022-11-15, Create file. \n
 */

#ifndef IPC_RING_H
#define IPC_RING_H

#include <stdint.h>
#include "errcode.h"
#include "ipc.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_driver_ipc_ring IPC Software Ring buffer Mailbox
 * @ingroup  drivers_driver_ipc
 * @{
 */

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
errcode_t ipc_ring_init(void);

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
errcode_t ipc_ring_deinit(void);

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
errcode_t ipc_ring_send_msg_sync(ipc_msg_info_t *msg_info);

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
errcode_t ipc_ring_send_msg_async(ipc_msg_info_t *msg_info);

/**
 * @if Eng
 * @brief  IPC receives messages.
 * @param  [in]  src_core The source core of IPC message.
 * @retval ERRCODE_SUCC Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  IPC接收消息。
 * @param  [in]  src_core IPC消息源核。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败。参考 @ref errcode_t
 * @endif
 */
errcode_t ipc_ring_receive_msg(uint8_t src_core, uint8_t channel);

/**
 * @if Eng
 * @brief  IPC registers the RX interrupt handler.
 * @note   A handler needs to be registered for each message ID.
 * @param  [in]  handler_info RX interrupt handler information.
 * @retval ERRCODE_SUCC Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  IPC注册接收中断处理程序。
 * @note   每个消息ID都需要注册一个中断处理程序。
 * @param  [in]  handler_info RX中断处理程序信息。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败。参考 @ref errcode_t
 * @endif
 */
errcode_t ipc_ring_register_rx_handler(ipc_rx_handler_info_t *handler_info);


/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif