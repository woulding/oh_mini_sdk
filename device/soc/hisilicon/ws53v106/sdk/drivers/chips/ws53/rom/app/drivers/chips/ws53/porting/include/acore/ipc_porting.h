/**
 * Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved. \n
 *
 * Description: Provides ipc port \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2022-11-26 Create file. \n
 */

#ifndef IPC_PORTING_H
#define IPC_PORTING_H

#include "platform_types.h"
#include "ipc_ring.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_port_ipc IPC
 * @ingroup  drivers_port
 * @{
 */

#define CORE0 CORES_APPS_CORE
#define CORE1 CORES_BT_CORE
#define CONFIG_IPC_SEND_MSG_MAX_WAIT_TIME_MS 0x400

/**
 * @brief  Shared memory address for IPC transmission.
 */
#define IPC_CORE0_1_SHARE_MEM_CH0_START_ADDR  0x10080000
#define IPC_CORE0_1_SHARE_MEM_CH0_LENGTH      0x800
#define IPC_CORE0_1_SHARE_MEM_CH1_START_ADDR  (IPC_CORE0_1_SHARE_MEM_CH0_START_ADDR + IPC_CORE0_1_SHARE_MEM_CH0_LENGTH)
#define IPC_CORE0_1_SHARE_MEM_CH1_LENGTH      0x800
#define IPC_CORE1_0_SHARE_MEM_CH0_START_ADDR  (IPC_CORE0_1_SHARE_MEM_CH1_START_ADDR + IPC_CORE0_1_SHARE_MEM_CH1_LENGTH)
#define IPC_CORE1_0_SHARE_MEM_CH0_LENGTH      0x800
#define IPC_CORE1_0_SHARE_MEM_CH1_START_ADDR  (IPC_CORE1_0_SHARE_MEM_CH0_START_ADDR + IPC_CORE1_0_SHARE_MEM_CH0_LENGTH)
#define IPC_CORE1_0_SHARE_MEM_CH1_LENGTH      0x800
/**
 * @brief  Number of IPC communication pipes, the value is equal to the number of cores that communicate with this core.
 */
#define CORE_IPC_TX_PIPE_NUM  2
#define CORE_IPC_RX_PIPE_NUM  2

#define IPC_MESSAGE_MAX_LENGTH 60

/**
 * @if Eng
 * @brief  IPC memory management configuration.
 * @else
 * @brief  IPC内存管理配置。
 * @endif
 */
typedef struct ipc_memory_manage {
    uint8_t  src_core;          /*!< @if Eng IPC interrupt source core.
                                     @else   IPC中断源核。  @endif */
    uint8_t  dst_core;          /*!< @if Eng IPC interrupt destination core.
                                     @else   IPC中断目的核。  @endif */
    uint8_t  channel;           /*!< @if Eng IPC interrupt destination channel.
                                     @else   IPC中断通道。  @endif */
    uint8_t  reserved;          /*!< @if Eng Reserved.
                                     @else   保留。  @endif */
    uint32_t start_addr;        /*!< @if Eng Start address of IPC messages in the shared memory.
                                     @else   IPC消息在共享内存中的开始地址。  @endif */
    uint32_t total_len;         /*!< @if Eng Total length of IPC messages in the shared memory.
                                     @else   IPC消息在共享内存中的总长度。  @endif */
} ipc_memory_manage_t;

/**
 * @brief  IPC TX pipes memory configuration, see @ref ipc_memory_manage_t.
 */
#define IPC_MEMORY_INIT_TX_CONFIG { \
    { \
        .src_core = CORE0, \
        .dst_core = CORE1, \
        .channel = 0, \
        .start_addr = IPC_CORE0_1_SHARE_MEM_CH0_START_ADDR, \
        .total_len = IPC_CORE0_1_SHARE_MEM_CH0_LENGTH \
    }, \
    { \
        .src_core = CORE0, \
        .dst_core = CORE1, \
        .channel = 1, \
        .start_addr = IPC_CORE0_1_SHARE_MEM_CH1_START_ADDR, \
        .total_len = IPC_CORE0_1_SHARE_MEM_CH1_LENGTH \
    }, \
}

/**
 * @brief  IPC RX pipes memory configuration, see @ref ipc_memory_manage_t.
 */
#define IPC_MEMORY_INIT_RX_CONFIG { \
    { \
        .src_core = CORE1, \
        .dst_core = CORE0, \
        .channel = 0, \
        .start_addr = IPC_CORE1_0_SHARE_MEM_CH0_START_ADDR, \
        .total_len = IPC_CORE1_0_SHARE_MEM_CH0_LENGTH \
    }, \
    { \
        .src_core = CORE1, \
        .dst_core = CORE0, \
        .channel = 1, \
        .start_addr = IPC_CORE1_0_SHARE_MEM_CH1_START_ADDR, \
        .total_len = IPC_CORE1_0_SHARE_MEM_CH1_LENGTH \
    }, \
}

/**
 * @brief  Enum specifying ipc direction.
 */
typedef enum {
    IPC_DIR_TX = 0,
    IPC_DIR_RX,
    IPC_DIR_MAX_NUM,
} ipc_dir_e;

/**
 * @brief  Enum specifying the relative priority of the IPC message, with 0 indicating the highest priority.
 * Using the incrementing values allows for easy loops
 *      for (ipc_priority_e p = IPC_PRIORITY_HIGHEST; p <= IPC_PRIORITY_LOWEST; p++)
 */
typedef enum {
    IPC_PRIORITY_HIGHEST = 0, // !< Highest priority (lowest numeric value).
    IPC_PRIORITY_LOWEST,      // !< Lowest priority (highest numeric value).
    IPC_PRIORITY_MAX_NUM,     // !< Used to size arrays.
} ipc_priority_e;

/**
 * @brief  IPC communication message ID.
 * @note   Each type of message requires a specific message ID.
 *         At the same time, a callback function needs to be registered for each message ID.
 */
typedef enum ipc_msg_id {
    IPC_MSG_CORE0_1_CMD,
    IPC_MSG_CORE1_0_CMD,
    IPC_MSG_CORE0_2_CMD,
    IPC_MSG_CORE2_0_CMD,
    IPC_MSG_CORE1_2_CMD,
    IPC_MSG_CORE2_1_CMD,
    IPC_MSG_BT_POWER_ON,
    IPC_MSG_BT_POWER_OFF,
    IPC_MSG_LOG_INFO,
    IPC_MSG_LOG_LEVEL,
    IPC_MSG_SYS_REBOOT_REQ,
    IPC_MSG_WIFI_H2D_NETBUF,
    IPC_MSG_WIFI_H2D_MSG,
    IPC_MSG_WIFI_H2D_CUSTOMIZE,
    IPC_MSG_WIFI_H2D_WLAN_OPEN,
    IPC_MSG_WIFI_D2H_NETBUF,
    IPC_MSG_WIFI_D2H_MSG,
    IPC_MSG_WIFI_D2H_WLAN_READY,
    IPC_MSG_UPDATE_SHARE_RANDOM_NUMBER,
    IPC_MSG_ID_MAX
} ipc_msg_id_t;

/**
 * @brief  IPC TX pipes memory configuration.
 */
extern ipc_memory_manage_t g_ipc_memory_init_tx_config[CORE_IPC_TX_PIPE_NUM];

/**
 * @brief  IPC RX pipes memory configuration.
 */
extern ipc_memory_manage_t g_ipc_memory_init_rx_config[CORE_IPC_RX_PIPE_NUM];

/**
 * @brief  Get the base address of a specified IPC.
 * @return The base address of specified IPC.
 */
uintptr_t ipc_porting_base_addr_get(void);

/**
 * @brief  Register hal funcs objects into hal_ipc module.
 */
void ipc_port_register_hal_funcs(void);

/**
 * @brief  Unregister hal funcs objects into hal_ipc module.
 */
void ipc_port_unregister_hal_funcs(void);

/**
 * @brief  Register the interrupt of ipc.
 */
void ipc_port_register_irq(void);

/**
 * @brief  Unregister the interrupt of ipc.
 */
void ipc_port_unregister_irq(void);

/**
 * @brief  Lock the interrupt of ipc.
 */
uint32_t ipc_port_irq_lock(void);

/**
 * @brief  Lock the interrupt of ipc.
 * @param  [in] status CPSR value before all interrupts are disabled.
 */
void ipc_port_irq_restore(uint32_t status);

/**
 * @brief  Get the IPC interrupt configuration mask based on the peer core.
 * @param  [in]  core The peer core.
 * @return The Mask to be configured based on the peer core.
 */
uint16_t ipc_port_get_int_mask(uint8_t core, uint8_t channel);

/**
 * @brief  Set IPC share memory info.
 * @param  [in]  config ipc config info
 * @param  [in]  cnt info number
 * @param  [dir] ipc direction
 */
void ipc_port_memory_init(ipc_memory_manage_t *config, uint8_t cnt, uint8_t dir);
/**
 * @}
 */

void irq_app_int0_handler_patch(void);
void irq_app_int1_handler_patch(void);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif