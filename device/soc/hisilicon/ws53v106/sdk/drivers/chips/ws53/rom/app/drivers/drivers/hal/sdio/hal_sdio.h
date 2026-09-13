/**
 * Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved. \n
 *
 * Description: Provides hal sdio \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-01-18， Create file. \n
 */
#ifndef HAL_SDIO_H
#define HAL_SDIO_H

#include <stdint.h>
#include <stdbool.h>
#include "common_def.h"
#include "errcode.h"
#include "sdio_porting.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_hal_sdios_api SDIOS
 * @ingroup  drivers_hal_sdios
 * @{
 */

/**
 * @if Eng
 * @brief  device receive interrupt callback of Host has read the message.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  device收到Host已经读取了消息的中断回调函数。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @endif
 */
typedef void (*sdio_fn1_msg_ack_t)(sdio_bus_t bus);

/* Argument Reg Field definition */
#define BLKCNT_OR_BYTES_MSK (uint32_t)0x000001ff
#define CMD53_ADDR_MSK      ((uint32_t)0x0001ffff << 9)
#define CMD53_OPCODE        bit(26)
#define CMD53_BLK_MODE      bit(27)
#define CMD53_FUN_NUM       (bit(28) | bit(29) | bit(30))
#define CMD53_RW_FLAG       bit(31)

/* Global interrupt */
#define INT_FRM_SOFT_RESET bit(0)
#define INT_FRM_MEM        bit(1)
#define INT_FRM_FN1        bit(2)

void sdio_force_exit_wait_card(void);
void sdio_clock_set(bool en);

/**
 * @if Eng
 * @brief  SDIO works status.
 * @else
 * @brief  SDIO工作状态
 * @endif
 */
typedef enum {
    HAL_SDIO_CHANNEL_ERR    = 0x0,          /*!< @if Eng SDIO err.
                                                 @else SDIO错误 @endif */
    HAL_SDIO_CHANNEL_RESET,                 /*!< @if Eng Reset SDIO.
                                                 @else 重置SDIO @endif */
    HAL_SDIO_CHANNEL_INIT,                  /*!< @if Eng Initialize the SDIO.
                                                 @else 初始化SDIO @endif */
    HAL_SDIO_CHANNEL_SLEEP,                 /*!< @if Eng Sleep the SDIO.
                                                 @else SDIO睡眠状态 @endif */
    HAL_SDIO_CHANNEL_WAKE,                  /*!< @if Eng Wake the SDIO.
                                                 @else 唤醒SDIO @endif */
    HAL_SDIO_CHANNEL_WORK,                  /*!< @if Eng SDIO work.
                                                 @else SDIO工作状态 @endif */
    HAL_SDIO_CHANNEL_BUTT                   /*!< @if Eng SDIO status number.
                                                 @else SDIO状态枚举数 @endif */
} sdio_channel_status_t;

/**
 * @if Eng
 * @brief  SDIO sleep stage.
 * @else
 * @brief  SDIO睡眠阶段状态
 * @endif
 */
typedef enum {
    SLEEP_REQ_WAITING       = 0,
    SLEEP_ALLOW_SND         = 1,
    SLEEP_DISALLOW_SND      = 2,
} sdio_host_sleep_stage_t;

/**
 * @if Eng
 * @brief  SDIO transfer channel structure.
 * @else
 * @brief  SDIO传输通道结构体。
 * @endif
 */
typedef struct hal_sdio_chan_info {
    uint32_t                 send_data_len;
    uint16_t                 last_msg;
    uint16_t                 panic_forced_timeout;
    uint16_t                 chan_msg_cnt[D2H_MSG_COUNT];
} hal_sdio_chan_info_t;

/**
 * @if Eng
 * @brief  SDIO message structure.
 * @else
 * @brief  SDIO消息结构体。
 * @endif
 */
typedef struct hal_sdio_msg {
    uint32_t pending_msg;                       /*!< @if Eng Pending message.
                                                     @else   挂起中的消息 @endif */
    uint32_t sending_msg;                       /*!< @if Eng Sending message.
                                                     @else   发送中的消息 @endif */
} hal_sdio_msg_t;

/**
 * @if Eng
 * @brief  SDIO status structure.
 * @else
 * @brief  SDIO状态结构体。
 * @endif
 */
typedef struct hal_sdio_status {
    uint16_t          rd_arg_invalid_cnt;
    uint16_t          wr_arg_invlaid_cnt;
    uint16_t          unsupport_int_cnt;
    uint16_t          mem_int_cnt;
    uint16_t          fn1_wr_over;
    uint16_t          fn1_rd_over;
    uint16_t          fn1_rd_error;
    uint16_t          fn1_rd_start;
    uint16_t          fn1_wr_start;
    uint16_t          fn1_rst;
    uint16_t          fn1_msg_rdy;
    uint16_t          fn1_ack_to_arm_int_cnt;
    uint16_t          fn1_adma_end_int;
    uint16_t          fn1_suspend;
    uint16_t          fn1_resume;
    uint16_t          fn1_adma_int;
    uint16_t          fn1_adma_err;
    uint16_t          fn1_en_int;
    uint16_t          fn1_msg_isr;
    uint16_t          soft_reset_cnt;
} hal_sdio_status_t;

typedef enum {
    MSG_FLAG_OFF    = 0,
    MSG_FLAG_ON     = 1,
} hal_msg_flag;

/**
 * @if Eng
 * @brief  SDIO information structure.
 * @else
 * @brief  SDIO信息结构体。
 * @endif
 */
typedef struct hal_sdio_info {
    uint8_t                 volt_switch_flag;

    uint8_t                 host_to_device_msg_flag;

    uint16_t                reinit_times;
    uint16_t                gpio_int_times;
    uint16_t                pad;
    hal_sdio_status_t           sdio_status;
    hal_sdio_chan_info_t        chan_info;
    hal_sdio_msg_t         sdio_msg_status;
} hal_sdio_info_t;

/**
 * @if Eng
 * @brief  SDIO adma desc table.
 * @else
 * @brief  SDIO adma表结构
 * @endif
 */
typedef struct {
    uint16_t param;                 /*!< @if Eng ADMA description table parameters.
                                         @else ADMA表的参数 @endif */
    uint16_t len;                   /*!< @if Eng ADMA Transmission data length.
                                         @else 传输数据长度 @endif */
    uint32_t address;               /*!< @if Eng ADMA transmission destination address.
                                         @else 传输目的地址 @endif */
} hal_sdio_adma_table_t;

/**
 * @if Eng
 * @brief  SDIO interrupt callback structure.
 * @else
 * @brief  SDIO中断回调函数结构体
 * @endif
 */
typedef struct hal_sdio_callback_func {
    uint32_t (*read_start_callback)(uint32_t len, uint8_t *dma_tbl);    /*!< @if Eng HOST reading.
                                                                             @else DEVICE感知到HOST发起了读操作 @endif */
    uint32_t (*read_over_callback)(void);                               /*!< @if Eng HOST reading over.
                                                                             @else DEVICE感知到HOST读操作结束 @endif */
    void (*read_err_callback)(void);                                    /*!< @if Eng HOST read error.
                                                                             @else DEVICE感知到HOST读数据错误 @endif */
    uint32_t (*write_start_callback)(uint32_t len, uint8_t *dma_tbl);   /*!< @if Eng HOST writting.
                                                                             @else DEVICE感知到HOST发起了写操作 @endif */
    uint32_t (*write_over_callback)(void);                              /*!< @if Eng HOST write over.
                                                                             @else DEVICE感知到HOST写操作结束 @endif */
    void (*process_msg_callback)(uint32_t);                             /*!< @if Eng HOST getting message.
                                                                             @else DEVICE接收到HOST发来的消息 @endif */
    void (*soft_rst_callback)(void);                                    /*!< @if Eng HOST getting reset interruption.
                                                                             @else DEVICE接收到HOST发来的软复位 @endif */
} hal_sdio_callback_func_t;

/**
 * @if Eng
 * @brief  Initialize for hal SDIO.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @param  [in]  wait_status wait or not.
 * @retval ERRCODE_SUCC   Success.
 * @retval Other        Failure. For details, see @ref errcode_t.
 * @else
 * @brief  HAL层SDIO的初始化接口。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @param  [in]  wait_status 是否等待function1 enable中断。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败，参考 @ref errcode_t 。
 * @endif
 */
typedef errcode_t (*hal_sdio_init_t)(sdio_bus_t bus, bool wait_status);

/**
 * @if Eng
 * @brief  Deinitialize for hal SDIO.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @retval ERRCODE_SUCC   Success.
 * @retval Other        Failure. For details, see @ref errcode_t.
 * @else
 * @brief  HAL层SDIO的去初始化接口。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败，参考 @ref errcode_t 。
 * @endif
 */
typedef void (*hal_sdio_deinit_t)(sdio_bus_t bus);

 /**
 * @if Eng
 * @brief  Init sdio but not wait host clock ready and not wait func1 enable interrupt.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  初始化SDIO，初始化过程中不判断host时钟是否就绪， 不判断是否接收到了使能function1的中断。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @endif
 */
typedef void (*hal_sdio_init_no_wait_t)(sdio_bus_t bus);

 /**
 * @if Eng
 * @brief  Get whether host clock ready.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @retval true  Ready.
 * @retval false Not ready.
 * @else
 * @brief  判断HOST时钟是否就绪。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @retval true  准备就绪。
 * @retval false 没有准备就绪。
 * @endif
 */
typedef bool (*hal_sdio_host_clk_ready_t)(sdio_bus_t bus);

 /**
 * @if Eng
 * @brief  start to send data.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @param  [in]  len Length of sent data.
 * @retval ERRCODE_SUCC   Success.
 * @retval Other        Failure. For details, see @ref errcode_t.
 * @else
 * @brief  启动数据发送接口。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @param  [in]  len 发送数据长度。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败，参考 @ref errcode_t 。
 * @endif
 */
typedef void (*hal_sdio_prepare_send_data_t)(sdio_bus_t bus, uint32_t len);

 /**
 * @if Eng
 * @brief  set adma table.
 * @param  [out]  adma_tab adma table first address.
 * @param  [in]  adma_index adma Transmission channel number.
 * @param  [out]  data_addr adma transmission destination address.
 * @param  [in]  data_len adma Transmission data length.
 * @retval ERRCODE_SUCC   Success.
 * @retval Other        Failure. For details, see @ref errcode_t.
 * @else
 * @brief  设置adma传输通道。
 * @param  [out]  adma_tab adma table首地址。
 * @param  [in]  adma_index 传输通道号。
 * @param  [out]  data_addr 传输目的地址。
 * @param  [in]  data_len 传输数据长度。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败，参考 @ref errcode_t 。
 * @endif
 */
typedef errcode_t (*hal_sdio_set_admatab_t)(uint8_t *adma_tab, uint32_t adma_index,
                                            const uint32_t *data_addr, uint32_t data_len);

/**
 * @if Eng
 * @brief  device send msg to host.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @param  [in]  msg message of sending to host.
 * @return ERRCODE_SUCC   Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  设备发送消息到主机。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @param  [in]  msg 发送给主机的消息。
 * @return ERRCODE_SUCC 成功。
 * @retval Other        失败，参考 @ref errcode_t
 * @endif
 */
typedef void (*hal_sdio_send_msg_t)(sdio_bus_t bus, uint32_t msg);

 /**
 * @if Eng
 * @brief  SDIO register interrupt callback function.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @param  [out]  fun SDIO interrupt callback structure. see @ref hal_sdio_callback_func_t
 * @retval ERRCODE_SUCC   Success.
 * @retval Other        Failure. For details, see @ref errcode_t.
 * @else
 * @brief  SDIO 注册中断回调函数。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @param  [out]  fun SDIO 中断回调函数结构体，参考 @ref hal_sdio_callback_func_t
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败，参考 @ref errcode_t 。
 * @endif
 */
typedef errcode_t (*hal_sdio_register_callback_t)(sdio_bus_t bus, const hal_sdio_callback_func_t *fun);

 /**
 * @if Eng
 * @brief  Set SDIO channel status.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @param  [in]  status SDIO channel status. see @ref sdio_channel_status_t
 * @else
 * @brief  设置SDIO通道状态。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @param  [in]  status SDIO 通道状态，参考 @ref sdio_channel_status_t
 * @endif
 */
typedef void (*hal_sdio_set_channel_status_t)(sdio_bus_t bus, sdio_channel_status_t status);

 /**
 * @if Eng
 * @brief  Get SDIO channel status.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @retval SDIO channel status. For details, see @ref sdio_channel_status_t.
 * @else
 * @brief  取得SDIO通道状态。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @retval SDIO通道状态，参考 @ref sdio_channel_status_t 。
 * @endif
 */
typedef sdio_channel_status_t (*hal_sdio_get_channel_status_t)(sdio_bus_t bus);

 /**
 * @if Eng
 * @brief  Set host receive message callback.
 * @param  [in]  callback device receive interrupt callback of Host has read the message. see @ref sdio_fn1_msg_ack_t
 * @else
 * @brief  设置host接收消息回调函数。
 * @param  [in]  callback device收到Host已经读取了消息的中断回调函数，参考 @ref sdio_fn1_msg_ack_t
 * @endif
 */
typedef void (*hal_sdio_set_msg_callback_t)(sdio_fn1_msg_ack_t callback);

 /**
 * @if Eng
 * @brief  Set host receive message callback.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  内存初始化函数。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @endif
 */
typedef void (*hal_sdio_memory_init_t)(sdio_bus_t bus);

 /**
 * @if Eng
 * @brief  sdio complete send function.
 * @param  [out]  adma_tab adma table first address.
 * @param  [in]  adma_index adma Transmission channel number.
 * @retval ERRCODE_SUCC   Success.
 * @retval Other        Failure. For details, see @ref errcode_t.
 * @else
 * @brief  结束发送接口函数。
 * @param  [out]  adma_tab adma table首地址。
 * @param  [in]  adma_index 传输通道号。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败，参考 @ref errcode_t 。
 * @endif
 */
typedef errcode_t (*hal_sdio_complete_send_t)(uint8_t *adma_tab, uint32_t adma_index);

 /**
 * @if Eng
 * @brief  set sdio pad adma table function.
 * @param  [out]  adma_tab adma table first address.
 * @param  [in]  adma_index adma Transmission channel number.
 * @param  [in]  padlen Length of data to be sent after data alignment.
 * @retval ERRCODE_SUCC   Success.
 * @retval Other        Failure. For details, see @ref errcode_t.
 * @else
 * @brief  配置数据对齐后的ADMA表。
 * @param  [out]  adma_tab adma table首地址。
 * @param  [in]  adma_index 传输通道号。
 * @param  [in]  padlen 据对齐后要发送的数据长度。
 * @retval ERRCODE_SUCC 成功。
 * @retval Other        失败，参考 @ref errcode_t 。
 * @endif
 */
typedef errcode_t (*hal_sdio_set_pad_admatab_t)(uint8_t *adma_tab, uint32_t adma_index, uint32_t padlen);

 /**
 * @if Eng
 * @brief  get sdio info function.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @retval pointer to SDIO information structure. For details, see @ref hal_sdio_info_t.
 * @else
 * @brief  取得SDIO信息。
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @retval SDIO信息结构体指针，参考 @ref hal_sdio_info_t 。
 * @endif
 */
typedef hal_sdio_info_t* (*hal_sdio_get_sdio_info_t)(sdio_bus_t bus);

/**
 * @if Eng
 * @brief  sdio memory initialization function.
 * @else
 * @brief  Driver层SDIO和HAL层SDIO的接口。
 * @endif
 */
typedef struct hal_sdio_funcs {
    hal_sdio_init_t                init;               /*!< @if Eng Init SDIO interface.
                                                            @else   HAL层SDIO的初始化接口 @endif */
    hal_sdio_deinit_t              deinit;             /*!< @if Eng Deinit SDIO interface.
                                                            @else   HAL层SDIO去初始化接口 @endif */
    hal_sdio_init_no_wait_t        init_no_wait;       /*!< @if Eng Init sdio but not wait interface.
                                                            @else   HAL层SDIO的不等待初始化接口 @endif */
    hal_sdio_host_clk_ready_t      clk_ready;          /*!< @if Eng SDIO Get whether host clock ready interface.
                                                            @else   HAL层SDIO的判断HOST时钟是否就绪接口 @endif */
    hal_sdio_prepare_send_data_t   prepare_send_data;  /*!< @if Eng DEVICE start to send data.
                                                            @else   从机启动数据发送接口 @endif */
    hal_sdio_set_admatab_t         set_admatab;        /*!< @if Eng DEVICE set adma table.
                                                            @else   设置adma传输通道 @endif */
    hal_sdio_send_msg_t            send_msg;           /*!< @if Eng DEVICE send msg to host.
                                                            @else   设备发送消息给主机 @endif */
    hal_sdio_register_callback_t   register_callback;  /*!< @if Eng SDIO register interrupt callback function.
                                                            @else   SDIO 注册中断回调函数 @endif */
    hal_sdio_get_channel_status_t  get_status;         /*!< @if Eng Get SDIO channel status.
                                                            @else   取得SDIO通道状态 @endif */
    hal_sdio_set_channel_status_t  set_status;         /*!< @if Eng Set SDIO channel status.
                                                            @else   设置SDIO通道状态 @endif */
    hal_sdio_set_msg_callback_t    set_msg_callback;   /*!< @if Eng Set host receive message callback.
                                                            @else   设置host接收消息回调函数 @endif */
    hal_sdio_memory_init_t         memory_init;        /*!< @if Eng sdio memory initialization function.
                                                            @else   内存初始化函数 @endif */
    hal_sdio_complete_send_t       complete_send;      /*!< @if Eng sdio complete send function.
                                                            @else   结束发送接口函数 @endif */
    hal_sdio_set_pad_admatab_t     set_pad_admatab;    /*!< @if Eng set sdio pad adma table function.
                                                            @else   sdio 配置数据对齐后的ADMA表 @endif */
    hal_sdio_get_sdio_info_t       get_sdio_info;      /*!< @if Eng get sdio info function.
                                                            @else   取得SDIO信息  @endif */
} hal_sdio_funcs_t;

/**
 * @if Eng
 * @brief  Register @ref hal_sdio_funcs_t into the g_hal_sdios_funcs.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @param  [out] funcs Interface between SDIO driver and SDIO hal.
 * @retval ERRCODE_SUCC   Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  注册 @ref hal_sdio_funcs_t 到 g_hal_dmas_funcs
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @param  [out] funcs Driver层SDIO和HAL层SDIO的接口实例
 * @retval ERRCODE_SUCC 成功
 * @retval Other        失败，参考 @ref errcode_t
 * @endif
 */
errcode_t hal_sdio_register_funcs(sdio_bus_t bus, hal_sdio_funcs_t *funcs);

/**
 * @if Eng
 * @brief  Unregister @ref hal_sdio_funcs_t from the g_hal_sdio_funcs.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  从g_hal_sdio_funcs注销 @ref hal_sdio_funcs_t
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @endif
 */
void hal_sdio_unregister_funcs(sdio_bus_t bus);

/**
 * @if Eng
 * @brief  Init the SDIO which will set the base address of registers.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @retval ERRCODE_SUCC Success.
 * @retval Other        Failure. For details, see @ref errcode_t
 * @else
 * @brief  初始化SDIO，设置寄存器的基地址
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @retval ERRCODE_SUCC 成功
 * @retval Other        失败，参考 @ref errcode_t
 * @endif
 */
errcode_t hal_sdio_regs_init(sdio_bus_t bus);

/**
 * @if Eng
 * @brief  Deinit the SDIO which will clear the base address of registers has been
 *         set by @ref hal_sdio_regs_init.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  去初始化，然后清除在 @ref hal_sdio_regs_init 中设置的寄存器地址
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @endif
 */
void hal_sdio_regs_deinit(sdio_bus_t bus);

/**
 * @if Eng
 * @brief  Get interface between SDIO driver and SDIO hal, see @ref hal_sdio_funcs_t.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @return Interface between SDIO driver and SDIO hal, see @ref hal_sdio_funcs_t.
 * @else
 * @brief  获取Driver层SDIO和HAL层SDIO的接口实例，参考 @ref hal_sdio_funcs_t.
 * @param  [in]  bus SDIO通道， 参考 @ref sdio_bus_t
 * @return Driver层SDIO和HAL层SDIO的接口实例，参考 @ref hal_sdio_funcs_t.
 * @endif
 */
hal_sdio_funcs_t *hal_sdio_get_funcs(sdio_bus_t bus);

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif