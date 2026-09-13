/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides uart port template \n
 *
 * History: \n
 * 2022-06-06， Create file. \n
 */
#ifndef UART_PORT_H
#define UART_PORT_H

#include <stdint.h>
#include "platform_core.h"
#include "std_def.h"
#include "debug_print.h"
#include "errcode.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_port_uart UART
 * @ingroup  drivers_port
 * @{
 */

#define SW_UART_BAUDRATE 115200UL
#define UART_L_BAUDRATE  115200UL
#define UART_BUS_MAX_NUM UART_BUS_MAX_NUMBER

#define UART_SHADOW  YES
#define UART_DLF_SIZE  6
#define UART_FIFO_ENABLED  YES

/*  Uart FIFO Level corresponding number of passes  */
#define UART_FIFO_INT_LEVEL_1_8_PASSNUM 4
#define UART_FIFO_INT_LEVEL_1_4_PASSNUM 8
#define UART_FIFO_INT_LEVEL_1_2_PASSNUM 16
#define UART_FIFO_INT_LEVEL_3_4_PASSNUM 24
#define UART_FIFO_INT_LEVEL_7_8_PASSNUM 28

/* rx fifo level */
#ifdef HSO_SUPPORT
#define HAL_UART_PL011_FIFO_INT_LEVEL_PORTING UART_FIFO_INT_LEVEL_3_4
#else
#define HAL_UART_PL011_FIFO_INT_LEVEL_PORTING UART_FIFO_INT_LEVEL_7_8
#endif

/** Uart FIFO Level */
typedef enum {
    UART_FIFO_INT_LEVEL_1_8,
    UART_FIFO_INT_LEVEL_1_4,
    UART_FIFO_INT_LEVEL_1_2,
    UART_FIFO_INT_LEVEL_3_4,
    UART_FIFO_INT_LEVEL_7_8,
    UART_FIFO_INT_LEVEL_MAX
} uart_fifo_int_lvl_t;

/**
 * @brief  Base address list for all of the IPs.
 */
extern const uintptr_t g_uart_base_addrs[UART_BUS_MAX_NUM];

uintptr_t uart_porting_base_addr_get(uart_bus_t bus);

/**
 * @brief  Register hal funcs objects into hal_uart module.
 */
void uart_port_register_hal_funcs(uart_bus_t bus);

/**
 * @brief  Get the bus clock of specified uart.
 * @param  [in]  bus The uart bus. see @ref uart_bus_t
 * @return The bus clock of specified uart.
 */
uint32_t uart_port_get_clock_value(uart_bus_t bus);

/**
 * @brief  Set the bus clock of specified uart.
 * @param  [in]  bus The uart bus. see @ref uart_bus_t
 * @return The bus clock of specified uart.
 */
void uart_port_set_clock_value(uart_bus_t bus, uint32_t clock);

/**
 * @brief  Config the pinmux of the uarts above.
 */
void uart_port_config_pinmux(uart_bus_t bus);

/**
 * @brief  Release the pinmux of the uarts above.
 */
void uart_port_release_pinmux(uart_bus_t bus);

/**
 * @brief  Register the interrupt of uarts.
 */
void uart_port_register_irq(uart_bus_t bus);

/**
 * @brief  unRegister the interrupt of uarts.
 */
void uart_port_unregister_irq(uart_bus_t bus);

/**
 * @brief  Handler of UART0 IRQ.
 */
void irq_uart0_handler(void);

/**
 * @brief  Handler of UART1 IRQ.
 */
void irq_uart1_handler(void);

/**
 * @brief  Handler of UART2 IRQ.
 */
void irq_uart2_handler(void);

void hal_uart_clear_pending(uart_bus_t uart);

/**
 * @brief Force trigger uart interrupt.
 */
void uart_port_set_pending_irq(uart_bus_t uart);

/**
 * @brief  uart lock.
 *
 * @param uart bus.
 */
uint32_t uart_porting_lock(uart_bus_t bus);

/**
 * @brief  uart unlock.
 *
 * @param uart bus.
 */
void uart_porting_unlock(uart_bus_t bus, uint32_t irq_sts);

#ifdef SUPPORT_DFX_LOG
void log_uart_port_init(void);
#endif

#if defined(CONFIG_UART_MULTI_CORE_RESUME)
bool uart_porting_skip_resume(uart_bus_t bus);
#endif
void set_sw_debug_uart(uart_bus_t bus);

#if defined(CONFIG_UART_SUPPORT_DMA)
uint8_t uart_port_get_dma_trans_dest_handshaking(uart_bus_t bus);

uint8_t uart_port_get_dma_trans_src_handshaking(uart_bus_t bus);
#if defined(CONFIG_UART_SUPPORT_INT_TRIGGER_DMA)
/**
 * @brief  uart irq enable.
 *
 * @param bus bus.
 */
void uart_porting_int_enable(uart_bus_t bus);

/**
 * @brief  uart irq disable.
 *
 * @param bus bus.
 */
void uart_porting_int_disable(uart_bus_t bus);
#endif  /* CONFIG_UART_SUPPORT_INT_TRIGGER_DMA */
#endif  /* CONFIG_UART_SUPPORT_DMA */

#if defined(AT_COMMAND)
void at_uart_init(uint32_t baud_rate);
#endif

void log_uart_port_write(const uint8_t *buffer, uint32_t length);
errcode_t uart_port_save_bus_id(int32_t dbg_uart_bus, int32_t at_uart_bus, int32_t hso_uart_bus);

#if defined(SW_UART_DEBUG)
void sw_debug_uart_reinit(uint32_t baud_rate);
#endif
/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif