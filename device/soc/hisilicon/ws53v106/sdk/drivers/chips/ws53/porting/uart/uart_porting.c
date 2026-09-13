/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides uart port template \n
 *
 * History: \n
 * 2022-06-06， Create file. \n
 */

#include "hal_uart_v151.h"
#ifdef SUPPORT_HAL_PINCTRL
#include "pinctrl_porting.h"
#include "pinctrl.h"
#endif
#include "chip_io.h"
#if (defined(SUPPORT_DFX_LOG) && (CORE == APPS))
#include "log_oam_msg.h"
#endif
#include "uart.h"
#include "platform_core.h"
#include "securec.h"
#include "osal_interrupt.h"
#include "soc_osal.h"
#include "clock_recover.h"
#if (defined(SUPPORT_DFX_LOG) && (CORE == APPS) && defined(CONFIG_HSO_UART_SUPPORT))
#include "dfx_channel.h"
#include "diag_filter.h"
#include "diag_mocked_shell.h"
#endif
#include "uart_porting.h"
#if defined(CONFIG_UART_SUPPORT_DMA)
#include "dma_porting.h"
#endif

#ifdef AT_COMMAND
#if (ENABLE_LOW_POWER == YES)
#include "idle_config.h"
#endif
#include "at_config.h"
#include "at_product.h"
#include "test_suite_uart.h"
#include "log_common.h"
#endif

#if defined(CONFIG_MIDDLEWARE_SUPPORT_NV)
#include "nv.h"
#endif

#define UART_SOFT_RST_H0_POS  0
#define UART_SOFT_RST_H1_POS  1
#define UART_SOFT_RST_L0_POS  7
#define UART_SOFT_RST_A       0x52000168
#define UART_SOFT_RST_C       0x570000B0

#define UART_BUS_0_BASE_ADDR UART0_BASE
#define UART_BUS_1_BASE_ADDR UART1_BASE
#define UART_BUS_2_BASE_ADDR UART2_BASE
#define UART_TRANS_LEN_MAX   128

static uart_bus_t g_sw_debug_uart = SW_DEBUG_UART_BUS;

const uintptr_t g_uart_base_addrs[UART_BUS_MAX_NUM] = {
#if UART_BUS_MAX_NUMBER > 0
    (uintptr_t)UART_BUS_0_BASE_ADDR,
#endif
#if UART_BUS_MAX_NUMBER > 1
    (uintptr_t)UART_BUS_1_BASE_ADDR,
#endif
#if UART_BUS_MAX_NUMBER > 2
    (uintptr_t)UART_BUS_2_BASE_ADDR,
#endif
};

uintptr_t uart_porting_base_addr_get(uart_bus_t bus)
{
    return g_uart_base_addrs[bus];
}

#ifdef SUPPORT_HAL_PINCTRL
uart_pin_config_t g_pin_config_map[UART_BUS_MAX_NUM] = {
#if UART_BUS_MAX_NUMBER > 0
    /* UART_BUS_0 */
    {
        .tx_pin     = PIN_NONE,
        .rx_pin     = PIN_NONE,
        .cts_pin    = PIN_NONE,
        .rts_pin    = PIN_NONE
    },
#endif
#if UART_BUS_MAX_NUMBER > 1
    /* UART_BUS_1 */
    {
        .tx_pin     = PIN_NONE,
        .rx_pin     = PIN_NONE,
        .cts_pin    = PIN_NONE,
        .rts_pin    = PIN_NONE
    }
#endif
};
#endif

#ifdef CONFIG_UART_SUPPORT_PORTTING_IRQ
typedef struct uart_interrupt {
    core_irq_t irq_num;
    osal_irq_handler irq_func;
}
hal_uart_interrupt_t;

static const hal_uart_interrupt_t g_uart_interrupt_lines[UART_BUS_MAX_NUMBER] = {
#if UART_BUS_MAX_NUMBER > 0
    { UART_0_IRQN, (osal_irq_handler)irq_uart0_handler },
#endif
#if UART_BUS_MAX_NUMBER > 1
    { UART_1_IRQN, (osal_irq_handler)irq_uart1_handler },
#endif
#if UART_BUS_MAX_NUMBER > 2
    { UART_2_IRQN, (osal_irq_handler)irq_uart2_handler },
#endif
#if UART_BUS_MAX_NUMBER > 3
    { UART_3_IRQN, (osal_irq_handler)irq_uart3_handler },
#endif
};
#endif

void uart_port_register_hal_funcs(uart_bus_t bus)
{
    hal_uart_register_funcs(bus, hal_uart_v151_funcs_get());
}

#include "debug_print.h"
#define UART_CLOCK_FRQ 32000000

static uint32_t g_uart_clock_value = UART_CLOCK_FRQ;

void uart_port_set_clock_value(uart_bus_t bus, uint32_t clock)
{
    unused(bus);
    g_uart_clock_value = clock;
}

uint32_t uart_port_get_clock_value(uart_bus_t bus)
{
    UNUSED(bus);
    return g_uart_clock_value;
}

static void uart_port_set_pin(uint32_t pin, pin_mode_t mode)
{
    uapi_pin_set_pull(pin, PIN_PULL_UP);
    uapi_pin_set_mode(pin, mode);
}

static void uart_port_set_reset(uint32_t reg, uint32_t pos)
{
    uapi_reg_clrbit16(reg, pos);
    uapi_reg_setbit16(reg, pos);
}

void uart_port_reset(uart_bus_t bus)
{
    if (bus == g_sw_debug_uart) {
        return;
    }
    if (bus == UART_BUS_0) {
        uart_port_set_reset(UART_SOFT_RST_A, UART_SOFT_RST_H1_POS);
    } else if (bus == UART_BUS_1) {
        uart_port_set_reset(UART_SOFT_RST_A, UART_SOFT_RST_H0_POS);
    } else if (bus == UART_BUS_2) {
        uart_port_set_reset(UART_SOFT_RST_C, UART_SOFT_RST_L0_POS);
    }
}

#if defined(CONFIG_UART_H0_PINSET_2) || defined(CONFIG_HSO_UART_SUPPORT)
#define H0_TXD_PIN S_MGPIO17
#define H0_RXD_PIN S_MGPIO18
#else
#define H0_TXD_PIN S_MGPIO8
#define H0_RXD_PIN S_MGPIO9
#endif

#define H1_TXD_PIN S_MGPIO12
#define H1_RXD_PIN S_AGPIO4

#define L0_TXD_PIN S_AGPIO1
#define L0_RXD_PIN S_AGPIO2

void uart_port_config_pinmux(uart_bus_t bus)
{
#ifdef SUPPORT_HAL_PINCTRL
    if (bus == UART_BUS_0) {
        uart_port_set_pin(H1_TXD_PIN, PIN_MODE_2);
        uart_port_set_pin(H1_RXD_PIN, PIN_MODE_2);
    } else if (bus == UART_BUS_1) {
#if defined(CONFIG_UART_H0_PINSET_2) || defined(CONFIG_HSO_UART_SUPPORT)
        uart_port_set_pin(H0_TXD_PIN, PIN_MODE_2);
        uart_port_set_pin(H0_RXD_PIN, PIN_MODE_2);
#else
        uart_port_set_pin(H0_TXD_PIN, PIN_MODE_1);
        uart_port_set_pin(H0_RXD_PIN, PIN_MODE_1);
#endif
    } else if (bus == UART_BUS_2) {
        uart_port_set_pin(L0_TXD_PIN, PIN_MODE_1);
#ifndef CONFIG_UART_L0_NOT_SUPPORT_RX
        uart_port_set_pin(L0_RXD_PIN, PIN_MODE_1);
#endif
    }
#ifdef CONFIG_UART_MULTI_CORE_RESUME
    writel(0x57000048, 0x1);            // l0中断只报A核
#endif
#else
    unused(bus);
#endif
}

void uart_port_release_pinmux(uart_bus_t bus)
{
    if (bus == g_sw_debug_uart) {
        return;
    }
#ifdef SUPPORT_HAL_PINCTRL
    if (bus == UART_BUS_0) {
        uart_port_set_pin(H1_TXD_PIN, PIN_MODE_0);
        uart_port_set_pin(H1_RXD_PIN, PIN_MODE_0);
    } else if (bus == UART_BUS_1) {
#if defined(CONFIG_UART_H0_PINSET_2) || defined(CONFIG_HSO_UART_SUPPORT)
        uart_port_set_pin(H0_TXD_PIN, PIN_MODE_0);
        uart_port_set_pin(H0_RXD_PIN, PIN_MODE_0);
#else
        uart_port_set_pin(H0_TXD_PIN, PIN_MODE_0);
        uart_port_set_pin(H0_RXD_PIN, PIN_MODE_0);
#endif
    } else if (bus == UART_BUS_2) {
        uart_port_set_pin(L0_TXD_PIN, PIN_MODE_0);
#ifndef CONFIG_UART_L0_NOT_SUPPORT_RX
        uart_port_set_pin(L0_RXD_PIN, PIN_MODE_0);
#endif
    }
    uart_port_reset(bus);
#else
    unused(bus);
#endif
}

#ifdef CONFIG_UART_SUPPORT_PORTTING_IRQ
void uart_port_register_irq(uart_bus_t bus)
{
    osal_irq_request(g_uart_interrupt_lines[bus].irq_num, g_uart_interrupt_lines[bus].irq_func, NULL, NULL, NULL);
    osal_irq_set_priority(g_uart_interrupt_lines[bus].irq_num, irq_prio(g_uart_interrupt_lines[bus].irq_num));
    osal_irq_enable(g_uart_interrupt_lines[bus].irq_num);
}

#if UART_BUS_MAX_NUMBER > 0
void irq_uart0_handler(void)
{
    hal_uart_irq_handler(UART_BUS_0);
}
#endif

#if UART_BUS_MAX_NUMBER > 1
void irq_uart1_handler(void)
{
    hal_uart_irq_handler(UART_BUS_1);
}
#endif

#if UART_BUS_MAX_NUMBER > 2
void irq_uart2_handler(void)
{
    hal_uart_irq_handler(UART_BUS_2);
}
#endif

void uart_port_unregister_irq(uart_bus_t bus)
{
    osal_irq_disable(g_uart_interrupt_lines[bus].irq_num);
    osal_irq_free(g_uart_interrupt_lines[bus].irq_num, NULL);
}

void uart_port_set_pending_irq(uart_bus_t uart)
{
    unused(uart);
}
#else
void uart_port_register_irq(uart_bus_t bus)
{
    unused(bus);
}

void uart_port_unregister_irq(uart_bus_t bus)
{
    unused(bus);
}
#endif

#if defined(AT_COMMAND)
#define CRLF_STR                      "\r\n"
#define CR_ASIC_II                    0xD

static uint8_t g_at_test_uart_rx_buffer_test[1];
static uart_bus_t g_at_uart_bus_id;

static uart_bus_t at_uart_get_bus_id(void)
{
#if defined CONFIG_DYNAMIC_UART_ID_BINDDING
    errcode_t ret;
    uint8_t uart_bus_id = 0;
    uint16_t uart_bus_id_len = 1;
    ret = uapi_nv_read(NV_ID_AT_UART_BUS_ID, uart_bus_id_len, &uart_bus_id_len, &uart_bus_id);
    if (ret != ERRCODE_SUCC) {
        uart_bus_id = TEST_SUITE_UART_BUS;
    }
    return (uart_bus_t)uart_bus_id;
#else
    return TEST_SUITE_UART_BUS;
#endif
}

static void at_write_func(const char *data)
{
    uapi_uart_write(g_at_uart_bus_id, (const uint8_t *)data, strlen(data), 0);
}

#define AT_CMD_DELAY 1000
static void at_uart_rx_callback(const void *buffer, uint16_t length, bool error)
{
    UNUSED(error);
    if (length == 0) {
        panic(PANIC_TESTSUIT, __LINE__);
    }
    if (((char *)buffer)[0] == CR_ASIC_II) {
        uapi_uart_write(g_at_uart_bus_id, (uint8_t *)CRLF_STR, (uint16_t)strlen(CRLF_STR), 0);
    } else {
        uapi_uart_write(g_at_uart_bus_id, (const uint8_t *)buffer, (uint32_t)length, 0);
    }

#if (ENABLE_LOW_POWER == YES)
    idle_pm_update_timeout(AT_CMD_DELAY);
#endif
#ifdef AT_DEBUG
    uint32_t ret = uapi_at_channel_data_recv(AT_UART_PORT, (uint8_t *)buffer, (uint32_t)length);
    if (ret != ERRCODE_SUCC) {
        PRINT("at exec fail:%x\r\n", ret);
    }
#else
    uapi_at_channel_data_recv(AT_UART_PORT, (uint8_t *)buffer, (uint32_t)length);
#endif
}

void at_uart_init(uint32_t baud_rate)
{
    uart_buffer_config_t uart_buffer_config;
    uart_pin_config_t uart_pin_config = {0};
    uart_attr_t uart_line_config = {
        .baud_rate = baud_rate,
        .data_bits = UART_DATA_BIT_8,
        .stop_bits = UART_STOP_BIT_1,
        .parity = UART_PARITY_NONE
    };
    uart_buffer_config.rx_buffer_size = sizeof(g_at_test_uart_rx_buffer_test);
    uart_buffer_config.rx_buffer = g_at_test_uart_rx_buffer_test;
    g_at_uart_bus_id = at_uart_get_bus_id();
    uapi_uart_deinit(g_at_uart_bus_id);
    uapi_uart_init(g_at_uart_bus_id, &uart_pin_config, &uart_line_config, NULL, &uart_buffer_config);
    uapi_uart_register_rx_callback(g_at_uart_bus_id, UART_RX_CONDITION_FULL_OR_SUFFICIENT_DATA_OR_IDLE,
        1, at_uart_rx_callback);
    uapi_at_channel_write_register(AT_UART_PORT, at_write_func);
}
#endif

#ifdef SW_UART_DEBUG
#include <stdio.h>
#ifdef USE_CMSIS_OS
#define DEBUG_UART_RX_BUFFER_SIZE 256
#else
#define DEBUG_UART_RX_BUFFER_SIZE 1
#endif

static uint8_t g_uart_rx_buffer[DEBUG_UART_RX_BUFFER_SIZE];

static void uart_rx_callback(const void *buf, uint16_t buf_len, bool remaining);

void sw_debug_uart_deinit(void)
{
    uapi_uart_deinit(g_sw_debug_uart);
}

void uart_rx_callback(const void *buf, uint16_t buf_len, bool remaining)
{
    UNUSED(remaining);
    uapi_uart_write(g_sw_debug_uart, (const void *)buf, buf_len, 0);
}

static uart_bus_t debug_uart_get_bus_id(void)
{
#if defined(CONFIG_DYNAMIC_UART_ID_BINDDING)
    errcode_t ret;
    uint8_t uart_bus_id = 0;
    uint16_t uart_bus_id_len = 1;
    ret = uapi_nv_read(NV_ID_DBG_UART_BUS_ID, uart_bus_id_len, &uart_bus_id_len, &uart_bus_id);
    if (ret != ERRCODE_SUCC) {
        uart_bus_id = SW_DEBUG_UART_BUS;
    }
    return (uart_bus_t)uart_bus_id;
#else
    return SW_DEBUG_UART_BUS;
#endif
}

/* 保存debug uart配置 */
static void sw_debug_uart_save(uart_bus_t uart_bus, uint32_t baud_rate)
{
    uint16_t uart_bus_cfg = 0;
    uint16_t valid = true;
    /* C核的BUS_0是L0, BUS_1是H1 */
    uart_bus_cfg = (uart_bus == UART_BUS_0) ? UART_BUS_1 : UART_BUS_0;
#ifdef CONFIG_UART_L0_NOT_SUPPORT_RX
    if (uart_bus == UART_BUS_2) {
        valid = false;
    }
#endif
    if (uart_bus == UART_BUS_1) {
        /* Acore BUS_1 is invalid for Ccore */
        valid = false;
    }
    uint16_t baud_rate_lsb = (uint16_t)(baud_rate & 0xFFFF);
    uint16_t baud_rate_msb = (uint16_t)((baud_rate >> UART_BAUD_RATE_SHIFT_BIT) & 0xFFFF);
    writel(UART_DBG_CFG, (uart_bus_cfg << UART_DBG_CFG_SHIFT_BIT) | valid);
    writel(UART_BAUD_RATE_LSB, baud_rate_lsb);
    writel(UART_BAUD_RATE_MSB, baud_rate_msb);
}

void sw_debug_uart_init(uint32_t baud_rate)
{
    uart_pin_config_t uart_pins = {0};
    uart_attr_t uart_line_config;
    uart_buffer_config_t uart_buffer_config;

    uart_line_config.baud_rate = baud_rate;
    uart_line_config.data_bits = UART_DATA_BIT_8;
    uart_line_config.parity = UART_PARITY_NONE;
    uart_line_config.stop_bits = UART_STOP_BIT_1;

    uart_buffer_config.rx_buffer_size = DEBUG_UART_RX_BUFFER_SIZE;
    uart_buffer_config.rx_buffer = g_uart_rx_buffer;
#ifdef SUPPORT_HAL_PINCTRL
    if (g_sw_debug_uart == UART_BUS_2) {
        uart_port_set_reset(UART_SOFT_RST_C, UART_SOFT_RST_L0_POS);
    }
#endif
    (void)uapi_uart_init(g_sw_debug_uart, &uart_pins, &uart_line_config, NULL, &uart_buffer_config);
    uapi_uart_register_rx_callback(g_sw_debug_uart, UART_RX_CONDITION_FULL_OR_SUFFICIENT_DATA_OR_IDLE,
                                   DEBUG_UART_RX_BUFFER_SIZE, uart_rx_callback);

    sw_debug_uart_save(g_sw_debug_uart, baud_rate);
}

void sw_debug_uart_reinit(uint32_t baud_rate)
{
    uart_bus_t bus = debug_uart_get_bus_id();
    if (bus == g_sw_debug_uart) {
        return;
    }

    uapi_uart_deinit(g_sw_debug_uart);
    g_sw_debug_uart = bus;
    sw_debug_uart_init(baud_rate);
    return;
}

#if (defined(SUPPORT_DFX_LOG) && (CORE == APPS) && defined(CONFIG_HSO_UART_SUPPORT))
#define LOG_UART_BAUD_RATE CONFIG_HSO_UART_BAUD_RATE
#define LOG_UART_RX_MAX_BUFFER_SIZE 16

static uart_bus_t g_hso_uart;
static uint8_t g_uart_log_rx_buffer[LOG_UART_RX_MAX_BUFFER_SIZE];
/* Initialise the UART and open it at the specified speed! */

static uart_bus_t hso_uart_get_bus_id(void)
{
#if defined CONFIG_DYNAMIC_UART_ID_BINDDING
    errcode_t ret;
    uint8_t uart_bus_id = 0;
    uint16_t uart_bus_id_len = 1;
    ret = uapi_nv_read(NV_ID_HSO_UART_BUS_ID, uart_bus_id_len, &uart_bus_id_len, &uart_bus_id);
    if (ret != ERRCODE_SUCC) {
        uart_bus_id = LOG_UART_BUS;
    }
    return (uart_bus_t)uart_bus_id;
#else
    return LOG_UART_BUS;
#endif
}

static void log_uart_rx_callback_all(const void *buffer, uint16_t length, bool remaining)
{
    log_uart_rx_callback(buffer, length, remaining);
#if (defined(AT_COMMAND))
    if (g_hso_uart == g_at_uart_bus_id && !zdiag_is_enable()) {
        at_uart_rx_callback(buffer, length, remaining);
}
#endif
}

void log_uart_port_init(void)
{
    /* Configure and open the UART port for use. */
    uart_pin_config_t log_uart_pins = {0};
    uart_attr_t uart_line_config = {
        .baud_rate = LOG_UART_BAUD_RATE,
        .data_bits = UART_DATA_BIT_8,
        .stop_bits = UART_STOP_BIT_1,
        .parity = UART_PARITY_NONE
    };
    uart_buffer_config_t uart_buffer_config;

    uart_buffer_config.rx_buffer_size = LOG_UART_RX_MAX_BUFFER_SIZE;
    uart_buffer_config.rx_buffer = g_uart_log_rx_buffer;

    g_hso_uart = hso_uart_get_bus_id();
    (void)uapi_uart_init(g_hso_uart, &log_uart_pins, &uart_line_config, NULL, &uart_buffer_config);

#if SYS_DEBUG_MODE_ENABLE == YES
    uapi_uart_register_rx_callback(g_hso_uart, UART_RX_CONDITION_FULL_OR_SUFFICIENT_DATA_OR_IDLE,
                                   LOG_UART_RX_MAX_BUFFER_SIZE, log_uart_rx_callback_all);
#endif
}
#endif
void log_uart_port_write(const uint8_t *buffer, uint32_t length)
{
#if (defined(SUPPORT_DFX_LOG) && (CORE == APPS) && defined(CONFIG_HSO_UART_SUPPORT))
    uapi_uart_write(g_hso_uart, buffer, length, 0);
#endif
    unused(buffer);
    unused(length);
}

errcode_t uart_port_save_bus_id(int32_t dbg_uart_bus, int32_t at_uart_bus, int32_t hso_uart_bus)
{
#define UART_PORT_BUS_NUM 3
    errcode_t err = ERRCODE_SUCC;
#if defined(CONFIG_DYNAMIC_UART_ID_BINDDING)
    uint16_t key[UART_PORT_BUS_NUM] = {NV_ID_DBG_UART_BUS_ID, NV_ID_AT_UART_BUS_ID, NV_ID_HSO_UART_BUS_ID};
    uint8_t bus[UART_PORT_BUS_NUM] = {(uint8_t)dbg_uart_bus, (uint8_t)at_uart_bus, (uint8_t)hso_uart_bus};

    for (uint8_t i = 0; i < UART_PORT_BUS_NUM; i++) {
        err = uapi_nv_write(key[i], &bus[i], sizeof(bus[i]));
        if (err != ERRCODE_SUCC) {
            break;
        }
    }
#else
    unused(dbg_uart_bus);
    unused(at_uart_bus);
    unused(hso_uart_bus);
#endif
    return err;
}

static errcode_t uartputs_hso(const char *s, uint32_t len)
{
#if (defined(SUPPORT_DFX_LOG) && (CORE == APPS) && defined(CONFIG_HSO_UART_SUPPORT))
    if (g_hso_uart != g_sw_debug_uart || !zdiag_is_enable()) {
        return ERRCODE_FAIL;
    }
    uint32_t sent_len = (uint32_t)zdiag_mocked_shell_uart_puts((unsigned char *)s, len);
    if (sent_len != len) {
        return ERRCODE_FAIL;
    }
    return ERRCODE_SUCC;
#else
    unused(s);
    unused(len);
    return ERRCODE_FAIL;
#endif
}
#ifdef SW_UART_CHIP_DEFINE
void UartPuts(const char *s, uint32_t len, bool is_lock)
{
    if ((s == NULL) || (strlen(s) == 0)) {
        return;
    }

    UNUSED(is_lock);
#ifdef SW_UART_DEBUG
     if (uartputs_hso(s, len) == ERRCODE_SUCC) {
        return;
    }
    uapi_uart_write(g_sw_debug_uart, (const void *)s, len, 0);
#elif defined(TEST_SUITE)
    test_suite_uart_send(s);
#elif defined(SW_RTT_DEBUG)
    SEGGER_RTT_Write(0, (const char *)s, len);
#else
    UNUSED(s);
    UNUSED(len);
#endif
}
#endif

static void print_str_inner(const char *fmt, va_list ap)
{
    int32_t len;
    static char str_buf[UART_TRANS_LEN_MAX] = {0};
    char *tmp_buf = NULL;
    uint32_t buflen = UART_TRANS_LEN_MAX;

    tmp_buf = str_buf;
    len = vsnprintf_s(tmp_buf, buflen, buflen - 1, fmt, ap);
    if ((len == -1) && (*tmp_buf == '\0')) {
        /* parameter is illegal or some features in fmt dont support */
        return;
    }
#ifdef CONFIG_PRINTF_BUFFER_DYNAMIC
    const char *errmsgmalloc = "print alloc err\n";
    while (len == -1) {
        /* tmp_buf is not enough */
        if (buflen != UART_TRANS_LEN_MAX) {
            osal_kfree(tmp_buf);
        }

        buflen = buflen << 1;
        tmp_buf = (char *)osal_kmalloc(buflen, OSAL_GFP_KERNEL);
        if (tmp_buf == NULL) {
            if (uartputs_hso(errmsgmalloc, strlen(errmsgmalloc)) != ERRCODE_SUCC) {
                uapi_uart_write(g_sw_debug_uart, (const uint8_t *)errmsgmalloc, (uint32_t)strlen(errmsgmalloc), 0);
            }
            return;
        }
        len = vsnprintf_s(tmp_buf, buflen, buflen - 1, fmt, ap);
        if (*tmp_buf == '\0') {
            /* parameter is illegal or some features in fmt dont support */
            osal_kfree(tmp_buf);
            return;
        }
    }
#endif
    *(tmp_buf + len) = '\0';
    if (uartputs_hso(tmp_buf, (uint32_t)len) != ERRCODE_SUCC) {
        uapi_uart_write(g_sw_debug_uart, (const uint8_t *)tmp_buf, (uint32_t)len, 0);
    }
#ifdef CONFIG_PRINTF_BUFFER_DYNAMIC
    if (buflen != UART_TRANS_LEN_MAX) {
        osal_kfree(tmp_buf);
    }
#endif
}

void print_str(const char *str, ...)
{
    va_list args;
    if ((str == NULL) || (strlen(str) == 0)) {
        return;
    }
    va_start(args, str);
    print_str_inner(str, args);
    va_end(args);
}

void __attribute__((weak)) uapi_at_print(const char* str, ...)
{
    va_list args;
    if ((str == NULL) || (strlen(str) == 0)) {
        return;
    }
    va_start(args, str);
    print_str_inner(str, args);
    va_end(args);
}
#endif

void hal_uart_clear_pending(uart_bus_t uart)
{
    switch (uart) {
#if UART_BUS_MAX_NUMBER > 0
        case UART_BUS_0:
            osal_irq_clear(UART_0_IRQN);
            break;
#endif
#if UART_BUS_MAX_NUMBER > 1
        case UART_BUS_1:
            osal_irq_clear(UART_1_IRQN);
            break;
#endif
#if UART_BUS_MAX_NUMBER > 2
        case UART_BUS_2:
            osal_irq_clear(UART_2_IRQN);
            break;
#endif
        default:
            break;
    }
}

uint32_t uart_porting_lock(uart_bus_t bus)
{
    unused(bus);
    return osal_irq_lock();
}

void uart_porting_unlock(uart_bus_t bus, uint32_t irq_sts)
{
    unused(bus);
    osal_irq_restore(irq_sts);
}

#if defined(CONFIG_UART_MULTI_CORE_RESUME)
#include "clock_recover.h"
bool uart_porting_skip_resume(uart_bus_t bus)
{
    if (bus == UART_BUS_2) {
        if (readl(UART_CFG_STS) == 0x1) {
            return true;
        } else {
            writel(UART_CFG_STS, 0x1); // 设置uart状态
        }
    }
    return false;
}
#endif

#if defined(CONFIG_UART_SUPPORT_DMA)
#if defined(CONFIG_UART_SUPPORT_INT_TRIGGER_DMA)
void uart_porting_int_enable(uart_bus_t bus)
{
    if (bus >= UART_BUS_MAX_NUM) {
        return;
    }

    osal_irq_enable(g_uart_interrupt_lines[bus].irq_num);
}

void uart_porting_int_disable(uart_bus_t bus)
{
    if (bus >= UART_BUS_MAX_NUM) {
        return;
    }

    osal_irq_disable(g_uart_interrupt_lines[bus].irq_num);
}
#endif  /* CONFIG_UART_SUPPORT_INT_TRIGGER_DMA */

uint8_t uart_port_get_dma_trans_dest_handshaking(uart_bus_t bus)
{
    switch (bus) {
        case UART_BUS_0:
            return (uint8_t)HAL_DMA_HANDSHAKING_UART_H1_TX;
        case UART_BUS_1:
            return (uint8_t)HAL_DMA_HANDSHAKING_UART_H0_TX;
        default:
            return (uint8_t)HAL_DMA_HANDSHAKING_MAX_NUM;
    }
    return 0;
}

uint8_t uart_port_get_dma_trans_src_handshaking(uart_bus_t bus)
{
    switch (bus) {
        case UART_BUS_0:
            return (uint8_t)HAL_DMA_HANDSHAKING_UART_H1_RX;
        case UART_BUS_1:
            return (uint8_t)HAL_DMA_HANDSHAKING_UART_H0_RX;
        default:
            return (uint8_t)HAL_DMA_HANDSHAKING_MAX_NUM;
    }
    return 0;
}
#endif  /* CONFIG_UART_SUPPORT_DMA */