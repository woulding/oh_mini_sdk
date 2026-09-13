/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description:  nonos interrupt
 */
#include "chip_io.h"
#include "td_type.h"
#include "errcode.h"
#include "vectors.h"
#include "non_os.h"
#include "watchdog.h"
#include "debug_print.h"
#include "arch_encoding.h"
#ifdef SUPPORT_EXCEPTION
#include "exception.h"
#endif
#include "nonos_isr.h"

#define INT_CCAUSE            0xFC2
#define INT_NUM_MAX           0xFFF
#define INT_MCAUSE_INTER_BIT  0x80000000
#define NMI_INTERRUPT         0x8000000C
typedef struct tag_hwi_handle_form {
    isr_function pfn_hook;  /* User registered callback function */
} hwi_handle_form_s;

hwi_handle_form_s g_hwiform[RISCV_VECTOR_CNT] = { 0 };

static bool hal_is_exception(void)
{
    if ((read_custom_csr(MCAUSE) & INT_MCAUSE_INTER_BIT) != 0) {
        return TD_FALSE;
    }
    return TD_TRUE;
}

/* 异常处理 */
void hal_exception_handle(void)
{
    uint32_t exc_type = read_csr(mcause);
    PRINT("exception:%x\r\n", exc_type);
    if (exc_type == NMI_INTERRUPT) {
        PRINT("NMI raw interrupt is 0x%x\r\n", non_os_get_nmi_raw_status());
    }
#ifdef SUPPORT_EXCEPTION
    except_info_t *exc_info = (except_info_t *)(uintptr_t)(CT_PRESERVE_SHARE_ORIGIN);
    do_hard_fault_handler(exc_info);
#endif
}

/* 中断处理 */
void hal_interrupt_handle(void)
{
    isr_function func = NULL;
    uint32_t irq_num = interrupt_number_get();
    if (irq_num >= ISR_VECTOR_IRQ_BUFF) {
        return;
    }

    func = g_hwiform[irq_num].pfn_hook;
    if (func != NULL) {
        func();
    } else {
        PRINT("hal_irq_handler err: irq_num[%d] not register.\r\n", irq_num);
    }
}

/* 中断/异常处理入口 */
void hal_trap_handler(void)
{
    /* 异常处理 */
    if (hal_is_exception()) {
        hal_exception_handle();
    } else {  /* 中断处理 */
        hal_interrupt_handle();
    }
}

/* 中断注册 */
uint32_t int_set_irq_func(uint32_t irq_num, isr_function callback)
{
    if (irq_num >= RISCV_VECTOR_CNT) {
        return ERRCODE_INVALID_PARAM;
    }

    if (callback == NULL) {
        g_hwiform[irq_num].pfn_hook = NULL;
        return ERRCODE_SUCC;
    }

    if (g_hwiform[irq_num].pfn_hook != NULL) {
        return ERRCODE_FAIL;
    }
    g_hwiform[irq_num].pfn_hook = callback;
    return ERRCODE_SUCC;
}

uint32_t hal_register_nmi_irq(void)
{
    return int_set_irq_func(NON_MASKABLE_INT_IRQN, (isr_function)hal_exception_handle);
}