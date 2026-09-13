/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:  OAM TRACE for RISCV31
 *
 * Create: 2021-10-25
 */
#include "oam_trace.h"
#include "memory_info.h"
#include "print_config.h"
#include "arch_encoding.h"
#include "arch_trace.h"
#include "mcpu_trace_porting.h"
#include "share_mem_config.h"

#define  USER_STACK_OFFSET_PER   4
#define  USER_STACK_PRINT_DEPTH  128

static bool check_txt_addr_range(uint32_t pc, uint32_t text_start, uint32_t text_end)
{
    if (pc >= text_start && pc < text_end) {
        return true;
    } else {
        return false;
    }
}

bool is_valid_txt_addr(uint32_t pc)
{
    /* sram text */
    if (check_txt_addr_range(pc, (uintptr_t)_g_sramtext_begin, (uintptr_t)_g_sramtext_end)) {
        return true;
    }

    /* flash text */
    if (check_txt_addr_range(pc, (uintptr_t)_g_flashtext_begin, (uintptr_t)_g_flashtext_end)) {
        return true;
    }

    /* rom */
    if (check_txt_addr_range(pc, ROM_START, ROM_START + ROM_LENGTH)) {
        return true;
    }

    return false;
}

static void back_trace(uint32_t sp)
{
    uint32_t back_sp = sp;
    uint32_t count = 0;
    print_stack_waterline_riscv();
    print_heap_statistics_riscv();
    oam_trace_print("*******backtrace begin*******\n");
    while (back_sp != 0) {
        if (is_valid_txt_addr(*((uint32_t *)(uintptr_t)(back_sp))) != 0) {
            oam_trace_print("traceback %d -- sp addr= 0x%x   sp content= 0x%x\n",
                count, back_sp, *((uint32_t *)(back_sp)));
        }
        back_sp = back_sp + USER_STACK_OFFSET_PER;
        count++;
        if (count == USER_STACK_PRINT_DEPTH) {
            break;
        }
    }
    oam_trace_print("*******backtrace end*******\n");
}

static void print_excptsc(void)
{
    oam_trace_print("cxcptsc = 0x%x\n", read_custom_csr(CXCPTSC));
}

#ifdef USE_CMSIS_OS
EXC_PROC_FUNC g_exec_hook;
void exec_fault_handler(uint32_t exc_type, const ExcContext *exc_buff_addr)
{
    riscv_cpu_trace_disable();
    if (g_exec_hook != NULL) {
        g_exec_hook(exc_type, exc_buff_addr);
    }
    print_excptsc();
    if (exc_buff_addr != NULL) {
        oam_trace_print("*******backtrace begin*******\r\n");
        ArchBackTraceGet(exc_buff_addr->taskContext.s0, NULL, USER_STACK_PRINT_DEPTH, 0);
        oam_trace_print("*******backtrace end*******\r\n");
        back_trace(exc_buff_addr->taskContext.sp);
    }
#if defined(SUPPORT_CPU_TRACE) && defined(CONFIG_ACORE_CPU_TRACE)
    mcpu_trace_print();
#endif
}
#endif

void register_os_exec_hook(void)
{
    g_exec_hook = ArchGetExcHook();
    ArchSetExcHook((EXC_PROC_FUNC)exec_fault_handler);
}

