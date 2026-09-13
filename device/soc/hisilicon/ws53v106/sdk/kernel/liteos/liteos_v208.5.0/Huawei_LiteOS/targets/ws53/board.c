/* ----------------------------------------------------------------------------
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Board config before os start.
 * Author: Huawei LiteOS Team
 * Create: 2022-01-28
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 * of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific prior written
 * permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * --------------------------------------------------------------------------- */

#include "los_typedef.h"
#include "los_printf.h"
#include "los_printf_pri.h"
#include "los_task_pri.h"
#include "los_tick_pri.h"
#include "asm/memmap_config.h"
#include "los_init_pri.h"
#include "los_memory_pri.h"
#include "los_memory.h"
#ifdef LOSCFG_MEM_LEAKCHECK_CUSTOM
#include "board_ws53.h"
#include "los_exc_pri.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

VOID BoardConfig(VOID)
{
#ifdef LOSCFG_LIB_CONFIGURABLE
    g_sysMemAddr = (void *)&g_intheap_begin;
    g_sysMemSize = (unsigned)&g_intheap_size;
#endif

    OsSetMainTask();
    OsCurrTaskSet(OsGetMainTask());
#if defined(LOSCFG_MEM_LEAKCHECK_CUSTOM) && defined(LOSCFG_MEM_LEAKCHECK)
    LOS_HookReg(LOS_HOOK_MEMLEAK_CUSTOM, ArchBackTraceCustom);
#endif
}

void irmalloc_init_default(void)
{
}

UINT32 oal_get_sleep_ticks(VOID)
{
    UINT32 intSave;
    intSave = LOS_IntLock();
    UINT32 taskTimeout = OsSortLinkGetNextExpireTime(&OsPercpuGet()->taskSortLink);
#ifdef LOSCFG_BASE_CORE_SWTMR
    UINT32 swtmrTimeout = OsSortLinkGetNextExpireTime(&OsPercpuGet()->swtmrSortLink);
    if (swtmrTimeout < taskTimeout) {
        taskTimeout = swtmrTimeout;
    }
#endif
    LOS_IntRestore(intSave);
    return taskTimeout;
}

VOID oal_ticks_restore(UINT32 ticks)
{
    UINT32 intSave;
    UINT32 taskTimeout;
    intSave = LOS_IntLock();
    g_tickCount[ArchCurrCpuid()] += ticks;

    taskTimeout = OsSortLinkGetNextExpireTime(&OsPercpuGet()->taskSortLink);
    if (taskTimeout > ticks) {
        OsSortLinkUpdateExpireTime(ticks + 1, &(OsPercpuGet()->taskSortLink));
    } else {
        OsSortLinkUpdateExpireTime(taskTimeout, &(OsPercpuGet()->taskSortLink));
    }
#ifdef LOSCFG_BASE_CORE_SWTMR
    taskTimeout = OsSortLinkGetNextExpireTime(&(OsPercpuGet()->swtmrSortLink));
    if (taskTimeout > ticks) {
        OsSortLinkUpdateExpireTime(ticks + 1, &(OsPercpuGet()->swtmrSortLink));
    } else {
        OsSortLinkUpdateExpireTime(taskTimeout, &(OsPercpuGet()->swtmrSortLink));
    }
#endif

    LOS_IntRestore(intSave);
}

#ifdef LOSCFG_MEM_TASK_STAT
unsigned int oal_get_sys_min_mem_bytes(void)
{
    LosMemPoolInfo *poolInfo = (LosMemPoolInfo *)OS_SYS_MEM_ADDR;
    UINT32 min_mem = 0;

    if (poolInfo == NULL) {
        return 0;
    }

    if (OS_SYS_MEM_SIZE > poolInfo->stat.memTotalPeak) {
        min_mem = OS_SYS_MEM_SIZE - poolInfo->stat.memTotalPeak;
    }

    return min_mem;
}
#endif

#ifdef LOSCFG_MEM_LEAKCHECK_CUSTOM
#define ROM_START  0x19C00
#define ROM_LENGTH 0x6400
#define ROM_END    (ROM_START + ROM_LENGTH)
#define RAM_END    0x20060000
/* 放在SRAM运行的代码的text&rodata段在初始阶段需要从flash拷贝到ram */
static bool check_txt_addr_range(uint32_t pc, uint32_t text_start, uint32_t text_end)
{
    if (pc >= text_start && pc < text_end) {
        return true;
    } else {
        return false;
    }
}

static bool is_valid_txt_addr(uint32_t pc)
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

#define  USER_STACK_OFFSET_PER   4
#define  USER_STACK_PRINT_DEPTH  128
#define get_temp_sp(temp_sp) __asm volatile("mv %0, sp" : "=r"(temp_sp))
LITE_OS_SEC_TEXT void ArchBackTraceCustom(UINTPTR *array, UINTPTR arry_len)
{
    unsigned long back_sp;
    get_temp_sp(back_sp);
    uint32_t count = 0;
    while ((back_sp != 0) && (back_sp < RAM_END)) {
        if (is_valid_txt_addr(*((uint32_t *)(uintptr_t)(back_sp))) != 0) {
            if (count < arry_len) {
                array[count] =  *((uint32_t *)(back_sp));
                count++;
            } else {
                break;
            }
        }
        back_sp = back_sp + USER_STACK_OFFSET_PER;
    }
}
#endif
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
