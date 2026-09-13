/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Malloc function.
 */

#include "chip_io.h"
#include "ccore_memory_config.h"
#ifdef _DEBUG_HEAP_MEM_MGR
#include "dbg_heap_memory.h"
#endif
#include "clock_recover.h"
#include "malloc.h"
#include "malloc_porting.h"

#define BANK_EM_USE_CFG_REG 0x57030390

void malloc_port_init(void)
{
    malloc_funcs malloc_funcs = { 0 };
    malloc_funcs.init = malloc_init;
    malloc_funcs.free = free;
    malloc_funcs.malloc = rom_malloc;
    malloc_register_funcs(&malloc_funcs);

#ifndef BUILD_NOOSAL // 区分boot/ssb/flashboot和APP
    // APP
#ifdef CONFIG_MCU_MODE_2
    malloc_init((uintptr_t)EM_MUX_RAM_ORIGIN, (uintptr_t)EM_MUX_RAM_ORIGIN + C_USER_SMALL_HEAP_LEN);
#else
    if (reg32_getbit(MCU_MODE_COMMON_REG, MCU_MODE_3_MASK) == 0x1) {
        malloc_init((uintptr_t)(&__bt_text_begin__), (uintptr_t)(&__bt_text_begin__) + C_USER_SMALL_HEAP_LEN);
    } else if (reg32_getbit(MCU_MODE_COMMON_REG, MCU_MODE_4_MASK) == 0x1) {
        malloc_init((uintptr_t)EM_MUX_RAM_ORIGIN + (uintptr_t)EM_MUX_RAM_LEN,
            (uintptr_t)EM_MUX_RAM_ORIGIN + (uintptr_t)EM_MUX_RAM_LEN + (uintptr_t)C_USER_HEAP_LEN);
    } else {
        malloc_init((uintptr_t)(&g_intheap_begin),
                    (uintptr_t)(&g_intheap_begin) + (uintptr_t)(&g_intheap_size));
    }
#endif
#else
    // boot
    malloc_init((uintptr_t)(&g_intheap_begin),
                (uintptr_t)(&g_intheap_begin) + (uintptr_t)(&g_intheap_size));
#endif

#ifdef _DEBUG_HEAP_MEM_MGR
    heap_mem_tab_init();
    malloc_funcs.free = heap_mem_free;
    malloc_funcs.malloc = heap_mem_malloc;
    malloc_register_funcs(&malloc_funcs);
#endif
}
