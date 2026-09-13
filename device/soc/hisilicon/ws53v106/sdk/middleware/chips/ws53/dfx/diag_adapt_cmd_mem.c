/*
 * Copyright (c) CompanyNameMagicTag 2022-2022. All rights reserved.
 * Description: diag mem adapt
 * This file should be changed only infrequently and with great care.
 */

#include "diag_cmd_mem_read_write.h"

typedef struct diag_mem_config {
    uintptr_t start_addr;
    uintptr_t end_addr;
} diag_mem_config_t;

static const diag_mem_config_t g_mem_config[] = {
    { 0x5900A060, 0x5900A064 }, // DURATION调整寄存器
    { 0x5900A0D0, 0x5900A0D4 }, // TXOP结束发送CF END的最小时间
    { 0x5900A138, 0x5900A13C }, // 旁路控制寄存器
    { 0x5900A064, 0x5900A06C }, // 接收Duration最大值
    { 0x5900A098, 0x5900A0A0 }, // AC队列/MU时各队列的竞争窗口
    { 0x5900A0B0, 0x5900A0B8 }, // AC各队列TXOP LIMIT
    { 0x570360A0, 0x570360b8 }, // SFC
    { 0x00020000, 0x0004FFFF }, // ITCM
    { 0x20000000, 0x20067FFF }, // DTCM
    { 0x00400000, 0x01400000 }, // FLASH
};

static bool diag_permit_check(uintptr_t start_addr, uintptr_t end_addr)
{
    bool ret = false;
    uint32_t loop;

    for (loop = 0; loop < sizeof(g_mem_config) / sizeof(diag_mem_config_t); loop++) {
        if ((g_mem_config[loop].start_addr <= start_addr) && (g_mem_config[loop].end_addr >= end_addr)) {
            ret = true;
            break;
        }
    }
    return ret;
}

bool diag_cmd_permit_read(uintptr_t start_addr, uintptr_t end_addr)
{
    return diag_permit_check(start_addr, end_addr);
}

bool diag_cmd_permit_write(uintptr_t start_addr, uintptr_t end_addr)
{
    return diag_permit_check(start_addr, end_addr);
}
