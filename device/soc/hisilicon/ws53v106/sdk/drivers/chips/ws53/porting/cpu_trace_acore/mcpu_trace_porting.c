/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Provides acore cpu trace port \n
 */

#include "debug_print.h"
#ifdef CONFIG_ACORE_CPU_TRACE
#include "securec.h"
#include "arch_trace.h"
#include "td_base.h"
#include "soc_osal.h"
#include "hal_cpu_trace.h"
#include "cpu_trace.h"
#ifdef CONFIG_SUPPORT_CRASHINFO_SAVE_TO_FLASH
#include "sfc.h"
#include "memory_config_common.h"
#endif
#include "mcpu_trace_porting.h"
#endif
#define MCU_DIAG_SAMPLE_DONE_ADDR_L 0x52004220
#define MCU_DIAG_SAMPLE_DONE_ADDR_H 0x52004224
#define MCU_DIAG_SAMPLE_DONE        0x52004220
#define MCU_DIAG_DATA_SIZE          0xC
/* 保证成对采集12的倍数 */
#define mcu_diag_data_len(len)      ((((len) - MCU_DIAG_DATA_SIZE) / MCU_DIAG_DATA_SIZE) * MCU_DIAG_DATA_SIZE)

#ifdef CONFIG_ACORE_CPU_TRACE
typedef struct {
    uint32_t data_a;
    uint32_t data_b;
    uint32_t data_curr;
    uint32_t len;
    cpu_trace_mode mode;
} mcpu_trace_stru;

static mcpu_trace_stru g_cpu_trace = {0};
static bool g_record_sw_data = false;

void mcpu_trace_init(cpu_trace_mode mode)
{
    uint32_t len = CPU_TRACE_MEM_REGION_LENGTH;
    uint32_t *p = (uint32_t *)osal_kmalloc_align(len, OSAL_GFP_KERNEL, sizeof(uint32_t));
    if (p == NULL) {
        PRINT("mcpu_trace_init malloc[%d] fail.\r\n", len);
        return;
    }
    uint32_t addr = (uint32_t)(uintptr_t)p;
    g_cpu_trace.data_a = addr;
    g_cpu_trace.data_curr = g_cpu_trace.data_a;
    g_cpu_trace.len = mcu_diag_data_len(len);
    g_cpu_trace.mode = mode;
    if (mode == PING_PANG_MODE) {
        g_cpu_trace.len = mcu_diag_data_len(len >> 1);
        g_cpu_trace.data_b = addr + g_cpu_trace.len;
    }
    mcpu_trace_enable();
}

void mcpu_trace_set_len(uint32_t len)
{
    g_cpu_trace.len = len;
}

void mcpu_trace_enable(void)
{
    uint32_t trace_start, trace_end;

    if (g_cpu_trace.data_curr == 0) {
        return;
    }
    trace_start = g_cpu_trace.data_curr;
    trace_end = trace_start + g_cpu_trace.len;
    cpu_trace_enable(CPU_TRACE_TRACED_MCPU, CPU_TRACE_SAMPLE_MODE_REPEAT, trace_start, trace_end);
}

/* 切换另一块内存 */
static void mcpu_trace_sw_curr_data(void)
{
    if (g_cpu_trace.mode != PING_PANG_MODE) {
        return;
    }
    if (g_cpu_trace.data_curr == g_cpu_trace.data_a) {
        g_cpu_trace.data_curr = g_cpu_trace.data_b;
    } else {
        g_cpu_trace.data_curr = g_cpu_trace.data_a;
    }
}

static void mcpu_trace_print_item(uint32_t sample_done_addr, uint32_t start, uint32_t end)
{
    riscv_cpu_trace_item_t *item = NULL;
    PRINT("acore: addr:0x%x-0x%x, len:%d, sample_done_addr[0x%x] .\r\n",
        start, end, end - start, sample_done_addr);
    item = (riscv_cpu_trace_item_t *)(uintptr_t)start;
    for (uint32_t i = 0; (uint32_t)(uintptr_t)(&item[i].time) < end; i++) {
        PRINT("trace %d --- addr 0x%x, time: 0x%x, LR: 0x%x, PC: 0x%x.\r\n", i, &item[i].time,
            item[i].time, item[i].lr, item[i].pc);
    }
}

void mcpu_trace_print(void)
{
    uint16_t sample_done, addr_l, addr_h;
    uint32_t start, end, sample_done_addr;

    /* 读取数据前需先停止数采 */
    cpu_trace_disable();
    sample_done = uapi_reg_read_val16(MCU_DIAG_SAMPLE_DONE);
    if (sample_done == 0) {
        PRINT("mcpu_trace_print: sample_done err.\r\n");
        return;
    }

    addr_l = uapi_reg_read_val16(MCU_DIAG_SAMPLE_DONE_ADDR_L);
    addr_h = uapi_reg_read_val16(MCU_DIAG_SAMPLE_DONE_ADDR_H);
    sample_done_addr = uapi_makeu32(addr_l, addr_h);
    start = g_cpu_trace.data_curr;
    end = start + g_cpu_trace.len;
    /* 输出当前cputrace数据 */
    mcpu_trace_print_item(sample_done_addr, start, end);

    /* 输出深睡前保存的cputrace数据 */
    if (g_cpu_trace.mode == PING_PANG_MODE && g_record_sw_data) {
        mcpu_trace_sw_curr_data();
        start = g_cpu_trace.data_curr;
        end = start + g_cpu_trace.len;
        PRINT("before lp.\r\n");
        mcpu_trace_print_item(0, start, end);
        g_record_sw_data = false;
    }
}

#ifdef CONFIG_SUPPORT_CRASHINFO_SAVE_TO_FLASH
void mcpu_trace_save(uint32_t addr, uint32_t size)
{
    uint16_t sample_done;
    uint32_t start, len, save_len;
    uint32_t flash_save_offset = addr;
    uint32_t left_size = size;
    uint32_t str_len = (uint32_t)sizeof(riscv_cpu_trace_item_t);

    sample_done = uapi_reg_read_val16(MCU_DIAG_SAMPLE_DONE);
    if (sample_done == 0) {
        return;
    }

    mcpu_trace_sw_curr_data();
    start = g_cpu_trace.data_curr;
    len = g_cpu_trace.len;

    uint32_t need_size = (uint32_t)(len + sizeof(uint32_t) + sizeof(uint32_t));
    if (need_size  > left_size) {
        save_len = (left_size - (uint32_t)sizeof(uint32_t) - (uint32_t)sizeof(uint32_t)) / str_len * str_len;
    } else {
        save_len = len;
    }

    uapi_sfc_reg_write(flash_save_offset, (uint8_t *)(uintptr_t)(&save_len), sizeof(uint32_t));
    flash_save_offset += (uint32_t)sizeof(uint32_t);
    uapi_sfc_reg_write(flash_save_offset, (uint8_t *)(uintptr_t)(&start), sizeof(uint32_t));
    flash_save_offset += (uint32_t)sizeof(uint32_t);

    riscv_cpu_trace_item_t *item = (riscv_cpu_trace_item_t *)(uintptr_t)start;
    for (uint32_t i = 0; (uint32_t)(uintptr_t)(&item[i].time) < start + save_len; i++) {
        uapi_sfc_reg_write(flash_save_offset, (uint8_t *)(uintptr_t)(&(item[i])), str_len);
        flash_save_offset += str_len;
    }

    left_size -= need_size;
    if (g_cpu_trace.mode == PING_PANG_MODE) {
        mcpu_trace_sw_curr_data();
        start = g_cpu_trace.data_curr;
        len = g_cpu_trace.len;

        need_size = len + (uint32_t)sizeof(uint32_t) + (uint32_t)sizeof(uint32_t);

        if (need_size  > left_size) {
            save_len = (left_size - (uint32_t)sizeof(uint32_t) - (uint32_t)sizeof(uint32_t)) / str_len * str_len;
        } else {
            save_len = len;
        }

        uapi_sfc_reg_write(flash_save_offset, (uint8_t *)(uintptr_t)(&save_len), sizeof(uint32_t));
        flash_save_offset += (uint32_t)sizeof(uint32_t);
        uapi_sfc_reg_write(flash_save_offset, (uint8_t *)(uintptr_t)(&start), sizeof(uint32_t));
        flash_save_offset += (uint32_t)sizeof(uint32_t);

        item = (riscv_cpu_trace_item_t *)(uintptr_t)start;
        for (uint32_t i = 0; (uint32_t)(uintptr_t)(&item[i].time) < start + save_len; i++) {
            uapi_sfc_reg_write(flash_save_offset, (uint8_t *)(uintptr_t)(&(item[i])), str_len);
            flash_save_offset += str_len;
        }
    }
}

static void mcpu_trace_dump_item(uint32_t sample_done_addr, uint32_t start, uint32_t end, uint32_t *offset)
{
    riscv_cpu_trace_item_t item = {0};
    PRINT("acore: addr:0x%x-0x%x, len:%d, sample_done_addr[0x%x] .\r\n", start, end, end - start, sample_done_addr);
    for (uint32_t i = 0; i * sizeof(riscv_cpu_trace_item_t) < end - start; i++) {
        uapi_sfc_reg_read(*offset, (uint8_t *)(uintptr_t)&item, sizeof(riscv_cpu_trace_item_t));
        *offset += (uint32_t)sizeof(riscv_cpu_trace_item_t);
        PRINT("trace %d --- addr 0x%x, time: 0x%x, LR: 0x%x, PC: 0x%x.\r\n", i,
            start + i * sizeof(riscv_cpu_trace_item_t), item.time, item.lr, item.pc);
    }
}

void mcpu_trace_dump(uint32_t addr)
{
    uint32_t flash_save_offset = addr;
    uint32_t len = 0;
    uint32_t start_addr = 0;
    uapi_sfc_reg_read(flash_save_offset, (uint8_t *)(uintptr_t)&len, sizeof(uint32_t));
    if (len > CPU_TRACE_MEM_REGION_LENGTH) {
        return;
    }
    flash_save_offset += (uint32_t)sizeof(uint32_t);
    uapi_sfc_reg_read(flash_save_offset, (uint8_t *)(uintptr_t)&start_addr, sizeof(uint32_t));
    flash_save_offset += (uint32_t)sizeof(uint32_t);
    mcpu_trace_dump_item(0, start_addr, start_addr + len, &flash_save_offset);
    uapi_sfc_reg_read(flash_save_offset, (uint8_t *)(uintptr_t)&len, sizeof(uint32_t));
    if (len > CPU_TRACE_MEM_REGION_LENGTH) {
        return;
    }
    flash_save_offset += (uint32_t)sizeof(uint32_t);
    uapi_sfc_reg_read(flash_save_offset, (uint8_t *)(uintptr_t)&start_addr, sizeof(uint32_t));
    flash_save_offset += (uint32_t)sizeof(uint32_t);
    PRINT("before lp.\r\n");
    mcpu_trace_dump_item(0, start_addr, start_addr + len, &flash_save_offset);
}
#endif

/* 深睡唤醒后，切换另一块内存数采 */
void mcpu_trace_resume(void)
{
    mcpu_trace_sw_curr_data();
    mcpu_trace_enable();
    g_record_sw_data = true;
}
#endif