/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Provides acore cpu trace port \n
 */

#ifndef MCPU_TRACE_PORTING_H
#define MCPU_TRACE_PORTING_H

#include <bits/alltypes.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef enum mode {
    PING_PANG_MODE = 0,
    ONE_PKT_MODE = 1
} cpu_trace_mode;

void mcpu_trace_init(cpu_trace_mode mode);
void mcpu_trace_enable(void);
void mcpu_trace_print(void);
void mcpu_trace_resume(void);
void mcpu_trace_set_len(uint32_t len);

#ifdef CONFIG_SUPPORT_CRASHINFO_SAVE_TO_FLASH
void mcpu_trace_save(uint32_t addr, uint32_t size);
void mcpu_trace_dump(uint32_t addr);
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif