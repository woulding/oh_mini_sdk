/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: for osal adapt.
 *
 * Create: 2023-04-21
*/

#include "crypto_osal_lib.h"
#include "drv_trng.h"
#include "crypto_osal_adapt.h"
#include "crypto_drv_common.h"
#include "tcxo.h"
#include "osal_adapt.h"
#include "limits.h"

unsigned long crypto_osal_get_phys_addr(const crypto_buf_attr *buf)
{
    crypto_chk_return(buf == NULL, 0, "buf is NULL\n");
    return (unsigned long)(buf->phys_addr);
}

void crypto_cache_flush(uintptr_t base_addr, td_u32 size)
{
    osal_dcache_region_clean((void *)base_addr, size);
}

void crypto_cache_inv(uintptr_t base_addr, td_u32 size)
{
    osal_dcache_region_inv((void *)base_addr, size);
}

void crypto_cache_all(void)
{
    osal_dcache_flush_all();
}

void crypto_dump_phys_addr(const char *name, const td_phys_addr_t phys_addr, td_u32 data_len)
{
    crypto_dump_data(name, (void *)(uintptr_t)phys_addr, data_len);
}

td_bool crypto_data_buf_check(const crypto_buf_attr *buf_attr, td_u32 length)
{
    crypto_unused(buf_attr);
    crypto_unused(length);
    return TD_TRUE;
}

static crypto_atomic g_deepsleep_vote = {0};

void crypto_preprocess(void)
{
    if (crypto_atomic_read(&g_deepsleep_vote) == 0) {
        uapi_pm_add_sleep_veto(PM_SECURITY_VETO_ID);
    }
    if (crypto_atomic_read(&g_deepsleep_vote) < INT_MAX) {
        crypto_atomic_inc(&g_deepsleep_vote);
    }
}

void crypto_postprocess(void)
{
    if (crypto_atomic_read(&g_deepsleep_vote) > 0) {
        crypto_atomic_dec(&g_deepsleep_vote);
    }
    if (crypto_atomic_read(&g_deepsleep_vote) == 0) {
        uapi_pm_remove_sleep_veto(PM_SECURITY_VETO_ID);
    }
}

#if defined(CONFIG_CRYPTO_PERF_STATISTICS)
#define CRYPTO_TIMER_COUNT                  10
#define CRYPTO_ITEM_COUNT_IN_ONE_TIMER      1024
typedef struct {
    td_u64 start_time;
    const td_char *name;
    td_u64 cost_times[CRYPTO_ITEM_COUNT_IN_ONE_TIMER];
    const td_char *item_name_list[CRYPTO_ITEM_COUNT_IN_ONE_TIMER];
    td_u32 current_idx;
} crypto_timer_t;

static crypto_timer_t g_timer_list[CRYPTO_TIMER_COUNT];

td_void crypto_timer_start(td_u32 timer_id, const td_char *name)
{
    if (timer_id >= CRYPTO_TIMER_COUNT) {
        crypto_log_err("invalid timer_id\n");
        return;
    }
    g_timer_list[timer_id].start_time = uapi_tcxo_get_us();
    g_timer_list[timer_id].name = name;
    g_timer_list[timer_id].current_idx = 0;
}

td_u64 crypto_timer_end(td_u32 timer_id, const td_char *item_name)
{
    td_u64 cost_in_us = 0;
    td_u32 idx = 0;
    if (timer_id >= CRYPTO_TIMER_COUNT) {
        crypto_log_err("invalid timer_id\n");
        return 0;
    }
    if (g_timer_list[timer_id].current_idx >= CRYPTO_ITEM_COUNT_IN_ONE_TIMER) {
        crypto_log_err("item count overflow\n");
        return 0;
    }

    idx = g_timer_list[timer_id].current_idx;
    cost_in_us = uapi_tcxo_get_us() - g_timer_list[timer_id].start_time;
    g_timer_list[timer_id].cost_times[idx] = cost_in_us;
    g_timer_list[timer_id].item_name_list[idx] = item_name;
    g_timer_list[timer_id].start_time = uapi_tcxo_get_us();
    g_timer_list[timer_id].current_idx++;
    return cost_in_us;
}

td_void crypto_timer_print(td_u32 timer_id)
{
    crypto_timer_t *timer = TD_NULL;
    td_u32 i;
    if (timer_id >= CRYPTO_TIMER_COUNT) {
        crypto_log_err("invalid timer_id\r\n");
        return;
    }

    timer = &g_timer_list[timer_id];
    if (timer->current_idx == 0) {
        return;
    }
    crypto_print("%s:\r\n", timer->name);
    for (i = 0; i < timer->current_idx; i++) {
        crypto_print("%d. %s cost %lld us\r\n", i, timer->item_name_list[i], timer->cost_times[i]);
    }
}

td_void crypto_timer_print_all(td_void)
{
    td_u32 i;
    for (i = 0; i < CRYPTO_TIMER_COUNT; i++) {
        crypto_timer_print(i);
    }
}
#endif