/*
 * @Copyright (c) CompanyNameMagicTag 2021-2023. All rights reserved.
 * Description: ftrace File.
 * Create: 2023-05-17
 */

#ifdef _PRE_WLAN_FEATURE_FTRACE
#include "ftrace.h"
#include "osal_types.h"
#include "oal_types_device_rom.h"
#include "oal_util.h"
#include "frw_util.h"

#define MAX_SYSTICK_VALUE (0x0)
#define FTRACE_TIME_INCREASE 1

unsigned int g_trace_enable = FTRACE_STAT_STOP;
unsigned int g_trace_index = 0;
ftrace_event g_ftrace_event_mem[FTRACE_EVENT_MEM_SIZE];
osal_spinlock g_ftrace_lock;

static inline NOTRACE unsigned long ftrace_get_time_cost(unsigned long old_time, unsigned long new_time)
{
    unsigned long ret;
#ifdef FTRACE_TIME_INCREASE
    if (new_time < old_time) {
        ret = new_time + MAX_SYSTICK_VALUE - old_time;
    } else {
        ret = new_time - old_time;
    }
#else
    if (new_time > old_time) {
        ret = old_time + MAX_SYSTICK_VALUE - new_time;
    } else {
        ret = old_time - new_time;
    }
#endif
    return ret;
}

static inline unsigned long NOTRACE ftrace_get_timestamp(void)
{
    unsigned long curr_timestamp;
    curr_timestamp = osal_ftrace_get_timeofday_us()&0xffff;
    return curr_timestamp;
}

static inline ftrace_event * NOTRACE ftrace_find_trace_event(void *func)
{
    return (ftrace_event *)ftrace_hash_find((unsigned long)(uintptr_t)func);
}

static inline ftrace_event * NOTRACE ftrace_find_and_create_trace_event(void *func)
{
    ftrace_event *pst_trace = ftrace_find_trace_event(func);
    if (pst_trace != OAL_PTR_NULL) {
        return pst_trace;
    }

    if (g_trace_index >= FTRACE_EVENT_MEM_SIZE) {
        return OAL_PTR_NULL;
    }

    pst_trace = &g_ftrace_event_mem[g_trace_index++];
    pst_trace->func_addr = (unsigned long)(uintptr_t)func;
    ftrace_hash_add(&pst_trace->list);
    return pst_trace;
}

void NOTRACE __cyg_profile_func_enter(void *func, void *caller)
{
    osal_ulong ul_flags;
    ftrace_event *pst_trace = OAL_PTR_NULL;

    if (g_trace_enable != FTRACE_STAT_RUNNING) {
        return;
    }

    osal_spin_lock_irqsave(&g_ftrace_lock, &ul_flags);
    pst_trace = ftrace_find_and_create_trace_event(func);
    if (pst_trace == OAL_PTR_NULL) {
        osal_spin_unlock_irqrestore(&g_ftrace_lock, &ul_flags);
        return;
    }

    pst_trace->total_count++;
    /* 首次进入开始计时 */
    if (pst_trace->refcount == 0) {
        pst_trace->time_stamp = ftrace_get_timestamp();
    }
    pst_trace->refcount++;
    osal_spin_unlock_irqrestore(&g_ftrace_lock, &ul_flags);
}

void NOTRACE __cyg_profile_func_exit(void *func, void *caller)
{
    osal_ulong ul_flags;
    unsigned long curr_time;
    ftrace_event *pst_trace = OAL_PTR_NULL;

    if (g_trace_enable != FTRACE_STAT_RUNNING) {
        return;
    }

    curr_time = ftrace_get_timestamp();
    osal_spin_lock_irqsave(&g_ftrace_lock, &ul_flags);
    pst_trace = ftrace_find_trace_event(func);
    if (pst_trace == OAL_PTR_NULL) {
        osal_spin_unlock_irqrestore(&g_ftrace_lock, &ul_flags);
        return;
    }
    /* 记录最后退出时间 */
    pst_trace->refcount--;
    if (pst_trace->refcount == 0) {
        unsigned long cost = ftrace_get_time_cost(pst_trace->time_stamp, curr_time);
        // cost maybe overflow
        pst_trace->total_cost += cost;
    }
    osal_spin_unlock_irqrestore(&g_ftrace_lock, &ul_flags);
}

int NOTRACE ftrace_start(void)
{
    osal_ulong ul_flags;
    osal_spin_lock_irqsave(&g_ftrace_lock, &ul_flags);
    g_trace_enable = FTRACE_STAT_STOP;
    g_trace_index = 0;
    ftrace_reinit();
    g_trace_enable = FTRACE_STAT_RUNNING;
    osal_spin_unlock_irqrestore(&g_ftrace_lock, &ul_flags);
    OAL_IO_PRINT("ftrace_start :%d\r\n", __LINE__);
    return 0; // 0 succ
}

void NOTRACE ftrace_stop(void)
{
    g_trace_enable = FTRACE_STAT_STOP;
    OAL_IO_PRINT("ftrace_stop :%d\r\n", __LINE__);
}

void NOTRACE ftrace_dbg_list(struct ftrace_list *entry)
{
    ftrace_event *pst_trace = (ftrace_event *)entry;
    OAL_IO_PRINT("total_count:%u total_cost:%u us func_addr=0x%x\r\n",
          pst_trace->total_count, (unsigned int)pst_trace->total_cost, (unsigned int)pst_trace->func_addr);
}

void NOTRACE ftrace_dump(void)
{
    int i;
    ftrace_event *pst_trace = OAL_PTR_NULL;
    for (i = 0; i < FTRACE_EVENT_MEM_SIZE; i++) {
        pst_trace = &g_ftrace_event_mem[i];
        if (pst_trace->func_addr != 0) {
            OAL_IO_PRINT("[%d]total_count:%u total_cost:%u us func_addr:0x%x",
                i, pst_trace->total_count, (unsigned int)pst_trace->total_cost,
                (unsigned int)pst_trace->func_addr);
            OAL_IO_PRINT("pre_cost:%lu\r\n",
                (pst_trace->total_cost/pst_trace->total_count));
        }
    }
    OAL_IO_PRINT("ftrace_event_mem:0x%x size: %d\r\n",
        (unsigned int)&g_ftrace_event_mem[0] + 0x0,
        sizeof(g_ftrace_event_mem));
}

int NOTRACE ftrace_mem_init(void)
{
    memset_s((void *)g_ftrace_event_mem, sizeof(g_ftrace_event_mem),
        0, sizeof(g_ftrace_event_mem));
    return 0;
}

void NOTRACE ftrace_init(void)
{
    ftrace_mem_init();
    ftrace_hash_init();
}

void NOTRACE ftrace_reinit(void)
{
    ftrace_init();
}
#endif
