/*
 * Copyright (c) @CompanyNameMagicTag 2021-2023. All rights reserved.
 * Description: Header file for ftrace.c.
 * Create: 2021-12-15
 */

#ifndef __FTRACE_H__
#define __FTRACE_H__
#ifdef _PRE_WLAN_FEATURE_FTRACE
#ifdef __GNUC__
#define NOTRACE __attribute__((__no_instrument_function__))
#endif

#include "osal_spinlock.h"
#include "oal_plat_type.h"

#define FTRACE_STAT_STOP    0
#define FTRACE_STAT_RUNNING 1
#define FTRACE_STAT_PAUSE   2

#if SUB_SYSTEM == SUB_SYS_ME
/*  TraceEvent个数，影响可以跟踪的函数个数，
    总共有多少个函数打桩在fpga.dis文件中全词匹配搜索
    __cyg_profile_func_enter 每一项24字节大小 */
#define FTRACE_EVENT_MEM_SIZE (1000)

/* --Hash大小，越大hash索引效率越高,每一项4字节大小 */
#define FTRACE_HASH_SIZE      (500)
#else
#define FTRACE_EVENT_MEM_SIZE (500)
#define FTRACE_HASH_SIZE      (500)
#endif

static INLINE__ osal_u64 NOTRACE osal_ftrace_get_timeofday_us(osal_void)
{
    osal_timeval tv;
    osal_gettimeofday(&tv);
    return (((osal_u64)tv.tv_sec) * 1000000 + tv.tv_usec);
}

struct ftrace_list {
    struct ftrace_list *next;
};

typedef struct _ftrace_event_ {
    struct ftrace_list list;  // must first element
    unsigned int total_count;
    unsigned int refcount;
    unsigned long time_stamp;  // enter time
    unsigned long total_cost;  // function total time cost
    unsigned long func_addr;   // function address
} ftrace_event;

typedef void (*fttrace_list_func)(struct ftrace_list*);

void NOTRACE __cyg_profile_func_exit(void *func, void *caller);
void NOTRACE __cyg_profile_func_enter(void *func, void *caller);

struct ftrace_list *NOTRACE ftrace_hash_find(unsigned long func_addr);
void NOTRACE ftrace_hash_add(struct ftrace_list *entry);
void NOTRACE ftrace_foreach_list(fttrace_list_func call);

void NOTRACE ftrace_init(void);
void NOTRACE ftrace_reinit(void);
void NOTRACE ftrace_hash_init(void);

int  NOTRACE ftrace_start(void);
void NOTRACE ftrace_stop(void);
void NOTRACE ftrace_test_main(void);
void NOTRACE ftrace_dump(void);
#endif
#endif
