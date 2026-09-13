/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2020-2023. All rights reserved.
 * Description: host driver os adapt.
 * Author: Huanghe
 * Create: 2020-12-20
 */

#ifndef __OAL_HCC_BUS_OS_ADAPT_H__
#define __OAL_HCC_BUS_OS_ADAPT_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define BUS_LOG_ERR  0
#define BUS_LOG_WARN 1
#define BUS_LOG_INFO 2
#define BUS_LOG_DBG  3
#define BUS_LOG_VERBOSE 4

#ifndef IS_ALIGNED
#define OAL_IS_ALIGNED(val, align)                 (((td_u32)(val) & ((align) - 1)) == 0)
#else
#define OAL_IS_ALIGNED                             IS_ALIGNED
#endif

#ifndef OAL_ROUND_UP
#define round_mask(x, y)                         ((__typeof__(x))((y)-1))
#ifndef round_up
#define round_up(x, y)                             ((((x)-1) | round_mask(x, y))+1)
#endif
#define OAL_ROUND_UP                               round_up
#endif

#ifndef OAL_LIKELY
#define OAL_LIKELY(_expr)                          likely((_expr))
#endif

#ifndef OAL_UNLIKELY
#define OAL_UNLIKELY(_expr)                        unlikely((_expr))
#endif

#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#define OAL_TIME_JIFFY                             jiffies
#ifndef OAL_WARN_ON
#define OAL_WARN_ON(condition) ({ \
    int __ret_warn_on = !!(condition); \
    if (unlikely(__ret_warn_on)) \
        dump_stack(); \
    unlikely(__ret_warn_on); \
})
#endif
#define OAL_ALIGN ALIGN
#define oal_sdio_log(loglevel, fmt, arg...) \
    do { \
        if (loglevel <= BUS_LOG_INFO) { \
            printk("%s%s" fmt"[%s:%d]\r\n", SDIO_MODULE_NAME, g_loglevel[loglevel], ##arg, __FUNCTION__, __LINE__); \
        } \
    } while (0)
#endif

#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define OAL_TIME_JIFFY                             LOS_TickCountGet()
#define msecs_to_jiffies(_msecs)                   LOS_MS2Tick(_msecs)
#define OAL_ALIGN ALIGN
#define oal_sdio_log(loglevel, fmt, arg...) \
    do { \
        if (loglevel <= BUS_LOG_INFO) { \
            printf("%s%s" fmt"[%s:%d]\r\n", SDIO_MODULE_NAME, g_loglevel[loglevel], ##arg, __FUNCTION__, __LINE__); \
        } \
    } while (0)
#endif

#if defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
#define OAL_TIME_JIFFY                             rt_tick_get()
#define msecs_to_jiffies(_msecs)                   rt_tick_from_millisecond(_msecs)
#define OAL_ALIGN(x, align) ((((unsigned int)(x)) + (align) - 1) & (~((align) - 1)))
#define oal_sdio_log(loglevel, fmt, arg...) \
    do { \
        if (loglevel <= BUS_LOG_INFO) { \
            rt_kprintf("%s%s" fmt"[%s:%d]\r\n", SDIO_MODULE_NAME, g_loglevel[loglevel], ##arg, __func__, __LINE__); \
        } \
    } while (0)
#endif

#if !(defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION))
#ifndef OAL_WARN_ON
#define OAL_WARN_ON(condition)                     ((condition))
#endif

static inline td_u32 time_after(td_u64 time_a, td_u64 time_b)
{
    return (td_u32)((td_s64)((td_s64)(time_b) - (time_a)) < 0);
}

#define BITS_PER_LONG                              32
#define is_bit_set(nr)                             (1UL << ((nr) % BITS_PER_LONG))
#define bit_word(nr)                               ((nr) >> 5)

static inline td_s32 test_bit(td_s32 nr, const unsigned long *addr)
{
    return (1UL & (addr[bit_word(nr)] >> (nr & 0x1F)));
}

static inline td_u32 test_and_clear_bit(td_u32 nr, unsigned long *addr)
{
    td_u32 int_save;
    int_save = osal_irq_lock();

    td_u32 mask = is_bit_set(nr);
    td_u32 *p = ((td_u32 *)addr) + bit_word(nr);
    td_u32 old = *p;
    *p = old & ~mask;

    osal_irq_restore(int_save);
    return (old & mask) != 0;
}

#define for_each_set_bit(cnt, addr, limit) \
                    for ((cnt) = 0; (cnt) < (limit); (cnt)++) \
                        if (test_bit((cnt), (addr)))

static inline td_void usleep_range(td_ulong min_us, td_ulong max_us)
{
    osal_udelay(min_us);
}
#endif
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
