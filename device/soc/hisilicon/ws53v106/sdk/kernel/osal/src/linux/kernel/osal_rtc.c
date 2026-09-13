/*
 * Copyright (c) @CompanyNameMagicTag 2012-2022. All rights reserved.
 */
#include <linux/rtc.h>
#include "soc_osal.h"
#include "osal_inner.h"

#define osal_rtc_convert(a, b) do { \
    (a)->tm_sec = (b)->tm_sec;      \
    (a)->tm_min = (b)->tm_min;      \
    (a)->tm_hour = (b)->tm_hour;    \
    (a)->tm_mday = (b)->tm_mday;    \
    (a)->tm_mon = (b)->tm_mon;      \
    (a)->tm_year = (b)->tm_year;    \
    (a)->tm_wday = (b)->tm_wday;    \
    (a)->tm_yday = (b)->tm_yday;    \
    (a)->tm_isdst = (b)->tm_isdst;  \
} while (0)

void osal_rtc_time_to_tm(unsigned long time, osal_rtc_time *tm)
{
    struct rtc_time _tm = { 0 };
    struct rtc_time *systm = &_tm;

    if (tm == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }

    rtc_time64_to_tm(time, &_tm);
    osal_rtc_convert(tm, systm);
}
EXPORT_SYMBOL(osal_rtc_time_to_tm);

void osal_rtc_tm_to_time(const osal_rtc_time *tm, unsigned long *time)
{
    struct rtc_time _tm;
    struct rtc_time *systm = &_tm;

    if (tm == NULL || time == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }

    osal_rtc_convert(systm, tm);
    *time = (unsigned long)rtc_tm_to_time64(systm);
}
EXPORT_SYMBOL(osal_rtc_tm_to_time);


int osal_rtc_valid_tm(const osal_rtc_time *tm)
{
    int ret;
    struct rtc_time _tm;
    struct rtc_time *systm = &_tm;

    if (tm == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }

    osal_rtc_convert(systm, tm);
    ret = rtc_valid_tm(systm);
    if (ret != 0) {
        return OSAL_FAILURE;
    }
    return OSAL_SUCCESS;
}
EXPORT_SYMBOL(osal_rtc_valid_tm);
