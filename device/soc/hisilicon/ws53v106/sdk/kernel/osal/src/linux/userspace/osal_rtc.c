/*
 * Copyright (c) CompanyNameMagicTag 2021-2022. All rights reserved.
 * Description: osal timer source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <time.h>
#include <limits.h>
#include <stdbool.h>
#include "soc_osal.h"
#include "osal_inner.h"

static const unsigned char rtc_days_in_month[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};
static bool is_leap_year(unsigned int year)
{
    return ((year % 4) == 0 && (year % 100) != 0) || (year % 400) == 0; // 4,100,400 for count leap year
}

static int rtc_month_days(unsigned int month, unsigned int year)
{
    return rtc_days_in_month[month] + (is_leap_year(year) && month == 1);
}

void osal_rtc_time_to_tm(unsigned long time, osal_rtc_time *tm)
{
    if (tm == NULL || time > LONG_MAX) {
        osal_log("parameter invalid!\n");
        return;
    }
    struct tm *_tm = NULL;
    long tmp = (long)time;
    _tm = localtime(&tmp);
    if (_tm == NULL) {
        return;
    }

    tm->tm_sec = _tm->tm_sec;
    tm->tm_min = _tm->tm_min;
    tm->tm_hour = _tm->tm_hour;
    tm->tm_mday = _tm->tm_mday;
    tm->tm_mon = _tm->tm_mon;
    tm->tm_year = _tm->tm_year;
    tm->tm_wday = _tm->tm_wday;
    tm->tm_yday = _tm->tm_yday;
    tm->tm_isdst = _tm->tm_isdst;
}

void osal_rtc_tm_to_time(const osal_rtc_time *tm, unsigned long *time)
{
    if (tm == NULL || time == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    struct tm _tm;

    _tm.tm_sec = tm->tm_sec;
    _tm.tm_min = tm->tm_min;
    _tm.tm_hour = tm->tm_hour;
    _tm.tm_mday = tm->tm_mday;
    _tm.tm_mon = tm->tm_mon;
    _tm.tm_year = tm->tm_year;
    _tm.tm_wday = tm->tm_wday;
    _tm.tm_yday = tm->tm_yday;
    _tm.tm_isdst = tm->tm_isdst;

    *time = (unsigned long)mktime(&_tm);
}

int osal_rtc_valid_tm(const osal_rtc_time *tm)
{
    if (tm == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_EINVAL;
    }

    if (tm->tm_year < 70 // 70 for max years
        || ((unsigned)tm->tm_mon) >= 12 // 12 for month
        || tm->tm_mday < 1
        || tm->tm_mday > rtc_month_days(tm->tm_mon, tm->tm_year + 1900) // rtc start from 1900
        || ((unsigned)tm->tm_hour) >= 24 // 24 for hour
        || ((unsigned)tm->tm_min) >= 60 // 60 for min
        || ((unsigned)tm->tm_sec) >= 60) // 60 for sec
        return OSAL_EINVAL;

    return OSAL_SUCCESS;
}
