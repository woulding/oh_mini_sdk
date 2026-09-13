/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal timer source file.
 * Author: AuthorNameMagicTag
 * Create: 2021-10-15
 */

#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <sys/timerfd.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>

#include "soc_osal.h"
#include "securec.h"
#include "osal_inner.h"

typedef struct {
    int t_fd;
    unsigned int th_run_flag;
    unsigned int th_create_flag;
    pthread_t th;
} osal_userspace_timer;

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

unsigned long osal_timer_get_private_data(const void *data)
{
    return (unsigned long)((uintptr_t)data);
}

static void *timed_action_watcher(void *ptr)
{
    osal_timer *t = (osal_timer*)ptr;
    osal_userspace_timer *u_timer = (osal_userspace_timer*)t->timer;
    while (u_timer->th_run_flag != 0) {
        uint64_t exp;
        ssize_t s = read(u_timer->t_fd, &exp, sizeof(uint64_t));
        if (s != sizeof(uint64_t)) {
            usleep(100); // read timefd every 100 usec
            continue;
        }
        t->handler(t->data);
    }
    return NULL;
}

int osal_timer_init(osal_timer *timer)
{
    osal_userspace_timer *u_timer = NULL;
    if (timer == NULL || timer->timer != NULL || timer->handler == NULL || timer->interval == 0) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }

    u_timer = malloc(sizeof(osal_userspace_timer));
    if (u_timer == NULL) {
        osal_log("malloc error!\n");
        return OSAL_FAILURE;
    }
    memset_s(u_timer, sizeof(osal_userspace_timer), 0, sizeof(osal_userspace_timer));

    u_timer->t_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (u_timer->t_fd < 0) {
        osal_log("timerfd create error!\n");
        free(u_timer);
        return OSAL_FAILURE;
    }
    u_timer->th_run_flag = 1;
    u_timer->th_create_flag = 0;

    timer->timer = u_timer;
    return OSAL_SUCCESS;
}


static int timer_set_expiry(int timefd, time_t sec, long nsec)
{
    struct itimerspec value;

    value.it_value.tv_sec = sec;
    value.it_value.tv_nsec = nsec;
    value.it_interval.tv_sec = 0;
    value.it_interval.tv_nsec = 0;

    if ((timerfd_settime(timefd, 0, &value, NULL)) < 0) {
        return OSAL_FAILURE;
    }
    return OSAL_SUCCESS;
}

int osal_timer_start(osal_timer *timer)
{
    int ret;
    time_t interval_sec;
    long interval_msec;
    osal_userspace_timer *u_timer = NULL;

    if ((timer == NULL) || (timer->timer == NULL)|| (timer->interval == 0) || (timer->handler == NULL)) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    u_timer = (osal_userspace_timer*)timer->timer;

    if (u_timer->th_create_flag == 0) {
        if (pthread_create(&u_timer->th, NULL, timed_action_watcher, timer)) {
            osal_log("pthread_create error \n");
            return OSAL_FAILURE;
        }
        u_timer->th_create_flag = 1;
    }

    interval_sec = timer->interval / 1000; // 1000 for count sec
    interval_msec = timer->interval % 1000; // 1000 for count sec

    if (u_timer->th_run_flag != 0) {
        ret = timer_set_expiry(u_timer->t_fd, interval_sec, interval_msec * 1000000); // 1000000 for count nsec
        if (ret != 0) {
            osal_log("timer_set_expiry error \n");
            return OSAL_FAILURE;
        }
    } else {
        osal_log("timer thread stop. \n");
        return OSAL_FAILURE;
    }
    return OSAL_SUCCESS;
}

int osal_timer_mod(osal_timer *timer, unsigned int interval)
{
    int ret;
    time_t interval_sec;
    long interval_msec;
    osal_userspace_timer *u_timer = NULL;

    if ((timer == NULL) || (timer->timer == NULL) || (interval == 0) || (timer->handler == NULL)) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    u_timer = (osal_userspace_timer*)timer->timer;

    if (u_timer->th_create_flag == 0) {
        if (pthread_create(&u_timer->th, NULL, timed_action_watcher, timer)) {
            osal_log("pthread_create error \n");
            return OSAL_FAILURE;
        }
        u_timer->th_create_flag = 1;
    }

    interval_sec = interval / 1000; // 1000 for count sec
    interval_msec = interval % 1000; // 1000 for count sec

    if (u_timer->th_run_flag != 0) {
        ret = timer_set_expiry(u_timer->t_fd, interval_sec, interval_msec * 1000000); // 1000000 for count nsec
        if (ret != 0) {
            osal_log("timer_set_expiry error!\n");
            return OSAL_FAILURE;
        }
    } else {
        osal_log("timer thread stop. \n");
        return OSAL_FAILURE;
    }
    timer->interval = interval;
    return OSAL_SUCCESS;
}

int osal_timer_stop(osal_timer *timer)
{
    osal_userspace_timer *u_timer = NULL;

    if ((timer == NULL) || (timer->timer == NULL)) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    u_timer = timer->timer;
    if (u_timer->th_create_flag != 0) {
        u_timer->th_run_flag = 0;
        close(u_timer->t_fd);
        if (pthread_join(u_timer->th, NULL) != 0) {
            osal_log("pthread join failed\n");
        }
    }
    return OSAL_SUCCESS;
}

int osal_timer_destroy(osal_timer *timer)
{
    osal_userspace_timer *u_timer = NULL;
    if ((timer == NULL) || (timer->timer == NULL)) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    u_timer = timer->timer;

    free(u_timer);
    timer->timer = NULL;
    return OSAL_SUCCESS;
}

unsigned long osal_msleep(unsigned int msecs)
{
    return (unsigned long)usleep(msecs * 1000); // 1000 for count usec
}

void osal_udelay(unsigned int usecs)
{
    usleep(usecs);
}

void osal_mdelay(unsigned int msecs)
{
    usleep(msecs * 1000); // 1000 for count usec
}

unsigned long long osal_sched_clock(void)
{
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (unsigned long long)(time.tv_sec * 1000000000ULL + time.tv_nsec); // 1000000000: for count nsec
}

void osal_gettimeofday(osal_timeval *tv)
{
    struct timeval t;

    if (tv == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    gettimeofday(&t, NULL);

    tv->tv_sec = t.tv_sec;
    tv->tv_usec = t.tv_usec;
}

void osal_rtc_time_to_tm(unsigned long time, osal_rtc_time *tm)
{
    struct tm *_tm = NULL;
    time_t tmp = (time_t)time;

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

unsigned long long osal_get_jiffies(void)
{
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (unsigned long long)time.tv_sec * 1000ULL + time.tv_nsec / 1000000ULL; // 1000,1000000
}

int osal_rtc_valid_tm(const osal_rtc_time *tm)
{
    if (tm == NULL) {
        osal_log("parameter invalid!\n");
        return -EINVAL;
    }

    if (tm->tm_year < 70 // 70 for max years
        || ((unsigned)tm->tm_mon) >= 12 // 12 for month
        || tm->tm_mday < 1
        || tm->tm_mday > rtc_month_days(tm->tm_mon, tm->tm_year + 1900) // rtc start from 1900
        || ((unsigned)tm->tm_hour) >= 24 // 24 for hour
        || ((unsigned)tm->tm_min) >= 60 // 60 for min
        || ((unsigned)tm->tm_sec) >= 60) // 60 for sec
        return -EINVAL;

    return OSAL_SUCCESS;
}
