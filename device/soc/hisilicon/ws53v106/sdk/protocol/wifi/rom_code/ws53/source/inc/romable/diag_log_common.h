/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: wal 11d api.
 */

#ifndef __DIAG_LOG_COMMON_H__
#define __DIAG_LOG_COMMON_H__

#if defined (_PRE_WLAN_PLAT_SUPPORT_HOST_HSO)
#include "zdiag_log_util.h"
#else
#include "soc_diag_util.h"
#if ((defined(_PRE_WLAN_FEATURE_WS53) || defined(CHIP_WS63)) && !defined(DIAG_PRINT) && !defined(UT_TEST))
#include "log_oam_logger.h"
#endif
#endif

#include "common_dft_rom.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#if !defined(_PRE_WLAN_PLAT_SUPPORT_HOST_PRINTK) // Macro Layer 1

#if ((defined(CHIP_WS63) || defined(_PRE_WLAN_FEATURE_WS53)) && defined(DIAG_PRINT) && !defined(UT_TEST))
#define oam_info_log0(_uc_vap_0, _en_feature_0, fmt) \
    uapi_diag_info_log0(0, fmt)
#define oam_info_log1(_uc_vap_0, _en_feature_0, fmt, p1) \
    uapi_diag_info_log1(0, fmt, (td_u32)(p1))
#define oam_info_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2) \
    uapi_diag_info_log2(0, fmt, (td_u32)(p1), (td_u32)(p2))
#define oam_info_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3) \
    uapi_diag_info_log3(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3))
#define oam_info_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4) \
    uapi_diag_info_log4(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3), (td_u32)(p4))
#define oam_info_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...) \
        uapi_diag_info_log(0, fmt, ##args)

#define oam_warning_log0(_uc_vap_0, _en_feature_0, fmt) \
    uapi_diag_warning_log0(0, fmt)
#define oam_warning_log1(_uc_vap_0, _en_feature_0, fmt, p1) \
    uapi_diag_warning_log1(0, fmt, (td_u32)(p1))
#define oam_warning_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2) \
    uapi_diag_warning_log2(0, fmt, (td_u32)(p1), (td_u32)(p2))
#define oam_warning_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3) \
    uapi_diag_warning_log3(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3))
#define oam_warning_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4) \
    uapi_diag_warning_log4(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3), (td_u32)(p4))
#define oam_warning_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...) \
    uapi_diag_warning_log(0, fmt, ##args)

#define oam_error_log0(_uc_vap_0, _en_feature_0, fmt) \
    uapi_diag_error_log0(0, fmt)
#define oam_error_log1(_uc_vap_0, _en_feature_0, fmt, p1) \
    uapi_diag_error_log1(0, fmt, (td_u32)(p1))
#define oam_error_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2) \
    uapi_diag_error_log2(0, fmt, (td_u32)(p1), (td_u32)(p2))
#define oam_error_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3) \
    uapi_diag_error_log3(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3))
#define oam_error_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4) \
    uapi_diag_error_log4(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3), (td_u32)(p4))
#define oam_error_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...) \
    uapi_diag_error_log(0, fmt, ##args)

#elif ((defined(CHIP_WS63) || defined(_PRE_WLAN_FEATURE_WS53)) && !defined(DIAG_PRINT) && !defined(UT_TEST))
#define oam_info_log0(_uc_vap_0, _en_feature_0, fmt)    oml_wifi_log_print0(0, LOG_LEVEL_INFO, fmt)
#define oam_info_log1(_uc_vap_0, _en_feature_0, fmt, p1)    oml_wifi_log_print1(0, LOG_LEVEL_INFO, fmt, p1)
#define oam_info_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)    oml_wifi_log_print2(0, LOG_LEVEL_INFO, fmt, p1, p2)
#define oam_info_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3) \
    oml_wifi_log_print3(0, LOG_LEVEL_INFO, fmt, p1, p2, p3)
#define oam_info_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4) \
    oml_wifi_log_print4(0, LOG_LEVEL_INFO, fmt, p1, p2, p3, p4)
#define oam_info_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...) \
    oml_wifi_log_alter(0, 0, LOG_LEVEL_INFO, fmt, num, ##args)

#define oam_warning_log0(_uc_vap_0, _en_feature_0, fmt)    oml_wifi_log_print0(0, LOG_LEVEL_WARNING, fmt)
#define oam_warning_log1(_uc_vap_0, _en_feature_0, fmt, p1)    oml_wifi_log_print1(0, LOG_LEVEL_WARNING, fmt, p1)
#define oam_warning_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2) \
    oml_wifi_log_print2(0, LOG_LEVEL_WARNING, fmt, p1, p2)
#define oam_warning_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3) \
    oml_wifi_log_print3(0, LOG_LEVEL_WARNING, fmt, p1, p2, p3)
#define oam_warning_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4) \
    oml_wifi_log_print4(0, LOG_LEVEL_WARNING, fmt, p1, p2, p3, p4)
#define oam_warning_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...) \
    oml_wifi_log_alter(0, 0, LOG_LEVEL_WARNING, fmt, num, ##args)

#define oam_error_log0(_uc_vap_0, _en_feature_0, fmt)    oml_wifi_log_print0(0, LOG_LEVEL_ERROR, fmt)
#define oam_error_log1(_uc_vap_0, _en_feature_0, fmt, p1)    oml_wifi_log_print1(0, LOG_LEVEL_ERROR, fmt, p1)
#define oam_error_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)    oml_wifi_log_print2(0, LOG_LEVEL_ERROR, fmt, p1, p2)
#define oam_error_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3) \
    oml_wifi_log_print3(0, LOG_LEVEL_ERROR, fmt, p1, p2, p3)
#define oam_error_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4) \
    oml_wifi_log_print4(0, LOG_LEVEL_ERROR, fmt, p1, p2, p3, p4)
#define oam_error_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...) \
    oml_wifi_log_alter(0, 0, LOG_LEVEL_ERROR, fmt, num, ##args)

#elif !defined(_PRE_WLAN_FEATURE_WS73) && !defined(UT_TEST)
#define oam_info_log0(_uc_vap_0, _en_feature_0, fmt)
#define oam_info_log1(_uc_vap_0, _en_feature_0, fmt, p1)
#define oam_info_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)
#define oam_info_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)
#define oam_info_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)
#define oam_info_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...)
#define oam_warning_log0(_uc_vap_0, _en_feature_0, fmt)
#define oam_warning_log1(_uc_vap_0, _en_feature_0, fmt, p1)
#define oam_warning_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)
#define oam_warning_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)
#define oam_warning_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)
#define oam_warning_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...)
#define oam_error_log0(_uc_vap_0, _en_feature_0, fmt)
#define oam_error_log1(_uc_vap_0, _en_feature_0, fmt, p1)
#define oam_error_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)
#define oam_error_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)
#define oam_error_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)
#define oam_error_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...)
#else

/* 日志宏定义 */
#if defined(WSCFG_PLAT_DIAG_LOG_OUT) || !defined(_PRE_WLAN_PLAT_SUPPORT_HOST_HSO)
/* info level log wapper macro */
#define oam_info_log0(_uc_vap_0, _en_feature_0, fmt) ext_diag_info_log0(0, fmt)
#define oam_info_log1(_uc_vap_0, _en_feature_0, fmt, p1) ext_diag_info_log1(0, fmt, (td_u32)(p1))
#define oam_info_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2) ext_diag_info_log2(0, fmt, (td_u32)(p1), (td_u32)(p2))
#define oam_info_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3) \
    ext_diag_info_log3(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3))
#define oam_info_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4) \
    ext_diag_info_log4(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3), (td_u32)(p4))

#define oam_info_buf(_uc_vap_0, _en_feature_0, buffer, data_size, fmt, type) \
    ext_diag_info_log_buff(0, buffer, data_size, fmt, type)

/* warning level log wapper macro */
#define oam_warning_log0(_uc_vap_0, _en_feature_0, fmt) \
    do {                                                \
        ext_diag_warning_log0(0, fmt);                  \
    } while (0)
#define oam_warning_log1(_uc_vap_0, _en_feature_0, fmt, p1) \
    do {                                                    \
        ext_diag_warning_log1(0, fmt, (td_u32)(p1));        \
    } while (0)
#define oam_warning_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)    \
    do {                                                           \
        ext_diag_warning_log2(0, fmt, (td_u32)(p1), (td_u32)(p2)); \
    } while (0)
#define oam_warning_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)              \
    do {                                                                         \
        ext_diag_warning_log3(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3)); \
    } while (0)
#define oam_warning_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)                        \
    do {                                                                                       \
        ext_diag_warning_log4(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3), (td_u32)(p4)); \
    } while (0)

/* error level log wapper macro */
#define oam_error_log0(_uc_vap_0, _en_feature_0, fmt) \
    do {                                              \
        ext_diag_error_log0(0, fmt);                  \
    } while (0)
#define oam_error_log1(_uc_vap_0, _en_feature_0, fmt, p1) \
    do {                                                  \
        ext_diag_error_log1(0, fmt, (td_u32)(p1));        \
    } while (0)
#define oam_error_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)    \
    do {                                                         \
        ext_diag_error_log2(0, fmt, (td_u32)(p1), (td_u32)(p2)); \
    } while (0)
#define oam_error_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)              \
    do {                                                                       \
        ext_diag_error_log3(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3)); \
    } while (0)
#define oam_error_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)                        \
    do {                                                                                     \
        ext_diag_error_log4(0, fmt, (td_u32)(p1), (td_u32)(p2), (td_u32)(p3), (td_u32)(p4)); \
    } while (0)
#else
/* info level log wapper macro */
#define oam_info_log0(_uc_vap_0, _en_feature_0, fmt)
#define oam_info_log1(_uc_vap_0, _en_feature_0, fmt, p1)
#define oam_info_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)
#define oam_info_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)
#define oam_info_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)

#define oam_info_buf(_uc_vap_0, _en_feature_0, buffer, data_size, fmt, type) do { \
    } while (0)

/* warning level log wapper macro */
#define oam_warning_log0(_uc_vap_0, _en_feature_0, fmt)
#define oam_warning_log1(_uc_vap_0, _en_feature_0, fmt, p1)
#define oam_warning_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)
#define oam_warning_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)
#define oam_warning_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)

/* error level log wapper macro */
#define oam_error_log0(_uc_vap_0, _en_feature_0, fmt)
#define oam_error_log1(_uc_vap_0, _en_feature_0, fmt, p1)
#define oam_error_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)
#define oam_error_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)
#define oam_error_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)
#endif

#define oam_info_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...)
#define oam_warning_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...)
#define oam_error_log_alter(_uc_vap_0, _en_feature_0, fmt, num, args...)

#endif // Macro Layer 2

#define oam_warning_buf(_uc_vap_0, _en_feature_0, buffer, data_size, fmt, type) \
    ext_diag_warning_log_buff(0, buffer, data_size, fmt, type)
#define oam_error_buf(_uc_vap_0, _en_feature_0, buffer, data_size, fmt, type) \
    ext_diag_error_log_buff(0, buffer, data_size, fmt, type)

#else
/* 日志宏定义 */
#define oam_info_log0(_uc_vap_0, _en_feature_0, fmt)
#define oam_info_log1(_uc_vap_0, _en_feature_0, fmt, p1)
#define oam_info_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)
#define oam_info_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)
#define oam_info_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)
#define oam_info_buf(_uc_vap_0, _en_feature_0, buffer, data_size, fmt, type)

#define oam_warning_log0(_uc_vap_0, _en_feature_0, fmt)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__); \
        } \
    } while (0)
#define oam_warning_log1(_uc_vap_0, _en_feature_0, fmt, p1)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__, p1); \
        } \
    } while (0)
#define oam_warning_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__, p1, p2); \
        } \
    } while (0)
#define oam_warning_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__, p1, p2, p3); \
        } \
    } while (0)
#define oam_warning_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__, p1, p2, p3, p4); \
        } \
    } while (0)

#define oam_error_log0(_uc_vap_0, _en_feature_0, fmt)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__); \
        } \
    } while (0)
#define oam_error_log1(_uc_vap_0, _en_feature_0, fmt, p1)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__, p1); \
        } \
    } while (0)
#define oam_error_log2(_uc_vap_0, _en_feature_0, fmt, p1, p2)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__, p1, p2); \
        } \
    } while (0)
#define oam_error_log3(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__, p1, p2, p3); \
        } \
    } while (0)
#define oam_error_log4(_uc_vap_0, _en_feature_0, fmt, p1, p2, p3, p4)    do { \
        if (dft_get_log_level_switch()) { \
            osal_printk("[%d %d][%d]" fmt "\r\n", _uc_vap_0, _en_feature_0, __LINE__, p1, p2, p3, p4); \
        } \
    } while (0)

#define oam_warning_buf(_uc_vap_0, _en_feature_0, buffer, data_size, fmt, type)
#define oam_error_buf(_uc_vap_0, _en_feature_0, buffer, data_size, fmt, type)

#define oam_info_log_alter(id, feature_id, fmt, num, arg...)
#define oam_warning_log_alter(id, feature_id, fmt, num, arg...)
#define oam_error_log_alter(id, feature_id, fmt, num, arg...)

#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* #ifdef __DIAG_LOG_COMMON_H__ */
