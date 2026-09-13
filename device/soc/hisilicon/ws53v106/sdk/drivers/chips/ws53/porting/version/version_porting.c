/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * Description: Provides version port source. \n
 *
 * History: \n
 * 2023-11-08， Create file. \n
 */

#include "stdint.h"
#include "stdbool.h"
#include "securec.h"
#include "at.h"
#include "version_porting.h"

#define PLAT_SW_VERSION_STR_MAX_LEN 32
#define PLAT_SW_VERSION_STR_FORMAT  "Version %03u.%03u.%03u"

/**
 * History:
 * 2023-11-08, version 1.1.1
 */
static plat_version_t g_plat_sw_version = {
    .v = 1,
    .r = 1,
    .c = 1
};

static bool g_is_set_sw_version_str = false;
static char g_plat_sw_version_str[PLAT_SW_VERSION_STR_MAX_LEN] = {0};

uint32_t plat_get_sw_version_code(void)
{
    /* 结构体元素分别移动8和16位，把 struct 转换成 uint32_t */
    return g_plat_sw_version.c + (g_plat_sw_version.r << 8) + (g_plat_sw_version.v << 16);
}

char *plat_get_sw_version_str(void)
{
    if (!g_is_set_sw_version_str) {
        sprintf_s(g_plat_sw_version_str, PLAT_SW_VERSION_STR_MAX_LEN, PLAT_SW_VERSION_STR_FORMAT,
                  g_plat_sw_version.v, g_plat_sw_version.r, g_plat_sw_version.c);
    }
    return g_plat_sw_version_str;
}

void print_version(void)
{
    uapi_at_print("SDK Version:%s\r\n", SDK_VERSION);
}
