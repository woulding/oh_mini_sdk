/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description:  Application Core Platform Definitions
 *
 * Create:  2025-05-15
 */
#ifndef HPM_H
#define HPM_H

#include <bits/alltypes.h>

typedef enum {
    HPM_0 = 0,
    HPM_1 = 1,
    HPM_2 = 2
} hpm_index;

#define     MEASUREMENT_COUNT_MAX  4

uint32_t hpm_port_read(hpm_index hpm_id, uint32_t measurement_count);

#endif
