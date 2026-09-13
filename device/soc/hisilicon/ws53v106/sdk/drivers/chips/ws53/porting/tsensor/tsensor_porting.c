/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * Description: Provides tsensor port \n
 *
 * History: \n
 * 2023-02-28， Create file. \n
 */

#include "common_def.h"
#include "tcxo.h"
#include "chip_io.h"
#include "debug_print.h"
#include "tsensor_porting.h"

#define TSENSOR_AUTO_REFRESH_PERIOD  0x59006330
#define TSENSOR_AUTO_REFRESH_CFG  0x59006334
#define TSENSOR_CTRL   0x59006304
#define TSENSOR_CTRL1  0x59006310
#define TSENSOR_AUTO_STS 0x59006308
#define TSENSOR_START 0x59006300

#define DELAY_10US 10
#define VALUE1 118
#define VALUE2 933
#define VALUE3 16500
#define VALUE4 4000
#define GAIN 100

typedef union tsensor_reg {
    uint32_t d32;
    struct {
        uint32_t tsensor_auto_clr             :  1;
        uint32_t tsensor_rdy_auto             :  1;
        uint32_t tsensor_data_auto            : 10;
        uint32_t reserved                     : 20;
    } b;
} tsensor_reg_t;

errcode_t uapi_tsensor_init(void)
{
    writel(TSENSOR_AUTO_REFRESH_PERIOD, 0xA0);  /* 配置采样周期：160个32k cycle，即5ms */
    writel(TSENSOR_CTRL, 0x3);                  /* 配置16点平均循环上报模式 */
    writel(TSENSOR_CTRL1, 0x2);                 /* 配置每次采样时间: 0.256ms */
    writel(TSENSOR_AUTO_REFRESH_CFG, 0x0);      /* 关闭auto refresh上报 */
    writel(TSENSOR_START, 0x1);                 /* 启动tsensor */

    return ERRCODE_SUCC;
}

#define HAL_TSENSOR_TEMP_THRESHOLD_H_MAX 125
errcode_t uapi_tsensor_get_current_temp(int8_t *temp)
{
    int32_t tmp = 0;
    tsensor_reg_t res;
    /* 如果已启动tsensor，不重复启动，避免每次都重新开始 */
    if (readl(TSENSOR_CTRL) == 0) {
        uapi_tsensor_init();
    }
    while (true) {
        res.d32 = readl(TSENSOR_AUTO_STS);
        if (res.b.tsensor_rdy_auto == 1) {
            int32_t code = (int32_t)res.b.tsensor_data_auto;
            tmp = (int32_t)(((code - VALUE1) * VALUE3 / (VALUE2 - VALUE1) - VALUE4) / GAIN) ;
            break;
        }
    }

    if (tmp > HAL_TSENSOR_TEMP_THRESHOLD_H_MAX) {
        tmp = HAL_TSENSOR_TEMP_THRESHOLD_H_MAX;
    }
    *temp = (int8_t)tmp;
    return ERRCODE_SUCC;
}