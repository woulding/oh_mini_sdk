/**
 * Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved. \n
 *
 * Description: Provides pm port \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-01-12， Create file. \n
 */
#ifndef PM_PORTING_H
#define PM_PORTING_H

#include "systick.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup middleware_chips_pm_port PM port
 * @ingroup  middleware_chips_pm
 * @{
 */

#define PM_FORCE_INNER_RC           0
#define PM_XO32K_SW_CHECK_MASK      1
#define PM_GET_CURRENT_MS   uapi_systick_get_ms()

uint8_t pm_check_device_ready(void);
void pm_config_xo32k_policy(uint8_t cfg);
/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif