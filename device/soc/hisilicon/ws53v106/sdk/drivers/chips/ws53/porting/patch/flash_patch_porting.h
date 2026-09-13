/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 *
 * Description: Provides flash_patch port template \n
 *
 * History: \n
 * 2023-07-26， Create file. \n
 */
#ifndef FLASH_PATCH_PORTING_H
#define FLASH_PATCH_PORTING_H

#include <stdint.h>
#ifndef PLATFORM_CORE_H
#include "platform_core.h"
#endif
#include "platform_types.h"
#include "flash_patch.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_port_patch_riscv31 FlashPatch porting info.
 * @ingroup  drivers_port_patch
 * @{
 */

/**
 * @brief  Initialises the patch.
 */
void patch_init(void);

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif