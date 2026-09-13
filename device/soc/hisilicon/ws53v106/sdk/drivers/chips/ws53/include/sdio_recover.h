/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * Description: Provides ws53 Flash recover API \n
 *
 * History: \n
 * 2023-06-28, Create file. \n
 */
#ifndef SDIO_RECOVER_H
#define SDIO_RECOVER_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup flash_recover_api Flash Recover
 * @ingroup flash_recover
 * @{
 */

/**
 * @if Eng
 * @brief  Suspend SDIO.
 * @else
 * @brief  挂起SDIO。
 * @endif
 */
void sdio_suspend(void);

/**
 * @if Eng
 * @brief  Resume SDIO.
 * @else
 * @brief  恢复SDIO。
 * @endif
 */
void sdio_resume(void);

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif