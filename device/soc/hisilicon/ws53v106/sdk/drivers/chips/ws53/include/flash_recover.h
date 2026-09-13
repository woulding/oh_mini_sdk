/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * Description: Provides ws53 Flash recover API \n
 *
 * History: \n
 * 2023-06-28, Create file. \n
 */
#ifndef FLASH_RECOVER_H
#define FLASH_RECOVER_H

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
 * @brief  Suspend Flash and SFC.
 * @else
 * @brief  挂起SFC和Flash。
 * @endif
 */
void sfc_flash_suspend(void);

/**
 * @if Eng
 * @brief  Resume Flash and SFC.
 * @else
 * @brief  恢复SFC和Flash。
 * @endif
 */
void sfc_flash_resume(void);

/**
 * @if Eng
 * @brief  Init encry enable flag.
 * @else
 * @brief  初始化flash加密标记。
 * @endif
 */
void sfc_init_pm_encry(void);

/**
 * @if Eng
 * @brief  Get encry enable flag.
 * @else
 * @brief  判断flash是否加密。
 * @endif
 */
bool sfc_encry_is_enable(void);
/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif