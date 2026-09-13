/*
 * Copyright (c) @CompanyNameMagicTag. 2022-2022. All rights reserved.
 * Description: UPG product definitions header file
 */

#ifndef UPG_DEFINITIONS_PORTING_H
#define UPG_DEFINITIONS_PORTING_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @defgroup middleware_chips_ws53_update_api update
 * @ingroup  middleware_chips
 * @{
 */

/**
 * @if Eng
 * @brief  SSB signature image ids.
 * @else
 * @brief  SSB签名镜像ID
 * @endif
 */
#define FLASH_BOOT_SIGNATURE_IMAGE_ID           0x4B1E3C1E

/**
 * @if Eng
 * @brief  Image ids.
 * @else
 * @brief  SSB镜像ID
 * @endif
 */
#define FLASH_BOOT_IMAGE_ID                    0x4B1E3C2D

/**
 * @if Eng
 * @brief  Acore signature image ids.
 * @else
 * @brief  Acore签名镜像ID
 * @endif
 */
#define APPLICATION_SIGNATURE_IMAGE_ID         0x4B0F2D1E

/**
 * @if Eng
 * @brief  Acore image ids.
 * @else
 * @brief  Acore镜像ID
 * @endif
 */
#define APPLICATION_IMAGE_ID                   0x4B0F2D2D


/**
 * @if Eng
 * @brief  Index file image ids.
 * @else
 * @brief  索引文件镜像ID
 * @endif
 */
#define UPG_IMAGE_ID_INDEX                     0xFF000000

/**
 * @if Eng
 * @brief  key area reserved length.
 * @else
 * @brief  key区保留字段长度
 * @endif
 */
#define KEY_AREA_RESERVED_LEN 52

/**
 * @if Eng
 * @brief  info area user defined length.
 * @else
 * @brief  info区用户字段长度
 * @endif
 */
#define INFO_AREA_USER_LEN 112

/**
 * @if Eng
 * @brief  signature length.
 * @else
 * @brief  签名字段长度
 * @endif
 */
#define SIG_LEN         64

/**
 * @if Eng
 * @brief  FOTA external public key.
 * @else
 * @brief  FOTA二级公钥长度
 * @endif
 */
#define PUBLIC_KEY_LEN 64

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

/**
 * @}
 */

#endif /* UPG_DEFINITIONS_PORTING_H */