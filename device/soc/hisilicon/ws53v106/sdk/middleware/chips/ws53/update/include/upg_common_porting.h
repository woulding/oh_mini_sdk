/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: UPG common functions header file
 */

#ifndef UPG_COMMON_PORTING_H
#define UPG_COMMON_PORTING_H

#include "memory_config_common.h"
#include "errcode.h"
#include "upg.h"
#include "upg_definitions_porting.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifndef SIZE_MAX
#define SIZE_MAX                        UINT32_MAX
#endif

#if MEMORY_MINI
#define UPG_FILE_PATH                   "/user/"
#define UPG_FILE_NAME                   "/user/update.fwpkg"
#else
#define UPG_FILE_PATH                   "/update/"
#define UPG_FILE_NAME                   "/update/update.fwpkg"
#endif

#define UPG_FLASH_SIZE                  (FLASH_MAX_END - FLASH_START)
#define UPG_FLASH_PAGE_SIZE             0x1000 /* Bytes per sector */
#define FOTA_DATA_STATUS_AREA_LEN       UPG_FLASH_PAGE_SIZE
#define FOTA_DATA_BUFFER_AREA_LEN       UPG_FLASH_PAGE_SIZE
#define FOTA_DATA_FLAG_AREA_LEN         UPG_FLASH_PAGE_SIZE
#define UPG_UPGRADE_FLAG_LENGTH     (FOTA_DATA_STATUS_AREA_LEN + FOTA_DATA_BUFFER_AREA_LEN + FOTA_DATA_FLAG_AREA_LEN)

#define UPG_META_DATA_LENGTH            0x0

/* APP Region */
#ifndef APP_FLASH_REGION_START
#define APP_FLASH_REGION_START          (0x104000)
#endif
#ifndef APP_FLASH_REGION_LENGTH
#define APP_FLASH_REGION_LENGTH         (0x203000)
#endif

#define OEM_ROOT_PUBLIC_KEY_IMAGE_ID    0x4BA5C31E
#define PARAMS_PARTITION_IMAGE_ID       0x4B87A52D
#define PARAMS_PARTITION_START_ADDR     0x200000
#define PARAMS_PARTITION_LENGTH         0x780

#define EFUSE_REE_SSB_VERSION           0xF0
#define EFUSE_REE_RECOVERT_VERSION      0xF0
#define EFUSE_REE_APP_VERSION           0xF0
#define EFUSE_REE_BT_VERSION            0xF0
#define EFUSE_REE_DSP_MAIN_VERSION      0xF0
#define EFUSE_REE_DSP_OVERLAY_VERSION   0xF0

#define ROOT_PUBLIC_KEY_RSV             32
/* root public key area, size is 0x80 */
typedef struct {
    uint32_t      image_id;
    uint32_t      structure_version;  /* currently version is 0x00010000 */
    uint32_t      structure_length;
    uint32_t      key_owner_id;
    uint32_t      key_id;
    uint32_t      key_alg;            /* 0x2A13C812: ECC256;  0x2A13C823: SM2 */
    uint32_t      ecc_curve_type;     /* 0x2A13C812: RFC 5639, BrainpoolP256r1 */
    uint32_t      key_length;
    uint8_t       reserved[ROOT_PUBLIC_KEY_RSV]; /* 32 bytes above */
    uint8_t       root_key_area[PUBLIC_KEY_LEN];
} root_public_key;

#ifndef CONFIG_MIDDLEWARE_SUPPORT_UPG_SAMPLE_VERIFY
// 下列宏值、结构体定义需与boot中定义保持一致
#define CODE_INFO_STRUCTURE_LENGTH      0x200
#define CODE_INFO_RESERVED_LENGTH       248
#define SIG_LEN                         64
#define EXT_SIG_LEN                     64

#define HASH_LEN                        32
#define PROTECT_KEY_LEN                 16
#define IV_LEN                          16

/* Code area info, size is 0x200 */
typedef struct {
    uint32_t      image_id;
    uint32_t      structure_version;
    uint32_t      structure_length;
    uint32_t      signature_length;
    uint32_t      version_ext;
    uint32_t      mask_version_ext;
    uint32_t      msid_ext;
    uint32_t      mask_msid_ext;
    uint32_t      code_area_addr;
    uint32_t      code_area_len;
    uint8_t       code_area_hash[HASH_LEN];
    uint32_t      code_enc_flag;
    uint8_t       protection_key_l1[PROTECT_KEY_LEN];
    uint8_t       protection_key_l2[PROTECT_KEY_LEN];
    uint8_t       iv[IV_LEN];
    uint32_t      code_compress_flag; /* 0x3C7896E1: is compressed */
    uint32_t      code_uncompress_len;
    uint32_t      text_segment_size;
    uint8_t       reserved[CODE_INFO_RESERVED_LENGTH];  /* 136 bytes above */
    uint8_t       sig_code_info[SIG_LEN];
    uint8_t       sig_code_info_ext[EXT_SIG_LEN];
} image_code_info_t;
#endif

/**
* @ingroup  iot_update
* @brief Upgrade the backup area of each image before start the upgrade.
*        CNcomment:升级开始前对各个镜像的备区升级。CNend
*
* @retval #ERRCODE_SUCC         Success.
* @retval #Other     Failure. For details, see soc_errno.h.
*/
errcode_t upg_image_backups_update(void);

void upg_progress_callback_register(void);

errcode_t ws53_upg_init(void);
/*
 * 擦除镜像对应的整个flash分区
 * img_header 镜像信息header，用于获取对应flash分区信息
 */
errcode_t upg_erase_whole_image(const upg_image_header_t *img_header);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* UPG_COMMON_PORTING_H */