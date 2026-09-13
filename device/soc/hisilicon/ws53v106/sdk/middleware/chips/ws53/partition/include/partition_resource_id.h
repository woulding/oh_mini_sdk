/**
 * Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved. \n
 *
 * Description: Provides configuration definitions related to partitions. \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2022-09-01, Create file. \n
 */
#ifndef PARTITION_RESOURCE_ID_H
#define PARTITION_RESOURCE_ID_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/* partition image id, must be same as flash partition bin */
#define PARTITION_IMAGE_ID  0x4B87A52D

/**
 * @defgroup middleware_chips_partition Partition
 * @ingroup  middleware_chips
 * @{
 */

/**
 * @if Eng
 * @brief  Partition ids.
 * @else
 * @brief  分区ID
 * @endif
 */
typedef enum {
    PARTITION_SSB = 0x0,
    PARTITION_FLASH_BOOT_IMAGE = 0x1,
    PARTITION_FLASH_BOOT_IMAGE_BACKUP = 0x2,
    PARTITION_FLASH_ROOT_PUBLIC_KEYS_AREA = 0x3,

    PARTITION_CUSTOMER_FACTORY = 0x8,
    PARTITION_NV_DATA_BACKUP = 0x9,
    PARTITION_NV_DATA = 0x10,
    PARTITION_CRASH_INFO = 0x11,

    PARTITION_CCPU_IMAGE = 0x20,
    PARTITION_APP_IMAGE = 0x21,
    PARTITION_FOTA_DATA = 0x22,
    PARTITION_CCPU_IMAGE_BACKUP = 0x23,

    PARTITION_RESERVE2 = 0x30,
    PARTITION_RESERVE3 = 0x31,
    PARTITION_RESERVE4 = 0x32,
    PARTITION_RESERVE5 = 0x33,

    PARTITION_MAX_CNT = 16 /*!< @if Eng Maximum number of partitions.
        The value is recorded only as the number of partitions and is not used to determine the ID validity.
                                @else   分区的数量，这个枚举只用来记录分区的数量，不作为分区ID有效性的判断 @endif */
} partition_ids_t;

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* PARTITION_RESOURCE_ID_H */
