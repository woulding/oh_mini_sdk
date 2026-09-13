/* ----------------------------------------------------------------------------
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: LiteOS FS multi_partition Inside Headfile
 * Author: Huawei LiteOS Team
 * Create: 2021-07-16
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 * of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific prior written
 * permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * --------------------------------------------------------------------------- */

/**
 * @defgroup filesystem FileSystem
 * @defgroup mtd_partition Multi Partition
 * @ingroup filesystem
 */
#ifndef _MTD_PARTITION_PRI_H
#define _MTD_PARTITION_PRI_H

#include "mtd_partition.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * bits [0,7] use for value operations instead of bitwise
 * operations in nuttx source header file : fs.h.
 */
#define FSNODEFLAG_EXTEND_TYPE_MTD 0x00000100

typedef struct par_param {
    mtd_partition *partition_head;
    struct mtd_info *flash_mtd;
    const struct block_operations *flash_ops;
    const struct file_operations_vfs *char_ops;
    CHAR *blockname;
    CHAR *charname;
    UINT32 block_size;
} partition_param;

#define ALIGN_ASSIGN(len, startAddr, startBlk, endBlk, blkSize) do {    \
    (len) = (((len) + ((blkSize) - 1)) & ~((blkSize) - 1));             \
    (startAddr) = ((startAddr) & ~((blkSize) - 1));                     \
    (startBlk) = (startAddr) / (blkSize);                               \
    (endBlk) = (len) / (blkSize) + ((startBlk) - 1);                    \
} while (0)

#define PAR_ASSIGNMENT(node, len, startAddr, num, mtd, blkSize) do {    \
    (node)->start_block = (startAddr) / (blkSize);                      \
    (node)->end_block = (len) / (blkSize) + ((node)->start_block - 1);  \
    (node)->patitionnum = (num);                                        \
    (node)->mtd_info = (mtd);                                           \
    (node)->mountpoint_name = NULL;                                     \
} while (0)

#if defined(LOSCFG_FS_YAFFS)
extern partition_param *g_nandPartParam;
#endif
#if defined(LOSCFG_FS_JFFS) || defined(LOSCFG_FS_ROMFS) || defined(LOSCFG_FS_LITTLEFS)
extern partition_param *g_spinorPartParam;
#endif

mtd_partition *GetSpinorPartitionHead(VOID);

/**
 * @ingroup mtd_partition
 * @brief initializes mtd partition.
 *
 * @par Description:
 * <ul>
 * <li>This API is used to initialize the mtd partition </li>
 * </ul>
 * @attention
 * <ul>
 * <li>Called only once.</li>
 * </ul>
 *
 * @param none
 *
 * @retval #VOID  None.
 *
 * @par Dependency:
 * <ul><li>mtd_partition.h: the header file that contains the API declaration.</li></ul>
 * @see add_mtd_partition | delete_mtd_partition
 * @since Huawei LiteOS V200R005C20
 */
extern VOID OsMtdPartitionInit(VOID);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _MTD_PARTITION_PRI_H */
