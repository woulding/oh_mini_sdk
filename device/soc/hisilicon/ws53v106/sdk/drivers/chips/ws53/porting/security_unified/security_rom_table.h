/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: define rom functions address
 * Create: 2024-05-28
*/

#ifndef SECURITY_ROM_TABLE_H
#define SECURITY_ROM_TABLE_H

/* drv rom cipher API */
#define DRV_ROM_CIPHER_INIT                     0x123a8
#define DRV_ROM_CIPHER_SHA256                   0x123d2
#define DRV_ROM_CIPHER_PKE_BP256R_VERIFY        0x124f6

/* PKE */
#define HAL_PKE_INIT                0x13c4a
#define HAL_PKE_DEINIT              0x13c5e
#define HAL_PKE_LOCK                0x13cb6
#define HAL_PKE_UNLOCK              0x13d30
#define HAL_PKE_ENABLE_NOISE        0x13d46
#define HAL_PKE_DISABLE_NOISE       0x13d5a
#define HAL_PKE_PRE_PROCESS         0x13d6a
#define HAL_PKE_CHECK_FREE          0x13d9e
#define HAL_PKE_SET_RAM             0x13dc6
#define HAL_PKE_GET_RAM             0x13e82
#define HAL_PKE_CLEAN_RAM           0x13eca
#define HAL_PKE_SET_MODE            0x13ee2
#define HAL_PKE_START               0x13f56
#define HAL_PKE_WAIT_DONE           0x13f7a
#define HAL_PKE_GET_ALIGN_VAL       0x13faa
#define HAL_PKE_SET_MONT_PARA       0x14008
#define HAL_PKE_SET_ECC_PARAM       0x1401c
#define HAL_PKE_SET_INIT_PARAM      0x140ea
/* PKE algorithm API */
#define ECC_ECFP_MUL_ADD            0x12b64

/* TRNG */
#define HAL_CIPHER_TRNG_INIT        0x14618
#define HAL_CIPHER_TRNG_GET_RANDOM  0x1464c

/* HASH */
#define HAL_CIPHER_HASH_INIT        0x14126
#define HAL_HASH_LOCK               0x14394
#define HAL_HASH_UNLOCK             0x14174
#define HAL_CIPHER_HASH_CONFIG      0x14194
#define HAL_CIPHER_HASH_ADD_IN_NODE 0x14274
#define HAL_CIPHER_HASH_START       0x142e8
#define HAL_CIPHER_HASH_WAIT_DONE   0x144be
#define HAL_CIPHER_HASH_DONE_TRY    0x1437a
#endif  /* DRV_ROM_TABLE_H */