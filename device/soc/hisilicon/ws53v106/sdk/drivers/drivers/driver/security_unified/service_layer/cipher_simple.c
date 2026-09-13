/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: Provides cipher simple driver source \n
 *
 * History: \n
 * 2024-05-23, Create file. \n
 */
#include "cipher.h"
#include "km.h"

#include "sl_common.h"
#include "crypto_common_macro.h"
#include "crypto_osal_adapt.h"

static errcode_t inner_klad_set_clear_key(uint32_t keyslot_handle, uapi_drv_cipher_symc_alg_t alg,
    const uint8_t *key, uint32_t key_len)
{
    errcode_t ret;
    uint32_t klad_handle;
    uapi_drv_klad_clear_key_t clear_key = {
        .key = (uint8_t *)key,
        .key_length = key_len
    };
    uapi_drv_klad_attr_t klad_attr = {
        .key_cfg = {
            .engine = UAPI_DRV_KLAD_ENGINE_AES,
            .decrypt_support = TD_TRUE,
            .encrypt_support = TD_TRUE
        },
        .key_sec_cfg = {
            .key_sec = TD_FALSE,
            .master_only_enable = TD_FALSE,
            .dest_buf_sec_support = TD_FALSE,
            .dest_buf_non_sec_support = TD_TRUE,
            .src_buf_sec_support = TD_FALSE,
            .src_buf_non_sec_support = TD_TRUE,
        }
    };
    if (alg == UAPI_DRV_CIPHER_SYMC_ALG_SM4) {
        klad_attr.key_cfg.engine = UAPI_DRV_KLAD_ENGINE_SM4;
    }

    ret = uapi_drv_klad_create(&klad_handle);
    crypto_chk_return(ret != ERRCODE_SUCC, ret, "uapi_drv_klad_create failed\n");

    ret = uapi_drv_klad_attach(klad_handle, UAPI_DRV_KLAD_DEST_MCIPHER, keyslot_handle);
    crypto_chk_goto(ret != ERRCODE_SUCC, exit_klad_destroy, "uapi_drv_klad_attach failed\n");

    ret = uapi_drv_klad_set_attr(klad_handle, &klad_attr);
    crypto_chk_goto(ret != ERRCODE_SUCC, exit_klad_destroy, "uapi_drv_klad_set_attr failed\n");

    ret = uapi_drv_klad_set_clear_key(klad_handle, &clear_key);
    crypto_chk_goto(ret != ERRCODE_SUCC, exit_klad_destroy, "uapi_drv_klad_set_clear_key failed\n");

exit_klad_destroy:
    (void)uapi_drv_klad_destroy(klad_handle);
    return ret;
}

static errcode_t inner_symc_crypt(uapi_drv_cipher_symc_alg_t alg, uapi_drv_cipher_symc_work_mode_t work_mode,
    uapi_drv_cipher_symc_bit_width_t bit_width, uapi_drv_cipher_symc_key_length_t symc_key_length,
    const uint8_t *src, uint8_t *dst, uint32_t data_len,
    uint8_t iv[16], uint32_t keyslot_handle, bool is_encrypt)
{
    errcode_t ret;
    uint32_t symc_handle;
    uapi_drv_cipher_symc_attr_t symc_attr = {
        .symc_alg = alg,
        .work_mode = work_mode,
        .is_long_term = TD_TRUE
    };
    uapi_drv_cipher_symc_ctrl_t symc_ctrl = {
        .symc_alg = alg,
        .work_mode = work_mode,
        .symc_key_length = symc_key_length,
        .symc_bit_width = bit_width,
        .iv_length = CRYPTO_IV_LEN_IN_BYTES
    };
    uapi_drv_cipher_buf_attr_t src_buf = {
        .phys_addr = (uintptr_t)src
    };
    uapi_drv_cipher_buf_attr_t dst_buf = {
        .phys_addr = (uintptr_t)dst
    };

    crypto_chk_return(memcpy_s(symc_ctrl.iv, sizeof(symc_ctrl.iv), iv, CRYPTO_IV_LEN_IN_BYTES) != EOK,
        ERROR_SECURITY_MEMCPY_S, "memcpy_s failed\n");

    ret = uapi_drv_cipher_symc_init();
    crypto_chk_return(ret != ERRCODE_SUCC, ret, "uapi_drv_cipher_symc_init failed\n");

    ret = uapi_drv_cipher_symc_create(&symc_handle, &symc_attr);
    crypto_chk_goto(ret != ERRCODE_SUCC, exit_symc_deinit, "uapi_drv_cipher_symc_create failed\n");

    ret = uapi_drv_cipher_symc_attach(symc_handle, keyslot_handle);
    crypto_chk_goto(ret != ERRCODE_SUCC, exit_symc_destroy, "uapi_drv_cipher_symc_attach failed\n");

    ret = uapi_drv_cipher_symc_set_config(symc_handle, &symc_ctrl);
    crypto_chk_goto(ret != ERRCODE_SUCC, exit_symc_detach, "uapi_drv_cipher_symc_set_config failed\n");

    if (is_encrypt) {
        ret = uapi_drv_cipher_symc_encrypt(symc_handle, &src_buf, &dst_buf, data_len);
    } else {
        ret = uapi_drv_cipher_symc_decrypt(symc_handle, &src_buf, &dst_buf, data_len);
    }
    crypto_chk_goto(ret != ERRCODE_SUCC, exit_symc_detach, "uapi_drv_cipher_symc_crypt failed\n");

exit_symc_detach:
    (void)uapi_drv_cipher_symc_detach(symc_handle, keyslot_handle);
exit_symc_destroy:
    (void)uapi_drv_cipher_symc_destroy(symc_handle);
exit_symc_deinit:
    (void)uapi_drv_cipher_symc_deinit();
    return ret;
}

errcode_t uapi_drv_cipher_symc_crypt(uapi_drv_cipher_symc_alg_t alg, uapi_drv_cipher_symc_work_mode_t work_mode,
    uapi_drv_cipher_symc_bit_width_t bit_width,
    const uint8_t *src, uint8_t *dst, uint32_t data_len,
    uint8_t iv[16], const uint8_t *key, uint32_t key_len, uint32_t keyslot_handle,
    bool is_encrypt
)
{
    errcode_t ret;
    uint32_t local_keyslot_handle = keyslot_handle;
    uapi_drv_cipher_symc_key_length_t symc_key_length = UAPI_DRV_CIPHER_SYMC_KEY_128BIT;

    ret = uapi_drv_km_init();
    crypto_chk_return(ret != ERRCODE_SUCC, ret, "uapi_drv_km_init failed\n");

    if (key != NULL) {
        ret = uapi_drv_keyslot_create(&local_keyslot_handle, UAPI_DRV_KEYSLOT_TYPE_MCIPHER);
        crypto_chk_goto(ret != ERRCODE_SUCC, exit_km_deinit, "uapi_drv_keyslot_create failed\n");

        ret = inner_klad_set_clear_key(local_keyslot_handle, alg, key, key_len);
        crypto_chk_goto(ret != ERRCODE_SUCC, exit_keyslot_destroy, "inner_klad_set_clear_key failed\n");
    }

    if (key_len == CRYPTO_192_KEY_LEN) {
        symc_key_length = UAPI_DRV_CIPHER_SYMC_KEY_192BIT;
    } else if (key_len == CRYPTO_256_KEY_LEN) {
        symc_key_length = UAPI_DRV_CIPHER_SYMC_KEY_256BIT;
    }
    ret = inner_symc_crypt(alg, work_mode, bit_width, symc_key_length,
        src, dst, data_len, iv, local_keyslot_handle, is_encrypt);
    crypto_chk_goto(ret != ERRCODE_SUCC, exit_keyslot_destroy, "inner_symc_crypt failed\n");

exit_keyslot_destroy:
    if (key != NULL) {
        (void)uapi_drv_keyslot_destroy(local_keyslot_handle);
    }
exit_km_deinit:
    (void)uapi_drv_km_deinit();
    return ret;
}