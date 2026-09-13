/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <limits.h>
#include <securec.h>
#include "mbedtls/base64.h"
#include "mbedtls/cipher.h"
#include "mbedtls/aes.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "attest_adapter.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_security.h"

// g_pskKey 和 g_encryptedPsk 是psk的计算因子，通过相关算法获取解码需要的psk。
// psk不能直接硬编码，因此设计两个计算因子。
uint8_t g_pskKey[BASE64_PSK_LENGTH] = {
    0x35, 0x4d, 0x36, 0x50, 0x42, 0x79, 0x39, 0x41, 0x71, 0x30, 0x41, 0x76,
    0x63, 0x56, 0x77, 0x65, 0x49, 0x68, 0x48, 0x46, 0x36, 0x67, 0x3d, 0x3d
};

uint8_t g_encryptedPsk[BASE64_PSK_LENGTH] = {
    0x74, 0x71, 0x57, 0x2b, 0x56, 0x6d, 0x52, 0x6b, 0x30, 0x67, 0x52, 0x5a,
    0x48, 0x58, 0x68, 0x78, 0x53, 0x56, 0x58, 0x67, 0x6a, 0x51, 0x3d, 0x3d
};

int32_t Base64Encode(const uint8_t* srcData, size_t srcDataLen, uint8_t* base64Encode, uint16_t base64EncodeLen)
{
    if ((srcData == NULL) || (base64Encode == NULL)) {
        ATTEST_LOG_ERROR("[Base64Encode] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    size_t outLen = 0;
    const size_t base64EncodeMaxLen = base64EncodeLen + 1;
    int32_t ret = mbedtls_base64_encode(NULL, 0, &outLen, srcData, srcDataLen);

    if ((outLen == 0) || (outLen > base64EncodeMaxLen)) {
        ATTEST_LOG_ERROR("[Base64Encode] Base64 encode get outLen failed, outLen = %zu, ret = -0x00%x", outLen, -ret);
        return ERR_ATTEST_SECURITY_BASE64_ENCODE;
    }
    uint8_t base64Data[outLen];
    (void)memset_s(base64Data, sizeof(base64Data), 0, sizeof(base64Data));
    ret = mbedtls_base64_encode(base64Data, sizeof(base64Data), &outLen, srcData, srcDataLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Base64Encode] Base64 encode failed, ret = -0x00%x", -ret);
        return ERR_ATTEST_SECURITY_BASE64_ENCODE;
    }
    ret = memcpy_s(base64Encode, base64EncodeLen, base64Data, outLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Base64Encode] memcpy_s base64Data fail");
        (void)memset_s(base64Data, sizeof(base64Data), 0, sizeof(base64Data));
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    (void)memset_s(base64Data, sizeof(base64Data), 0, sizeof(base64Data));
    return ATTEST_OK;
}

void GetSalt(uint8_t* salt, uint32_t saltLen)
{
    if ((salt == NULL) || (saltLen != SALT_LEN)) {
        ATTEST_LOG_ERROR("[GetSalt] Invalid parameter");
        return;
    }

    const uint8_t randomNumBytes = 4;
    const uint8_t offsetBits = 8;
    uint32_t temp = 0;
    for (uint32_t i = 0; i < saltLen; i++) {
        if ((i % randomNumBytes) == 0) {
            temp = (uint32_t)GetRandomNum(); // 生成的随机数为4字节
        }
        // temp右移8bits
        salt[i] = (uint8_t)((temp >> ((i % randomNumBytes) * offsetBits)) & 0xff);
        if (salt[i] == 0) {
            salt[i]++;
        }
    }
}

static int32_t GetPsk(uint8_t psk[], size_t pskLen)
{
    if (pskLen != PSK_LEN) {
        ATTEST_LOG_ERROR("[GetPsk] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    size_t outLen = 0;
    (void)mbedtls_base64_decode(NULL, 0, &outLen, g_pskKey, sizeof(g_pskKey));
    if (outLen != pskLen) {
        ATTEST_LOG_ERROR("[GetPsk] pskKey base64 decode fail");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    uint8_t base64PskKey[outLen];
    (void)memset_s(base64PskKey, sizeof(base64PskKey), 0, sizeof(base64PskKey));
    int32_t ret = mbedtls_base64_decode(base64PskKey, outLen, &outLen, g_pskKey, sizeof(g_pskKey));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetPsk] GetPsk Base64Decode base64PskKey failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_BASE64_DECODE;
    }
    outLen = 0;
    (void)mbedtls_base64_decode(NULL, 0, &outLen, g_encryptedPsk, sizeof(g_encryptedPsk));
    if (outLen != pskLen) {
        ATTEST_LOG_ERROR("[GetPsk] encryptedPsk base64 decode fail");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    uint8_t base64Psk[outLen];
    (void)memset_s(base64Psk, sizeof(base64Psk), 0, sizeof(base64Psk));
    ret = mbedtls_base64_decode(base64Psk, outLen, &outLen, g_encryptedPsk, sizeof(g_encryptedPsk));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetPsk] GetPsk Base64Decode base64Psk failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_BASE64_DECODE;
    }
    for (size_t i = 0; i < pskLen; i++) {
        psk[i] = base64Psk[i] ^ base64PskKey[i];
    }
    (void)memset_s(base64Psk, sizeof(base64Psk), 0, sizeof(base64Psk));
    return ATTEST_OK;
}

static int32_t GetProductInfo(const char* version, SecurityParam* productInfoParam)
{
    if (productInfoParam == NULL) {
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    int32_t ret = AttestGetManufacturekey(productInfoParam->param, MANUFACTUREKEY_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetProductInfo] Get AC Key failed, ret = %d", ret);
        return ret;
    }

    if (strcmp(version, TOKEN_VER0_0) == 0) { // productInfo = Manufacturekey + productId
        uint8_t productId[PRODUCT_ID_LEN] = {0};
        ret = AttestGetProductId(productId, sizeof(productId));
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[GetProductInfo] Get product id failed, ret = %d", ret);
            return ret;
        }
        if (memcpy_s(productInfoParam->param + MANUFACTUREKEY_LEN, PRODUCT_ID_LEN, productId, PRODUCT_ID_LEN) != 0) {
            ATTEST_LOG_ERROR("[GetProductInfo] Copy product id failed");
            return ERR_ATTEST_SECURITY_MEM_MEMCPY;
        }
        (void)memset_s(productId, PRODUCT_ID_LEN, 0, PRODUCT_ID_LEN);
    } else if (strcmp(version, TOKEN_VER1_0) == 0) { // productInfo = Manufacturekey
        productInfoParam->paramLen = MANUFACTUREKEY_LEN;
    }
    return ATTEST_OK;
}

int32_t GetAesKey(const SecurityParam* salt, const VersionData* versionData,  const SecurityParam* aesKey)
{
    if ((salt == NULL) || (versionData == NULL) || (aesKey == NULL) || (versionData->versionLen == 0)) {
        ATTEST_LOG_ERROR("[GetAesKey] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    uint8_t productInfo[MANUFACTUREKEY_LEN + PRODUCT_ID_LEN] = {0};
    SecurityParam info = {productInfo, sizeof(productInfo)};
    int32_t ret = GetProductInfo(versionData->version, &info);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetAesKey] Get product info failed, ret = %d", ret);
        return ret;
    }
    uint8_t psk[PSK_LEN] = {0};
    ret = GetPsk(psk, PSK_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetAesKey] Get psk failed, ret = %d", ret);
        return ret;
    }
    SecurityParam key = {psk, sizeof(psk)};
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    // 导出秘钥
    ret = mbedtls_hkdf(mdInfo, salt->param, salt->paramLen,
                       key.param, key.paramLen,
                       info.param, info.paramLen,
                       aesKey->param, aesKey->paramLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetAesKey] HKDF derive key failed, ret = -0x%x", -ret);
    }
    memset_s(psk, PSK_LEN, 0, PSK_LEN);
    return ret;
}

// AES-128-CBC-PKCS#7解密
static int32_t DecryptAesCbc(AesCryptBufferDatas* datas, const uint8_t* aesKey,
                             const uint8_t* iv, size_t ivLen)
{
    if ((datas == NULL) || (datas->input == NULL) || (datas->output == NULL) ||
        (datas->outputLen == NULL) || (aesKey == NULL)) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    if ((iv == NULL) || (ivLen != IV_LEN)) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] iv out of range");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    mbedtls_aes_context aesCtx;
    mbedtls_aes_init(&aesCtx);
    int32_t ret = mbedtls_aes_setkey_dec(&aesCtx, aesKey, AES_CIPHER_BITS);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Set mbedtls enc key failed, ret = -0x%x", ret);
        return ret;
    }

    uint8_t ivTmp[IV_LEN] = {0};
    ret = memcpy_s(ivTmp, sizeof(ivTmp), iv, ivLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] memcpy_s iv fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    // iv is updated after use, so define ivTmp
    ret = mbedtls_aes_crypt_cbc(&aesCtx, MBEDTLS_AES_DECRYPT, datas->inputLen, ivTmp,
                                (const uint8_t*)datas->input, datas->output);
    (void)memset_s(ivTmp, sizeof(ivTmp), 0, sizeof(ivTmp));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Encrypt failed, ret = -0x%x", ret);
        return ret;
    }

    mbedtls_cipher_info_t cipherInfo;
    (void)memset_s(&cipherInfo, sizeof(cipherInfo), 0, sizeof(cipherInfo));
    cipherInfo.mode = MBEDTLS_MODE_CBC;

    mbedtls_cipher_context_t cipherCtx;
    mbedtls_cipher_init(&cipherCtx);
    cipherCtx.cipher_info = &cipherInfo;
    ret = mbedtls_cipher_set_padding_mode(&cipherCtx, MBEDTLS_PADDING_PKCS7);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Set padding mode failed, ret = -0x%x", ret);
        return ret;
    }
    size_t invalid_padding = 0;
    (void)cipherCtx.get_padding(datas->output, datas->inputLen, datas->outputLen, &invalid_padding);
    ret = (int)invalid_padding;
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Get padding failed, ret = -0x%x", ret);
    }
    return ret;
}
// AES-128-CBC-PKCS#7加密
static int32_t EncryptAesCbc(AesCryptBufferDatas* datas, const uint8_t* aesKey,
                             const char* iv, size_t ivLen)
{
    if ((datas == NULL) || (datas->input == NULL) || (datas->output == NULL) ||
        (datas->outputLen == NULL) || (aesKey == NULL)) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    if ((iv == NULL) || (ivLen != IV_LEN)) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] iv out of range");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    
    if ((datas->inputLen / AES_BLOCK + 1) > (UINT_MAX / AES_BLOCK)) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] AesCryptBufferDatas inputLen overflow");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    *datas->outputLen = (datas->inputLen / AES_BLOCK + 1) * AES_BLOCK;

    mbedtls_cipher_info_t cipherInfo;
    (void)memset_s(&cipherInfo, sizeof(cipherInfo), 0, sizeof(cipherInfo));
    cipherInfo.mode = MBEDTLS_MODE_CBC;

    mbedtls_cipher_context_t cipherCtx;
    mbedtls_cipher_init(&cipherCtx);
    cipherCtx.cipher_info = &cipherInfo;
    int32_t ret = mbedtls_cipher_set_padding_mode(&cipherCtx, MBEDTLS_PADDING_PKCS7);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] Set padding mode failed, ret = -0x%x", ret);
        return ret;
    }
    cipherCtx.add_padding(datas->input, *(datas->outputLen), datas->inputLen);

    mbedtls_aes_context aesCtx;
    mbedtls_aes_init(&aesCtx);
    ret = mbedtls_aes_setkey_enc(&aesCtx, aesKey, AES_CIPHER_BITS);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] Set mbedtls enc key failed, ret = -0x%x", ret);
        return ret;
    }

    uint8_t ivTmp[IV_LEN] = {0};
    if (memcpy_s(ivTmp, sizeof(ivTmp), iv, ivLen) != 0) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] memcpy_s iv fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    // iv is updated after use, so define ivTmp
    ret = mbedtls_aes_crypt_cbc(&aesCtx, MBEDTLS_AES_ENCRYPT, *datas->outputLen, ivTmp,
                                (const uint8_t*)datas->input, datas->output);
    (void)memset_s(ivTmp, sizeof(ivTmp), 0, sizeof(ivTmp));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] Encrypt failed, ret = -0x%x", ret);
    }
    return ret;
}

int32_t Encrypt(uint8_t* inputData, size_t inputDataLen, const uint8_t* aesKey,
                uint8_t* outputData, size_t outputDataLen)
{
    if ((inputData == NULL) || (inputDataLen == 0) || (aesKey == NULL) || (outputData == NULL)) {
        ATTEST_LOG_ERROR("[Encrypt] Encrypt Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    size_t aesOutLen = 0;
    uint8_t encryptedData[ENCRYPT_LEN] = {0};
    AesCryptBufferDatas datas = {inputData, inputDataLen, encryptedData, &aesOutLen};
    int32_t ret = EncryptAesCbc(&datas, aesKey, (const char*)(aesKey + PSK_LEN), AES_KEY_LEN - PSK_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Encrypt] Aes CBC encrypt symbol info failed, ret = %d", ret);
        return ret;
    }

    size_t outputLen = 0;
    uint8_t base64Data[BASE64_LEN + 1] = {0};
    ret = mbedtls_base64_encode(base64Data, sizeof(base64Data), &outputLen,
                                (const uint8_t*)encryptedData, aesOutLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Encrypt] Base64 encode symbol info failed, ret = -0x00%x", -ret);
        return ret;
    }

    if (outputLen > outputDataLen) {
        ATTEST_LOG_ERROR("[Encrypt] output Len is wrong length");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    ret = memcpy_s(outputData, outputDataLen, base64Data, outputLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Encrypt] Encrypt memcpy_s failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    (void)memset_s(base64Data, BASE64_LEN + 1, 0, BASE64_LEN + 1);
    return ATTEST_OK;
}

int32_t Decrypt(const uint8_t* inputData, size_t inputDataLen, const uint8_t* aesKey,
                uint8_t* outputData, size_t outputDataLen)
{
    if ((inputData == NULL) || (inputDataLen == 0) || (aesKey == NULL) || (outputData == NULL)) {
        ATTEST_LOG_ERROR("[Decrypt] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    size_t base64Len = 0;
    uint8_t encryptData[ENCRYPT_LEN] = {0};
    int32_t ret = mbedtls_base64_decode(encryptData, sizeof(encryptData), &base64Len, inputData, inputDataLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Decrypt] Base64 decode symbol info failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_BASE64_DECODE;
    }

    size_t decryptDataLen = 0;
    uint8_t decryptData[ENCRYPT_LEN] = {0};
    AesCryptBufferDatas datas = {encryptData, base64Len, decryptData, &decryptDataLen};
    if (DecryptAesCbc(&datas, aesKey, aesKey + PSK_LEN, AES_KEY_LEN - PSK_LEN) != 0) {
        ATTEST_LOG_ERROR("[Decrypt] Aes CBC encrypt symbol info failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_DECRYPT;
    }

    if ((decryptDataLen == 0) || (decryptDataLen > outputDataLen)) {
        ATTEST_LOG_ERROR("[Decrypt] decryptData Len out of range");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    ret = memcpy_s(outputData, outputDataLen, decryptData, decryptDataLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Decrypt] memcpy_s decryptData fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    (void)memset_s(decryptData, ENCRYPT_LEN, 0, ENCRYPT_LEN);
    return ATTEST_OK;
}

int32_t MD5Encode(const uint8_t* srcData, size_t srcDataLen, uint8_t* outputStr, int outputLen)
{
    if (srcData == NULL || srcDataLen == 0 || outputStr == NULL) {
        ATTEST_LOG_ERROR("[MD5Encode] Invalid parameter");
        return ATTEST_ERR;
    }

    uint8_t hash[MD5_LEN] = {0};
    char buf[DEV_BUF_LENGTH] = {0};

    mbedtls_md5_context md5_ctx;
    mbedtls_md5_init(&md5_ctx);
    mbedtls_md5_starts(&md5_ctx);
    mbedtls_md5_update(&md5_ctx, srcData, srcDataLen);
    mbedtls_md5_finish(&md5_ctx, hash);
    mbedtls_md5_free(&md5_ctx);

    int32_t ret = ATTEST_OK;
    for (size_t i = 0; i < MD5_LEN; i++) {
        uint8_t value = hash[i];
        (void)memset_s(buf, DEV_BUF_LENGTH, 0, DEV_BUF_LENGTH);
        if (sprintf_s(buf, sizeof(buf), "%02x", value) < 0) {
            ATTEST_LOG_ERROR("[MD5Encode] Failed to sprintf");
            ret = ATTEST_ERR;
            break;
        }

        if (strcat_s((char*)outputStr, outputLen, buf) != 0) {
            ATTEST_LOG_ERROR("[MD5Encode] Failed to strcat");
            ret = ATTEST_ERR;
            break;
        }
    }
    (void)memset_s(buf, DEV_BUF_LENGTH, 0, DEV_BUF_LENGTH);
    (void)memset_s(hash, MD5_LEN, 0, MD5_LEN);
    return ret;
}
