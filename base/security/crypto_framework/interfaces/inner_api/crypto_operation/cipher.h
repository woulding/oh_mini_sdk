/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HCF_CIPHER_H
#define HCF_CIPHER_H

#include "blob.h"
#include "key.h"
#include "algorithm_parameter.h"

enum HcfCryptoMode {
    /**
     * The value of aes and 3des encrypt operation
     * @syscap SystemCapability.Security.CryptoFramework
     * @since 9
     */
    ENCRYPT_MODE = 0,

    /**
     * The value of aes and 3des decrypt operation
     * @syscap SystemCapability.Security.CryptoFramework
     * @since 9
     */
    DECRYPT_MODE = 1,
};

typedef enum {
    OAEP_MD_NAME_STR = 100,
    OAEP_MGF_NAME_STR = 101,
    OAEP_MGF1_MD_STR = 102,
    OAEP_MGF1_PSRC_UINT8ARR = 103,
    SM2_MD_NAME_STR = 104
} CipherSpecItem;

typedef struct HcfCipher HcfCipher;
/**
 * @brief this class provides cipher algorithms for cryptographic operations,
 * mainly including encrypt and decrypt.
 *
 * @since 9
 * @version 1.0
 */
struct HcfCipher {
    HcfObjectBase base;

    HcfResult (*init)(HcfCipher *self, enum HcfCryptoMode opMode,
        HcfKey *key, HcfParamsSpec *params);

    HcfResult (*update)(HcfCipher *self, HcfBlob *input, HcfBlob *output);

    HcfResult (*doFinal)(HcfCipher *self, HcfBlob *input, HcfBlob *output);

    const char *(*getAlgorithm)(HcfCipher *self);

    HcfResult (*setCipherSpecUint8Array)(HcfCipher *self, CipherSpecItem item, HcfBlob blob);

    HcfResult (*getCipherSpecString)(HcfCipher *self, CipherSpecItem item, char **returnString);

    HcfResult (*getCipherSpecUint8Array)(HcfCipher *self, CipherSpecItem item, HcfBlob *returnUint8Array);
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate a corresponding cryptographic operation cipher object according to the algorithm name.
 *
 * @param transformation Specifies the type of generated cipher object.
 * @param returnObj The address of the pointer to the generated cipher object.
 * @return Returns the status code of the execution.
 * @since 9
 * @version 1.0
 */
HcfResult HcfCipherCreate(const char *transformation, HcfCipher **returnObj);

#ifdef __cplusplus
}
#endif

#endif
