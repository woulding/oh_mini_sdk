/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "rsa_common_param_spec.h"
#include <gtest/gtest.h>
#include "securec.h"

#include "asy_key_generator.h"
#include "asy_key_generator_spi.h"
#include "blob.h"
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "openssl_class.h"
#include "openssl_common.h"

void RemoveLastChar(const unsigned char *str, unsigned char *dest, uint32_t destLen)
{
    for (size_t i = 0; i < destLen; i++) {
        dest[i] = str[i];
    }
    return;
}

void EndianSwap(unsigned char *pData, int startIndex, int length)
{
    int cnt = length / 2;
    int start = startIndex;
    int end  = startIndex + length - 1;
    for (int i = 0; i < cnt; i++) {
        unsigned char tmp = pData[start + i];
        pData[start + i] = pData[end - i];
        pData[end - i] = tmp;
    }
}

// 512 defined the length of byte array
void GenerateRsa512CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    if (dataN == nullptr) {
        return;
    }
    RemoveLastChar(CORRECT_512_N, dataN, RSA_512_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_512_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_512_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

void GenerateRsa512CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa512CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_512_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_512_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_512_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

void GenerateRsa512CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa512CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_512_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_512_D, dataD, RSA_512_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_512_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_512_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_512_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_512_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 768 defined the length of byte array
void GenerateRsa768CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_768_N, dataN, RSA_768_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_768_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_768_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

void GenerateRsa768CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa768CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_768_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_768_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_768_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

void GenerateRsa768CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa768CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_768_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_768_D, dataD, RSA_768_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_768_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_768_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_768_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_768_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 1024 defined the length of byte array
void GenerateRsa1024CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_1024_N, dataN, RSA_1024_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_1024_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_1024_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

void GenerateRsa1024CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa1024CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_1024_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_1024_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_1024_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

void GenerateRsa1024CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa1024CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_1024_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_1024_D, dataD, RSA_1024_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_1024_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_1024_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_1024_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_1024_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 2048 defined the length of byte array
void GenerateRsa2048CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_2048_N, dataN, RSA_2048_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_2048_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_2048_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

void GenerateRsa2048CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_2048_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_2048_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_2048_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

void GenerateRsa2048CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_2048_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_2048_D, dataD, RSA_2048_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_2048_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_2048_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_2048_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_2048_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 3072 defined the length of byte array
void GenerateRsa3072CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_3072_N, dataN, RSA_3072_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_3072_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_3072_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

void GenerateRsa3072CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa3072CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_3072_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_3072_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_3072_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

void GenerateRsa3072CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa3072CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_3072_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_3072_D, dataD, RSA_3072_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_3072_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_3072_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_3072_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_3072_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 4096 defined the length of byte array
void GenerateRsa4096CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_4096_N, dataN, RSA_4096_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_4096_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_4096_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

void GenerateRsa4096CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa4096CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_4096_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_4096_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_4096_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

void GenerateRsa4096CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa4096CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_4096_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_4096_D, dataD, RSA_4096_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_4096_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_4096_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_4096_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_4096_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 8192 defined the length of byte array
void GenerateRsa8192CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_8192_N, dataN, RSA_8192_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_8192_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_8192_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

void GenerateRsa8192CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa8192CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_8192_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_8192_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_8192_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

void GenerateRsa8192CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa8192CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_8192_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_8192_D, dataD, RSA_8192_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_8192_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_8192_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_8192_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_8192_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

bool CheckGeneratorBySpecKeyFunc(HcfAsyKeyGeneratorBySpec *generator)
{
    if (generator->generateKeyPair == nullptr || generator->generatePriKey == nullptr ||
        generator->generatePubKey == nullptr) {
        return false;
    }
    return true;
}