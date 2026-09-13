/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "ecc_asy_key_generator_openssl.h"
#include "ecc_common_asy_key_generator_openssl.h"

#include "securec.h"

#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include <openssl/param_build.h>
#include "utils.h"

#define OPENSSL_ECC_KEY_GENERATOR_CLASS "OPENSSL.ECC.KEY_GENERATOR_CLASS"
#define OPENSSL_ECC_ALGORITHM "EC"
#define OPENSSL_ECC_PUB_KEY_FORMAT "X.509"
#define OPENSSL_ECC_PRI_KEY_FORMAT "PKCS#8"
#define ECC_COORDINATE_COUNT 2
#define ECC_COORDINATE_COUNT_3 3
#define ECC_OCTET_PREFIX_SIZE 1
#define BITS_PER_BYTE 8
#define OPENSSL_ECC160_BITS 160
#define OPENSSL_ECC192_BITS 192
#define OPENSSL_ECC224_BITS 224
#define OPENSSL_ECC256_BITS 256
#define OPENSSL_ECC320_BITS 320
#define OPENSSL_ECC384_BITS 384
#define OPENSSL_ECC512_BITS 512
#define OPENSSL_ECC521_BITS 521

#define UNCOMPRESSED_FORMAT "UNCOMPRESSED"
#define COMPRESSED_FORMAT "COMPRESSED"

static const char *g_eccGenerateFieldType = "Fp";

// JS side AsyKeyDataItem values:
// EC_PRIVATE_K=6
// EC_PRIVATE_04_X_Y_K=7
// EC_PUBLIC_X_Y=8
// EC_PUBLIC_04_X_Y=9
// EC_PUBLIC_COMPRESS_X=10
#define EC_PRIVATE_K 6
#define EC_PRIVATE_04_X_Y_K 7
#define EC_PUBLIC_X_Y 8
#define EC_PUBLIC_04_X_Y 9
#define EC_PUBLIC_COMPRESS_X 10

typedef struct {
    BIGNUM *p;
    BIGNUM *b;
    BIGNUM *x;
    BIGNUM *y;
}HcfBigIntegerParams;

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    int32_t curveId;
} HcfAsyKeyGeneratorSpiOpensslEccImpl;

typedef struct {
    const uint8_t *pStdBin;
    const uint8_t *bStdBin;
    const uint8_t *xStdBin;
    const uint8_t *yStdBin;
    int32_t binLen;
    const char *curveName;
} HcfCurveInfo;

static HcfResult CheckCurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y, const HcfCurveInfo *curveInfo)
{
    BIGNUM *pStd = OpensslBin2Bn(curveInfo->pStdBin, curveInfo->binLen, NULL);
    BIGNUM *bStd = OpensslBin2Bn(curveInfo->bStdBin, curveInfo->binLen, NULL);
    BIGNUM *xStd = OpensslBin2Bn(curveInfo->xStdBin, curveInfo->binLen, NULL);
    BIGNUM *yStd = OpensslBin2Bn(curveInfo->yStdBin, curveInfo->binLen, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        if (curveInfo->curveName != NULL) {
            LOGE("%{public}s Curve convert to BN fail", curveInfo->curveName);
        }
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslBnCmp(p, pStd) == 0 && OpensslBnCmp(b, bStd) == 0 &&
        OpensslBnCmp(x, xStd) == 0 && OpensslBnCmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGD("%{public}s compare fail", curveInfo->curveName);
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckEc224CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_ecc224CorrectBigP,
        .bStdBin = g_ecc224CorrectBigB,
        .xStdBin = g_ecc224CorrectBigGX,
        .yStdBin = g_ecc224CorrectBigGY,
        .binLen = NID_secp224r1_len,
        .curveName = "EC 224",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckEc256CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_ecc256CorrectBigP,
        .bStdBin = g_ecc256CorrectBigB,
        .xStdBin = g_ecc256CorrectBigGX,
        .yStdBin = g_ecc256CorrectBigGY,
        .binLen = NID_X9_62_prime256v1_len,
        .curveName = "EC 256",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckEc384CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_ecc384CorrectBigP,
        .bStdBin = g_ecc384CorrectBigB,
        .xStdBin = g_ecc384CorrectBigGX,
        .yStdBin = g_ecc384CorrectBigGY,
        .binLen = NID_secp384r1_len,
        .curveName = "EC 384",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckEc521CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_ecc521CorrectBigP,
        .bStdBin = g_ecc521CorrectBigB,
        .xStdBin = g_ecc521CorrectBigGX,
        .yStdBin = g_ecc521CorrectBigGY,
        .binLen = NID_secp521r1_len,
        .curveName = "EC 521",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP160r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp160r1CorrectBigP,
        .bStdBin = g_bp160r1CorrectBigB,
        .xStdBin = g_bp160r1CorrectBigGX,
        .yStdBin = g_bp160r1CorrectBigGY,
        .binLen = NID_brainpoolP160r1_len,
        .curveName = "BP 160r1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP160t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp160t1CorrectBigP,
        .bStdBin = g_bp160t1CorrectBigB,
        .xStdBin = g_bp160t1CorrectBigGX,
        .yStdBin = g_bp160t1CorrectBigGY,
        .binLen = NID_brainpoolP160t1_len,
        .curveName = "BP 160t1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP192r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp192r1CorrectBigP,
        .bStdBin = g_bp192r1CorrectBigB,
        .xStdBin = g_bp192r1CorrectBigGX,
        .yStdBin = g_bp192r1CorrectBigGY,
        .binLen = NID_brainpoolP192r1_len,
        .curveName = "BP 192r1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP192t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp192t1CorrectBigP,
        .bStdBin = g_bp192t1CorrectBigB,
        .xStdBin = g_bp192t1CorrectBigGX,
        .yStdBin = g_bp192t1CorrectBigGY,
        .binLen = NID_brainpoolP192t1_len,
        .curveName = "BP 192t1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP224r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp224r1CorrectBigP,
        .bStdBin = g_bp224r1CorrectBigB,
        .xStdBin = g_bp224r1CorrectBigGX,
        .yStdBin = g_bp224r1CorrectBigGY,
        .binLen = NID_brainpoolP224r1_len,
        .curveName = "BP 224r1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP224t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp224t1CorrectBigP,
        .bStdBin = g_bp224t1CorrectBigB,
        .xStdBin = g_bp224t1CorrectBigGX,
        .yStdBin = g_bp224t1CorrectBigGY,
        .binLen = NID_brainpoolP224t1_len,
        .curveName = "BP 224t1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP256r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp256r1CorrectBigP,
        .bStdBin = g_bp256r1CorrectBigB,
        .xStdBin = g_bp256r1CorrectBigGX,
        .yStdBin = g_bp256r1CorrectBigGY,
        .binLen = NID_brainpoolP256r1_len,
        .curveName = "BP 256r1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP256t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp256t1CorrectBigP,
        .bStdBin = g_bp256t1CorrectBigB,
        .xStdBin = g_bp256t1CorrectBigGX,
        .yStdBin = g_bp256t1CorrectBigGY,
        .binLen = NID_brainpoolP256t1_len,
        .curveName = "BP 256t1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckSecp256k1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_secp256k1CorrectBigP,
        .bStdBin = g_secp256k1CorrectBigB,
        .xStdBin = g_secp256k1CorrectBigGX,
        .yStdBin = g_secp256k1CorrectBigGY,
        .binLen = NID_secp256k1_len,
        .curveName = "Secp256k1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckNistp192CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_nistp192CorrectBigP,
        .bStdBin = g_nistp192CorrectBigB,
        .xStdBin = g_nistp192CorrectBigGX,
        .yStdBin = g_nistp192CorrectBigGY,
        .binLen = NID_X9_62_prime192v1_len,
        .curveName = "NIST P-192",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP320r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp320r1CorrectBigP,
        .bStdBin = g_bp320r1CorrectBigB,
        .xStdBin = g_bp320r1CorrectBigGX,
        .yStdBin = g_bp320r1CorrectBigGY,
        .binLen = NID_brainpoolP320r1_len,
        .curveName = "BP 320r1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP320t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp320t1CorrectBigP,
        .bStdBin = g_bp320t1CorrectBigB,
        .xStdBin = g_bp320t1CorrectBigGX,
        .yStdBin = g_bp320t1CorrectBigGY,
        .binLen = NID_brainpoolP320t1_len,
        .curveName = "BP 320t1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP384r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp384r1CorrectBigP,
        .bStdBin = g_bp384r1CorrectBigB,
        .xStdBin = g_bp384r1CorrectBigGX,
        .yStdBin = g_bp384r1CorrectBigGY,
        .binLen = NID_brainpoolP384r1_len,
        .curveName = "BP 384r1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP384t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp384t1CorrectBigP,
        .bStdBin = g_bp384t1CorrectBigB,
        .xStdBin = g_bp384t1CorrectBigGX,
        .yStdBin = g_bp384t1CorrectBigGY,
        .binLen = NID_brainpoolP384t1_len,
        .curveName = "BP 384t1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP512r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp512r1CorrectBigP,
        .bStdBin = g_bp512r1CorrectBigB,
        .xStdBin = g_bp512r1CorrectBigGX,
        .yStdBin = g_bp512r1CorrectBigGY,
        .binLen = NID_brainpoolP512r1_len,
        .curveName = "BP 512r1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CheckBP512t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    HcfCurveInfo curveInfo = {
        .pStdBin = g_bp512t1CorrectBigP,
        .bStdBin = g_bp512t1CorrectBigB,
        .xStdBin = g_bp512t1CorrectBigGX,
        .yStdBin = g_bp512t1CorrectBigGY,
        .binLen = NID_brainpoolP512t1_len,
        .curveName = "BP 512t1",
    };
    return CheckCurveId(p, b, x, y, &curveInfo);
}

static HcfResult CompareOpenssl160BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    if (CheckBP160r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP160r1;
        return HCF_SUCCESS;
    } else if (CheckBP160t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP160t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl192BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    if (CheckNistp192CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_X9_62_prime192v1;
        return HCF_SUCCESS;
    } else if (CheckBP192r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP192r1;
        return HCF_SUCCESS;
    } else if (CheckBP192t1CurveId(bigIntegerParams->p, bigIntegerParams->b,
        bigIntegerParams->x, bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP192t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl224BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    HcfResult res = HCF_INVALID_PARAMS;
    res = CheckEc224CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x, bigIntegerParams->y);
    if (res == HCF_SUCCESS) {
        *curveId = NID_secp224r1;
        return res;
    } else if (CheckBP224r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP224r1;
        return HCF_SUCCESS;
    } else if (CheckBP224t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP224t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl256BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    HcfResult res = HCF_INVALID_PARAMS;
    res = CheckEc256CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x, bigIntegerParams->y);
    if (res == HCF_SUCCESS) {
        *curveId = NID_X9_62_prime256v1;
        return res;
    } else if (CheckBP256r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP256r1;
        return HCF_SUCCESS;
    } else if (CheckBP256t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP256t1;
        return HCF_SUCCESS;
    } else if (CheckSecp256k1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_secp256k1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl320BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    if (CheckBP320r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP320r1;
        return HCF_SUCCESS;
    } else if (CheckBP320t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP320t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl384BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    HcfResult res = HCF_INVALID_PARAMS;
    res = CheckBP384r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x, bigIntegerParams->y);
    if (res == HCF_SUCCESS) {
        *curveId = NID_brainpoolP384r1;
        return res;
    } else if (CheckEc384CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_secp384r1;
        return HCF_SUCCESS;
    } else if (CheckBP384t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP384t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl512BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    if (CheckBP512r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP512r1;
        return HCF_SUCCESS;
    } else if (CheckBP512t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP512t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl521BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    HcfResult res = CheckEc521CurveId(bigIntegerParams->p, bigIntegerParams->b,
        bigIntegerParams->x, bigIntegerParams->y);
    if (res == HCF_SUCCESS) {
        *curveId = NID_secp521r1;
        return res;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult EccMatchParamsSpecToCurveId(int32_t bitLenP, const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    switch (bitLenP) {
        case OPENSSL_ECC160_BITS:
            return CompareOpenssl160BitsType(ecParams, curveId, bigIntegerParams);
        case OPENSSL_ECC192_BITS:
            return CompareOpenssl192BitsType(ecParams, curveId, bigIntegerParams);
        case OPENSSL_ECC224_BITS:
            return CompareOpenssl224BitsType(ecParams, curveId, bigIntegerParams);
        case OPENSSL_ECC256_BITS:
            return CompareOpenssl256BitsType(ecParams, curveId, bigIntegerParams);
        case OPENSSL_ECC320_BITS:
            return CompareOpenssl320BitsType(ecParams, curveId, bigIntegerParams);
        case OPENSSL_ECC384_BITS:
            return CompareOpenssl384BitsType(ecParams, curveId, bigIntegerParams);
        case OPENSSL_ECC512_BITS:
            return CompareOpenssl512BitsType(ecParams, curveId, bigIntegerParams);
        case OPENSSL_ECC521_BITS:
            return CompareOpenssl521BitsType(ecParams, curveId, bigIntegerParams);
        default:
            LOGE("Find no bit len:%{public}d", bitLenP);
            return HCF_INVALID_PARAMS;
    }
}

static HcfResult CheckParamsSpecToGetCurveId(const HcfEccCommParamsSpec *ecParams, int32_t *curveId)
{
    HcfBigIntegerParams bigIntegerParams;
    bigIntegerParams.p = NULL;
    bigIntegerParams.b = NULL;
    bigIntegerParams.x = NULL;
    bigIntegerParams.y = NULL;
    HcfECFieldFp *field = (HcfECFieldFp *)(ecParams->field);
    if (BigIntegerToBigNum(&(field->p), &(bigIntegerParams.p)) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->b), &(bigIntegerParams.b)) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->g.x), &(bigIntegerParams.x)) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->g.y), &(bigIntegerParams.y)) != HCF_SUCCESS) {
        LOGE("Failed to convert BigInteger to BIGNUM.");
        FreeCurveBigNum(bigIntegerParams.p, bigIntegerParams.b, bigIntegerParams.x, bigIntegerParams.y);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    int32_t bitLenP = (int32_t)OpensslBnNumBits(bigIntegerParams.p);
    HcfResult res = EccMatchParamsSpecToCurveId(bitLenP, ecParams, curveId, &bigIntegerParams);
    FreeCurveBigNum(bigIntegerParams.p, bigIntegerParams.b, bigIntegerParams.x, bigIntegerParams.y);
    return res;
}

static HcfResult GenerateEcKeyWithParamsSpec(const HcfEccCommParamsSpec *ecParams, EC_KEY **returnKey)
{
    if (ecParams == NULL || returnKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    int32_t curveId = 0;
    HcfResult ret = CheckParamsSpecToGetCurveId(ecParams, &curveId);
    if (ret == HCF_SUCCESS && curveId != 0) {
        ecKey = OpensslEcKeyNewByCurveName(curveId);
        LOGD("generate EC_KEY by curve name");
        if (ecKey == NULL) {
            LOGE("new ec key failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    } else {
        EC_GROUP *group = NULL;
        ret = GenerateEcGroupWithParamsSpec(ecParams, &group);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to generate EC group from params spec.");
            return ret;
        }
        ecKey = OpensslEcKeyNew();
        if (ecKey == NULL) {
            LOGE("Failed to create a new EC key.");
            OpensslEcGroupFree(group);
            return HCF_ERR_CRYPTO_OPERATION;
        }
        if (OpensslEcKeySetGroup(ecKey, group) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to set EC group on key.");
            OpensslEcGroupFree(group);
            OpensslEcKeyFree(ecKey);
            return HCF_ERR_CRYPTO_OPERATION;
        }
        OpensslEcGroupFree(group);
        LOGD("generate EC_KEY by group spec parmas");
    }
    // all exceptions have been returned above.
    *returnKey = ecKey;
    return HCF_SUCCESS;
}

static HcfResult NewEcKeyPairWithCommSpec(const HcfEccCommParamsSpec *ecParams, EC_KEY **returnEckey)
{
    if (ecParams == NULL || returnEckey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateEcKeyWithParamsSpec(ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("generate EC key fails");
        return ret;
    }
    if (OpensslEcKeyGenerateKey(ecKey) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to generate EC key pair.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcKeyCheckKey(ecKey) <= 0) {
        LOGE("Check key fail.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEckey = ecKey;
    return ret;
}

static HcfResult NewEcPubKeyWithPubSpec(const HcfEccPubKeyParamsSpec *ecParams, EC_KEY **returnEcKey)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateEcKeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("generate EC key fails");
        return ret;
    }
    ret = SetEcKey(&(ecParams->pk), NULL, ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Set pub ecKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcKeyCheckKey(ecKey) <= 0) {
        LOGE("Check key fail.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return ret;
}

static HcfResult NewEcPriKeyWithPriSpec(const HcfEccPriKeyParamsSpec *ecParams, EC_KEY **returnEcKey)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateEcKeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("generate EC key fails");
        return ret;
    }
    ret = SetEcKey(NULL, &(ecParams->sk), ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Set pri ecKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcKeyCheckKey(ecKey) <= 0) {
        LOGE("Check key fail.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return ret;
}

static HcfResult NewEcKeyWithKeyPairSpec(const HcfEccKeyPairParamsSpec *ecParams, EC_KEY **returnEcKey,
    bool needPrivate)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateEcKeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("generate EC key fails");
        return ret;
    }
    if (needPrivate) {
        ret = SetEcKey(&(ecParams->pk), &(ecParams->sk), ecKey);
    } else {
        ret = SetEcKey(&(ecParams->pk), NULL, ecKey);
    }
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to set EC key.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcKeyCheckKey(ecKey) <= 0) {
        LOGE("Check key fail.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return ret;
}

static HcfResult GenKeyPairEcKeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = NewEcKeyPairWithCommSpec((HcfEccCommParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewEcKeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, true);
            break;
        default:
            LOGE("Invalid input spec to gen key pair.");
            break;
    }
    return ret;
}

static HcfResult GenPubKeyEcKeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            ret = NewEcPubKeyWithPubSpec((HcfEccPubKeyParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewEcKeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, false);
            break;
        default:
            LOGE("Invalid input spec to gen pub key");
            break;
    }
    return ret;
}

static HcfResult GenPriKeyEcKeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            ret = NewEcPriKeyWithPriSpec((HcfEccPriKeyParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewEcKeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, true);
            break;
        default:
            LOGE("Invalid input spec to gen pri key");
            break;
    }
    return ret;
}

static const char *GetEccKeyPairGeneratorClass(void)
{
    return OPENSSL_ECC_KEY_GENERATOR_CLASS;
}

static const char *GetEccKeyPairClass(void)
{
    return HCF_OPENSSL_ECC_KEY_PAIR_CLASS;
}

static const char *GetEccPubKeyClass(void)
{
    return HCF_OPENSSL_ECC_PUB_KEY_CLASS;
}

static const char *GetEccPriKeyClass(void)
{
    return HCF_OPENSSL_ECC_PRI_KEY_CLASS;
}

static void DestroyEccKeyPairGenerator(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEccKeyPairGeneratorClass())) {
        return;
    }
    HcfFree(self);
}

static void DestroyEccPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEccPubKeyClass())) {
        return;
    }
    HcfOpensslEccPubKey *impl = (HcfOpensslEccPubKey *)self;
    OpensslEcKeyFree(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroyEccPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEccPriKeyClass())) {
        return;
    }
    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
    OpensslEcKeyFree(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroyEccKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEccKeyPairClass())) {
        return;
    }
    HcfOpensslEccKeyPair *impl = (HcfOpensslEccKeyPair *)self;
    if (impl->base.pubKey != NULL) {
        DestroyEccPubKey((HcfObjectBase *)impl->base.pubKey);
        impl->base.pubKey = NULL;
    }
    if (impl->base.priKey != NULL) {
        DestroyEccPriKey((HcfObjectBase *)impl->base.priKey);
        impl->base.priKey = NULL;
    }
    HcfFree(impl);
}

static const char *GetEccPubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_ECC_ALGORITHM;
}

static const char *GetEccPriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_ECC_ALGORITHM;
}

static HcfResult GetEccPubKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    const HcfOpensslEccPubKey *impl = (const HcfOpensslEccPubKey *)self;
    if (impl->ecKey == NULL) {
        LOGE("EC_KEY is NULL.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    const EC_GROUP *group = OpensslEcKeyGet0Group(impl->ecKey);
    if (group == NULL) {
        LOGE("EC_GROUP is NULL.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int degree = OpensslEcGroupGetDegree(group);
    if (degree < 0) {
        LOGE("EC get degree failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *keySize = degree;
    return HCF_SUCCESS;
}

static HcfResult GetEccPriKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    const HcfOpensslEccPriKey *impl = (const HcfOpensslEccPriKey *)self;
    if (impl->ecKey == NULL) {
        LOGE("EC_KEY is NULL.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    const EC_GROUP *group = OpensslEcKeyGet0Group(impl->ecKey);
    if (group == NULL) {
        LOGE("EC_GROUP is NULL.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int degree = OpensslEcGroupGetDegree(group);
    if (degree < 0) {
        LOGE("EC get degree failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *keySize = degree;
    return HCF_SUCCESS;
}

static const char *GetEccPubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_ECC_PUB_KEY_FORMAT;
}

static const char *GetEccPriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_ECC_PRI_KEY_FORMAT;
}

static HcfResult CheckAndUpdateEccPubKeyFormat(const char **format)
{
    if (format == NULL || *format == NULL) {
        LOGE("Invalid format parameter");
        return HCF_INVALID_PARAMS;
    }

    const char *x509Str = "X509|";

    if (strncmp(*format, x509Str, HcfStrlen(x509Str)) != 0) {
        LOGE("Invalid x509Str parameter");
        return HCF_INVALID_PARAMS;
    }

    const char *formatPtr = *format + HcfStrlen(x509Str);

    if (strcmp(formatPtr, UNCOMPRESSED_FORMAT) == 0 || strcmp(formatPtr, COMPRESSED_FORMAT) == 0) {
        *format = formatPtr;
        return HCF_SUCCESS;
    } else {
        LOGE("Invalid formatPtr parameter");
        return HCF_INVALID_PARAMS;
    }
}

static OSSL_PARAM *ConvertHcfBlobToOsslParams(const char *groupName, HcfBlob *pointBlob, const char *format)
{
    OSSL_PARAM_BLD *paramBld = OpensslOsslParamBldNew();
    if (paramBld == NULL) {
        LOGE("paramBld is null");
        return NULL;
    }
    if (OpensslOsslParamBldPushUtf8String(paramBld, "group", groupName, 0) != HCF_OPENSSL_SUCCESS) {
        LOGE("Invalid groupName parameter.");
        OpensslOsslParamBldFree(paramBld);
        return NULL;
    }
    if (OpensslOsslParamBldPushUtf8String(paramBld, "point-format", format, 0) != HCF_OPENSSL_SUCCESS) {
        LOGE("Invalid format parameter.");
        OpensslOsslParamBldFree(paramBld);
        return NULL;
    }
    if (OpensslOsslParamBldPushOctetString(paramBld, "pub", pointBlob->data, pointBlob->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Invalid pointBlob parameter.");
        OpensslOsslParamBldFree(paramBld);
        return NULL;
    }
    OSSL_PARAM *params = OpensslOsslParamBldToParam(paramBld);
    if (params == NULL) {
        LOGE("Failed to convert OSSL_PARAM_BLD to OSSL_PARAM");
        HcfPrintOpensslError();
        OpensslOsslParamBldFree(paramBld);
        return NULL;
    }
    OpensslOsslParamBldFree(paramBld);
    return params;
}

static EC_KEY *ConvertOsslParamsToEccPubKey(const char *groupName, int32_t curveId,
                                            HcfBlob *pointBlob, const char *format)
{
    OSSL_PARAM *params = ConvertHcfBlobToOsslParams(groupName, pointBlob, format);
    if (params == NULL) {
        LOGE("Failed to convert OSSL_PARAM_BLD to OSSL_PARAM");
        return NULL;
    }
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *returnKey = NULL;
    do {
        ctx = OpensslEvpPkeyCtxNewId(EVP_PKEY_EC, NULL);
        if (ctx == NULL) {
            LOGE("Failed to create EVP_PKEY_CTX");
            break;
        }
        if (OpensslEvpPkeyParamGenInit(ctx) <= 0) {
            LOGE("Create EVP_PKEY_CTX by curveId fail, curveId is %{public}d", curveId);
            break;
        }
        if (OpensslEvpPkeyCtxSetEcParamgenCurveNid(ctx, curveId) <= 0) {
            LOGE("EVP init curveId fail");
            HcfPrintOpensslError();
            break;
        }
        if (OpensslEvpPkeyFromDataInit(ctx) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP init fail");
            break;
        }
        if (OpensslEvpPkeyFromData(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP get pkey fail");
            HcfPrintOpensslError();
            break;
        }
        returnKey = OpensslEvpPkeyGet1EcKey(pkey);
        if (returnKey == NULL) {
            LOGE("Return key is NULL");
            break;
        }
    } while (0);
    OpensslEvpPkeyFree(pkey);
    OpensslEvpPkeyCtxFree(ctx);
    OpensslOsslParamFree(params);
    return returnKey;
}

static HcfResult GetCompressedEccPointEncoded(HcfOpensslEccPubKey *impl, HcfBlob *returnBlob)
{
    EC_KEY *ecKey = impl->ecKey;
    if (ecKey == NULL) {
        LOGE("EC key object is null.");
        return HCF_INVALID_PARAMS;
    }
    const EC_GROUP *group = OpensslEcKeyGet0Group(ecKey);
    if (group == NULL) {
        LOGE("Failed to get group.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    const EC_POINT *point = OpensslEcKeyGet0PublicKey(ecKey);
    if (point == NULL) {
        LOGE("Failed to get point.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    size_t returnDataLen = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    if (returnDataLen == 0) {
        LOGE("Failed to get compressed key length.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *returnData = (uint8_t *)HcfMalloc(returnDataLen, 0);
    if (returnData == NULL) {
        LOGE("Failed to allocate memory for returnBlob data.");
        return HCF_ERR_MALLOC;
    }
    size_t result = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
        returnData, returnDataLen, NULL);
    if (result != returnDataLen) {
        LOGE("Failed to convert public key to compressed format.");
        HcfPrintOpensslError();
        HcfFree(returnData);
        returnBlob = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static HcfResult GetDerEccPubKeyEncoded(EC_KEY *ecKey, HcfBlob *returnBlob)
{
    unsigned char *returnData = NULL;
    int returnDataLen = OpensslI2dEcPubKey(ecKey, &returnData);
    if (returnDataLen <= 0) {
        LOGE("i2d_EC_PUBKEY fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static void SetEccKeyAsn1Flag(HcfOpensslEccPubKey *impl)
{
    if (impl->curveId != 0) {
        LOGD("have a curveId");
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_NAMED_CURVE);
    } else {
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_EXPLICIT_CURVE);
    }
}

static HcfResult GetEccPubKeyEncodedDer(const HcfPubKey *self, const char *format, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (CheckAndUpdateEccPubKeyFormat(&format) != HCF_SUCCESS) {
        LOGE("Invalid format.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        LOGE("Invalid input parameter type.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslEccPubKey *impl = (HcfOpensslEccPubKey *)self;
    SetEccKeyAsn1Flag(impl);

    char *groupName = NULL;
    HcfResult ret = GetGroupNameByNid(impl->curveId, &groupName);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to get group name.");
        return ret;
    }
    HcfBlob tmpBlob = { .data = NULL, .len = 0 };
    ret = GetCompressedEccPointEncoded(impl, &tmpBlob);
    if (ret != HCF_SUCCESS) {
        LOGE("Invalid input parameter.");
        return ret;
    }
    EC_KEY *tmpEcKey = ConvertOsslParamsToEccPubKey(groupName, impl->curveId, &tmpBlob, format);
    if (tmpEcKey == NULL) {
        LOGE("Failed to convert ECC parameters to EC public key.");
        HcfBlobDataFree(&tmpBlob);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = GetDerEccPubKeyEncoded(tmpEcKey, returnBlob);
    OpensslEcKeyFree(tmpEcKey);
    HcfBlobDataFree(&tmpBlob);
    return ret;
}

static HcfResult GetEccPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslEccPubKey *impl = (HcfOpensslEccPubKey *)self;
    SetEccKeyAsn1Flag(impl);

    unsigned char *returnData = NULL;
    int returnDataLen = OpensslI2dEcPubKey(impl->ecKey, &returnData);
    if (returnDataLen <= 0) {
        LOGE("i2d_EC_PUBKEY fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    LOGD("ECC pubKey i2d success");
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static HcfResult GetEccPubKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    return GetEccPubKeyEncodedPemInCommon(self, format, returnString);
}

static HcfResult GetEccPubKeyData(const HcfPubKey *self, uint32_t type, HcfBlob *returnBlob)
{
    return GetEccPubKeyDataInCommon(self, type, returnBlob);
}

static HcfResult GetEccPriKeyData(const HcfPriKey *self, uint32_t type, HcfBlob *returnBlob)
{
    return GetEccPriKeyDataInCommon(self, type, returnBlob);
}

static HcfResult GetEccPriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
    if (impl->curveId != 0) {
        LOGD("have a curveId");
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_NAMED_CURVE);
    } else {
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_EXPLICIT_CURVE);
    }
    // keep consistence of 3.2
    OpensslEcKeySetEncFlags(impl->ecKey, EC_PKEY_NO_PUBKEY);
    // if the convert key has no pubKey, it will generate pub key automatically,
    // and set the no pubKey flag to ensure the consistency of blob.
    unsigned char *returnData = NULL;
    int returnDataLen = OpensslI2dEcPrivateKey(impl->ecKey, &returnData);
    if (returnDataLen <= 0) {
        LOGE("i2d_ECPrivateKey fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    LOGD("ECC priKey i2d success");
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static HcfResult GetEccPriKeyEncodedPem(const HcfPriKey *self, HcfParamsSpec *paramsSpec, const char *format,
    char **returnString)
{
    if (self == NULL || format == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        LOGE("Invalid ecc pri key class.");
        return HCF_INVALID_PARAMS;
    }
    if (paramsSpec != NULL) {
        LOGE("Ecc pri key pem with params is not supported.");
        return HCF_INVALID_PARAMS;
    }

    return GetEccPriKeyEncodedPemInCommon(self, format, returnString);
}

static HcfResult ParamCheck(const HcfPriKey *self, const char *format, const HcfBlob *returnBlob)
{
    if ((self == NULL) || (format == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        LOGE("Invalid ecc params.");
        return HCF_INVALID_PARAMS;
    }
    if (strcmp(format, "PKCS8") != 0) {
        LOGE("Invalid point format.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult CopyMemFromBIO(BIO *bio, HcfBlob *returnBlob)
{
    int len = BIO_pending(bio);
    if (len <= 0) {
        LOGE("Bio len less than 0.");
        return HCF_INVALID_PARAMS;
    }
    HcfBlob tmpBlob;
    tmpBlob.len = len;
    tmpBlob.data = (uint8_t *)HcfMalloc(sizeof(uint8_t) * len, 0);
    if (tmpBlob.data == NULL) {
        LOGE("Malloc mem for blob fail.");
        return HCF_ERR_MALLOC;
    }
    if (OpensslBioRead(bio, tmpBlob.data, tmpBlob.len) <= 0) {
        LOGE("Bio read fail");
        HcfPrintOpensslError();
        HcfFree(tmpBlob.data);
        tmpBlob.data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->len = tmpBlob.len;
    returnBlob->data = tmpBlob.data;
    return HCF_SUCCESS;
}

static HcfResult GetECPriKeyEncodedDer(const HcfPriKey *self, const char *format, HcfBlob *returnBlob)
{
    HcfResult ret = ParamCheck(self, format, returnBlob);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
    if (impl->curveId != 0) {
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_NAMED_CURVE);
    } else {
        OpensslEcKeySetAsn1Flag(impl->ecKey, OPENSSL_EC_EXPLICIT_CURVE);
    }
    // keep consistence of 3.2
    OpensslEcKeySetEncFlags(impl->ecKey, EC_PKEY_NO_PUBKEY);
    EVP_PKEY *pkey = OpensslEvpPkeyNew();
    if (pkey == NULL) {
        HcfPrintOpensslError();
        LOGE("New pKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeySet1EcKey(pkey, impl->ecKey) != HCF_OPENSSL_SUCCESS) {
        OpensslEvpPkeyFree(pkey);
        HcfPrintOpensslError();
        LOGE("set ec key failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR2;
    }
    if (i2d_PKCS8PrivateKey_bio(bio, pkey, NULL, NULL, 0, NULL, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("i2d privateKey bio fail.");
        HcfPrintOpensslError();
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR1;
    }
    ret = CopyMemFromBIO(bio, returnBlob);
    if (ret != HCF_SUCCESS) {
        LOGE("Copy mem from BIO fail.");
    }
ERR1:
    OpensslBioFreeAll(bio);
ERR2:
    OpensslEvpPkeyFree(pkey);
    return ret;
}

static void EccPriKeyClearMem(HcfPriKey *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccPriKeyClass())) {
        return;
    }
    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
    OpensslEcKeyFree(impl->ecKey);
    impl->ecKey = NULL;
}

static HcfResult GetCurveName(const HcfKey *self, const bool isPrivate, char **returnString)
{
    int32_t curveId = 0;
    if (isPrivate) {
        curveId = ((HcfOpensslEccPriKey *)self)->curveId;
    } else {
        curveId = ((HcfOpensslEccPubKey *)self)->curveId;
    }

    char *tmp = NULL;
    if (GetCurveNameByCurveId(curveId, &tmp) != HCF_SUCCESS) {
        LOGE("get vurveName by curveId failed.");
        return HCF_INVALID_PARAMS;
    }

    if (tmp == NULL) {
        LOGE("tmp is null.");
        return HCF_INVALID_PARAMS;
    }
    size_t len = HcfStrlen(tmp);
    if (len == 0) {
        LOGE("fieldType is empty!");
        return HCF_INVALID_PARAMS;
    }

    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Alloc returnString memory failed.");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(*returnString, len, tmp, len);
    return HCF_SUCCESS;
}

static HcfResult CheckEcKeySelf(const HcfKey *self, bool *isPrivate)
{
    if (HcfIsClassMatch((HcfObjectBase *)self, GetEccPubKeyClass())) {
        *isPrivate = false;
        return HCF_SUCCESS;
    } else if (HcfIsClassMatch((HcfObjectBase *)self, GetEccPriKeyClass())) {
        if (((HcfOpensslEccPriKey *)self)->ecKey == NULL) {
            LOGE("Cannot use priKey after free");
            return HCF_INVALID_PARAMS;
        }
        *isPrivate = true;
        return HCF_SUCCESS;
    } else {
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult GetEcKeySpecBigInteger(const HcfKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate = false;
    HcfResult res = CheckEcKeySelf(self, &isPrivate);
    if (res != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }
    const EC_GROUP *group = NULL;
    if (isPrivate) {
        group = OpensslEcKeyGet0Group(((HcfOpensslEccPriKey *)self)->ecKey);
    } else {
        group = OpensslEcKeyGet0Group(((HcfOpensslEccPubKey *)self)->ecKey);
    }
    switch (item) {
        case ECC_FP_P_BN:
        case ECC_A_BN:
        case ECC_B_BN:
            res = GetCurveGFp(group, item, returnBigInteger);
            break;
        case ECC_G_X_BN:
        case ECC_G_Y_BN:
            res = GetGenerator(group, item, returnBigInteger);
            break;
        case ECC_N_BN:
            res = GetOrder(group, returnBigInteger);
            break;
        case ECC_SK_BN:
        case ECC_PK_X_BN:
        case ECC_PK_Y_BN:
            res = GetPkSkBigInteger(self, isPrivate, item, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            res = HCF_INVALID_PARAMS;
            break;
    }
    return res;
}

static HcfResult GetEcKeySpecString(const HcfKey *self, const AsyKeySpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate = false;
    HcfResult res = CheckEcKeySelf(self, &isPrivate);
    if (res != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }

    switch (item) {
        case ECC_FIELD_TYPE_STR:
            res = GetFieldType(self, isPrivate, returnString);
            break;
        case ECC_CURVE_NAME_STR:
            res = GetCurveName(self, isPrivate, returnString);
            break;
        default:
            res = HCF_INVALID_PARAMS;
            LOGE("Invalid spec of ec string");
            break;
    }
    return res;
}

static HcfResult GetEcKeySpecInt(const HcfKey *self, const AsyKeySpecItem item, int *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate = false;
    HcfResult res = CheckEcKeySelf(self, &isPrivate);
    if (res != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }
    const EC_GROUP *group = NULL;
    if (isPrivate) {
        group = OpensslEcKeyGet0Group(((HcfOpensslEccPriKey *)self)->ecKey);
    } else {
        group = OpensslEcKeyGet0Group(((HcfOpensslEccPubKey *)self)->ecKey);
    }
    switch (item) {
        case ECC_H_INT:
            res = GetCofactor(group, returnInt);
            break;
        case ECC_FIELD_SIZE_INT:
            res = GetFieldSize(group, returnInt);
            break;
        default:
            res = HCF_INVALID_PARAMS;
            LOGE("invalid ec key int spec");
            break;
    }
    return res;
}

static HcfResult GetECPubKeySpecBigInteger(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    return GetEcKeySpecBigInteger((HcfKey *)self, item, returnBigInteger);
}

static HcfResult GetECPubKeySpecString(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString)
{
    return GetEcKeySpecString((HcfKey *)self, item, returnString);
}

static HcfResult GetECPubKeySpecInt(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt)
{
    return GetEcKeySpecInt((HcfKey *)self, item, returnInt);
}

static HcfResult GetECPriKeySpecBigInteger(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    return GetEcKeySpecBigInteger((HcfKey *)self, item, returnBigInteger);
}

static HcfResult GetECPriKeySpecString(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString)
{
    return GetEcKeySpecString((HcfKey *)self, item, returnString);
}

static HcfResult GetECPriKeySpecInt(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt)
{
    return GetEcKeySpecInt((HcfKey *)self, item, returnInt);
}

static HcfResult PackEccPubKey(int32_t curveId, EC_KEY *ecKey, const char *fieldType,
    HcfOpensslEccPubKey **returnObj)
{
    HcfOpensslEccPubKey *returnPubKey = (HcfOpensslEccPubKey *)HcfMalloc(sizeof(HcfOpensslEccPubKey), 0);
    if (returnPubKey == NULL) {
        LOGE("Failed to allocate returnPubKey memory!");
        return HCF_ERR_MALLOC;
    }
    char *tmpFieldType = NULL;
    if (fieldType != NULL) {
        size_t len = HcfStrlen(fieldType);
        if (len == 0) {
            LOGE("fieldType is empty!");
            HcfFree(returnPubKey);
            returnPubKey = NULL;
            return HCF_INVALID_PARAMS;
        }
        tmpFieldType = (char *)HcfMalloc(len + 1, 0);
        if (tmpFieldType == NULL) {
            LOGE("Alloc tmpFieldType memory failed.");
            HcfFree(returnPubKey);
            returnPubKey = NULL;
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(tmpFieldType, len, fieldType, len);
    }

    returnPubKey->base.base.base.destroy = DestroyEccPubKey;
    returnPubKey->base.base.base.getClass = GetEccPubKeyClass;
    returnPubKey->base.base.getAlgorithm = GetEccPubKeyAlgorithm;
    returnPubKey->base.base.getEncoded = GetEccPubKeyEncoded;
    returnPubKey->base.base.getEncodedPem = GetEccPubKeyEncodedPem;
    returnPubKey->base.base.getFormat = GetEccPubKeyFormat;
    returnPubKey->base.base.getKeySize = GetEccPubKeySize;
    returnPubKey->base.getKeyData = GetEccPubKeyData;
    returnPubKey->base.getAsyKeySpecBigInteger = GetECPubKeySpecBigInteger;
    returnPubKey->base.getAsyKeySpecString = GetECPubKeySpecString;
    returnPubKey->base.getAsyKeySpecInt = GetECPubKeySpecInt;
    returnPubKey->base.getEncodedDer = GetEccPubKeyEncodedDer;
    returnPubKey->curveId = curveId;
    returnPubKey->ecKey = ecKey;
    returnPubKey->fieldType = tmpFieldType;

    *returnObj = returnPubKey;
    return HCF_SUCCESS;
}

static HcfResult GetEccPubKeyFromPriKey(const HcfPriKey *self, HcfPubKey **returnPubKey)
{
    if ((self == NULL) || (returnPubKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccPriKeyClass())) {
        LOGE("Invalid input key type.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
    if (impl->ecKey == NULL) {
        LOGE("EC_KEY is NULL.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    EC_KEY *ecPubKey = NULL;
    HcfResult ret = HcfSetPubKeyDataToNewEcKey(impl->ecKey, &ecPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to set pub key to new ec key.");
        return ret;
    }
    const EC_GROUP *group = OpensslEcKeyGet0Group(ecPubKey);
    int32_t curveId = 0;
    if (group != NULL) {
        curveId = (int32_t)OpensslEcGroupGetCurveName(group);
        if (curveId != 0) {
            impl->curveId = curveId;
        }
    }

    HcfOpensslEccPubKey *pubKey = NULL;
    ret = PackEccPubKey(impl->curveId, ecPubKey, g_eccGenerateFieldType, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to pack ECC public key.");
        OpensslEcKeyFree(ecPubKey);
        return ret;
    }
    *returnPubKey = (HcfPubKey *)pubKey;
    return HCF_SUCCESS;
}

static HcfResult PackEccPriKey(int32_t curveId, EC_KEY *ecKey, const char *fieldType,
    HcfOpensslEccPriKey **returnObj)
{
    HcfOpensslEccPriKey *returnPriKey = (HcfOpensslEccPriKey *)HcfMalloc(sizeof(HcfOpensslEccPriKey), 0);
    if (returnPriKey == NULL) {
        LOGE("Failed to allocate returnPriKey memory!");
        return HCF_ERR_MALLOC;
    }
    char *tmpFieldType = NULL;
    if (fieldType != NULL) {
        size_t len = HcfStrlen(fieldType);
        if (len == 0) {
            LOGE("fieldType is empty!");
            HcfFree(returnPriKey);
            returnPriKey = NULL;
            return HCF_INVALID_PARAMS;
        }
        tmpFieldType = (char *)HcfMalloc(len + 1, 0);
        if (tmpFieldType == NULL) {
            LOGE("Alloc tmpFieldType memory failed.");
            HcfFree(returnPriKey);
            returnPriKey = NULL;
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(tmpFieldType, len, fieldType, len);
    }

    returnPriKey->base.base.base.destroy = DestroyEccPriKey;
    returnPriKey->base.base.base.getClass = GetEccPriKeyClass;
    returnPriKey->base.base.getAlgorithm = GetEccPriKeyAlgorithm;
    returnPriKey->base.base.getEncoded = GetEccPriKeyEncoded;
    returnPriKey->base.getEncodedPem = GetEccPriKeyEncodedPem;
    returnPriKey->base.base.getFormat = GetEccPriKeyFormat;
    returnPriKey->base.base.getKeySize = GetEccPriKeySize;
    returnPriKey->base.clearMem = EccPriKeyClearMem;
    returnPriKey->base.getKeyData = GetEccPriKeyData;
    returnPriKey->base.getAsyKeySpecBigInteger = GetECPriKeySpecBigInteger;
    returnPriKey->base.getAsyKeySpecString = GetECPriKeySpecString;
    returnPriKey->base.getAsyKeySpecInt = GetECPriKeySpecInt;
    returnPriKey->base.getEncodedDer = GetECPriKeyEncodedDer;
    returnPriKey->base.getPubKey = GetEccPubKeyFromPriKey;
    returnPriKey->curveId = curveId;
    returnPriKey->ecKey = ecKey;
    returnPriKey->fieldType = tmpFieldType;

    *returnObj = returnPriKey;
    return HCF_SUCCESS;
}

static HcfResult PackEccKeyPair(HcfOpensslEccPubKey *pubKey, HcfOpensslEccPriKey *priKey,
    HcfOpensslEccKeyPair **returnObj)
{
    HcfOpensslEccKeyPair *returnKeyPair = (HcfOpensslEccKeyPair *)HcfMalloc(sizeof(HcfOpensslEccKeyPair), 0);
    if (returnKeyPair == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        return HCF_ERR_MALLOC;
    }
    returnKeyPair->base.base.getClass = GetEccKeyPairClass;
    returnKeyPair->base.base.destroy = DestroyEccKeyPair;
    returnKeyPair->base.pubKey = (HcfPubKey *)pubKey;
    returnKeyPair->base.priKey = (HcfPriKey *)priKey;

    *returnObj = returnKeyPair;
    return HCF_SUCCESS;
}

HcfResult EccPackPubKeyForConvert(int32_t curveId, EC_KEY *ecKey, HcfOpensslEccPubKey **returnPubKey)
{
    return PackEccPubKey(curveId, ecKey, g_eccGenerateFieldType, returnPubKey);
}

HcfResult EccPackPriKeyForConvert(int32_t curveId, EC_KEY *ecKey, HcfOpensslEccPriKey **returnPriKey)
{
    return PackEccPriKey(curveId, ecKey, g_eccGenerateFieldType, returnPriKey);
}

static HcfResult EngineConvertEccKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }
    bool pubKeyValid = HcfIsBlobValid(pubKeyBlob);
    bool priKeyValid = HcfIsBlobValid(priKeyBlob);
    if ((!pubKeyValid) && (!priKeyValid)) {
        LOGE("The private key and public key cannot both be NULL.");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    HcfResult res = HCF_SUCCESS;
    HcfOpensslEccPubKey *pubKey = NULL;
    HcfOpensslEccPriKey *priKey = NULL;
    HcfOpensslEccKeyPair *keyPair = NULL;
    do {
        if (pubKeyValid) {
            res = ConvertEcPubKey(impl->curveId, pubKeyBlob, &pubKey);
            if (res != HCF_SUCCESS) {
                break;
            }
        }
        if (priKeyValid) {
            res = ConvertEcPriKey(impl->curveId, priKeyBlob, &priKey);
            if (res != HCF_SUCCESS) {
                break;
            }
        }
        res = PackEccKeyPair(pubKey, priKey, &keyPair);
    } while (0);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(pubKey);
        pubKey = NULL;
        HcfObjDestroy(priKey);
        priKey = NULL;
        return res;
    }

    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult ConvertEcPemPubKey(int32_t curveId, const char *pubKeyStr, HcfOpensslEccPubKey **returnPubKey)
{
    EVP_PKEY *pkey = NULL;
    const char *keyType = "EC";
    HcfResult ret = ConvertPubPemStrToKey(&pkey, keyType, EVP_PKEY_PUBLIC_KEY, pubKeyStr);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert ecc pem public key failed.");
        return ret;
    }

    EC_KEY *ecKey = OpensslEvpPkeyGet1EcKey(pkey);
    OpensslEvpPkeyFree(pkey);
    if (ecKey == NULL) {
        LOGE("Pkey to ec key failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult res = PackEccPubKey(curveId, ecKey, g_eccGenerateFieldType, returnPubKey);
    if (res != HCF_SUCCESS) {
        LOGE("Pack ec public key failed.");
        OpensslEcKeyFree(ecKey);
        return res;
    }

    return HCF_SUCCESS;
}

static HcfResult ConvertEcPemPriKey(int32_t curveId, const char *priKeyStr, HcfOpensslEccPriKey **returnPriKey)
{
    EVP_PKEY *pkey = NULL;
    const char *keyType = "EC";
    HcfResult ret = ConvertPriPemStrToKey(priKeyStr, &pkey, keyType);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert ecc pem private key failed.");
        return ret;
    }

    EC_KEY *ecKey = OpensslEvpPkeyGet1EcKey(pkey);
    OpensslEvpPkeyFree(pkey);
    if (ecKey == NULL) {
        LOGE("Pkey to ec key failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    ret = PackEccPriKey(curveId, ecKey, g_eccGenerateFieldType, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Pack ec private key failed.");
        OpensslEcKeyFree(ecKey);
        return ret;
    }

    return HCF_SUCCESS;
}

static HcfResult EngineConvertEccPemKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, const char *pubKeyStr,
    const char *priKeyStr, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyStr == NULL) && (priKeyStr == NULL))) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    HcfResult res = HCF_SUCCESS;
    HcfOpensslEccPubKey *pubKey = NULL;
    HcfOpensslEccPriKey *priKey = NULL;
    HcfOpensslEccKeyPair *keyPair = NULL;

    do {
        if (pubKeyStr != NULL && strlen(pubKeyStr) != 0) {
            res = ConvertEcPemPubKey(impl->curveId, pubKeyStr, &pubKey);
            if (res != HCF_SUCCESS) {
                break;
            }
        }
        if (priKeyStr != NULL && strlen(priKeyStr) != 0) {
            res = ConvertEcPemPriKey(impl->curveId, priKeyStr, &priKey);
            if (res != HCF_SUCCESS) {
                break;
            }
        }
        res = PackEccKeyPair(pubKey, priKey, &keyPair);
    } while (0);
    if (res != HCF_SUCCESS) {
        LOGE("Convert ec keyPair failed.");
        HcfObjDestroy(pubKey);
        pubKey = NULL;
        HcfObjDestroy(priKey);
        priKey = NULL;
        return res;
    }

    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult PackAndAssignPubKey(const HcfAsyKeyGeneratorSpiOpensslEccImpl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfPubKey **returnObj)
{
    HcfOpensslEccPubKey *pubKey = NULL;
    HcfResult res = PackEccPubKey(impl->curveId, ecKey, fieldType, &pubKey);
    if (res != HCF_SUCCESS) {
        return res;
    }
    *returnObj = (HcfPubKey *)pubKey;
    return HCF_SUCCESS;
}

static HcfResult PackAndAssignPriKey(const HcfAsyKeyGeneratorSpiOpensslEccImpl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfPriKey **returnObj)
{
    HcfOpensslEccPriKey *priKey = NULL;
    HcfResult res = PackEccPriKey(impl->curveId, ecKey, fieldType, &priKey);
    if (res != HCF_SUCCESS) {
        return res;
    }
    *returnObj = (HcfPriKey *)priKey;
    return HCF_SUCCESS;
}

static HcfResult CreateAndAssignKeyPair(const HcfAsyKeyGeneratorSpiOpensslEccImpl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfKeyPair **returnObj)
{
    EC_KEY *ecPriKey = EC_KEY_dup(ecKey);
    if (ecPriKey == NULL) {
        LOGE("copy ecKey fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslEccPriKey *priKey = NULL;
    HcfResult res = PackEccPriKey(impl->curveId, ecPriKey, fieldType, &priKey);
    if (res != HCF_SUCCESS) {
        OpensslEcKeyFree(ecPriKey);
        return res;
    }
    HcfOpensslEccPubKey *pubKey = NULL;
    EC_KEY *ecPubKey = EC_KEY_dup(ecKey);
    if (ecPubKey == NULL) {
        LOGE("copy ecKey fail.");
        HcfObjDestroy(priKey);
        priKey = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = PackEccPubKey(impl->curveId, ecPubKey, fieldType, &pubKey);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(priKey);
        priKey = NULL;
        OpensslEcKeyFree(ecPubKey);
        return res;
    }

    HcfOpensslEccKeyPair *returnKeyPair = (HcfOpensslEccKeyPair *)HcfMalloc(sizeof(HcfOpensslEccKeyPair), 0);
    if (returnKeyPair == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        HcfObjDestroy(pubKey);
        pubKey = NULL;
        HcfObjDestroy(priKey);
        priKey = NULL;
        return HCF_ERR_MALLOC;
    }
    returnKeyPair->base.base.getClass = GetEccKeyPairClass;
    returnKeyPair->base.base.destroy = DestroyEccKeyPair;
    returnKeyPair->base.pubKey = (HcfPubKey *)pubKey;
    returnKeyPair->base.priKey = (HcfPriKey *)priKey;

    *returnObj = (HcfKeyPair *)returnKeyPair;
    return HCF_SUCCESS;
}

static HcfResult EngineGenerateKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnObj)
{
    if ((self == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult res = NewEcKeyPair(impl->curveId, &ecKey);
    if (res != HCF_SUCCESS) {
        return res;
    }
    res = CreateAndAssignKeyPair(impl, g_eccGenerateFieldType, ecKey, returnObj);
    OpensslEcKeyFree(ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create and assign key pair.");
        return res;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGenerateKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL) || (params == NULL) ||
        (((HcfEccCommParamsSpec *)params)->field == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult res = GenKeyPairEcKeyBySpec(params, &ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("Gen ec key pair with spec failed.");
        return res;
    }

    // curveId == 0 means no curve to match.
    const EC_GROUP *group = OpensslEcKeyGet0Group(ecKey);
    int32_t curveId = 0;
    if (group != NULL) {
        curveId = (int32_t)OpensslEcGroupGetCurveName(group);
        if (curveId != 0) {
            impl->curveId = curveId;
        }
    }
    // deep copy of ecKey, free ecKey whether it succeed or failed.
    res = CreateAndAssignKeyPair(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnKeyPair);
    OpensslEcKeyFree(ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create and assign key pair.");
        return res;
    }

    return HCF_SUCCESS;
}

static HcfResult EngineGeneratePubKeyBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfPubKey **returnPubKey)
{
    if ((self == NULL) || (returnPubKey == NULL) || (params == NULL) ||
        (((HcfEccCommParamsSpec *)params)->field == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult res = GenPubKeyEcKeyBySpec(params, &ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("Gen ec pubKey with spec failed.");
        return res;
    }
    const EC_GROUP *group = OpensslEcKeyGet0Group(ecKey);
    int32_t curveId = 0;
    if (group != NULL) {
        curveId = (int32_t)OpensslEcGroupGetCurveName(group);
        if (curveId != 0) {
            impl->curveId = curveId;
        }
    }
    res = PackAndAssignPubKey(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnPubKey);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to pack and assign public key.");
        OpensslEcKeyFree(ecKey);
        return res;
    }

    return HCF_SUCCESS;
}

static HcfResult EngineGeneratePriKeyBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfPriKey **returnPriKey)
{
    if ((self == NULL) || (returnPriKey == NULL) || (params == NULL) ||
        (((HcfEccCommParamsSpec *)params)->field == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult res = GenPriKeyEcKeyBySpec(params, &ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("Gen ec pubKey with spec failed.");
        return res;
    }

    const EC_GROUP *group = OpensslEcKeyGet0Group(ecKey);
    int32_t curveId = 0;
    if (group != NULL) {
        curveId = (int32_t)OpensslEcGroupGetCurveName(group);
        if (curveId != 0) {
            impl->curveId = curveId;
        }
    }

    res = PackAndAssignPriKey(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnPriKey);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to pack and assign private key.");
        OpensslEcKeyFree(ecKey);
        return res;
    }

    return HCF_SUCCESS;
}

HcfResult HcfAsyKeyGeneratorSpiEccCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj)
{
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    int32_t curveId = 0;
    if (params->bits != 0) {
        if (GetOpensslCurveId(params->bits, &curveId) != HCF_SUCCESS) {
            return HCF_INVALID_PARAMS;
        }
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *returnImpl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)HcfMalloc(
        sizeof(HcfAsyKeyGeneratorSpiOpensslEccImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetEccKeyPairGeneratorClass;
    returnImpl->base.base.destroy = DestroyEccKeyPairGenerator;
    returnImpl->base.engineConvertKey = EngineConvertEccKey;
    returnImpl->base.engineConvertPemKey = EngineConvertEccPemKey;
    returnImpl->base.engineGenerateKeyPair = EngineGenerateKeyPair;
    returnImpl->base.engineGenerateKeyPairBySpec = EngineGenerateKeyPairBySpec;
    returnImpl->base.engineGeneratePubKeyBySpec = EngineGeneratePubKeyBySpec;
    returnImpl->base.engineGeneratePriKeyBySpec = EngineGeneratePriKeyBySpec;
    returnImpl->curveId = curveId;

    *returnObj = (HcfAsyKeyGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
