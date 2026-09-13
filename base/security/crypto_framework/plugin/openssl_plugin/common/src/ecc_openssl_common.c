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
#include "ecc_openssl_common.h"

#include "securec.h"

#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "utils.h"

HcfResult NewEcKeyPair(int32_t curveId, EC_KEY **returnEcKey)
{
    EC_KEY *ecKey = OpensslEcKeyNewByCurveName(curveId);
    if (ecKey == NULL) {
        LOGE("new ec key failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEcKeyGenerateKey(ecKey) <= 0) {
        LOGE("generate ec key failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEcKeyCheckKey(ecKey) <= 0) {
        LOGE("check key fail.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return HCF_SUCCESS;
}

void FreeCurveBigNum(BIGNUM *pStd, BIGNUM *bStd, BIGNUM *xStd, BIGNUM *yStd)
{
    OpensslBnFree(pStd);
    OpensslBnFree(bStd);
    OpensslBnFree(xStd);
    OpensslBnFree(yStd);
}

static HcfResult NewGroupFromCurveGFp(const HcfEccCommParamsSpec *ecParams, EC_GROUP **ecGroup, BN_CTX *ctx)
{
    HcfResult ret = HCF_SUCCESS;
    HcfECFieldFp *field = (HcfECFieldFp *)(ecParams->field);
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    EC_GROUP *group = NULL;
    do {
        if (BigIntegerToBigNum(&(field->p), &p) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->a), &a) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->b), &b) != HCF_SUCCESS) {
            LOGE("BigInteger to BigNum failed");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        group = OpensslEcGroupNewCurveGfp(p, a, b, ctx);
        if (group == NULL) {
            LOGE("Alloc group memory failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    OpensslBnFree(p);
    OpensslBnFree(a);
    OpensslBnFree(b);

    if (ret == HCF_SUCCESS) {
        *ecGroup = group;
        return ret;
    }
    OpensslEcGroupFree(group);
    return ret;
}

static HcfResult SetEcPointToGroup(const HcfEccCommParamsSpec *ecParams, EC_GROUP *group, BN_CTX *ctx)
{
    HcfResult ret = HCF_SUCCESS;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *order = NULL;
    EC_POINT *generator = NULL;
    BIGNUM *cofactor = OpensslBnNew();
    if (cofactor == NULL) {
        LOGE("Alloc cofactor memory failed.");
        return HCF_ERR_MALLOC;
    }
    do {
        if (BigIntegerToBigNum(&(ecParams->g.x), &x) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->g.y), &y) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->n), &order) != HCF_SUCCESS ||
            !OpensslBnSetWord(cofactor, (uint32_t)ecParams->h)) {
            LOGE("BigInteger to BigNum failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        generator = OpensslEcPointNew(group);
        if (generator == NULL) {
            LOGE("Alloc group memory failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (!OpensslEcPointSetAffineCoordinatesGfp(group, generator, x, y, ctx)) {
            LOGE("Failed to set EC point affine coordinates.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            HcfPrintOpensslError();
            break;
        }

        if (!OpensslEcGroupSetGenerator(group, generator, order, cofactor)) {
            LOGE("Failed to set EC group generator.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            HcfPrintOpensslError();
            break;
        }
    } while (0);
    OpensslBnFree(x);
    OpensslBnFree(y);
    OpensslBnFree(order);
    OpensslBnFree(cofactor);
    OpensslEcPointFree(generator);
    return ret;
}

HcfResult GenerateEcGroupWithParamsSpec(const HcfEccCommParamsSpec *ecParams, EC_GROUP **ecGroup)
{
    if (ecParams == NULL || ecGroup == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_GROUP *group = NULL;
    BN_CTX *ctx = OpensslBnCtxNew();
    if (ctx == NULL) {
        LOGE("Alloc ctx memory failed.");
        return HCF_ERR_MALLOC;
    }
    HcfResult ret = NewGroupFromCurveGFp(ecParams, &group, ctx);
    if (ret != HCF_SUCCESS) {
        LOGE("New Ec group fail");
        OpensslBnCtxFree(ctx);
        return ret;
    }
    ret = SetEcPointToGroup(ecParams, group, ctx);
    if (ret != HCF_SUCCESS) {
        OpensslBnCtxFree(ctx);
        OpensslEcGroupFree(group);
        LOGE("Set Ec point fail");
        return ret;
    }
    OpensslBnCtxFree(ctx);
    *ecGroup = group;
    return ret;
}

static HcfResult InitEcKeyByPubKey(const HcfPoint *pubKey, EC_KEY *ecKey)
{
    const EC_GROUP *group = OpensslEcKeyGet0Group(ecKey);
    if (group == NULL) {
        LOGE("Not find group from ecKey.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EC_POINT *point = OpensslEcPointNew(group);
    if (point == NULL) {
        LOGE("New ec point failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIGNUM *pkX = NULL;
    BIGNUM *pkY = NULL;
    if (BigIntegerToBigNum(&(pubKey->x), &pkX) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(pubKey->y), &pkY) != HCF_SUCCESS) {
        LOGE("BigInteger to BigNum failed.");
        OpensslEcPointFree(point);
        OpensslBnFree(pkX);
        OpensslBnFree(pkY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    // only support fp point.
    // can use EC_POINT_set_affine_coordinates() set x and y by group, deep copy.
    int32_t ret = (int32_t)OpensslEcPointSetAffineCoordinatesGfp(group, point, pkX, pkY, NULL);
    OpensslBnFree(pkX);
    OpensslBnFree(pkY);

    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to set EC point affine coordinates.");
        OpensslEcPointFree(point);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = OpensslEcKeySetPublicKey(ecKey, point);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to set EC public key.");
        OpensslEcPointFree(point);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEcPointFree(point);
    return HCF_SUCCESS;
}

static HcfResult InitEcKeyByPriKey(const HcfBigInteger *priKey, EC_KEY *ecKey)
{
    BIGNUM *sk = NULL;
    if (BigIntegerToBigNum(priKey, &sk) != HCF_SUCCESS) {
        LOGE("BigInteger to BigNum failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int32_t ret = (int32_t)OpensslEcKeySetPrivateKey(ecKey, sk);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to set EC private key.");
        OpensslBnClearFree(sk);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBnClearFree(sk);
    return HCF_SUCCESS;
}

static HcfResult SetEcPubKeyFromPriKey(const HcfBigInteger *priKey, EC_KEY *ecKey)
{
    const EC_GROUP *group = OpensslEcKeyGet0Group(ecKey);
    if (group == NULL) {
        LOGE("Not find group from ecKey.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIGNUM *sk = NULL;
    if (BigIntegerToBigNum(priKey, &sk) != HCF_SUCCESS) {
        LOGE("BigInteger to BigNum failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    EC_POINT *point = OpensslEcPointNew(group);
    do {
        if (point == NULL) {
            LOGE("Failed to create a new EC point.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (!OpensslEcPointMul(group, point, sk, NULL, NULL, NULL)) {
            LOGE("EC_POINT_mul failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (!OpensslEcKeySetPublicKey(ecKey, point)) {
            LOGE("Failed to set EC public key.");
            ret = HCF_ERR_CRYPTO_OPERATION;
        }
    } while (0);
    OpensslEcPointFree(point);
    OpensslBnClearFree(sk);
    return ret;
}

HcfResult SetEcKey(const HcfPoint *pubKey, const HcfBigInteger *priKey, EC_KEY *ecKey)
{
    HcfResult ret = HCF_SUCCESS;
    if (pubKey != NULL) {
        ret = InitEcKeyByPubKey(pubKey, ecKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to initialize EC key from public key.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (priKey != NULL) {
        ret = InitEcKeyByPriKey(priKey, ecKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to initialize EC key from private key.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        if (pubKey == NULL) {
            ret = SetEcPubKeyFromPriKey(priKey, ecKey);
            if (ret != HCF_SUCCESS) {
                LOGE("Failed to set EC public key from private key.");
                return HCF_ERR_CRYPTO_OPERATION;
            }
        }
    }
    return ret;
}

HcfResult GetCurveGFp(const EC_GROUP *group, const AsyKeySpecItem item, HcfBigInteger *returnBigInteger)
{
    BIGNUM *p = OpensslBnNew();
    BIGNUM *a = OpensslBnNew();
    BIGNUM *b = OpensslBnNew();
    if (p == NULL || a == NULL || b == NULL) {
        LOGE("new BN failed.");
        OpensslBnFree(p);
        OpensslBnFree(a);
        OpensslBnFree(b);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcGroupGetCurveGfp(group, p, a, b, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to get EC group curve parameters.");
        OpensslBnFree(p);
        OpensslBnFree(a);
        OpensslBnFree(b);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult ret = HCF_INVALID_PARAMS;
    int curveId = OpensslEcGroupGetCurveName(group);
    if (curveId == NID_secp256k1 && item == ECC_A_BN) {
        ret = BigNumToBigIntegerSecp256k1(a, returnBigInteger);
        OpensslBnFree(p);
        OpensslBnFree(a);
        OpensslBnFree(b);
        return ret;
    }
    switch (item) {
        case ECC_FP_P_BN:
            ret = BigNumToBigInteger(p, returnBigInteger);
            break;
        case ECC_A_BN:
            ret = BigNumToBigInteger(a, returnBigInteger);
            break;
        case ECC_B_BN:
            ret = BigNumToBigInteger(b, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            break;
    }
    OpensslBnFree(p);
    OpensslBnFree(a);
    OpensslBnFree(b);
    return ret;
}

HcfResult GetGenerator(const EC_GROUP *group, const AsyKeySpecItem item, HcfBigInteger *returnBigInteger)
{
    const EC_POINT *generator = OpensslEcGroupGet0Generator(group);
    if (generator == NULL) {
        LOGE("OpensslEcGroupGet0Generator failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    BIGNUM *gX = OpensslBnNew();
    BIGNUM *gY = OpensslBnNew();
    if (gX == NULL || gY == NULL) {
        LOGE("new BN failed.");
        OpensslBnFree(gX);
        OpensslBnFree(gY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcPointGetAffineCoordinatesGfp(group, generator, gX, gY, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to get EC point affine coordinates.");
        OpensslBnFree(gX);
        OpensslBnFree(gY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case ECC_G_X_BN:
            ret = BigNumToBigInteger(gX, returnBigInteger);
            break;
        case ECC_G_Y_BN:
            ret = BigNumToBigInteger(gY, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            break;
    }
    OpensslBnFree(gX);
    OpensslBnFree(gY);
    return ret;
}

HcfResult GetOrder(const EC_GROUP *group, HcfBigInteger *returnBigInteger)
{
    BIGNUM *order = OpensslBnNew();
    if (order == NULL) {
        LOGE("new BN failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcGroupGetOrder(group, order, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to get EC point affine coordinates.");
        OpensslBnFree(order);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult ret = BigNumToBigInteger(order, returnBigInteger);
    OpensslBnFree(order);
    return ret;
}

HcfResult GetCofactor(const EC_GROUP *group, int *returnCofactor)
{
    BIGNUM *cofactor = OpensslBnNew();
    if (cofactor == NULL) {
        LOGE("new BN failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcGroupGetCofactor(group, cofactor, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to get EC point affine coordinates.");
        OpensslBnFree(cofactor);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    *returnCofactor = (int)(OpensslBnGetWord(cofactor));
    // cofactor should not be zero.
    if (*returnCofactor == 0) {
        LOGE("Failed to get BIGNUM word value.");
        OpensslBnFree(cofactor);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBnFree(cofactor);
    return HCF_SUCCESS;
}

HcfResult GetFieldSize(const EC_GROUP *group, int32_t *fieldSize)
{
    *fieldSize = OpensslEcGroupGetDegree(group);
    if (*fieldSize == 0) {
        LOGE("Failed to get EC group degree.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult GetFieldType(const HcfKey *self, const bool isPrivate, char **returnString)
{
    char *fieldType = NULL;
    if (isPrivate) {
        fieldType = ((HcfOpensslEccPriKey *)self)->fieldType;
    } else {
        fieldType = ((HcfOpensslEccPubKey *)self)->fieldType;
    }

    if (fieldType == NULL) {
        LOGE("No fieldType in EccPubKey struct.");
        return HCF_INVALID_PARAMS;
    }

    size_t len = HcfStrlen(fieldType);
    if (len == 0) {
        LOGE("fieldType is empty!");
        return HCF_INVALID_PARAMS;
    }
    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Alloc returnString memory failed.");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(*returnString, len, fieldType, len);

    return HCF_SUCCESS;
}

static HcfResult GetPubKeyXOrY(const EC_GROUP *group, const EC_POINT *point, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (group == NULL || point == NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    BIGNUM *pkX = OpensslBnNew();
    BIGNUM *pkY = OpensslBnNew();
    if (pkX == NULL || pkY == NULL) {
        LOGE("new BN failed.");
        OpensslBnFree(pkX);
        OpensslBnFree(pkY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEcPointGetAffineCoordinatesGfp(group, point, pkX, pkY, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to get EC point affine coordinates.");
        OpensslBnFree(pkX);
        OpensslBnFree(pkY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case ECC_PK_X_BN:
            ret = BigNumToBigInteger(pkX, returnBigInteger);
            break;
        case ECC_PK_Y_BN:
            ret = BigNumToBigInteger(pkY, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            break;
    }
    OpensslBnFree(pkX);
    OpensslBnFree(pkY);
    return ret;
}

HcfResult GetPkSkBigInteger(const HcfKey *self, bool isPrivate,
    const AsyKeySpecItem item, HcfBigInteger *returnBigInteger)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    if (item == ECC_SK_BN) {
        if (!isPrivate) {
            LOGE("ecc pub key has no private key spec item");
            return ret;
        }
        ret = BigNumToBigInteger(OpensslEcKeyGet0PrivateKey(((HcfOpensslEccPriKey *)self)->ecKey),
            returnBigInteger);
    } else {
        if (isPrivate) {
            LOGE("ecc pri key cannot get pub key spec item");
            return ret;
        }
        ret = GetPubKeyXOrY(OpensslEcKeyGet0Group(((HcfOpensslEccPubKey *)self)->ecKey),
            OpensslEcKeyGet0PublicKey(((HcfOpensslEccPubKey *)self)->ecKey), item, returnBigInteger);
    }
    return ret;
}

HcfResult HcfSetPubKeyDataToNewEcKey(EC_KEY *ecKey, EC_KEY **returnEcKey)
{
    if (ecKey == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
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
    EC_KEY *newEcKey = OpensslEcKeyNew();
    if (newEcKey == NULL) {
        LOGE("Failed to create a new EC key.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEcKeySetGroup(newEcKey, group) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to set EC group on EC key.");
        OpensslEcKeyFree(newEcKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEcKeySetPublicKey(newEcKey, point) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to set pub key.");
        OpensslEcKeyFree(newEcKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = newEcKey;
    return HCF_SUCCESS;
}
