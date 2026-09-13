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

#include "ecc_common_param_spec_generator_openssl.h"
#include "securec.h"

#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "utils.h"

static EC_POINT *BuildEcPoint(const EC_GROUP *ecGroup)
{
    EC_POINT *point = OpensslEcPointNew(ecGroup);
    if (point == NULL) {
        LOGE("new ec point failed.");
        return NULL;
    }
    const EC_POINT *tmpPoint = OpensslEcGroupGet0Generator(ecGroup);
    if (tmpPoint == NULL) {
        LOGE("Get ec generator failed.");
        OpensslEcPointFree(point);
        return NULL;
    }
    if (!OpensslEcPointCopy(point, tmpPoint)) {
        LOGE("Ec point copy failed.");
        OpensslEcPointFree(point);
        return NULL;
    }

    return point;
}

static HcfResult BuildCommonParamPart(const EC_GROUP *ecGroup, HcfEccCommParamsSpecSpi *returnCommonParamSpec)
{
    EC_POINT *point = NULL;
    point = BuildEcPoint(ecGroup);
    if (point == NULL) {
        LOGE("Build ec point failed.");
        return HCF_ERR_MALLOC;
    }
    BIGNUM *x = OpensslBnNew();
    if (x == NULL) {
        LOGE("New x failed.");
        OpensslEcPointFree(point);
        return HCF_ERR_MALLOC;
    }
    BIGNUM *y = OpensslBnNew();
    if (y == NULL) {
        LOGE("New y failed.");
        OpensslBnFree(x);
        OpensslEcPointFree(point);
        return HCF_ERR_MALLOC;
    }
    HcfResult ret = HCF_SUCCESS;
    do {
        if (!OpensslEcPointGetAffineCoordinatesGfp(ecGroup, point, x, y, NULL)) {
            LOGE("EC_POINT_get_affine_coordinates_GFp failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (BigNumToBigInteger(x, &(returnCommonParamSpec->paramsSpec.g.x)) != HCF_SUCCESS) {
            LOGE("Build commonParamSpec x failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (BigNumToBigInteger(y, &(returnCommonParamSpec->paramsSpec.g.y)) != HCF_SUCCESS) {
            LOGE("Build commonParamSpec y failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    OpensslBnFree(x);
    OpensslBnFree(y);
    OpensslEcPointFree(point);
    return ret;
}

static HcfResult BuildCommonParamGFp(const EC_GROUP *ecGroup, HcfEccCommParamsSpecSpi *returnCommonParamSpec)
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
    if (!OpensslEcGroupGetCurveGfp(ecGroup, p, a, b, NULL)) {
        LOGE("EC_GROUP_get_curve_GFp failed.");
        OpensslBnFree(p);
        OpensslBnFree(a);
        OpensslBnFree(b);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    do {
        if (OpensslEcGroupGetCurveName(ecGroup) == NID_secp256k1) {
            if (BigNumToBigIntegerSecp256k1(a, &(returnCommonParamSpec->paramsSpec.a)) != HCF_SUCCESS) {
                LOGE("Build Secp256k1CommonParamSpec a failed.");
                ret = HCF_ERR_CRYPTO_OPERATION;
                break;
            }
        } else {
            if (BigNumToBigInteger(a, &(returnCommonParamSpec->paramsSpec.a)) != HCF_SUCCESS) {
                LOGE("Build commonParamSpec a failed.");
                ret = HCF_ERR_CRYPTO_OPERATION;
                break;
            }
        }
        if (BigNumToBigInteger(b, &(returnCommonParamSpec->paramsSpec.b)) != HCF_SUCCESS) {
            LOGE("Build commonParamSpec b failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        HcfECFieldFp *tmpField = (HcfECFieldFp *)(returnCommonParamSpec->paramsSpec.field);
        if (BigNumToBigInteger(p, &(tmpField->p)) != HCF_SUCCESS) {
            LOGE("Build commonParamSpec p failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);

    OpensslBnFree(p);
    OpensslBnFree(a);
    OpensslBnFree(b);
    return ret;
}

static HcfResult BuildCommonParam(const EC_GROUP *ecGroup, HcfEccCommParamsSpecSpi *returnCommonParamSpec)
{
    if (BuildCommonParamPart(ecGroup, returnCommonParamSpec)!= HCF_SUCCESS) {
        LOGE("Failed to build ECC common parameters.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BuildCommonParamGFp(ecGroup, returnCommonParamSpec)!= HCF_SUCCESS) {
        LOGE("Failed to build GFp common parameters.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (GetOrder(ecGroup, &(returnCommonParamSpec->paramsSpec.n)) != HCF_SUCCESS) {
        LOGE("Failed to get curve order data.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (GetCofactor(ecGroup, &(returnCommonParamSpec->paramsSpec.h)) != HCF_SUCCESS) {
        LOGE("Failed to get curve cofactor data.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfEccCommParamsSpecSpi *BuildEccCommonParamObject(void)
{
    HcfEccCommParamsSpecSpi *spi = (HcfEccCommParamsSpecSpi*)HcfMalloc(sizeof(HcfEccCommParamsSpecSpi), 0);
    if (spi == NULL) {
        LOGE("failed to build ecc commonParam object.");
        return NULL;
    }
    spi->paramsSpec.field = (HcfECField *)HcfMalloc(sizeof(HcfECFieldFp), 0);
    if (spi->paramsSpec.field == NULL) {
        LOGE("field malloc failed.");
        HcfFree(spi);
        spi = NULL;
        return NULL;
    }
    char *fieldType = "Fp";
    size_t srcFieldTypeLen = HcfStrlen(fieldType);
    if (srcFieldTypeLen == 0) {
        LOGE("fieldType is empty!");
        HcfFree(spi->paramsSpec.field);
        spi->paramsSpec.field = NULL;
        HcfFree(spi);
        spi = NULL;
        return NULL;
    }
    spi->paramsSpec.field->fieldType = (char *)HcfMalloc(srcFieldTypeLen + 1, 0);
    if (spi->paramsSpec.field->fieldType == NULL) {
        LOGE("fieldType malloc failed.");
        HcfFree(spi->paramsSpec.field);
        spi->paramsSpec.field = NULL;
        HcfFree(spi);
        spi = NULL;
        return NULL;
    }

    if (memcpy_s(spi->paramsSpec.field->fieldType, srcFieldTypeLen, fieldType, srcFieldTypeLen) != EOK) {
        LOGE("memcpy fieldType failed.");
        HcfFree(spi->paramsSpec.field->fieldType);
        spi->paramsSpec.field->fieldType = NULL;
        HcfFree(spi->paramsSpec.field);
        spi->paramsSpec.field = NULL;
        HcfFree(spi);
        spi = NULL;
        return NULL;
    }
    return spi;
}

static void FreeEccCommParamObject(HcfEccCommParamsSpecSpi *spec)
{
    if (spec == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    HcfFree(spec->paramsSpec.base.algName);
    spec->paramsSpec.base.algName = NULL;
    if (spec->paramsSpec.field != NULL) {
        HcfECFieldFp *tmp = (HcfECFieldFp *)spec->paramsSpec.field;
        HcfFree(tmp->p.data);
        tmp->p.data = NULL;
        HcfFree(spec->paramsSpec.field->fieldType);
        spec->paramsSpec.field->fieldType = NULL;
        HcfFree(spec->paramsSpec.field);
        spec->paramsSpec.field = NULL;
    }
    HcfFree(spec->paramsSpec.a.data);
    spec->paramsSpec.a.data = NULL;
    HcfFree(spec->paramsSpec.b.data);
    spec->paramsSpec.b.data = NULL;
    HcfFree(spec->paramsSpec.n.data);
    spec->paramsSpec.n.data = NULL;
    HcfFree(spec->paramsSpec.g.x.data);
    spec->paramsSpec.g.x.data = NULL;
    HcfFree(spec->paramsSpec.g.y.data);
    spec->paramsSpec.g.y.data = NULL;
    HcfFree(spec);
}

HcfResult HcfECCCommonParamSpecCreate(HcfAsyKeyGenParams *params, HcfEccCommParamsSpecSpi **returnCommonParamSpec)
{
    if ((params == NULL) || (returnCommonParamSpec == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    int32_t curveId = 0;
    if (params->bits != 0) {
        if (GetOpensslCurveId(params->bits, &curveId) != HCF_SUCCESS) {
            LOGE("Get curveId parameter failed.");
            return HCF_INVALID_PARAMS;
        }
    }
    EC_GROUP *ecGroup = OpensslEcGroupNewByCurveName(curveId);
    if (ecGroup == NULL) {
        LOGE("Create ecGroup failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfEccCommParamsSpecSpi *object = BuildEccCommonParamObject();
    if (object == NULL) {
        LOGE("Build ecc common params object failed.");
        OpensslEcGroupFree(ecGroup);
        return HCF_ERR_MALLOC;
    }
    object->paramsSpec.base.specType = HCF_COMMON_PARAMS_SPEC;
    if (GetAlgNameByBits(params->bits, &(object->paramsSpec.base.algName)) != HCF_SUCCESS) {
        LOGE("Get algName parameter by bits failed.");
        FreeEccCommParamObject(object);
        object = NULL;
        OpensslEcGroupFree(ecGroup);
        return HCF_INVALID_PARAMS;
    }
    if (BuildCommonParam(ecGroup, object)!= HCF_SUCCESS) {
        LOGE("Get common params failed.");
        FreeEccCommParamObject(object);
        object = NULL;
        OpensslEcGroupFree(ecGroup);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnCommonParamSpec = object;
    OpensslEcGroupFree(ecGroup);
    return HCF_SUCCESS;
}

static HcfResult InitEccPoint(const int32_t curveNameValue, EC_GROUP **ecGroup,
                              EC_POINT **ecPoint, BIGNUM **x, BIGNUM **y)
{
    int32_t nid = 0;
    if (GetNidByCurveNameValue(curveNameValue, &nid) != HCF_SUCCESS) {
        LOGE("Failed to get curveNameValue.");
        return HCF_INVALID_PARAMS;
    }
    *ecGroup = OpensslEcGroupNewByCurveName(nid);
    if (*ecGroup == NULL) {
        LOGE("Failed to create EC group with nid %{public}d.", nid);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *ecPoint = OpensslEcPointNew(*ecGroup);
    if (*ecPoint == NULL) {
        LOGE("Failed to allocate memory for EC_POINT.");
        OpensslEcGroupFree(*ecGroup);
        *ecGroup = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (x != NULL) {
        *x = OpensslBnNew();
        if (*x == NULL) {
            LOGE("Failed to allocate memory for BIGNUM x.");
            OpensslEcGroupFree(*ecGroup);
            *ecGroup = NULL;
            OpensslEcPointFree(*ecPoint);
            *ecPoint = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (y != NULL) {
        *y = OpensslBnNew();
        if (*y == NULL) {
            LOGE("Failed to allocate memory for BIGNUM y.");
            OpensslBnFree(*x);
            *x = NULL;
            OpensslEcGroupFree(*ecGroup);
            *ecGroup = NULL;
            OpensslEcPointFree(*ecPoint);
            *ecPoint = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static void FreeHcfBigInteger(HcfBigInteger *bigInt)
{
    HcfFree(bigInt->data);
    bigInt->data = NULL;
    bigInt->len = 0;
}

static HcfResult ConvertBigNumToEccPoint(const BIGNUM *x, const BIGNUM *y,
                                         HcfBigInteger *bigIntX, HcfBigInteger *bigIntY)
{
    HcfResult ret = BigNumToBigInteger(x, bigIntX);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to convert XBIGNUM to HcfBigInteger.");
        return ret;
    }
    ret = BigNumToBigInteger(y, bigIntY);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to convert YBIGNUM to HcfBigInteger.");
        FreeHcfBigInteger(bigIntX);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult GetECCPointEncoded(const int32_t formatValue, EC_GROUP *ecGroup,
                                    EC_POINT *ecPoint, HcfBlob *returnBlob)
{
    int32_t formatType = 0;
    if (GetFormatTypeByFormatValue(formatValue, &formatType) != HCF_SUCCESS) {
        LOGE("Failed to get formatType.");
        return HCF_INVALID_PARAMS;
    }

    size_t returnDataLen = EC_POINT_point2oct(ecGroup, ecPoint, formatType, NULL, 0, NULL);
    if (returnDataLen == 0) {
        LOGE("Failed to get encoded point length.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    uint8_t *returnData = (uint8_t *)HcfMalloc(returnDataLen, 0);
    if (returnData == NULL) {
        LOGE("Failed to allocate memory for encoded point data.");
        return HCF_ERR_MALLOC;
    }
    size_t result = EC_POINT_point2oct(ecGroup, ecPoint, formatType, returnData, returnDataLen, NULL);
    if (result != returnDataLen) {
        LOGE("Failed to get ECC point encoding.");
        HcfPrintOpensslError();
        HcfFree(returnData);
        returnData = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

HcfResult HcfEngineConvertPoint(const int32_t curveNameValue, HcfBlob *pointBlob, HcfPoint *returnPoint)
{
    if ((curveNameValue == 0) || !HcfIsBlobValid(pointBlob) || (returnPoint == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    EC_GROUP *ecGroup = NULL;
    EC_POINT *ecPoint = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    HcfBigInteger tmpBigIntX = { .data = NULL, .len = 0 };
    HcfBigInteger tmpBigIntY = { .data = NULL, .len = 0 };
    HcfResult ret = HCF_SUCCESS;
    do {
        ret = InitEccPoint(curveNameValue, &ecGroup, &ecPoint, &x, &y);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to get EccPoint.");
            break;
        }
        if (!OpensslEcOct2Point(ecGroup, ecPoint, pointBlob->data, pointBlob->len, NULL)) {
            LOGE("Failed to convert pointBlob data to EC_POINT.");
            HcfPrintOpensslError();
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (!OpensslEcPointGetAffineCoordinates(ecGroup, ecPoint, x, y, NULL)) {
            LOGE("Failed to get affine coordinates from EC_POINT.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        ret = ConvertBigNumToEccPoint(x, y, &tmpBigIntX, &tmpBigIntY);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to convert BIGNUMs to HcfBigIntegers.");
            break;
        }
        returnPoint->x = tmpBigIntX;
        returnPoint->y = tmpBigIntY;
    } while (0);
    OpensslEcGroupFree(ecGroup);
    OpensslEcPointFree(ecPoint);
    OpensslBnFree(x);
    OpensslBnFree(y);
    return ret;
}

HcfResult HcfEngineGetEncodedPoint(const int32_t curveNameValue, HcfPoint *point,
                                   const int32_t formatValue, HcfBlob *returnBlob)
{
    if ((curveNameValue == 0) || (point == NULL) || (formatValue == 0) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    EC_GROUP *ecGroup = NULL;
    EC_POINT *ecPoint = NULL;
    BIGNUM *bnX = NULL;
    BIGNUM *bnY = NULL;
    HcfResult ret = HCF_SUCCESS;
    do {
        ret = InitEccPoint(curveNameValue, &ecGroup, &ecPoint, NULL, NULL);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to get EccPoint.");
            break;
        }
        ret = BigIntegerToBigNum(&(point->x), &bnX);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to convert HcfBigInteger to XBIGNUMs.");
            break;
        }
        ret = BigIntegerToBigNum(&(point->y), &bnY);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to convert HcfBigInteger to YBIGNUMs.");
            break;
        }
        if (OpensslEcPointSetAffineCoordinates(ecGroup, ecPoint, bnX, bnY, NULL) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to set point coordinates.");
            HcfPrintOpensslError();
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        ret = GetECCPointEncoded(formatValue, ecGroup, ecPoint, returnBlob);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to get EccPointEncoded.");
            break;
        }
    } while (0);
    OpensslEcGroupFree(ecGroup);
    OpensslEcPointFree(ecPoint);
    OpensslBnFree(bnX);
    OpensslBnFree(bnY);
    return ret;
}
