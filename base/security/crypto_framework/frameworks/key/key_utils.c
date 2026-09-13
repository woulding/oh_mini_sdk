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

#include "key_utils.h"
#include <securec.h>
#include "config.h"
#include "params_parser.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

HcfResult CopyAsyKeyParamsSpec(const HcfAsyKeyParamsSpec *srcSpec, HcfAsyKeyParamsSpec *destSpec)
{
    if (srcSpec == NULL || srcSpec->algName == NULL || destSpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    size_t srcAlgNameLen = HcfStrlen(srcSpec->algName);
    if (!srcAlgNameLen) {
        LOGE("algName is empty!");
        return HCF_INVALID_PARAMS;
    }
    destSpec->algName = (char *)HcfMalloc(srcAlgNameLen + 1, 0);
    if (destSpec->algName == NULL) {
        LOGE("Failed to allocate alg name memory");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(destSpec->algName, srcAlgNameLen, srcSpec->algName, srcAlgNameLen);
    destSpec->specType = srcSpec->specType;
    return HCF_SUCCESS;
}

HcfResult CopyPoint(const HcfPoint *src, HcfPoint *dest)
{
    if (src == NULL || src->x.data == NULL || src->x.len == 0 ||
        src->y.data == NULL || src->y.len == 0 || dest == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    dest->x.data = (unsigned char *)HcfMalloc(src->x.len, 0);
    if (dest->x.data == NULL) {
        LOGE("Failed to allocate x data memory");
        return HCF_ERR_MALLOC;
    }
    dest->y.data = (unsigned char *)HcfMalloc(src->y.len, 0);
    if (dest->y.data == NULL) {
        LOGE("Failed to allocate y data memory");
        HcfFree(dest->x.data);
        dest->x.data = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(dest->x.data, src->x.len, src->x.data, src->x.len);
    (void)memcpy_s(dest->y.data, src->y.len, src->y.data, src->y.len);
    dest->x.len = src->x.len;
    dest->y.len = src->y.len;
    return HCF_SUCCESS;
}

static HcfResult CopyEcField(const HcfECField *src, HcfECField **dest)
{
    if (src == NULL || src->fieldType == NULL || dest == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfECField *tmpField = (HcfECField *)HcfMalloc(sizeof(HcfECFieldFp), 0);
    if (tmpField == NULL) {
        LOGE("Alloc memory failed.");
        return HCF_ERR_MALLOC;
    }
    size_t srcFieldTypeLen = HcfStrlen(src->fieldType);
    if (!srcFieldTypeLen) {
        LOGE("fieldType is empty!");
        HcfFree(tmpField);
        tmpField = NULL;
        return HCF_INVALID_PARAMS;
    }
    tmpField->fieldType = (char *)HcfMalloc(srcFieldTypeLen + 1, 0);
    if (tmpField->fieldType == NULL) {
        LOGE("Failed to allocate field memory.");
        HcfFree(tmpField);
        tmpField = NULL;
        return HCF_ERR_MALLOC;
    }
    HcfECFieldFp *tmpDest = (HcfECFieldFp *)(tmpField);
    HcfECFieldFp *tmpSrc = (HcfECFieldFp *)(src);
    tmpDest->p.data = (unsigned char *)HcfMalloc(tmpSrc->p.len, 0);
    if (tmpDest->p.data == NULL) {
        LOGE("Failed to allocate b data memory");
        HcfFree(tmpField->fieldType);
        tmpField->fieldType = NULL;
        HcfFree(tmpField);
        tmpField = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpField->fieldType, srcFieldTypeLen, src->fieldType, srcFieldTypeLen);
    (void)memcpy_s(tmpDest->p.data, tmpSrc->p.len, tmpSrc->p.data, tmpSrc->p.len);
    tmpDest->p.len = tmpSrc->p.len;
    *dest = tmpField;
    return HCF_SUCCESS;
}

HcfResult CopyEccCommonSpec(const HcfEccCommParamsSpec *srcSpec, HcfEccCommParamsSpec *destSpec)
{
    if (srcSpec == NULL || srcSpec->a.data == NULL || srcSpec->a.len == 0 || srcSpec->b.data == NULL ||
        srcSpec->b.len == 0 || srcSpec->n.data == NULL || srcSpec->n.len == 0 || destSpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(destSpec->base)) != HCF_SUCCESS) {
        LOGE("Failed to copy src common spec");
        return HCF_INVALID_PARAMS;
    }
    destSpec->a.data = (unsigned char *)HcfMalloc(srcSpec->a.len, 0);
    if (destSpec->a.data == NULL) {
        LOGE("Failed to allocate a data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->b.data = (unsigned char *)HcfMalloc(srcSpec->b.len, 0);
    if (destSpec->b.data == NULL) {
        LOGE("Failed to allocate b data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->n.data = (unsigned char *)HcfMalloc(srcSpec->n.len, 0);
    if (destSpec->n.data == NULL) {
        LOGE("Failed to allocate n data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    HcfResult res = CopyEcField(srcSpec->field, &(destSpec->field));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate field data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    res = CopyPoint(&(srcSpec->g), &(destSpec->g));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate field data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->h = srcSpec->h;
    (void)memcpy_s(destSpec->a.data, srcSpec->a.len, srcSpec->a.data, srcSpec->a.len);
    (void)memcpy_s(destSpec->b.data, srcSpec->b.len, srcSpec->b.data, srcSpec->b.len);
    (void)memcpy_s(destSpec->n.data, srcSpec->n.len, srcSpec->n.data, srcSpec->n.len);
    destSpec->a.len = srcSpec->a.len;
    destSpec->b.len = srcSpec->b.len;
    destSpec->n.len = srcSpec->n.len;
    return HCF_SUCCESS;
}

HcfResult CreateEccCommonSpecImpl(const HcfEccCommParamsSpec *srcSpec, HcfEccCommParamsSpec **destSpec)
{
    if (srcSpec == NULL || destSpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfEccCommParamsSpec *tmpSpec = (HcfEccCommParamsSpec *)HcfMalloc(sizeof(HcfEccCommParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyEccCommonSpec(srcSpec, tmpSpec) != HCF_SUCCESS) {
        LOGE("CreateEccCommonSpecImpl error!");
        HcfFree(tmpSpec);
        tmpSpec = NULL;
        return HCF_INVALID_PARAMS;
    }
    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

HcfResult CopyDhCommonSpec(const HcfDhCommParamsSpec *srcSpec, HcfDhCommParamsSpec *destSpec)
{
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(destSpec->base)) != HCF_SUCCESS) {
        LOGE("Failed to copy src common spec");
        return HCF_INVALID_PARAMS;
    }
    destSpec->p.data = (unsigned char *)HcfMalloc(srcSpec->p.len, 0);
    if (destSpec->p.data == NULL) {
        LOGE("Failed to allocate p data memory");
        FreeDhCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }

    destSpec->g.data = (unsigned char *)HcfMalloc(srcSpec->g.len, 0);
    if (destSpec->g.data == NULL) {
        LOGE("Failed to allocate g data memory");
        FreeDhCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->length = srcSpec->length;
    (void)memcpy_s(destSpec->p.data, srcSpec->p.len, srcSpec->p.data, srcSpec->p.len);
    (void)memcpy_s(destSpec->g.data, srcSpec->g.len, srcSpec->g.data, srcSpec->g.len);
    destSpec->p.len = srcSpec->p.len;
    destSpec->g.len = srcSpec->g.len;
    return HCF_SUCCESS;
}

HcfResult CreateDhCommonSpecImpl(const HcfDhCommParamsSpec *srcSpec, HcfDhCommParamsSpec **destSpec)
{
    HcfDhCommParamsSpec *spec = (HcfDhCommParamsSpec *)HcfMalloc(sizeof(HcfDhCommParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }

    if (CopyDhCommonSpec(srcSpec, spec) != HCF_SUCCESS) {
        LOGE("Failed to copy src spec");
        HcfFree(spec);
        spec = NULL;
        return HCF_INVALID_PARAMS;
    }

    *destSpec = spec;
    return HCF_SUCCESS;
}
