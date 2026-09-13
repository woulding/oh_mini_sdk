/*
* Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef HC_PARCEL_H
#define HC_PARCEL_H

#include <stdint.h>
#include <stdbool.h>
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PARCEL_DEFAULT_LENGTH 0
#define PARCEL_DEFAULT_ALLOC_UNIT 0

    typedef struct {
        char *data;
        unsigned int beginPos;
        unsigned int endPos;
        unsigned int length;
        unsigned int allocUnit;
    } HcParcel;

    HcParcel CreateParcel(uint32_t size, uint32_t allocUnit);
    void DeleteParcel(HcParcel *parcel);
    bool ParcelWrite(HcParcel *parcel, const void *src, uint32_t dataSize);
    uint32_t GetParcelDataSize(const HcParcel *parcel);
    const char *GetParcelData(const HcParcel *parcel);

    bool ParcelWriteInt8(HcParcel *parcel, char src);
    bool ParcelPopBack(HcParcel *parcel, uint32_t size);

#ifdef __cplusplus
}
#endif
#endif
