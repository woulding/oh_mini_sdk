/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTEDSCHEDULE_DMSLITE_UTILS_H
#define OHOS_DISTRIBUTEDSCHEDULE_DMSLITE_UTILS_H

#include <stdbool.h>
#ifdef WEARABLE_PRODUCT
#include "ohos_mem_pool.h"
#endif

#define PACKET_MARSHALL_HELPER(type, fieldType, field) \
    do { \
        bool ret = Marshall##type((field), (fieldType)); \
        if (!ret) { \
            HILOGE("%{public}s marshall value failed!", __func__); \
            CleanBuild(); \
            return -1; \
        } \
    } while (0)

#define RAWDATA_MARSHALL_HELPER(type, fieldType, field, length) \
    do { \
        bool ret = Marshall##type((field), (fieldType), (length)); \
        if (!ret) { \
            HILOGE("%{public}s marshall value failed!", __func__); \
            CleanBuild(); \
            return -1; \
        } \
    } while (0)

static inline bool IsBigEndian()
{
    union {
        uint16_t a;
        uint8_t b;
    } c;
    c.a = 1;
    return (c.b == 0);
}

#ifdef WEARABLE_PRODUCT
#define DMS_ALLOC(size) OhosMalloc(MEM_TYPE_APPFMK_LSRAM, size)
#define DMS_FREE(a) \
    do { \
        if ((a) != NULL) { \
            (void) OhosFree((void *)(a)); \
            (a) = NULL; \
        } \
    } while (0)
#else
#define DMS_ALLOC(size) malloc(size)
#define DMS_FREE(a) \
    do { \
        if ((a) != NULL) { \
            (void) free((void *)(a)); \
            (a) = NULL; \
        } \
    } while (0)
#endif

static const uint32_t ONE_BITE = 1;
static const uint32_t TWO_BITE = 2;
static const uint32_t THREE_BITE = 3;
static const uint32_t FOUR_BITE = 4;
static const uint32_t FIVE_BITE = 5;
static const uint32_t SIX_BITE = 6;
static const uint32_t SEVEN_BITE = 7;

static const uint32_t BITS_NUM_OF_PER_BITE = 8;
static const uint32_t BITS_NUM_OF_TWO_BITE = BITS_NUM_OF_PER_BITE * TWO_BITE;
static const uint32_t BITS_NUM_OF_THREE_BITE = BITS_NUM_OF_PER_BITE * THREE_BITE;
static const uint32_t BITS_NUM_OF_FOUR_BITE = BITS_NUM_OF_PER_BITE * FOUR_BITE;
static const uint32_t BITS_NUM_OF_FIVE_BITE = BITS_NUM_OF_PER_BITE * FIVE_BITE;
static const uint32_t BITS_NUM_OF_SIX_BITE = BITS_NUM_OF_PER_BITE * SIX_BITE;
static const uint32_t BITS_NUM_OF_SEVEN_BITE = BITS_NUM_OF_PER_BITE * SEVEN_BITE;

/*
 * convert u16 data from Big Endian to Little Endian
 * dataIn: pointer to start of u16 data
 * dataOut: the converted u16 data
 */
static inline void Convert16DataBig2Little(const uint8_t *dataIn, uint16_t *dataOut)
{
    *dataOut  = ((uint16_t)(*dataIn++) << BITS_NUM_OF_PER_BITE);
    *dataOut |=  (uint16_t)(*dataIn);
}

/*
 * convert u32 data from Big Endian to Little Endian
 * dataIn: pointer to start of u32 data
 * dataOut: the converted u32 data
 */
static inline void Convert32DataBig2Little(const uint8_t *dataIn, uint32_t *dataOut)
{
    *dataOut  = ((uint32_t)(*dataIn++) << BITS_NUM_OF_THREE_BITE);
    *dataOut |= ((uint32_t)(*dataIn++) << BITS_NUM_OF_TWO_BITE);
    *dataOut |= ((uint32_t)(*dataIn++) << BITS_NUM_OF_PER_BITE);
    *dataOut |=  (uint32_t)(*dataIn);
}

/*
 * convert u64 data from Big Endian to Little Endian
 * dataIn: pointer to start of u64 data
 * dataOut: the converted u64 data
 */
static inline void Convert64DataBig2Little(const uint8_t *dataIn, uint64_t *dataOut)
{
    *dataOut  = ((uint64_t)(*dataIn++) << BITS_NUM_OF_SEVEN_BITE);
    *dataOut |= ((uint64_t)(*dataIn++) << BITS_NUM_OF_SIX_BITE);
    *dataOut |= ((uint64_t)(*dataIn++) << BITS_NUM_OF_FIVE_BITE);
    *dataOut |= ((uint64_t)(*dataIn++) << BITS_NUM_OF_FOUR_BITE);
    *dataOut |= ((uint64_t)(*dataIn++) << BITS_NUM_OF_THREE_BITE);
    *dataOut |= ((uint64_t)(*dataIn++) << BITS_NUM_OF_TWO_BITE);
    *dataOut |= ((uint64_t)(*dataIn++) << BITS_NUM_OF_PER_BITE);
    *dataOut |=  (uint64_t)(*dataIn);
}

/*
 * convert u16 data from Little Endian to Big Endian
 * dataIn: pointer of the u16 data
 * dataOut: the converted u16 data
 */
static inline void Convert16DataLittle2Big(const uint8_t *dataIn, uint8_t *dataOut)
{
    *dataOut++ = *(dataIn + ONE_BITE);
    *dataOut   = *(dataIn);
}

/*
 * convert u32 data from Little Endian to Big Endian
 * dataIn: pointer of the u32 data
 * dataOut: the converted u32 data
 */
static inline void Convert32DataLittle2Big(const uint8_t *dataIn, uint8_t *dataOut)
{
    *dataOut++ = *(dataIn + THREE_BITE);
    *dataOut++ = *(dataIn + TWO_BITE);
    *dataOut++ = *(dataIn + ONE_BITE);
    *dataOut   = *(dataIn);
}

/*
 * convert u64 data from Little Endian to Big Endian
 * dataIn: pointer of the u64 data
 * dataOut: the converted u64 data
 */
static inline void Convert64DataLittle2Big(const uint8_t *dataIn, uint8_t *dataOut)
{
    *dataOut++ = *(dataIn + SEVEN_BITE);
    *dataOut++ = *(dataIn + SIX_BITE);
    *dataOut++ = *(dataIn + FIVE_BITE);
    *dataOut++ = *(dataIn + FOUR_BITE);
    *dataOut++ = *(dataIn + THREE_BITE);
    *dataOut++ = *(dataIn + TWO_BITE);
    *dataOut++ = *(dataIn + ONE_BITE);
    *dataOut   = *(dataIn);
}
#endif // OHOS_DISTRIBUTEDSCHEDULE_DMSLITE_UTILS_H