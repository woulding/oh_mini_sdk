/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef HCF_MAC_SPI_H
#define HCF_MAC_SPI_H

#include <stdint.h>
#include "result.h"
#include "sym_key.h"

typedef struct HcfMacSpi HcfMacSpi;

struct HcfMacSpi {
    HcfObjectBase base;
    // init the Mac with given key
    HcfResult (*engineInitMac)(HcfMacSpi *self, const HcfSymKey *key);
    // update mac with input datablob
    HcfResult (*engineUpdateMac)(HcfMacSpi *self, HcfBlob *input);
    // output mac in output datablob
    HcfResult (*engineDoFinalMac)(HcfMacSpi *self, HcfBlob *output);
    // get the length of chosen hash algo
    uint32_t (*engineGetMacLength)(HcfMacSpi *self);
};

#endif