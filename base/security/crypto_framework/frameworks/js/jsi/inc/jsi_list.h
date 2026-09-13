/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef JSI_LIST_H
#define JSI_LIST_H

#include "los_list.h"
#include "jsi_api_common.h"

namespace OHOS {
namespace ACELite {

typedef struct {
    LiteAlgType type;
    LOS_DL_LIST *objListHeader;
} ListInfo;

typedef struct {
    LOS_DL_LIST listNode;
    uint32_t objAddr;
} ObjList;

void ListObjInit(LiteAlgType type);
HcfResult ListAddObjNode(LiteAlgType type, uint32_t addAddr);
void ListDeleteObjNode(LiteAlgType type, uint32_t deleteAddr);
void ListDestroy(LiteAlgType type);

}  // namespace ACELite
}  // namespace OHOS

#endif // JSI_LIST_H
