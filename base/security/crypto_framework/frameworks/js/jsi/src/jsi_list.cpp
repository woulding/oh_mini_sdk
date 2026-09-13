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

#include "jsi_list.h"
#include "memory.h"

static LOS_DL_LIST g_mdObjListHeader = { .pstPrev = nullptr, .pstNext = nullptr };
static LOS_DL_LIST g_randObjListHeader = { .pstPrev = nullptr, .pstNext = nullptr };

namespace OHOS {
namespace ACELite {

ListInfo g_listMap[] = {
    { JSI_ALG_MD, &g_mdObjListHeader },
    { JSI_ALG_RAND, &g_randObjListHeader }
};

LOS_DL_LIST *GetListHeader(LiteAlgType type)
{
    for (uint32_t index = 0; index < sizeof(g_listMap) / sizeof(g_listMap[0]); index++) {
        if (type == g_listMap[index].type) {
            return g_listMap[index].objListHeader;
        }
    }

    return nullptr;
}

void ListObjInit(LiteAlgType type)
{
    LOS_ListInit(GetListHeader(type));
}

HcfResult ListAddObjNode(LiteAlgType type, uint32_t addAddr)
{
    if (GetListHeader(type) == nullptr) {
        return HCF_INVALID_PARAMS;
    }
    ObjList *obj = static_cast<ObjList *>(HcfMalloc(sizeof(ObjList), 0));
    if (obj == nullptr) {
        return HCF_ERR_MALLOC;
    }
    obj->objAddr = addAddr;

    if (GetListHeader(type)->pstNext == nullptr) {
        LOS_ListInit(GetListHeader(type));
    }
    LOS_ListAdd(GetListHeader(type), &(obj->listNode));

    return HCF_SUCCESS;
}

void ListDeleteObjNode(LiteAlgType type, uint32_t deleteAddr)
{
    ObjList *obj = nullptr;
    ObjList *objNext = nullptr;
    if (GetListHeader(type) == nullptr) {
        return;
    }
    LOS_DL_LIST_FOR_EACH_ENTRY_SAFE(obj, objNext, GetListHeader(type), ObjList, listNode) {
        if (obj == nullptr) {
            return;
        }
        if ((obj->objAddr != 0) && (obj->objAddr == deleteAddr)) {
            LOS_ListDelete(&(obj->listNode));
            HcfObjDestroy(reinterpret_cast<void *>(deleteAddr));
            obj->objAddr = 0;
            HcfFree(obj);
            obj = nullptr;
        }
    }
}

void ListDestroy(LiteAlgType type)
{
    ObjList *obj = nullptr;
    ObjList *objNext = nullptr;
    if (GetListHeader(type) == nullptr) {
        return;
    }
    LOS_DL_LIST_FOR_EACH_ENTRY_SAFE(obj, objNext, GetListHeader(type), ObjList, listNode) {
        if (obj == nullptr) {
            return;
        }
        LOS_ListDelete(&(obj->listNode));
        HcfObjDestroy(reinterpret_cast<void *>(obj->objAddr));
        HcfFree(obj);
        obj = nullptr;
    }
}

}  // ACELite
}  // OHOS
