/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "ut_utils.h"

LocalIface *CreateLocalIface()
{
    struct LocalIface *iface = (struct LocalIface *)calloc(1, sizeof(struct LocalIface));
    strcpy_s(iface->ifname, sizeof(iface->ifname), "eth");
    strcpy_s(iface->ipStr, sizeof(iface->ipStr), "127.0.0.1");
    iface->type = IFACE_TYPE_ETH;
    return iface;
}

void FreeLocalIface(LocalIface *localInterface)
{
    free(localInterface);
}

coap_context_t *CreateCoapContext()
{
    return coap_new_context(NULL);
}

void FreeCoapContext(coap_context_t *context)
{
    coap_free_context(context);
}

CoapCtxType *CreateCoapCtxType()
{
    CoapCtxType *ctx = (CoapCtxType *)malloc(1 * sizeof(CoapCtxType));
    ctx->ctx = CreateCoapContext();
    ctx->iface = (void *)CreateLocalIface();
    return ctx;
}

void FreeCoapCtxType(CoapCtxType *coapCtxType)
{
    if (coapCtxType != NULL) {
        FreeCoapContext(coapCtxType->ctx);
        FreeLocalIface((LocalIface *)coapCtxType->iface);
    }
    free(coapCtxType);
}

CoapCtxType *InsertDevice(void)
{
    CoapCtxType *ctx = CreateCoapCtxType();
    List *list = GetCoapContextList();
    ListInsertTail(list, &ctx->node);
    return ctx;
}

void RemoveDevice(CoapCtxType *ctx)
{
    ListRemoveNode(&ctx->node);
    FreeCoapCtxType(ctx);
}