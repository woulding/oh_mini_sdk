/*
 * Copyright (c) 2026 Hihope Open Source Organization.
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
 *
 * Description: Static backing store for the OHOS lite param service on bs21e.
 *
 * The param service allocates its workspaces (DAC 5K + BASE 5K + SIZE 1K,
 * see base/startup/init/services/param/include/param_osadp.h) through the
 * weak GetSysParamMem(). The default implementation malloc()s them from the
 * LiteOS heap, which is too small on bs21e (52 KB total, shared with the BT
 * stack) and dies with "No mem to alloc 0x100c" during OHOS_SystemInit.
 *
 * These workspaces are allocated once at init and never freed, so give them
 * a dedicated static buffer instead. GetSysParamMem() is weak, so this
 * definition simply overrides it.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Values mirrored from base/startup/init/services/param/include/param_osadp.h
 * (__LITEOS_M__ branch). Deliberately hardcoded: the SDK build cannot include
 * OHOS tree headers. Keep in sync when bumping the param component. */
#define PARAM_WORKSPACE_MAX   (1024 * 5)   /* PARAM_WORKSPACE_SMALL == MAX on liteos_m */
#define PARAM_WORKSPACE_MIN   (1024)

/* DAC 5K + BASE 5K + SIZE 1K, plus headroom for the WorkSpace headers. */
#define OHOS_PARAM_MEM_POOL_SIZE (PARAM_WORKSPACE_MAX + PARAM_WORKSPACE_MAX + \
                                  PARAM_WORKSPACE_MIN + 512)

static uint8_t g_paramMemPool[OHOS_PARAM_MEM_POOL_SIZE];
static uint32_t g_paramMemUsed;

void *GetSysParamMem(uint32_t spaceSize)
{
    void *mem = NULL;

    if (spaceSize == 0 || spaceSize > (OHOS_PARAM_MEM_POOL_SIZE - g_paramMemUsed)) {
        return NULL;
    }
    /* 4-byte aligned bump allocator; never freed by design. */
    g_paramMemUsed = (g_paramMemUsed + 3) & ~0x3U;
    mem = &g_paramMemPool[g_paramMemUsed];
    g_paramMemUsed += spaceSize;
    (void)memset(mem, 0, spaceSize);
    return mem;
}

void FreeSysParamMem(void *mem)
{
    /* Static pool: nothing to free. */
    (void)mem;
}
