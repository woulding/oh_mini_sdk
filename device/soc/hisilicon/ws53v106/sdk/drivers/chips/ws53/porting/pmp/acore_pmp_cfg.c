/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description:  PMP CFG.
 */

#include "drv_pmp.h"
#include "pmp_cfg.h"

typedef enum {
    STARTUP_ROM_IDX,
    ITCM_IDX = 1,
    NONE_MEM_IDX1 = 2,
    FLASH_IDX = 3,
    NONE_MEM_IDX2 = 4,
    DTCM_IDX = 5,
    MAX_REGION_NUM
} region_index_t;

static const pmp_conf_t g_region_attr[MAX_REGION_NUM] = {
    {.idx = STARTUP_ROM_IDX,
     .addr = (uint32_t)0x20000,
     .conf.rwx_permission = PMPCFG_READ_ONLY_EXECUTE,
     .conf.addr_match = PMPCFG_ADDR_MATCH_TOR,
     .conf.lock = true,
     .conf.pmp_attr = PMP_ATTR_WRITEBACK_RWALLOCATE,
    },
    {.idx = ITCM_IDX,
     .addr = (uint32_t)0x050000,
     .conf.rwx_permission = PMPCFG_RW_EXECUTE,
     .conf.addr_match = PMPCFG_ADDR_MATCH_TOR,
     .conf.lock = true,
     .conf.pmp_attr = PMP_ATTR_NO_CACHEABLE_AND_BUFFERABLE,
    },
    {.idx = NONE_MEM_IDX1,
     .addr = (uint32_t)0x00400000,  // 0x50000-0x00400000 是空置的空间
     .conf.rwx_permission = PMPCFG_NO_ACCESS,
     .conf.addr_match = PMPCFG_ADDR_MATCH_TOR,
     .conf.lock = true,
     .conf.pmp_attr = PMP_ATTR_NO_CACHEABLE_AND_BUFFERABLE,
    },
    {.idx = FLASH_IDX,
     .addr = (uint32_t)0x01400000,
     .conf.rwx_permission = PMPCFG_READ_ONLY_EXECUTE,
     .conf.addr_match = PMPCFG_ADDR_MATCH_TOR,
     .conf.lock = true,
     .conf.pmp_attr = PMP_ATTR_WRITEBACK_RWALLOCATE,
    },
    {.idx = NONE_MEM_IDX2,
     .addr = (uint32_t)0x20000000,
     .conf.rwx_permission = PMPCFG_RW_EXECUTE,
     .conf.addr_match = PMPCFG_ADDR_MATCH_TOR,
     .conf.lock = true,
     .conf.pmp_attr = PMP_ATTR_NO_CACHEABLE_AND_BUFFERABLE,
    },
    {.idx = DTCM_IDX,
     .addr = (uint32_t)0x20068000,
     .conf.rwx_permission = PMPCFG_RW_EXECUTE,
     .conf.addr_match = PMPCFG_ADDR_MATCH_TOR,
     .conf.lock = true,
     .conf.pmp_attr = PMP_ATTR_NO_CACHEABLE_AND_BUFFERABLE,
    }
};

void pmp_enable(void)
{
    uapi_pmp_config((pmp_conf_t *)g_region_attr, MAX_REGION_NUM);
}
