/*
 * Copyright (c) @CompanyNameMagicTag 2026-2026. All rights reserved.
 *
 * Description: bth customize.
 *
 * Author: BGTP
 *
 * Create: 2026-3-25
 */

#include "bth_customize.h"
#ifdef CONFIG_MIDDLEWARE_SUPPORT_NV
#include "nv_config.h"
#endif

bool bth_customize_config_nv_support(void)
{
#if (defined(CONFIG_MIDDLEWARE_SUPPORT_NV) && defined(CONFIG_BTH_NV_CFG) && (CONFIG_BTH_NV_CFG == 1))
    return true;
#else
    return false;
#endif
}

bool bth_customize_config_encrypt_support(void)
{
#if (defined(CONFIG_MIDDLEWARE_SUPPORT_NV) && defined(CONFIG_NV_SUPPORT_ENCRYPT) && defined(NV_YES) &&(CONFIG_NV_SUPPORT_ENCRYPT == NV_YES))
    return true;
#else
    return false;
#endif
}