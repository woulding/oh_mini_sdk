/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: Provides tcxo trim port \n
 *
 * History: \n
 * 2024-01-31， Create file. \n
 */
#include "xo_trim_porting.h"
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
#include "efuse.h"
#include "chip_io.h"
#include "idle_config.h"
#include "tcxo.h"
#endif

#ifdef _PRE_WLAN_FEATURE_MFG_TEST

#define PMU_MAN_1 0x570040D8
#define CMU_MAN 0x570040E0
#define EN_XLDO_DELAY_TIME 0x57030620
#define PMU_SEL_1 0x570040EC
#define CMU_SEL 0x570040F4
#define RST_MAN 0x570040E4
#define EFUSE_ULP_SEL1 0x57031004
#define RST_AON_CRG_WKUP_TIME_SOC 0x57030638
#define RST_AON_LGC_WKUP_TIME_SOC 0x57030640

#define EFUSE_ULP_SEL1_VAL (1 << 15)

/* Define the union u_cmu_xo_sig */
typedef union {
    /* Define the struct bits */
    struct {
        uint16_t rg_cmu_xo_trim_fine : 4; /* [3..0] */
        uint16_t rg_cmu_xo_trim_coarse : 6; /* [9..4] */
        uint16_t rg_cmu_xo_trim_rev : 1; /* [10] */
        uint16_t reserved_0 : 5; /* [15..11] */
    } bits;

    /* Define an unsigned member */
    uint16_t u16;
} u_cmu_xo_sig;

static void cmu_xo_trim_cfg(void)
{
    uint16_t ulp = 0;

    /* 校准前关闭低功耗 */
    idle_set_open_pm(0);

    /* 配置FSXO启动 */
    writel(PMU_MAN_1, 0x1EFF);
    writel(CMU_MAN, 0x2338);
    writel(EN_XLDO_DELAY_TIME, 0xB);
    writel(PMU_SEL_1, 0x1EFF);
    writel(CMU_SEL, 0xEF3D);
    writel(RST_MAN, 0x17);
    ulp = readl(EFUSE_ULP_SEL1);
    ulp |= EFUSE_ULP_SEL1_VAL;
    writel(EFUSE_ULP_SEL1, ulp);
    writel(RST_AON_CRG_WKUP_TIME_SOC, 0x0);
    writel(RST_AON_LGC_WKUP_TIME_SOC, 0x0);
    return;
}

void cmu_xo_trim_temp_comp_print(void)
{
    return;
}

static void cmu_xo_trim_reg_set(uint32_t fine, uint32_t coarse)
{
    u_cmu_xo_sig val;

    val.u16 = readl(CMU_XO_CORE_CTRIM);
    val.bits.rg_cmu_xo_trim_fine = fine;
    val.bits.rg_cmu_xo_trim_coarse = coarse;
    writel(CMU_XO_CORE_CTRIM, val.u16);
    writel(CMU_XOCLKOUTDIE_EN, 0);
    uapi_tcxo_delay_us(100);  /* 延时100us */
    writel(CMU_XOCLKOUTDIE_EN, 1);
}

void cmu_xo_trim_init(void)
{
    uint8_t lock = 0;
    uint16_t value = 0;
    int32_t index;
    uint8_t writable = false;
    uint32_t fine = 0;
    uint32_t coarse = 0;
    uint8_t id[EFUSE_GROUP_MAX] = {EXT_EFUSE_XO_TRIM_1_ID, EXT_EFUSE_XO_TRIM_2_ID, EXT_EFUSE_XO_TRIM_3_ID};
    uint32_t lock_bit[EFUSE_GROUP_MAX] = {XO_TRIM_1_PG1, XO_TRIM_2_PG2, XO_TRIM_3_PG3};

    cmu_xo_trim_cfg();

    for (index = (EFUSE_GROUP_MAX - 1); index >= 0; --index) {
        if (uapi_efuse_read_bit(&lock, (lock_bit[index] / SIZE_8_BITS), (lock_bit[index] % SIZE_8_BITS)) != SUCC) {
            return;
        }
        writable = (lock == 0) ? false : true;
        if (writable == false) {
            continue;
        }
        if (uapi_efuse_read_buffer((uint8_t *)&value, id[index], sizeof(value)) != SUCC) {
            return;
        }
        break;
    }
    if (writable == false) {
        return;
    }
    value = ((value >> SIZE_1_BITS) & 0x7FF);
    fine = (value & 0xF);
    coarse = ((value >> SIZE_4_BITS) & 0x3F);
    cmu_xo_trim_reg_set(fine, coarse);
    return;
}
#endif
