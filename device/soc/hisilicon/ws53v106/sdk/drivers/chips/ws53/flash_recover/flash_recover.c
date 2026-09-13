/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * Description: Provides ws53 sfc flash recover \n
 *
 * History: \n
 * 2023-06-28, Create file. \n
 */
#include "arch_barrier.h"
#include "common_def.h"
#include "chip_io.h"
#include "memory_config_common.h"
#include "flash_recover.h"

typedef enum {
    FLASH_RECOVER_TYPE_GD,    // GD
    FLASH_RECOVER_TYPE_WB,    // winbond
    FLASH_RECOVER_TYPE_END
} flash_recover_type_t;

#define SFC_REG_NUM                      6
#define ENCRY_REG_NUM                    21
#define FLASH_QSPI_MODE                  0x570305F8  // 0:GD 1:Winbond

#define SFC_BASE_ADDR                    0x53000000
#define KM_BASE_ADDR                     0x52022000

/* BUS Config Registers */
#define SFC_TIMING_REG                   (SFC_BASE_ADDR + 0x110)
#define SFC_BUS_CONFIG1_REG              (SFC_BASE_ADDR + 0x200)
#define SFC_BUS_CONFIG2_REG              (SFC_BASE_ADDR + 0x204)
#define SFC_BUS_FLASH_SIZE_REG           (SFC_BASE_ADDR + 0x210)
#define SFC_BUS_BASE_ADDR_CS0_REG        (SFC_BASE_ADDR + 0x214)
#define SFC_BUS_BASE_ADDR_CS1_REG        (SFC_BASE_ADDR + 0x218)

/* SPI Command opreation Registers */
#define SFC_CMD_CONFIG_REG               (SFC_BASE_ADDR + 0x300)
#define DATA_CNT_POS                     9
#define RW_POS                           8

#define SFC_CMD_INS_REG                  (SFC_BASE_ADDR + 0x308)
#define SFC_CMD_ADDR_REG                 (SFC_BASE_ADDR + 0x30C)

#define SFC_CMD_DATABUF_BASE_ADDR        (SFC_BASE_ADDR + 0x400)

#define SFC_APC_CFG_START_ADDR0          (SFC_BASE_ADDR + 0x1000)
#define SFC_APC_CFG_START_ADDR1          (SFC_BASE_ADDR + 0x1004)
#define SFC_APC_CFG_END_ADDR0            (SFC_BASE_ADDR + 0x1040)
#define SFC_APC_CFG_END_ADDR1            (SFC_BASE_ADDR + 0x1044)
#define SFC_SFC_FAPC_DEC_AUTH_CFG        (SFC_BASE_ADDR + 0x1180)
#define SFC_FAPC_ONE_WAY_LOCK            (SFC_BASE_ADDR + 0x1220)
#define SFC_LEA_IV_VLD                   (SFC_BASE_ADDR + 0x1600)
#define SFC_LEA_IV_ACPU_0                (SFC_BASE_ADDR + 0x1620)
#define SFC_LEA_IV_ACPU_1                (SFC_BASE_ADDR + 0x1624)
#define SFC_LEA_IV_ACPU_2                (SFC_BASE_ADDR + 0x1628)
#define SFC_LEA_IV_ACPU_3                (SFC_BASE_ADDR + 0x162C)
#define SFC_LEA_IV_ACPU_START_ADDR0      (SFC_BASE_ADDR + 0x1640)

#define KM_RKP_LOCK                      (KM_BASE_ADDR + 0x0)
#define KM_RKP_CMD_CFG                   (KM_BASE_ADDR + 0x4)
#define KM_RKP_RAW_INT                   (KM_BASE_ADDR + 0x10)
#define KM_RKP_DEOB_CFG                  (KM_BASE_ADDR + 0x20)
#define KM_RKP_ONEWAY_REG                (KM_BASE_ADDR + 0x360)
#define KM_RKP_SALT0                     (KM_BASE_ADDR + 0x340)
#define KM_RKP_SALT1                     (KM_BASE_ADDR + 0x344)
#define KM_RKP_SALT2                     (KM_BASE_ADDR + 0x348)
#define KM_RKP_SALT3                     (KM_BASE_ADDR + 0x34C)
#define KM_RKP_SALT4                     (KM_BASE_ADDR + 0x350)
#define KM_RKP_SALT5                     (KM_BASE_ADDR + 0x354)
#define KM_RKP_SALT6                     (KM_BASE_ADDR + 0x358)
#define KM_KL_COM_CTRL0                  (KM_BASE_ADDR + 0x1084)
#define KM_KL_INT_RAW                    (KM_BASE_ADDR + 0x1044)
#define KM_KL_UNLOCK_CTRL                (KM_BASE_ADDR + 0x1078)
#define KM_KL_KEY_CFG                    (KM_BASE_ADDR + 0x1014)
#define KM_KL_KEY_SEC_CFG                (KM_BASE_ADDR + 0x1018)
#define KM_KL_LOCK_CTRL                  (KM_BASE_ADDR + 0x1074)
#define SFC_ENCRY_CFG                    0x2

#define SPI_READ_FLASH_ID                0x9F

#define WB_WRITE_ENABLE                  0x6
#define WB_GET_STS1                      0x5
#define WB_SET_STS2                      0x31
#define WB_SET_STS2_VAL                  0x2

#define FLASH_SET_STS1                   0x1
#define GD_SET_STS_VAL                   0x200

uint32_t sfc_suspend_regs[SFC_REG_NUM] = {0};
uint32_t sfc_encry_regs[ENCRY_REG_NUM] = {0};

bool g_sfc_encry_enable = false;
bool sfc_encry_is_enable(void)
{
    return g_sfc_encry_enable;
}

static void sfc_save_encry_cfg(void)
{
    uint32_t cnt = 0;
    /* 存km配置 */
    sfc_encry_regs[cnt++] = readl(KM_KL_KEY_CFG);
    sfc_encry_regs[cnt++] = readl(KM_KL_KEY_SEC_CFG);
    sfc_encry_regs[cnt++] = readl(KM_RKP_ONEWAY_REG);
    sfc_encry_regs[cnt++] = readl(KM_RKP_SALT0);
    sfc_encry_regs[cnt++] = readl(KM_RKP_SALT1);
    sfc_encry_regs[cnt++] = readl(KM_RKP_SALT2);
    sfc_encry_regs[cnt++] = readl(KM_RKP_SALT3);
    sfc_encry_regs[cnt++] = readl(KM_RKP_SALT4);
    sfc_encry_regs[cnt++] = readl(KM_RKP_SALT5);
    sfc_encry_regs[cnt++] = readl(KM_RKP_SALT6);

    /* 存fapc配置 */
    sfc_encry_regs[cnt++] = readl(SFC_LEA_IV_ACPU_0);
    sfc_encry_regs[cnt++] = readl(SFC_LEA_IV_ACPU_1);
    sfc_encry_regs[cnt++] = readl(SFC_LEA_IV_ACPU_2);
    sfc_encry_regs[cnt++] = readl(SFC_LEA_IV_ACPU_3);
    sfc_encry_regs[cnt++] = readl(SFC_APC_CFG_START_ADDR0);
    sfc_encry_regs[cnt++] = readl(SFC_APC_CFG_END_ADDR0);
    sfc_encry_regs[cnt++] = readl(SFC_SFC_FAPC_DEC_AUTH_CFG);
    sfc_encry_regs[cnt++] = readl(SFC_LEA_IV_ACPU_START_ADDR0);
    sfc_encry_regs[cnt++] = readl(SFC_APC_CFG_START_ADDR1);
    sfc_encry_regs[cnt++] = readl(SFC_APC_CFG_END_ADDR1);
    sfc_encry_regs[cnt++] = readl(SFC_FAPC_ONE_WAY_LOCK);
}

void sfc_init_pm_encry(void)
{
    uint32_t auth = readl(SFC_SFC_FAPC_DEC_AUTH_CFG);
    uint32_t start = readl(SFC_APC_CFG_START_ADDR0);
    uint32_t end = readl(SFC_APC_CFG_END_ADDR0);
    if ((auth == SFC_ENCRY_CFG) && (start < end) &&
        (start >= FLASH_START) && (end <= FLASH_MAX_END)) {
        g_sfc_encry_enable = true;
        sfc_save_encry_cfg();
    }
}

static void sfc_encry_resume(void)
{
    uint32_t cnt = 0;
    /* 恢复km配置 */
    writel(KM_KL_KEY_CFG, sfc_encry_regs[cnt++]);
    writel(KM_KL_KEY_SEC_CFG, sfc_encry_regs[cnt++]);
    writel(KM_KL_LOCK_CTRL, 0x1);             // klad lock
    writel(KM_RKP_LOCK, 0x1);                 // rkp lock
    dsb();
    writel(KM_RKP_DEOB_CFG, 0x1);
    uint32_t result = readl(KM_RKP_DEOB_CFG); // wait update key
    while ((result & 0x1) != 0) {
        result = readl(KM_RKP_DEOB_CFG);
    }
    writel(KM_RKP_ONEWAY_REG, sfc_encry_regs[cnt++]);
    writel(KM_RKP_SALT0, sfc_encry_regs[cnt++]);
    writel(KM_RKP_SALT1, sfc_encry_regs[cnt++]);
    writel(KM_RKP_SALT2, sfc_encry_regs[cnt++]);
    writel(KM_RKP_SALT3, sfc_encry_regs[cnt++]);
    writel(KM_RKP_SALT4, sfc_encry_regs[cnt++]);
    writel(KM_RKP_SALT5, sfc_encry_regs[cnt++]);
    writel(KM_RKP_SALT6, sfc_encry_regs[cnt++]);
    dsb();
    writel(KM_RKP_CMD_CFG, 0x4004081);
    result = readl(KM_RKP_CMD_CFG);      // wait km calculation
    while ((result & 0x1) != 0) {
        result = readl(KM_RKP_CMD_CFG);
    }
    writel(KM_RKP_RAW_INT, 0x1);         // clr irq
    writel(KM_KL_COM_CTRL0, 0x741);
    result = readl(KM_KL_COM_CTRL0);     // wait common key ladder
    while ((result & 0x1) != 0) {
        result = readl(KM_KL_COM_CTRL0);
    }
    writel(KM_KL_INT_RAW, 0x1);          // clr irq
    writel(KM_RKP_LOCK, 0x0);            // rpk unlock
    writel(KM_KL_UNLOCK_CTRL, 0x1);      // klad unlock

    /* 恢复fapc配置 */
    writel(SFC_LEA_IV_ACPU_0, sfc_encry_regs[cnt++]);
    writel(SFC_LEA_IV_ACPU_1, sfc_encry_regs[cnt++]);
    writel(SFC_LEA_IV_ACPU_2, sfc_encry_regs[cnt++]);
    writel(SFC_LEA_IV_ACPU_3, sfc_encry_regs[cnt++]);
    writel(SFC_LEA_IV_VLD, 0x1);
    writel(SFC_APC_CFG_START_ADDR0, sfc_encry_regs[cnt++]);
    writel(SFC_APC_CFG_END_ADDR0, sfc_encry_regs[cnt++]);
    writel(SFC_SFC_FAPC_DEC_AUTH_CFG, sfc_encry_regs[cnt++]);
    writel(SFC_LEA_IV_ACPU_START_ADDR0, sfc_encry_regs[cnt++]);
    writel(SFC_APC_CFG_START_ADDR1, sfc_encry_regs[cnt++]);
    writel(SFC_APC_CFG_END_ADDR1, sfc_encry_regs[cnt++]);
    writel(SFC_FAPC_ONE_WAY_LOCK, sfc_encry_regs[cnt++]);
}

void sfc_flash_suspend(void)
{
    sfc_suspend_regs[0x0] = readl(SFC_TIMING_REG);
    sfc_suspend_regs[0x1] = readl(SFC_BUS_CONFIG1_REG);
    sfc_suspend_regs[0x2] = readl(SFC_BUS_CONFIG2_REG);
    sfc_suspend_regs[0x3] = readl(SFC_BUS_FLASH_SIZE_REG);
    sfc_suspend_regs[0x4] = readl(SFC_BUS_BASE_ADDR_CS0_REG);
    sfc_suspend_regs[0x5] = readl(SFC_BUS_BASE_ADDR_CS1_REG);
}

void sfc_flash_resume(void)
{
    /* recover SFC register */
    writel(SFC_TIMING_REG, sfc_suspend_regs[0x0]);
    writel(SFC_BUS_CONFIG1_REG, sfc_suspend_regs[0x1]);
    writel(SFC_BUS_CONFIG2_REG, sfc_suspend_regs[0x2]);
    writel(SFC_BUS_FLASH_SIZE_REG, sfc_suspend_regs[0x3]);
    writel(SFC_BUS_BASE_ADDR_CS0_REG, sfc_suspend_regs[0x4]);
    writel(SFC_BUS_BASE_ADDR_CS1_REG, sfc_suspend_regs[0x5]);
    if (g_sfc_encry_enable) {
        sfc_encry_resume();
    }
}

