/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description:  dyn mem driver.
 *
 * Create:  2023-06-27
 */

#include <stdint.h>
#include "chip_io.h"
#include "clock_recover.h"
#include "dyn_mem.h"

/**
 * @brief  This union represents the bit fields in the BRAM_SHARE_COM register.
 *         Read the register into the <i>d32</i> member then
 *         set/clear the bits using the <i>b</i> elements.
 */
typedef union bram_share_cfg {
    uint32_t d32;                           /*!< Raw register data. */
    struct {
        uint32_t bram_share_mode : 4;       /*!< share_ram 切换选择，4bit，每1bit对应一组交织share_ram。按memmap中地址从低到高的顺序排布。
                                                即: RAM6/7 对应bit0；RAM8/9 对应bit1；RAM10/11 对应bit2；RAM12/13对应bit3。
                                                1'b0: 切给ACPU
                                                1'b1: 切给CCPU */
        uint32_t bram_share_mode_gt : 4;    /*!< 模式切换CG信号，4bit，每1bit对应一组交织share_ram。按memmap中地址从低到高的顺序排布。
                                                即: RAM6/7 对应bit0；RAM8/9 对应bit1；RAM10/11 对应bit2；RAM12/13对应bit3。
                                                1'b1:打开时钟
                                                1'b0:关闭时钟 */
        uint32_t share_ram_addr_offset : 4; /*!< 分配给C核的基地址偏移， 对应memmap的bit16-19。
                                                切32KB(RAM12-13)：设置 4'h6；
                                                切96KB(RAM10-13)：设置 4'h5；
                                                切160KB(RAM8-13)：设置 4'h4；
                                                切224KB(RAM6-13)：设置 4'h3； */
        uint32_t reserved : 20;             /*!< reserved. */
    } b;
} bram_share_cfg_t;


/*
 * Acore I/DTCM & DTCM(share with Ccore) 's cfg
 */
// RAM6-RAM13 @bram_share_cfg_t
#define BRAM_SHARE_COM_REG          0x57030234

// RAM0-RAM5 分别对应 bit0-bit5, 0:ITCM 1:DTCM
#define DTCM_SHARE_MODE_REG         0x57030238

/*
 * Ccore RAM0~5 's cfg
 * RAM0: size 8K
 * RAM1: size 8K
 * RAM2: size 16K
 * RAM3: size 32K
 * RAM4: size 32K
 */
// 门控开关: 1:开 0:关, bit0-bit4 分别对应 RAM0-RAM4
#define CPU_MEM_SHARE_CFG_REG       0x59000A98

// RAM0~2 RAM0 对应 bit4-5; RAM1 对应 bit2-3; RAM2 对应 bit0-1;
#define BANK_EM_USE_CFG_REG         0x57030390

// RAM3~4 RAM3 对应 bit2-3; RAM4 对应 bit0-1;
#define BANK_PKTMEM_USE_CFG_REG     0x57030394

/*
 * EM偏移地址控制
 * 仅可配置为如下三档：
 * 0x0:  用于EM-32K场景
 * 0x2:  用于EM-24K场景
 * 0x4:  用于EM-16K场景
 * 对EM地址进行偏移调整
 * 软件必须根据场景进行配置
 */
#define EM_OFFSET_ADDR_CFG_REG      0x57030398

/* Ccore RAM0~5 start addr cfg */
#define BANK_RAM0_START_ADDR_H 0x59000A9C
#define BANK_RAM0_START_ADDR_L 0x59000AA0
#define BANK_RAM1_START_ADDR_H 0x59000AA4
#define BANK_RAM1_START_ADDR_L 0x59000AA8
#define BANK_RAM2_START_ADDR_H 0x59000AAC
#define BANK_RAM2_START_ADDR_L 0x59000AB0
#define BANK_RAM3_START_ADDR_H 0x59000AB4
#define BANK_RAM3_START_ADDR_L 0x59000AB8
#define BANK_RAM4_START_ADDR_H 0x59000ABC
#define BANK_RAM4_START_ADDR_L 0x59000AC0
/**
 * @brief  Acore SHARE I/DTCM0 ~ I/DTCM5 's configuration.
 */
__attribute__((section(".text.runtime.init"))) void acore_idtcm_dyn_cfg(void)
{
    /*
     * RAM0 对应 bit0;  RAM1 对应 bit1;  RAM2 对应 bit2;
     * RAM3 对应 bit3;  RAM4 对应 bit4;  RAM5 对应 bit5;
     */
#if defined(CONFIG_DEVICE_MODE) || defined(_PRE_FEATURE_WS53_DEVICE_MODE)
    // use default val: 0x38
#elif defined(CONFIG_MCU_MODE_3) // WiFi only
    writel(DTCM_SHARE_MODE_REG, 0x3E); // 0x3E: 6'111110  RAM0 配置给ITCM接口访问;  RAM1~5 配置给DTCM接口访问
    reg32_setbit(MCU_MODE_COMMON_REG, MCU_MODE_3_MASK); // bit 6~8 -> b010, 表示MCU_MODE_3
#elif defined(CONFIG_MCU_MODE_4)
    writel(DTCM_SHARE_MODE_REG, 0x3C); // 0x3C: 6'111100  RAM0~1 配置给ITCM接口访问;  RAM2~5 配置给DTCM接口访问
    reg32_setbit(MCU_MODE_COMMON_REG, MCU_MODE_4_MASK); // bit 6~8 -> b100, 表示MCU_MODE_4
#elif defined(CONFIG_MCU_MODE_2)
    writel(DTCM_SHARE_MODE_REG, 0x3C); // 0x3C: 6'111100  RAM0~1 配置给ITCM接口访问;  RAM2~5 配置给DTCM接口访问
    reg32_setbit(MCU_MODE_COMMON_REG, MCU_MODE_2_MASK); // bit 6~8 -> b001, 表示MCU_MODE_2
#else
    // 0x3C: 6'111100  RAM0~1 配置给ITCM接口访问;  RAM2~5 配置给DTCM接口访问
    writel(DTCM_SHARE_MODE_REG, 0x3C);
    reg32_clrbits(MCU_MODE_COMMON_REG, MCU_MODE_MASK_OFFSET, MCU_MODE_MASK_LEN); // bit 6~8-> b000, 表示MCU_MODE_1
#endif
    return;
}
/**
 * @brief  Acore SHARE DTCM6 ~ DTCM13 's configuration, share with Ccore's CRAM.
 */
__attribute__((section(".text.runtime.init"))) void acore_dtcm_dyn_cfg(void)
{
    bram_share_cfg_t cfg;
    cfg.d32 = readl(BRAM_SHARE_COM_REG);

    // 关闭时钟
    cfg.b.bram_share_mode_gt = 0x0;
    writel(BRAM_SHARE_COM_REG, cfg.d32);

#if defined(CONFIG_MCU_MODE_1) // WiFi BLE GLE GLE图传
    // 该模式下，配置：DTCM12 ~ DTCM13 配置给CCPU
    cfg.b.bram_share_mode = 0x8; // 4'1000
#elif defined(CONFIG_MCU_MODE_4) // WiFi only
    // 该模式下，配置：DTCM6 ~ DTCM13 配置给ACPU
    cfg.b.bram_share_mode = 0x0; // 0'0000
#elif defined(CONFIG_MCU_MODE_3) // MODE3
    // 该模式下，配置：DTCM6 ~ DTCM13 配置给ACPU
    cfg.b.bram_share_mode = 0x0; // 0'0000
#elif defined(CONFIG_MCU_MODE_2) // MODE2
    // 该模式下，配置：DTCM6 ~ DTCM13 配置给ACPU
    cfg.b.bram_share_mode = 0x0; // 0'0000
#elif defined(CONFIG_DEVICE_MODE) || defined(_PRE_FEATURE_WS53_DEVICE_MODE)
    // 该模式下，配置：DTCM6 ~ DTCM13 配置给CCPU
    cfg.b.bram_share_mode = 0xF; // 4'1111
#elif defined(CONFIG_DIAG_MODE)
    // 该模式下，配置：DTCM12 ~ DTCM13 配置给CCPU
    cfg.b.bram_share_mode = 0x8; // 4'1000
#else
    // 该模式下，配置：DTCM12 ~ DTCM13 配置给CCPU
    cfg.b.bram_share_mode = 0x8; // 4'1000
#endif

    writel(BRAM_SHARE_COM_REG, cfg.d32);

    // 打开时钟
    cfg.b.bram_share_mode_gt = 0xF;
    writel(BRAM_SHARE_COM_REG, cfg.d32);

    return;
}

/**
 * @brief  Ccore CPU_RAM/PKT/BT_EM s configuration.
 */
__attribute__((section(".text.runtime.init"))) void ccore_shareram_dyn_cfg(void)
{
    // disable
    writel(CPU_MEM_SHARE_CFG_REG, 0x0); // 0x0: 5'00000b

#if defined(CONFIG_MCU_MODE_1)
    /*
     * Ccore CPU RAM: 88K, PKT_RAM:48K, BT_EM:24K, DIAG_RAM:0K
     *       CPU RAM: [0x00010000, 0x00024000)
     *       PKT_RAM: [0x00024000, 0x00030000)
     *         BT_EM: [0x59410000, 0x59416000)
     *
     * pktram use default cfg:
     *     RAM3~4 as PKTRAM, RAM3's addr is [0x00020000, 0x00028000) note: 16K of the head as CPU RAM
     *                       RAM4's addr is [0x00028000, 0x00030000)
     */

    // pktram cfg (default cfg)
    // bt_em cfg

    // EM-24K
    // writel(BANK_EM_USE_CFG_REG, 0xF) // 6'001111b RAM0 as CPURAM; RAM1~2 as BT_EM (default cfg)
    // writel(EM_OFFSET_ADDR_CFG_REG, 0x2) // 0x2: 用于EM-24K场景

    // EM-32K
    writel(BANK_EM_USE_CFG_REG, 0x3F); // 6'111111b RAM0~2 as BT_EM
    writel(EM_OFFSET_ADDR_CFG_REG, 0x0); // 0x0: 用于EM-32K场景
#elif defined(CONFIG_MCU_MODE_4) || defined(CONFIG_DEVICE_MODE) || defined(_PRE_FEATURE_WS53_DEVICE_MODE)
    /*
     * Ccore CPU RAM: 64K, PKT_RAM:64K, BT_EM:0K, DIAG_RAM:0K, DTCM(from Acore):224K
     *       CPU RAM: [0x00010000, 0x00020000)
     *       PKT_RAM: [0x00020000, 0x00030000)
     *          DTCM: [0x00090000, 0x000C8000)
     */
    writel(BANK_EM_USE_CFG_REG, 0x0); // 0'000000b RAM1~2 as CPURAM

#elif defined(CONFIG_DIAG_MODE)
    /*
     * Ccore CPU RAM: 88K, PKT_RAM:32K, BT_EM:24K, DIAG_RAM:32K
     *       CPU RAM: [0x00010000, 0x00024000)
     *       PKT_RAM: [0x00020000, 0x00030000) note: DIAG use half
     *         BT_EM: [0x59410000, 0x59416000)
     *          DTCM: [0x000C0000, 0x000C8000) note: heap use
     *
     * pktram use default cfg:
     *     RAM3~4 as PKTRAM, RAM3's addr is [0x00020000, 0x00028000) note: 16K of the head as CPU RAM
     *                       RAM4's addr is [0x00028000, 0x00030000)
     */

    // bt_em cfg
    writel(BANK_EM_USE_CFG_REG, 0xF); // 6'001111b RAM0 as CPURAM; RAM1~2 as BT_EM
    writel(EM_OFFSET_ADDR_CFG_REG, 0x2); // 0x2: 用于EM-24K场景
#elif defined(CONFIG_MCU_MODE_3)
    writel(BANK_EM_USE_CFG_REG, 0x0); // 6'000000b RAM0~2 as CPURAM
#elif defined(CONFIG_MCU_MODE_2)
    writel(BANK_EM_USE_CFG_REG, 0x3); // 6'000011b RAM2 as BT_EM
    writel(EM_OFFSET_ADDR_CFG_REG, 0x4); // 0x4: 用于EM-16K场景
#else // same as CONFIG_MCU_MODE_1
    // bt_em cfg

    // EM-24K
    // writel(BANK_EM_USE_CFG_REG, 0xF) // 6'001111b RAM0 as CPURAM; RAM1~2 as BT_EM (default cfg)
    // writel(EM_OFFSET_ADDR_CFG_REG, 0x2) // 0x2: 用于EM-24K场景

    // EM-32K
    writel(BANK_EM_USE_CFG_REG, 0x3F); // 6'111111b RAM0~2 as BT_EM
    writel(EM_OFFSET_ADDR_CFG_REG, 0x0); // 0x0: 用于EM-32K场景

#endif

    // enable
    writel(CPU_MEM_SHARE_CFG_REG, 0x1F); // 0x1F: 5'11111b
    return;
}


/**
 * @brief  Acore SHARE RAM configuration.
 */
__attribute__((section(".text.runtime.init"))) void acore_dyn_mem_cfg(void)
{
    acore_idtcm_dyn_cfg();
    acore_dtcm_dyn_cfg();
    return;
}

/**
 * @brief  Ccore SHARE RAM configuration.
 */
__attribute__((section(".text.runtime.init"))) void ccore_dyn_mem_cfg(void)
{
    ccore_shareram_dyn_cfg();
    return;
}
