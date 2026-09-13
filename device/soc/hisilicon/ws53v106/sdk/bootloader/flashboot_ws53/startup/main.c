/*
 * Copyright (c) @CompanyNameMagicTag 2021-2023. All rights reserved.
 * Description: main
 * Author: @CompanyNameTag
 * Create: 2021-03-09
 */

#include "boot_verify.h"
#include "boot_serial.h"
#include "boot_init.h"
#include "boot_flash.h"
#include "boot_delay.h"
#include "boot_jump.h"
#include "boot_reset.h"
#include "boot_debug.h"
#include "secure_verify_boot.h"
#include "drv_flashboot_cipher.h"
#include "reset_porting.h"
#include "upg_common.h"
#include "upg_alloc.h"
#include "upg_config.h"
#include "partition.h"
#include "watchdog.h"
#include "pinctrl.h"
#include "efuse.h"
#include "sfc.h"
#ifdef CONFIG_MIDDLEWARE_SUPPORT_UPG
#include "upg_porting.h"
#ifdef CONFIG_MIDDLEWARE_SUPPORT_UPG_AB
#include "upg_ab.h"
#endif
#endif
#include "malloc_porting.h"
#include "sfc_protect.h"
#include "factory.h"
#ifdef CONFIG_SEC_UPGRADE_VERSION_VALIDATE
#include "efuse_porting.h"
#endif

#define APP_IMAGE_HEADER_LEN  ((KEY_AREA_STRUCTURE_LENGTH) + (CODE_INFO_STRUCTURE_LENGTH))
#define FLASHBOOT_WDT_TIMOUT   7    // 7s
#define FLASHBOOT_RAM_ADDR     0x28000
#define FLASHBOOT_UART_DEFAULT_PARAM    {115200, 8, 1, 0, 0, 2, 1, 4, 0}
#define APP_START_INSTRUCTION  0x40006f
#ifndef FLASH_PAGE_SIZE
#define FLASH_PAGE_SIZE        0x1000
#endif

static void sfc_pin_mode_set(void)
{
    /* Set Sfc PinMux */
    writel(0x52008060, 1);
    writel(0x52008064, 1);
    writel(0x52008068, 1);
    writel(0x5200806c, 1);
    writel(0x52008070, 1);
    writel(0x52008074, 1);
}

#define FAMA_REMAP_SRC_BASE_ADDR 0x5208F800
#define FAMA_REMAP_LEN_BASE_ADDR 0x5208F820
#define FAMA_REMAP_DST_BASE_ADDR 0x5208F840
#define FAMA_REMAP_REGION_OFFSET 0x4
#define FAMA_REMAP_LOW_BITS 12
static void dmmu_set(uint32_t src_start_addr, uint32_t src_end_addr, uint32_t dst_start_addr, uint32_t region)
{
    uint32_t src_reg_addr = FAMA_REMAP_SRC_BASE_ADDR + region * FAMA_REMAP_REGION_OFFSET;
    uint32_t len_reg_addr = FAMA_REMAP_LEN_BASE_ADDR + region * FAMA_REMAP_REGION_OFFSET;
    uint32_t dst_reg_addr = FAMA_REMAP_DST_BASE_ADDR  + region * FAMA_REMAP_REGION_OFFSET;
    uint32_t src_start_align_addr = src_start_addr  >> FAMA_REMAP_LOW_BITS;
    uint32_t src_end_align_addr = src_end_addr >> FAMA_REMAP_LOW_BITS;
    uint32_t dst_start_align_addr = dst_start_addr >> FAMA_REMAP_LOW_BITS;
    uint32_t dst_src_offset = 0;
    if (region >= FAMA_REMAP_LOW_BITS) {
        return ;
    }
    writel(src_reg_addr, src_start_align_addr);
    writel(len_reg_addr, src_end_align_addr);
    if (src_start_align_addr > dst_start_align_addr) {
        dst_src_offset = src_start_align_addr - dst_start_align_addr;
        dst_src_offset = ~dst_src_offset;
        dst_src_offset = dst_src_offset + 1;
    } else {
        dst_src_offset = dst_start_align_addr - src_start_align_addr;
    }
    writel(dst_reg_addr, dst_src_offset);
}

#define AON_XIP_SFC_CR 0x52000570
static void boot_flash_clk_init(void)
{
    reg_clrbit(AON_XIP_SFC_CR, 0, POS_0);
    udelay(1);
    reg16_setbits(AON_XIP_SFC_CR, POS_1, 0x3, 0x6);
    udelay(1);
    reg_setbit(AON_XIP_SFC_CR, 0, POS_0);
    udelay(1);
}

static void boot_flash_init(void)
{
    sfc_flash_config_t sfc_cfg = {
        .read_type = FAST_READ_QUAD_OUTPUT,
        .write_type = PAGE_PROGRAM,
        .mapping_addr = FLASH_HEAD_ADDR,
        .mapping_size = FLASH_MEM_SIZE,
    };
    sfc_pin_mode_set();
    errcode_t ret = uapi_sfc_init(&sfc_cfg);
    if (ret != ERRCODE_SUCC) {
        serial_cancel_mute();
        boot_msg1("flash fail = ", ret);
        serial_set_mute();
    }
    boot_flash_clk_init();
}

static void flashboot_init(void)
{
    errcode_t err;
    uart_param_stru uart_param = FLASHBOOT_UART_DEFAULT_PARAM;
    delay_init();
    uapi_pin_init();
    uapi_partition_init();
    hiburn_uart_init(uart_param, UART_DEBUG_PORT);
    serial_set_mute();
    boot_msg0("boot.");
    malloc_port_init();
    boot_msg0("Flashboot Malloc Init Succ!");
    boot_flash_init();
    err = sfc_port_fix_sr();
    if (err != ERRCODE_SUCC) {
        serial_cancel_mute();
        boot_msg1("SFC fix SR ret =", err);
        serial_set_mute();
    }
}


static bool flashboot_need_recovery(void)
{
#define FLASH_BOOT_TYPE_REG      0x5200001C
#define FLASH_BOOT_TYPE_REG_MAIN 0xA5A5
#define FLASH_BOOT_TYPE_REG_BKUP 0x5A5A
    uint16_t reg = readw(FLASH_BOOT_TYPE_REG);
    writew(FLASH_BOOT_TYPE_REG, 0);
    return (reg == FLASH_BOOT_TYPE_REG_BKUP) ? true : false;
}

static void flashboot_recovery(void)
{
    if (!flashboot_need_recovery()) {
        return;
    }
    serial_cancel_mute();
    uapi_watchdog_kick();
    boot_msg0("Flashboot backup is working!");
    partition_information_t src_img_info = {0};
    partition_information_t dst_img_info = {0};
    errcode_t ret;
    ret = uapi_partition_get_info(PARTITION_FLASH_BOOT_IMAGE_BACKUP, &src_img_info);
    ret |= uapi_partition_get_info(PARTITION_FLASH_BOOT_IMAGE, &dst_img_info);
    if (ret != ERRCODE_SUCC) {
        boot_msg0("Flashboot partition info get fail!");
        serial_set_mute();
        return;
    }

    ret = uapi_sfc_reg_erase(dst_img_info.part_info.addr_info.addr, dst_img_info.part_info.addr_info.size);
    if (ret != ERRCODE_SUCC) {
        boot_msg1("flashboot recovery erase failed!! ret = ", ret);
    }
    ret = uapi_sfc_reg_write(dst_img_info.part_info.addr_info.addr,
        (uint8_t *)(uintptr_t)(src_img_info.part_info.addr_info.addr + FLASH_START),
        src_img_info.part_info.addr_info.size);
    if (ret != ERRCODE_SUCC) {
        boot_msg1("flashboot recovery write failed!! ret = ", ret);
    }
    boot_msg0("Flashboot fix ok!");
    serial_set_mute();
}

static bool ws53_upg_need_upgrade(void)
{
    uint32_t fota_address = 0;
    partition_information_t info;
    errcode_t ret_val = uapi_partition_get_info(PARTITION_FOTA_DATA, &info);
    if (ret_val != ERRCODE_SUCC || info.type != PARTITION_BY_ADDRESS) {
        boot_msg1("uapi_partition_get_info failed ", __LINE__);
        return false;
    }
    upg_get_upgrade_flag_flash_start_addr(&fota_address);
    fota_upgrade_flag_area_t upg_flag_info;
    ret_val = upg_flash_read(fota_address, sizeof(fota_upgrade_flag_area_t), (uint8_t *)(&upg_flag_info));
    if (ret_val != ERRCODE_SUCC) {
        boot_msg1("upg_flash_read failed ", ret_val);
        return false;
    }
    if (!(upg_flag_info.head_magic == UPG_HEAD_MAGIC &&
          upg_flag_info.head_end_magic == UPG_END_MAGIC &&
          upg_flag_info.complete_flag != 0)) {
        /* 不需要升级直接返回 */
        boot_msg0("No need to upgrade...");
        return false;
    }
    return true;
}

static void ws53_upg_check(void)
{
    (void)ws53_upg_init();
#ifdef CONFIG_MIDDLEWARE_SUPPORT_UPG_AB
    return;
#endif
    if (ws53_upg_need_upgrade()) {
        serial_cancel_mute();
        boot_msg0("need upgrade");
        errcode_t ret = uapi_upg_start();
        // 1, 没有升级包、或者升级标记区结果已经设置的情况不需要重启
        // 2, 升级模块没有初始化不需要重启
        // 3, 升级成功不需要重启
        // 4, 升级失败的时候需要重启重新进入升级流程，尝试三次未成功，后会变为1的情况
        if (!(ret == ERRCODE_UPG_NOT_NEED_TO_UPDATE || ret == ERRCODE_UPG_NOT_INIT || ret == ERRCODE_SUCC)) {
            boot_msg0("--------------------------");
            boot_msg0("upgrade failed, reset now");
        } else {
            // 升级后重启
            boot_msg0("--------------------------");
            boot_msg0("upgrade success, reset now");
        }
        upg_reboot();
        serial_set_mute();
    }
}

#define UPG_FIX_RETRY_CNT_REG   RESET_COUNT_REG
#define VERIFY_RETRY_CNT_THRES  0x3
#define UPG_FIX_RETRY_CNT_THRES (VERIFY_RETRY_CNT_THRES + 0x3)
#define UPG_AB_RETRY_CNT_THRES (VERIFY_RETRY_CNT_THRES + 0x3)

static uint8_t ws53_get_try_fix_cnt(void)
{
    gp_reg1_union gp;
    gp.u16 = (uint16_t)readl(UPG_FIX_RETRY_CNT_REG);
    return gp.bits.fota_fix_app_cnt;
}

static void ws53_set_try_fix_cnt(uint8_t cnt)
{
    gp_reg1_union gp;
    gp.u16 = (uint16_t)readl(UPG_FIX_RETRY_CNT_REG);
    gp.bits.fota_fix_app_cnt = cnt & 0xF;
    writel(UPG_FIX_RETRY_CNT_REG, gp.u16);
}

#ifdef CONFIG_MIDDLEWARE_SUPPORT_UPG_AB
static void ws53_try_fix_app(void)
{
    uint8_t try_cnt = ws53_get_try_fix_cnt() + 1;
    ws53_set_try_fix_cnt(try_cnt);

    /* 启动分区连续验签失败次数等于阈值倍数时，切换启动分区 */
    if (try_cnt % VERIFY_RETRY_CNT_THRES) { // 1 2 4 5 7 8 a b d e
        return;
    } else { // 3 6 9 c f
        boot_msg0("switch booting");
        upg_set_run_region(upg_get_upg_region());
        return;
    }
}
#else // 压缩
/* 尝试ota修复运行区镜像 */
static void ws53_try_fix_app(void)
{
    errcode_t ret;
    uint8_t try_cnt = ws53_get_try_fix_cnt();
    /* 连续验签失败次数小于阈值不做处理 */
    if (try_cnt < VERIFY_RETRY_CNT_THRES) {
        ws53_set_try_fix_cnt(try_cnt + 1);
        return;
    }

    /* 修复app超次数阈值后不再尝试 */
    if (try_cnt >= UPG_FIX_RETRY_CNT_THRES) {
        return;
    }
    ws53_set_try_fix_cnt(try_cnt + 1);

#if (UPG_CFG_VERIFICATION_SUPPORT == YES)
    /* 升级包校验 */
    upg_package_header_t *pkg_header = NULL;
    ret = upg_get_package_header(&pkg_header);
    if (ret != ERRCODE_SUCC || pkg_header == NULL) {
        boot_msg1("get_pkg_header fail, ret = ", ret);
        return;
    }
    ret = uapi_upg_verify_file((const upg_package_header_t *)pkg_header);
    if (ret != ERRCODE_SUCC) {
        boot_msg1("upg_verify fail, ret = ", ret);
        return;
    }
#endif

    /* 重置升级标记 */
    ret = uapi_upg_reset_upgrade_flag();
    if (ret != ERRCODE_SUCC) {
        boot_msg1("reset_upgrade_flag fail, ret = ", ret);
        return;
    }

    /* 请求升级 */
    ret = uapi_upg_request_upgrade(false);
    if (ret != ERRCODE_SUCC) {
        boot_msg0("request_upgrade fail, fota_pkt_not_exit.");
        return;
    }
    boot_msg0("fota_pkt exit, try_fota_fix_app.");
}
#endif

static errcode_t ws53_verify_app(uint32_t image_addr)
{
    image_key_area_t *flashboot_key_area = (image_key_area_t *)(FLASHBOOT_RAM_ADDR);

    errcode_t ret = verify_image_head(APP_BOOT_TYPE, (uint32_t)(uintptr_t)(flashboot_key_area->ext_pulic_key_area),
        image_addr);
    if (ret != ERRCODE_SUCC) {
        boot_msg1("flashboot verify_image_app_head failed!! ret = ", ret);
        return ret;
    }

    ret = verify_image_body(image_addr, image_addr + APP_IMAGE_HEADER_LEN);
    if (ret != ERRCODE_SUCC) {
        boot_msg1("verify_image_app_body failed!! ret = ", ret);
        return ret;
    }
    return ERRCODE_SUCC;
}

static void ws53_verify_app_handle(uint32_t addr)
{
    errcode_t ret = ws53_verify_app(addr);
    if (ret != ERRCODE_SUCC) {
        ws53_try_fix_app();
        reset();
    }
    set_reset_count(0);
    ws53_set_try_fix_cnt(0);
}

#define FLASH_KEY_SALT_LEN     28
#define FLASH_ENCRY_ADDR_ALINE 256
#define FLASH_NO_ENCRY_FLAG    0x3C7896E1
static void ws53_flash_encrypt_config(uint32_t image_addr, uint32_t image_size)
{
    crypto_klad_effective_key flash_key = {0};
    uint32_t start_addr, end_addr;
    errcode_t ret;

    image_code_info_t *code_info = (image_code_info_t *)(uintptr_t)(image_addr + sizeof(image_key_area_t));
    if (code_info->code_enc_flag == FLASH_NO_ENCRY_FLAG) {
        boot_msg0("flash_encrypt disable.");
        return;
    }

    boot_msg0("flash_encrypt enable.");
    start_addr = image_addr + APP_IMAGE_HEADER_LEN;
    end_addr = image_addr + image_size;
    if (start_addr % FLASH_ENCRY_ADDR_ALINE != 0 || end_addr % FLASH_ENCRY_ADDR_ALINE != 0) {
        boot_msg2("app_image start or end addr err, must 256byte alignment ", start_addr, end_addr);
        reset();
    }

    flash_key.kdf_hard_alg = CRYPTO_KDF_HARD_ALG_SHA256;
    flash_key.key_parity = TD_FALSE;
    flash_key.key_size = CRYPTO_KLAD_KEY_SIZE_128BIT;
    flash_key.salt = code_info->protection_key_l1;
    flash_key.salt_length = FLASH_KEY_SALT_LEN;
    flash_key.oneway = TD_TRUE;
    ret = (uint32_t)drv_rom_cipher_config_odrk1(flash_key);
    if (ret != ERRCODE_SUCC) {
        boot_msg1("fapc_set_config drv_rom_cipher_config_odrk1 err = ", ret);
        reset();
    }
    ret = (uint32_t)drv_rom_cipher_fapc_config(0, start_addr, end_addr, code_info->iv, IV_LEN);
    if (ret != ERRCODE_SUCC) {
        boot_msg1("fapc_set_config drv_rom_cipher_fapc_config err = ", ret);
        reset();
    }

    ret = (uint32_t)drv_rom_cipher_fapc_bypass_config(1, end_addr, FLASH_MAX_END, TD_TRUE);
    if (ret != ERRCODE_SUCC) {
        boot_msg1("fapc_set_config drv_rom_cipher_fapc_bypass_config err = ", ret);
        reset();
    }
}

#define EFUSE0_CTL      0x57024030
#define EFUSE0_WR_DATA4 0x57024810
#define EFUSE0_WR_DATA5 0x57024814
#define EFUSE0_WR_DATA11 0x5702482C
#define PMU_TRIM_CTL_0 0x57031010
#define EFUSE_ULP_SEL0 0x57031000
#define EFUSE_READ_TAG 0x5a5a
#define YEAR_MASK 0x3f
#define MONTH_MASK 0x3
#define DAY_MASK 0x1f
#define YEAR_24 24
#define MONTH_1 1
#define MONTH_2 2
#define MONTH_3 3
#define DAY_15 15
#define DAY_32 32
#define DAY_13 13
#define DATA_MASK 0x1f
static void repair_efuse_error(void)
{
    uint32_t efuse_read_order = EFUSE_READ_TAG;
    uint32_t data4 = 0;
    uint32_t data5 = 0;
    uint32_t data11 = 0;
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t trim_ctrl = 0;

    writel(EFUSE0_CTL, efuse_read_order);
    data4 = readl(EFUSE0_WR_DATA4);
    data5 = readl(EFUSE0_WR_DATA5);
    year = (data4 >> POS_8) & YEAR_MASK;
    month = ((data5 & MONTH_MASK) << POS_2) | ((data4 >> POS_14) & MONTH_MASK);
    day = (data5 >> POS_2) & DAY_MASK;
    if ((year == YEAR_24) &&
        (((month == MONTH_1) && (day > DAY_15) && (day < DAY_32)) ||
        (month == MONTH_2) || ((month == MONTH_3) && (day < DAY_13)))) {
        data11 = readl(EFUSE0_WR_DATA11);
        trim_ctrl = (data11 >> POS_10) & DATA_MASK;
        trim_ctrl = trim_ctrl | ((data11 & DATA_MASK) << POS_5);
        trim_ctrl = trim_ctrl | (((data11 >> POS_5) & DATA_MASK) << POS_10);
        writel(PMU_TRIM_CTL_0, trim_ctrl);
        reg_setbit(EFUSE_ULP_SEL0, 0, POS_15);
    }
}

static void ws53_ftm_mode_init(uint32_t image_addr)
{
    uint32_t image_size = 0;
    uint32_t jump_addr = 0;
    mfg_factory_config_t mfg_factory_cfg = {0};
    uint32_t run_region = mfg_get_ftm_run_region(&mfg_factory_cfg);
    if (run_region == FTM_REGION_SERVICE) {
        return;
    }
    jump_addr = mfg_factory_cfg.factory_addr_start;
    image_size = mfg_factory_cfg.factory_size;
    image_key_area_t *mfg_key_area = (image_key_area_t *)(uintptr_t)(jump_addr);

    if (mfg_key_area->image_id == FACTORYBOOT_KEY_AREA_IMAGE_ID && mfg_factory_cfg.factory_valid == MFG_FACTORY_VALID &&
        mfg_key_area->structure_length == sizeof(image_key_area_t)) {
        // dmmu配置都是闭区间，- 0x1才是源区间的结束地址, 0: 第0组dmmu配置
        dmmu_set(image_addr, image_addr + image_size - 0x1, jump_addr, 0);
    }
}

static void ws53_get_image_addr(uint32_t *image_addr)
{
    partition_information_t acore_img_info = {0};
    partition_information_t ccore_img_info = {0};
    uint32_t acore_img_addr, ccore_img_addr;
    errcode_t ret = 0;

    ret |= uapi_partition_get_info(PARTITION_APP_IMAGE, &acore_img_info);
    ret |= uapi_partition_get_info(PARTITION_CCPU_IMAGE, &ccore_img_info);
    if (ret != ERRCODE_SUCC) {
        serial_cancel_mute();
        boot_msg1("flashboot get image partition failed!, ret = ", ret);
        serial_set_mute();
        reset();
    }
    acore_img_addr = acore_img_info.part_info.addr_info.addr + FLASH_START;
    ccore_img_addr = ccore_img_info.part_info.addr_info.addr + FLASH_START;
#ifdef CONFIG_MIDDLEWARE_SUPPORT_UPG_AB
    char *boot_str = "A";
    uint32_t jump_addr = upg_get_region_addr(upg_get_run_region()) + FLASH_START;
    uint32_t image_size = upg_get_region_size(UPG_REGION_A);
    *boot_str = (ccore_img_addr == jump_addr) ? 'A' : 'B';
    boot_msg0(boot_str);
    ws53_flash_encrypt_config(jump_addr, image_size); /* flash加密配置 */
    ws53_verify_app_handle(jump_addr); /* app验签 */
    if (ccore_img_addr != jump_addr) {
        // dmmu配置都是闭区间，- 0x1才是源区间的结束地址, 0: 第0组dmmu配置
        dmmu_set(ccore_img_addr, ccore_img_addr + image_size - 0x1, jump_addr, 0);
        // dmmu配置都是闭区间，- 0x1才是源区间的结束地址, 1: 第1组dmmu配置
        dmmu_set(jump_addr, jump_addr + image_size - 0x1, ccore_img_addr, 1);
    }
#else // 压缩
    uint32_t ccore_img_size = ccore_img_info.part_info.addr_info.size;
    ws53_flash_encrypt_config(ccore_img_addr, ccore_img_size); /* flash加密配置 */
    ws53_verify_app_handle(ccore_img_addr); /* app验签 */
#endif
    ws53_ftm_mode_init(ccore_img_addr);
    *image_addr = acore_img_addr;
}

/* the entry of C. */
void start_fastboot(void)
{
    uint32_t image_addr = 0;
    uapi_watchdog_init(FLASHBOOT_WDT_TIMOUT);
    uapi_watchdog_enable(WDT_MODE_RESET);
    flashboot_init();
    repair_efuse_error();
    uapi_efuse_init();
    ws53_upg_check();
    ws53_get_image_addr(&image_addr);
#ifdef CONFIG_SEC_UPGRADE_VERSION_VALIDATE
    set_board_rollback_version();
#endif
    flashboot_recovery();
    uapi_watchdog_kick();
    jump_to_execute_addr(image_addr + APP_IMAGE_HEADER_LEN);
}
