/*
 * Copyright (c) @CompanyNameMagicTag 2021-2021. All rights reserved.
 * Description:  share memory configurations
 * Author: @CompanyNameTag
 * Create:  2021-06-16
 */

#ifndef SHARE_MEM_CONFIG_H
#define SHARE_MEM_CONFIG_H

#ifndef FIXED_ROM_ENABLE
/* 未固定码点时，ROM的text段在初始阶段需要从flash拷贝到ram */
extern unsigned int __romtext_begin__;
extern unsigned int __romtext_load__;
extern unsigned int __romtext_size__;
extern unsigned int __romtext_end__;
#endif

/* ROM的data段在初始阶段需要从flash拷贝到ram */
extern unsigned int __romdata_begin__;
extern unsigned int __romdata_load__;
extern unsigned int __romdata_size__;

/* ROM的bss段在初始阶段需要清0 */
extern unsigned int __rombss_begin__;
extern unsigned int __rombss_end__;

/* FlashPatch机制用到的remap table & cmp table; 和ROM2.0机制的跳转表 */
extern unsigned int __rom_patch_begin__;
extern unsigned int __rom_patch_load__;
extern unsigned int __rom_patch_size__;

extern unsigned int __patch_begin__;
extern unsigned int __patch_load__;
extern unsigned int __patch_size__;

extern unsigned int __rom_ram_cb_begin__;
extern unsigned int __rom_ram_cb_load__;
extern unsigned int __rom_ram_cb_size__;

/* 放在SRAM运行的代码的text&rodata段在初始阶段需要从flash拷贝到ram */
extern unsigned int __sramtext_begin__;
extern unsigned int __sramtext_end__;
extern unsigned int __sramtext_load__;
extern unsigned int __sramtext_size__;

/* 放在Flash运行的代码的起始和结束地址 */
extern unsigned int __flashtext_begin__;
extern unsigned int __flashtext_end__;

extern unsigned int __sramdata_begin__;
extern unsigned int __sramdata_load__;
extern unsigned int __sramdata_size__;

extern unsigned int __flashdata_begin__;
extern unsigned int __flashdata_load__;
extern unsigned int __flashdata_size__;

extern unsigned int __em_text_begin__;
extern unsigned int __em_text_load__;
extern unsigned int __em_text_size__;

/* 除去放在ROM&TCM运行的代码，其他代码的data段，在初始阶段需要从flash拷贝到ram */
extern unsigned int __data_begin__;
extern unsigned int __data_load__;
extern unsigned int __data_size__;

/* 除去放在ROM&TCM运行的代码，其他代码的bss段，在初始阶段需要清0 */
extern unsigned int __bss_begin__;
extern unsigned int __bss_end__;

extern unsigned int __bt_text_begin__;
extern unsigned int __bt_text_load__;
extern unsigned int __bt_text_size__;
extern unsigned int __bt_data_begin__;
extern unsigned int __bt_data_load__;
extern unsigned int __bt_data_size__;
extern unsigned int __bt_bss_begin__;
extern unsigned int __bt_bss_end__;

extern unsigned int __em_ram_begin__;
extern unsigned int __em_ram_end__;
extern unsigned int __itcm_bss_begin__;
extern unsigned int __itcm_bss_end__;

extern unsigned int __text_begin__;
extern unsigned int __text_end__;

extern unsigned int __stack_top__;

#ifndef FIXED_ROM_ENABLE
/* 未固定码点时，ROM的text段在初始阶段需要从flash拷贝到ram */
extern unsigned int _g_romtext_begin;
extern unsigned int _g_romtext_load;
extern unsigned int _g_romtext_size;
extern unsigned int _g_romtext_end;
#endif

/* ROM的data段在初始阶段需要从flash拷贝到ram */
extern unsigned int _g_romdata_begin;
extern unsigned int _g_romdata_load;
extern unsigned int _g_romdata_size;

/* ROM的bss段在初始阶段需要清0 */
extern unsigned int _g_rombss_begin;
extern unsigned int _g_rombss_end;

/* FlashPatch机制用到的remap table & cmp table; 和ROM2.0机制的跳转表 */
extern unsigned int _g_rom_patch_begin;
extern unsigned int _g_rom_patch_load;
extern unsigned int _g_rom_patch_size;

/* 放在SRAM运行的代码的text&rodata段在初始阶段需要从flash拷贝到ram */
extern unsigned int _g_sramtext_begin;
extern unsigned int _g_sramtext_end;
extern unsigned int _g_sramtext_load;
extern unsigned int _g_sramtext_size;

/* 放在Flash运行的代码的起始和结束地址 */
extern unsigned int _g_flashtext_begin;
extern unsigned int _g_flashtext_end;

/* 放在em运行的代码的起始和结束地址 */
extern unsigned int _g_em_text_begin;
extern unsigned int _g_em_text_end;

/* 除去放在ROM&TCM运行的代码，其他代码的data段，在初始阶段需要从flash拷贝到ram */
extern unsigned int _g_data_begin;
extern unsigned int _g_data_load;
extern unsigned int _g_data_size;

/* 除去放在ROM&TCM运行的代码，其他代码的bss段，在初始阶段需要清0 */
extern unsigned int _g_bss_begin;
extern unsigned int _g_bss_end;

extern unsigned int _g_text_begin;
extern unsigned int _g_text_end;

extern unsigned int _g_stack_top;
extern unsigned int _g_system_stack_begin;
extern unsigned int _g_system_stack_end;
extern unsigned int _g_system_stack_size;

extern unsigned int _g_logbuff_start;
extern unsigned int _g_ipc_share_start;

typedef struct _ccore_cc_symbols {
    unsigned int rsv_0;
    unsigned int rsv_1;
    unsigned int startup_load_addr;
    unsigned int startup_begin_addr;
    unsigned int startup_size;
    unsigned int logbuff_start;
    unsigned int ipc_share_mem_start;
} ccore_cc_symbols_t;

#endif
