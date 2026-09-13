/******************************************************************************
 * @brief    riscv31 mem info in lds
 * Copyright (c) 2023 HiSilicon (Shanghai) Technologies Co., Ltd.
******************************************************************************/

.section .data.mem.vars
.align 4

#ifndef FIXED_ROM_ENABLE
/* 未固定码点时，ROM的text段在初始阶段需要从flash拷贝到ram */
.global _g_romtext_begin
_g_romtext_begin: .word __romtext_begin__

.global _g_romtext_load
_g_romtext_load: .word __romtext_load__

.global _g_romtext_size
_g_romtext_size: .word __romtext_size__

.global _g_romtext_end
_g_romtext_end: .word __romtext_end__
#endif


/* ROM的data段在初始阶段需要从flash拷贝到ram */
.global _g_romdata_begin
_g_romdata_begin: .word __romdata_begin__

.global _g_romdata_load
_g_romdata_load: .word __romdata_load__

.global _g_romdata_size
_g_romdata_size: .word __romdata_size__


/* ROM的bss段在初始阶段需要清0 */
.global _g_rombss_begin
_g_rombss_begin: .word __rombss_begin__

.global _g_rombss_end
_g_rombss_end: .word __rombss_end__

/* 放在SRAM运行的代码的text&rodata段在初始阶段需要从flash拷贝到ram */
.global _g_sramtext_begin
_g_sramtext_begin: .word __sramtext_begin__

.global _g_sramtext_end
_g_sramtext_end: .word __sramtext_end__

.global _g_sramtext_load
_g_sramtext_load: .word __sramtext_load__

.global _g_sramtext_size
_g_sramtext_size: .word __sramtext_size__


/* 放在Flash运行的代码的起始和结束地址 */
.global _g_flashtext_begin
_g_flashtext_begin: .word __flashtext_begin__

.global _g_flashtext_end
_g_flashtext_end: .word __flashtext_end__


/* 除去放在ROM&TCM运行的代码，其他代码的data段，在初始阶段需要从flash拷贝到ram */
.global _g_data_begin
_g_data_begin: .word __data_begin__

.global _g_data_load
_g_data_load: .word __data_load__

.global _g_data_size
_g_data_size: .word __data_size__


/* 除去放在ROM&TCM运行的代码，其他代码的bss段，在初始阶段需要清0 */
.global _g_bss_begin
_g_bss_begin: .word __bss_begin__

.global _g_bss_end
_g_bss_end: .word __bss_end__


.global _g_text_begin
_g_text_begin: .word __text_begin__

.global _g_text_end
_g_text_end: .word __text_end__


.global _g_stack_top
_g_stack_top: .word __stack_top__

.global _g_system_stack_begin
_g_system_stack_begin: .word __system_stack_begin__

.global _g_system_stack_end
_g_system_stack_end: .word __system_stack_end__

.global _g_system_stack_size
_g_system_stack_size: .word __system_stack_size__

.global _g_stack_system
_g_stack_system: .word __system_stack_size__
