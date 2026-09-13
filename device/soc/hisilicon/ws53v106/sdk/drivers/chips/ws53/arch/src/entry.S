/******************************************************************************
 * @brief riscv31 inter handler
 * Copyright (c) 2023 HiSilicon (Shanghai) Technologies Co., Ltd.
******************************************************************************/
#ifndef ENTRY_S
#define ENTRY_S

#define REGBYTES                    4
#define INT_SIZE_ON_STACK           (16 * REGBYTES)

.extern hal_trap_handler
.option norvc

.macro push_reg
    addi  sp, sp, -(INT_SIZE_ON_STACK)
    stmia {ra, t0-t2, a0-a7, t3-t6}, (sp)
    addi  sp, sp, -(INT_SIZE_ON_STACK)
    csrw mscratch, sp
.endm

.macro pop_reg
    addi  sp, sp, INT_SIZE_ON_STACK
    ldmia {ra, t0-t2, a0-a7, t3-t6}, (sp)
    addi  sp, sp, INT_SIZE_ON_STACK
.endm

.align 4
.global trap_entry
trap_entry:
    push_reg
    call hal_trap_handler
    pop_reg
    mret

#endif
