/******************************************************************************
 * @brief    CRT0 file used for starting up the rest of the code
 * Copyright (c) @CompanyNameMagicTag 2021-2021. All rights reserved.
******************************************************************************/

/**
 * @brief  This is the code that gets called when the processor first
 *          starts execution following a reset event. Only the absolutely
 *          necessary set is performed, after which the application
 *          supplied main() routine is called.
 * @param  None
 * @retval : None
*/

#if defined(__FREERTOS__)
        .extern freertos_risc_v_trap_handler
#elif defined(__LITEOS__)
        .extern TrapVector
#endif
        .extern runtime_init
        .section .text.entry
        .global _start
        .option norvc
_start:
        j Reset_Handler

Reset_Handler:
        li t0,0x0
        csrw pmpcfg0,t0
        li t0,0x0
        csrw pmpcfg1,t0
#if defined(__FREERTOS__)
        la t0, freertos_risc_v_trap_handler
        andi t0,t0,0xfffffffc
        csrw mtvec, t0
#elif defined(__LITEOS__)
        la t0, TrapVector
        csrw    mtvec, t0
#endif

        csrwi   mstatus, 0
        csrwi   mie, 0

        .option push
        .option norelax
        /* initialize global pointer */
        la      gp, _gp_
        .option pop

        # initialize stack pointer
        la sp, __stack_top__

        /* init stack */
        la      t0, __system_stack_begin__
        la      t1, __system_stack_end__
        beq     t0, t1, end_set_stack_loop
        li      t2, 0xefbeadde

set_stack_loop:
        sw      t2, (t0)
        addi    t0, t0, 4
        blt     t0, t1, set_stack_loop
end_set_stack_loop:

        mv a0, t5
        la t0, runtime_init
        jr t0
