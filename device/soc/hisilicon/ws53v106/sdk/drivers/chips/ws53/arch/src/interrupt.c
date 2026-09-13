/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:  Interrupt DRIVER
 *
 * Create: 2021-07-01
 */
#include "chip_io.h"
#include "arch_encoding.h"
#include "vectors.h"
#include "arch_barrier.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define INT_NUM_MAX             0xFFF
#define UINT32_CUT_MASK         0xFFFFFFFF
#define int_set_inter_pri(reg, irq_id, pri) do {                              \
    uint32_t pri_val = read_custom_csr(reg);                              \
    /* clear the irq_num-th local interrupt priority */                              \
    pri_val &= (~((0xfU << (((uint32_t)(irq_id) & 0x7U) << 2)) & UINT32_CUT_MASK)); \
    /* set the irq_num-th local interrupt priority */                                   \
    pri_val |= ((uint32_t)(pri) << (((uint32_t)(irq_id) & 0x7U) << 2));             \
    write_custom_csr_val(reg, pri_val);                                      \
} while (0)

void int_enable_irq(uint32_t irq_id)
{
    uint32_t irqorder;
    uint32_t locien_offset;

    // enable local interrupt 26 -31 by irq_id
    if ((irq_id < RISCV_LOCAL_IRQ_VECTOR_CNT) && (irq_id >= RISCV_SYS_VECTOR_CNT)) {
        irqorder = irq_id;
        set_csr(mie, ((uint32_t)1 << irqorder));
    } else {
        irqorder = (uint32_t)((irq_id - RISCV_LOCAL_IRQ_VECTOR_CNT) % LOCIEN_IRQ_NUM);
        locien_offset = (uint32_t)((irq_id - RISCV_LOCAL_IRQ_VECTOR_CNT) / LOCIEN_IRQ_NUM);
        switch (locien_offset) {
            case EXTERNAL_INTERRUPT_GROUP0:
                set_custom_csr(LOCIEN0, (uint32_t)((uint32_t)1 << irqorder));
                break;
            case EXTERNAL_INTERRUPT_GROUP1:
                set_custom_csr(LOCIEN1, (uint32_t)((uint32_t)1 << irqorder));
                break;
            case EXTERNAL_INTERRUPT_GROUP2:
                set_custom_csr(LOCIEN2, (uint32_t)((uint32_t)1 << irqorder));
                break;
            default:
                break;
        }
    }
    dsb();
}

void int_disable_irq(uint32_t irq_id)
{
    uint32_t irqorder;
    uint32_t locien_offset;

    // Disable local interrupt 26 -31 by irq_id
    if ((irq_id < RISCV_LOCAL_IRQ_VECTOR_CNT) && (irq_id >= RISCV_SYS_VECTOR_CNT)) {
        irqorder = irq_id;
        clear_csr(mie, ((uint32_t)1 << irqorder));
    } else {
        irqorder = (uint32_t)((irq_id - RISCV_LOCAL_IRQ_VECTOR_CNT) % LOCIEN_IRQ_NUM);
        locien_offset = (uint32_t)((irq_id - RISCV_LOCAL_IRQ_VECTOR_CNT) / LOCIEN_IRQ_NUM);
        switch (locien_offset) {
            case EXTERNAL_INTERRUPT_GROUP0:
                clear_custom_csr(LOCIEN0, ((uint32_t)1 << irqorder));
                break;
            case EXTERNAL_INTERRUPT_GROUP1:
                clear_custom_csr(LOCIEN1, ((uint32_t)1 << irqorder));
                break;
            case EXTERNAL_INTERRUPT_GROUP2:
                clear_custom_csr(LOCIEN2, ((uint32_t)1 << irqorder));
                break;
            default:
                break;
        }
    }
    dsb();
    int_clear_pending_irq(irq_id);
}

uint32_t int_get_enable_irq(uint32_t irq_id)
{
    uint32_t irqorder;
    uint32_t locien_offset;
    uint32_t enable = 0;

    if ((irq_id < RISCV_LOCAL_IRQ_VECTOR_CNT) && (irq_id >= RISCV_SYS_VECTOR_CNT)) {
        irqorder = irq_id;
        enable = read_csr(mie) & (((uint32_t)1 << irqorder));
    } else {
        irqorder = (uint32_t)((irq_id - RISCV_LOCAL_IRQ_VECTOR_CNT) % LOCIEN_IRQ_NUM);
        locien_offset = (uint32_t)((irq_id - RISCV_LOCAL_IRQ_VECTOR_CNT) / LOCIEN_IRQ_NUM);
        switch (locien_offset) {
            case EXTERNAL_INTERRUPT_GROUP0:
                enable = read_custom_csr(LOCIEN0) & (((uint32_t)1 << irqorder));
                break;
            case EXTERNAL_INTERRUPT_GROUP1:
                enable = read_custom_csr(LOCIEN1) & (((uint32_t)1 << irqorder));
                break;
            case EXTERNAL_INTERRUPT_GROUP2:
                enable = read_custom_csr(LOCIEN2) & (((uint32_t)1 << irqorder));
                break;
            default:
                break;
        }
    }
    return enable;
}

void int_clear_pending_irq(uint32_t irq_id)
{
    write_custom_csr_val(LOCIPCLR, irq_id);
    dsb();
}

void int_set_priority(uint32_t irq_id, uint32_t priority)
{
    uint32_t locipri_offset;
    uint32_t irqorder;

    if (priority < INTERRUPT_PRIO_LOWEST || priority > INTERRUPT_PRIO_HIGHEST) {
        return;
    }
    // set the priority of non-standard local interrupt
    if (irq_id >= RISCV_SYS_VECTOR_CNT && irq_id < RISCV_VECTOR_CNT) {
        irqorder = irq_id - RISCV_SYS_VECTOR_CNT;
        locipri_offset = irqorder / LOCIPRI_IRQ_NUM;
        switch (locipri_offset) {
            case EXTERNAL_INTERRUPT_GROUP0:
                int_set_inter_pri(LOCIPRI0, irqorder, priority);
                break;
            case EXTERNAL_INTERRUPT_GROUP1:
                int_set_inter_pri(LOCIPRI1, irqorder, priority);
                break;
            case EXTERNAL_INTERRUPT_GROUP2:
                int_set_inter_pri(LOCIPRI2, irqorder, priority);
                break;
            case EXTERNAL_INTERRUPT_GROUP3:
                int_set_inter_pri(LOCIPRI3, irqorder, priority);
                break;
            case EXTERNAL_INTERRUPT_GROUP4:
                int_set_inter_pri(LOCIPRI4, irqorder, priority);
                break;
            case EXTERNAL_INTERRUPT_GROUP5:
                int_set_inter_pri(LOCIPRI5, irqorder, priority);
                break;
            case EXTERNAL_INTERRUPT_GROUP6:
                int_set_inter_pri(LOCIPRI6, irqorder, priority);
                break;
            case EXTERNAL_INTERRUPT_GROUP7:
                int_set_inter_pri(LOCIPRI7, irqorder, priority);
                break;
            default:
                break;
        }
    }
}

uint32_t int_get_priority(uint32_t irq_id)
{
    uint32_t irqorder;
    uint32_t locipri_offset;
    uint32_t priority = 0;

    // get the priority of non-standard local interrupt
    if (irq_id >= RISCV_SYS_VECTOR_CNT && irq_id < RISCV_VECTOR_CNT) {
        irqorder = (uint32_t)((irq_id - RISCV_SYS_VECTOR_CNT) % LOCIPRI_IRQ_NUM);
        locipri_offset = (uint32_t)((irq_id - RISCV_SYS_VECTOR_CNT) / LOCIPRI_IRQ_NUM);
        switch (locipri_offset) {
            case EXTERNAL_INTERRUPT_GROUP0:
                priority = read_custom_csr(LOCIPRI0) & ((uint32_t)0x3 << (irqorder * LOCIPRI_IRQ_BITS));
                break;
            case EXTERNAL_INTERRUPT_GROUP1:
                priority = read_custom_csr(LOCIPRI1) & ((uint32_t)0x3 << (irqorder * LOCIPRI_IRQ_BITS));
                break;
            case EXTERNAL_INTERRUPT_GROUP2:
                priority = read_custom_csr(LOCIPRI2) & ((uint32_t)0x3 << (irqorder * LOCIPRI_IRQ_BITS));
                break;
            case EXTERNAL_INTERRUPT_GROUP3:
                priority = read_custom_csr(LOCIPRI3) & ((uint32_t)0x3 << (irqorder * LOCIPRI_IRQ_BITS));
                break;
            case EXTERNAL_INTERRUPT_GROUP4:
                priority = read_custom_csr(LOCIPRI4) & ((uint32_t)0x3 << (irqorder * LOCIPRI_IRQ_BITS));
                break;
            case EXTERNAL_INTERRUPT_GROUP5:
                priority = read_custom_csr(LOCIPRI5) & ((uint32_t)0x3 << (irqorder * LOCIPRI_IRQ_BITS));
                break;
            case EXTERNAL_INTERRUPT_GROUP6:
                priority = read_custom_csr(LOCIPRI6) & ((uint32_t)0x3 << (irqorder * LOCIPRI_IRQ_BITS));
                break;
            case EXTERNAL_INTERRUPT_GROUP7:
                priority = read_custom_csr(LOCIPRI7) & ((uint32_t)0x3 <<  (irqorder * LOCIPRI_IRQ_BITS));
                break;
            default:
                break;
        }
    }

    return priority;
}

static void int_set_default_priority(void)
{
    write_custom_csr_val(LOCIPRI0, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI1, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI2, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI3, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI4, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI5, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI6, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI7, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI8, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI9, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI10, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI11, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI12, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI13, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI14, LOCIPRI_DEFAULT_VAL);
    write_custom_csr_val(LOCIPRI15, LOCIPRI_DEFAULT_VAL);
}

void int_setup(void)
{
    set_csr(mstatus, MSTATUS_MIE);
    int_set_default_priority();
}

uint32_t interrupt_number_get(void)
{
    return (read_custom_csr(MCAUSE) & INT_NUM_MAX);
}

bool int_is_interrupt_context(void)
{
    return (interrupt_number_get() > 0);
}

uint32_t int_get_current_priority(void)
{
    return int_get_priority(interrupt_number_get());
}

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */