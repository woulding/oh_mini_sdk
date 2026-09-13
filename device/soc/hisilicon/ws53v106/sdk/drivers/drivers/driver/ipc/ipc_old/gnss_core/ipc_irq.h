/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 *
 * Description: Gnss core ipc irq driver header \n
 *
 * History: \n
 * 2022-07-27, Create file. \n
 */

#ifndef HAL_IPC_IRQ_H
#define HAL_IPC_IRQ_H

/**
 * @brief  Enable the appropriate interrupts for the IPC mechanism on this core (core specific).
 * @return None.
 */
void ipc_init_interrupts(void);

/**
 * @brief  Disable interrupts used by the IPC mechanism on this core (core specific).
 * @return None.
 */
void ipc_deinit_interrupts(void);

#endif
