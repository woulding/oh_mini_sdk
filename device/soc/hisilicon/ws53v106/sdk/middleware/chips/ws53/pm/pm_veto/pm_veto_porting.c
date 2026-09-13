/**
 * Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved. \n
 *
 * Description: Provides pm veto port \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-01-13， Create file. \n
 */

#include "uart.h"
#include "pm_veto_porting.h"

bool pm_port_get_customized_sleep_veto(void)
{
    if (uapi_uart_has_pending_transmissions(SW_DEBUG_UART_BUS) || uapi_uart_has_pending_transmissions(LOG_UART_BUS)) {
        return true;
    }
    return false;
}