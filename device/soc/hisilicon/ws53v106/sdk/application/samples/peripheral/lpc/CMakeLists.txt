#===============================================================================
# @brief    cmake file
# Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
#===============================================================================
if(DEFINED CONFIG_SAMPLE_SUPPORT_LPC)
    set(SOURCES "${SOURCES}" "${CMAKE_CURRENT_SOURCE_DIR}/lpc_gpio_wakeup_demo.c" PARENT_SCOPE)
endif()