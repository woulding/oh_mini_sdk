#===============================================================================
# @brief    cmake file
# Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
#===============================================================================
add_subdirectory_if_exist(${CHIP})

if(${CHIP_FAMILY} MATCHES "bs2x")
    add_subdirectory_if_exist(${CHIP_FAMILY})
endif()