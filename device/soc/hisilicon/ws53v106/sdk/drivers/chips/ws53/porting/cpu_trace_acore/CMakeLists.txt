#===============================================================================
# @brief    cmake file
# Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "mcpu_trace_porting")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/mcpu_trace_porting.c
)

set(PUBLIC_HEADER
)

set(WHOLE_LINK
    true
)

build_component()
