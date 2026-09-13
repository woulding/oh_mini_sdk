#===============================================================================
# @brief    cmake file
# Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "version_port")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/version_porting.c
)

set(PUBLIC_HEADER
)

set(PRIVATE_HEADER
)

set(WHOLE_LINK
    true
)

build_component()
