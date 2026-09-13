#===============================================================================
# @brief    cmake file
# Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "ws53_flash_patch_port")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/flash_patch_porting.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set(PRIVATE_HEADER
)

set(PRIVATE_DEFINES
)

set(PUBLIC_DEFINES
)

# use this when you want to add ccflags like -include xxx
set(COMPONENT_PUBLIC_CCFLAGS
)

set(COMPONENT_CCFLAGS
)

set(WHOLE_LINK
    true
)

set(MAIN_COMPONENT
    false
)

build_component()


set(COMPONENT_NAME "plat_patch")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/dma_patch.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ipc_patch.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdio_patch.c
    ${CMAKE_CURRENT_SOURCE_DIR}/acccode.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set(PRIVATE_HEADER
)

set(PRIVATE_DEFINES
    CONFIG_HCC_SUPPORT_IPC
    CONFIG_HCC_SUPPORT_MULTI_CHANNEL
    CONFIG_HCC_SUPPORT_FLOW_CONTRL
    CONFIG_HCC_SUPPORT_FLOW_CONTRL_ACTIVE
    CONFIG_HCC_SUPPORT_DFX
    CONFIG_HCC_SUPPORT_TEST
    CONFIG_HCC_SUPPORT_SDIO
    CONFIG_HCC_SUPPORT_IPC
    CONFIG_HCC_SUPPORT_IPC_HOST
    CONFIG_HCC_SUPPORT_UNC_POOL
)

set(PUBLIC_DEFINES
)

# use this when you want to add ccflags like -include xxx
set(COMPONENT_PUBLIC_CCFLAGS
)

set(COMPONENT_CCFLAGS
)

set(WHOLE_LINK
    true
)

set(MAIN_COMPONENT
    false
)

build_component()

set(COMPONENT_NAME "ws53_ccore_efuse_patch")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/efuse_patch.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set(PRIVATE_HEADER
)

set(PRIVATE_DEFINES
)

set(PUBLIC_DEFINES
)

# use this when you want to add ccflags like -include xxx
set(COMPONENT_PUBLIC_CCFLAGS
)

set(COMPONENT_CCFLAGS
)

set(WHOLE_LINK
    true
)

set(MAIN_COMPONENT
    false
)

build_component()