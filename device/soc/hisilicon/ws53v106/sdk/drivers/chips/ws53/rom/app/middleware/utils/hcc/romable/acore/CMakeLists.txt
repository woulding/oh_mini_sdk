#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved.
#===============================================================================

install_sdk("${CMAKE_CURRENT_SOURCE_DIR}/" "CMakeLists.txt")

set(COMPONENT_NAME "hcc_host_rom")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/master/hcc_ipc_host_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/slave/hcc_sdio_device_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../comm_share/hcc_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../comm_share/hcc_adapt_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../comm_share/hcc_bus_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../comm_share/hcc_channel_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../comm_share/hcc_dfx_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../comm_share/hcc_flow_ctrl_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../comm_share/hcc_list_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../comm_share/hcc_service_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../comm_share/hcc_rom_callback_rom.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/../../inc
)

set(PRIVATE_HEADER
)

set(PRIVATE_DEFINES
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
