#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved.
#===============================================================================

set(COMPONENT_NAME "hcc_host_ram")

set(MODULE_NAME "pf")
set(AUTO_DEF_FILE_ID FALSE)

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/master/hcc_test_host.c
    ${CMAKE_CURRENT_SOURCE_DIR}/master/hcc_ipc_host.c
    ${CMAKE_CURRENT_SOURCE_DIR}/master/comm/hcc.c	
    ${CMAKE_CURRENT_SOURCE_DIR}/master/comm/hcc_bus.c
    ${CMAKE_CURRENT_SOURCE_DIR}/master/comm/hcc_test_service.c
    ${CMAKE_CURRENT_SOURCE_DIR}/slave/hcc_sdio_device.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../romable/comm/hcc_channel.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../romable/comm/hcc_dfx.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../romable/comm/hcc_flow_ctrl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../romable/comm/hcc_service.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../romable/comm/hcc_test.c
)

if("_PRE_FEATURE_WS53_DEVICE_MODE" IN_LIST DEFINES)
    list(APPEND SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/master/comm/hcc_agent.c")
endif()

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/../inc
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
    HCC_SUPPORT_ACORE_HSO
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
