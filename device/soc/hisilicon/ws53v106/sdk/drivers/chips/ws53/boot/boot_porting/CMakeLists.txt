#===============================================================================
# @brief    cmake file
# Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "chip_boot_port")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/delay/delay.c
    ${CMAKE_CURRENT_SOURCE_DIR}/serial/serial.c
    ${CMAKE_CURRENT_SOURCE_DIR}/watchdog/boot_watchdog.c
    ${CMAKE_CURRENT_SOURCE_DIR}/reset/reset_porting.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/efuse_wrap/
    ${CMAKE_CURRENT_SOURCE_DIR}/reset/
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
#============================================================================================
set(COMPONENT_NAME "boot_sdio")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/sdio/boot.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdio/bus_layer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdio/firmware.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdio/link_layer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdio/sdio_bus.c
    #${CMAKE_CURRENT_SOURCE_DIR}/sdio/startup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdio/sdio.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/sdio/
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
