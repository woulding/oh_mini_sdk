#===============================================================================
# @brief    cmake make file
# Copyright (c) 2021 Huawei Technologies Co. Ltd
#===============================================================================
set(COMPONENT_NAME "ws53_standard")


if(${OS} STREQUAL "freertos")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/jumper.S
    ${CMAKE_CURRENT_SOURCE_DIR}/startup.S
    ${CMAKE_CURRENT_SOURCE_DIR}/main_freertos.c
)
else()
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/jumper.S
    ${CMAKE_CURRENT_SOURCE_DIR}/startup.S
    ${CMAKE_CURRENT_SOURCE_DIR}/app_os_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bt_customize.c
    ${CMAKE_CURRENT_SOURCE_DIR}/btc_hcc_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bth_customize.c
)
endif()

set(PRIVATE_HEADER
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/version
)

set(PRIVATE_DEFINES
)

set(PUBLIC_DEFINES
)

set(COMPONENT_CCFLAGS
)

set(WHOLE_LINK
true
)

set(BUILD_AS_OBJ
false
)

set(MAIN_COMPONENT
true
)
build_component()