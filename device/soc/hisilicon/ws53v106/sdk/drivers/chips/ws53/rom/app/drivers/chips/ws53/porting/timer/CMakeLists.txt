#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "timer_port_rom")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/timer_porting.c
)

set(PUBLIC_HEADER
)

if(${CORE} MATCHES "control_core")
set(PUBLIC_DEFINES
    DEFAULT_TIMER_C_CORE=0
    DEFAULT_TIMER=0
)
else()
set(PUBLIC_DEFINES
    DEFAULT_TIMER_C_CORE=0
    DEFAULT_TIMER=1
)
endif()


set(WHOLE_LINK
    true
)

build_component()

install_sdk(${CMAKE_CURRENT_SOURCE_DIR}/ "*.h")

