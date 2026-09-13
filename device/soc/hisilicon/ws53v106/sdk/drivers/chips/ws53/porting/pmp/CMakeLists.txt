#===============================================================================
# @brief    cmake file
# Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "pmp_port")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/pmp_porting.c
)

if(${CORE} MATCHES "acore")
list (APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/acore_pmp_cfg.c
)
else()
list (APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/ccore_pmp_cfg.c
)
endif()

set(PUBLIC_HEADER
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
