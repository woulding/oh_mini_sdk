#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "ipc_porting_acore_rom")

install_sdk("${CMAKE_CURRENT_SOURCE_DIR}" "*.h")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/ipc_porting.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
	${CMAKE_CURRENT_SOURCE_DIR}/../include/${CORE}
)

set(WHOLE_LINK
    true
)

build_component()
