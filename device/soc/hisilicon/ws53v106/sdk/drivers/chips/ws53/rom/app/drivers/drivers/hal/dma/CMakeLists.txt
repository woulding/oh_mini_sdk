#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "hal_dma_v151_rom")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/romable/hal_dma_mem.c
	${CMAKE_CURRENT_SOURCE_DIR}/romable/v151/hal_dmac_v151.c
	${CMAKE_CURRENT_SOURCE_DIR}/romable/v151/hal_dmac_v151_regs_op.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/romable
    ${CMAKE_CURRENT_SOURCE_DIR}/romable/v151
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

set(COMPONENT_NAME "hal_dma_v151_flash")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/hal_dma.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/romable
    ${CMAKE_CURRENT_SOURCE_DIR}/romable/v151
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
