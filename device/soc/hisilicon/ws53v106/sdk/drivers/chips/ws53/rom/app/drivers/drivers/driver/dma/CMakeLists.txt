#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "dma_flash")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/dma.c
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/romable
)

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

install_sdk("${CMAKE_CURRENT_SOURCE_DIR}" "*.h")

build_component()

set(COMPONENT_NAME "dma_rom")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/romable/dma_rom.c
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/romable
)

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

install_sdk("${CMAKE_CURRENT_SOURCE_DIR}" "*.h")

build_component()