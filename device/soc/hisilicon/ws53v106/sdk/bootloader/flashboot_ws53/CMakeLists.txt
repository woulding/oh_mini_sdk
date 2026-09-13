#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved.
#===============================================================================
set(COMPONENT_NAME "flashboot_common")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/startup/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/startup/riscv_init.S
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/include
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


set(COMPONENT_NAME "ssb_common")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/ssb/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ssb/riscv_init.S
    ${CMAKE_CURRENT_SOURCE_DIR}/../commonboot/src/boot_jump.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/../commonboot/include
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