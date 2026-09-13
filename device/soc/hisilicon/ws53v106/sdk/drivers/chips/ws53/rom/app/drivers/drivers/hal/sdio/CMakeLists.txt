set(COMPONENT_NAME "hal_sdio_rom")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/hal_sdio.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set(PRIVATE_HEADER
)

set(PRIVATE_DEFINES
)

if(DEFINED CONFIG_SDIO_USING_V120)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/v120/hal_sdio_v120.c)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/v120/hal_sdio_v120_regs_op.c)
    list(APPEND PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/v120)
endif()

if(DEFINED CONFIG_SDIO_USING_V151)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/v151/hal_sdio_v151.c)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/v151/hal_sdio_v151_regs_op.c)
    list(APPEND PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/v151)
endif()

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

install_sdk(${CMAKE_CURRENT_SOURCE_DIR}/ "*.h")

