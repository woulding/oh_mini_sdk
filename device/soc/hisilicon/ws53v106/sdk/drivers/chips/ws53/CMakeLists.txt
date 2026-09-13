#===============================================================================
# @brief    cmake file
# Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
#===============================================================================
add_subdirectory_if_exist(porting)
add_subdirectory_if_exist(flash_recover)
add_subdirectory_if_exist(sdio_recover)
add_subdirectory_if_exist(boot)
if(USE_WS53_ROM_REPO IN_LIST DEFINES)
    add_subdirectory_if_exist(rom)
endif()

set(COMPONENT_NAME "chip_ws53_acore")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/mem.S
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/entry.S
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/nonos_isr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/interrupt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/interrupt/interrupt_adapter.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clock_recover/clock_recover.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clock_recover/acore/acore_clock_recover.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/${CORE}
    ${CMAKE_CURRENT_SOURCE_DIR}/porting/include
)

if(DEFINED OS AND NOT ${OS} STREQUAL "non-os")
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/oam_trace.c)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/interrupt/interrupt_os_adapter.c)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${OS}/memory_info.c)
if(NOT ${OS} STREQUAL "freertos")
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${OS}/idle_config.c)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${OS}/tick_timer.c)
endif()
endif()

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

set(COMPONENT_NAME "chip_ws53_ccore")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/entry.S
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/nonos_isr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/interrupt/interrupt_adapter_ccore.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/${CORE}
    ${CMAKE_CURRENT_SOURCE_DIR}/porting/include
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

set(COMPONENT_NAME "ws53_ccore_clock_recover")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/clock_recover/clock_recover.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clock_recover/ccore/rf_power_recover.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clock_recover/ccore/ccore_clock_recover.c
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

build_component()

set(COMPONENT_NAME "chip_ws53_ccore_master")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/entry.S
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/mem.S
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/nonos_isr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/interrupt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/interrupt/interrupt_adapter_ccore.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/${CORE}
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

set(COMPONENT_NAME "ws53_clocks")

set(SOURCES
)

set(PUBLIC_HEADER
)

set(PRIVATE_HEADER
)

set(PRIVATE_DEFINES
)

set(PUBLIC_DEFINES
    SUPPORT_CLOCKS
    SUPPORT_CLOCKS_CORE
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

set(COMPONENT_NAME "rom_callback")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/rom_config/${CORE}/output/rom_callback.S
)

if(DEFINED ROM_SYM_PATH)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rom_config/${CORE}/plat_rom_data.c)
endif()

set(WHOLE_LINK
    true
)

set(MAIN_COMPONENT
    false
)

if(${BUILD_ROM_CALLBACK} OR rom_callback IN_LIST TARGET_COMPONENT)
    install_sdk(${CMAKE_CURRENT_SOURCE_DIR}/rom_config/${CORE}/output "*.lds")
    install_sdk(${CMAKE_CURRENT_SOURCE_DIR}/rom_config/${CORE}/acore.sym "*")
    install_sdk(${CMAKE_CURRENT_SOURCE_DIR}/rom_config/${CORE}/output/rom_data.lds "*")
    execute_process(
        COMMAND ${CP} ${CMAKE_CURRENT_SOURCE_DIR}/rom_config/${CORE}/output/function.lds ${CMAKE_BINARY_DIR}
        COMMAND ${CP} ${CMAKE_CURRENT_SOURCE_DIR}/rom_config/${CORE}/output/data.lds ${CMAKE_BINARY_DIR}
        COMMAND ${CP} ${CMAKE_CURRENT_SOURCE_DIR}/rom_config/${CORE}/output/rom_data.lds ${CMAKE_BINARY_DIR}
    )
endif()

if(rom_callback IN_LIST TARGET_COMPONENT)
    include(${CMAKE_CURRENT_SOURCE_DIR}/rom_config/${CORE}/output/rom_callback_wrap.cmake)
    target_link_options(${TARGET_NAME}
        PRIVATE
        ${CMAKE_CB_FLGAS}
    )
endif()
build_component()

add_subdirectory_if_exist(patch)
add_subdirectory_if_exist(dyn_mem)
add_subdirectory_if_exist(hpm)

install_sdk("${CMAKE_CURRENT_SOURCE_DIR}/porting/include" "*.h")
