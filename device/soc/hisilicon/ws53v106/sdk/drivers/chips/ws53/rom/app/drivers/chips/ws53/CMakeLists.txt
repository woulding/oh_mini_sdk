#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved.
#===============================================================================
add_subdirectory_if_exist(porting)

set(COMPONENT_NAME "dfx_exception_rom")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/mem.S
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/exception.c
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/src/nonos_trace.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/include/
)

set(PRIVATE_HEADER
)

set(PRIVATE_DEFINES
)

set(PUBLIC_DEFINES
    SUPPORT_EXCEPTION
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

set(COMPONENT_NAME "ws53_clocks_rom")

set(SOURCES
${CMAKE_CURRENT_SOURCE_DIR}/clocks/drivers/acore/clocks_config_private.c
${CMAKE_CURRENT_SOURCE_DIR}/clocks/drivers/acore/clocks.c

${CMAKE_CURRENT_SOURCE_DIR}/clocks/hal/hal_clocks_glb.c
${CMAKE_CURRENT_SOURCE_DIR}/clocks/hal/hal_clocks_security.c
${CMAKE_CURRENT_SOURCE_DIR}/clocks/hal/hal_clocks.c

${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/drivers/shared/clocks_core_common.c

)

if(NOT ((${APPLICATION} STREQUAL "rom") OR (${APPLICATION} STREQUAL "loaderboot") OR
        (${APPLICATION} STREQUAL "flashboot") OR (${APPLICATION} STREQUAL "romboot")))
set(SOURCES
    ${SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/drivers/shared/clock_calibration.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/hal/hal_32k_clock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks/hal/hal_clocks_application.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks/hal/hal_clocks_application_private.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks/hal/hal_clocks_display.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks/hal/hal_clocks_sdio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks/hal/hal_cpu_clocks.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/drivers/acore/clocks_core.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/drivers/acore/clocks_switch_private.c
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/drivers/acore/clocks_switch.c
)
endif()

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks/drivers/acore
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks/hal
    # ${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/drivers/acore
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/drivers/shared
    ${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/hal
)

if(NOT ((${APPLICATION} STREQUAL "rom") OR (${APPLICATION} STREQUAL "loaderboot") OR
        (${APPLICATION} STREQUAL "flashboot") OR (${APPLICATION} STREQUAL "romboot")))
# list(APPEND PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/clocks/drivers/acore)
list(APPEND PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/clocks_core/drivers/acore)
endif()

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

set(COMPONENT_NAME "ws53_pmu_rom")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/drivers/acore/pmu_cmu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/drivers/acore/pmu_interrupt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/drivers/acore/pmu_ldo.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/drivers/acore/pmu_pg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/drivers/acore/pmu_vdd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/drivers/shared/pmu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal/hal_pmu_cmu_private.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal/hal_pmu_cmu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal/hal_pmu_interrupt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal/hal_pmu_ldo.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal/hal_pmu_pg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal/hal_pmu_vdd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal/hal_pmu_peripheral_bt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal/hal_pmu_peripheral_gnss.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal/hal_pmu_peripheral_application.c
)

set(PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/drivers/acore
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/drivers/shared
    ${CMAKE_CURRENT_SOURCE_DIR}/pmu/hal
)

set(PRIVATE_HEADER
)

set(PRIVATE_DEFINES
)

set(PUBLIC_DEFINES
    SUPPORT_CLOCKS
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
add_subdirectory_if_exist(patch)

install_sdk("${CMAKE_CURRENT_SOURCE_DIR}/porting/include" "*.h")
