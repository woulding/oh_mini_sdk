#===============================================================================
# @brief    cmake file
# Copyright (c) CompanyNameMagicTag 2022-2022. All rights reserved.
#===============================================================================
set(MODULE_NAME "bt")
set(BTC_RAM_LIST  "" CACHE INTERNAL "" FORCE)
set(BTC_ROM_LIST  "" CACHE INTERNAL "" FORCE)
set(BTC_HEADER_LIST  "" CACHE INTERNAL "" FORCE)

if("TARGET_LOCATION_ROM" IN_LIST DEFINES)
    set(BT_ROM_VERSION true)
else()
    set(BT_ROM_VERSION false)
endif()

if("DEVICE_ONLY" IN_LIST DEFINES)
    set(BGTP_DEVICE_ONLY true)
else()
    set(BGTP_DEVICE_ONLY false)
endif()

if("BTC_CENTRAL_ROLE_SUPPORT" IN_LIST DEFINES)
    MESSAGE("BTC_CENTRAL_ROLE_SUPPORT ON")
else()
    MESSAGE("BTC_CENTRAL_ROLE_SUPPORT OFF")
endif()

MESSAGE("BGTP_PROJECT=" ${BGTP_PROJECT})
MESSAGE("BGTP_ROM_VERSION=" ${BT_ROM_VERSION})
MESSAGE("BGTP_DEVICE_ONLY=" ${BGTP_DEVICE_ONLY})

add_subdirectory_if_exist(chip)

set(GMSSL_PATH ${PROJECT_SOURCE_DIR}/open_source/GmSSL3.1.1)

set(GMSSL_HEADER_LIST
    ${GMSSL_PATH}/include/
    ${GMSSL_PATH}/include/gmssl/
    ${GMSSL_PATH}/src/
)

if("DEVICE_ONLY" IN_LIST DEFINES)
    set(PRIVATE_DEFINES
        HCC_NOT_ADAPTION  # HCC适配前先用宏括起来
    )
else()

endif()

set(PUBLIC_DEFINES
    "BTC_SYS_PART=100"
)

# use this when you want to add ccflags like -include xxx
set(COMPONENT_PUBLIC_CCFLAGS
)

set(COMPONENT_CCFLAGS
    -Wmissing-declarations -Wundef  -Wmissing-prototypes -Wswitch-default
)

set(WHOLE_LINK
    true
)

set(MAIN_COMPONENT
    false
)

set(LOG_DEF
    ${CMAKE_CURRENT_SOURCE_DIR}/chip/ws53/ram/comm/log_def_btc.h
)

# ram组件，编译BTC_RAM_LIST
set(COMPONENT_NAME "bgtp")

set(SOURCES
    ${BTC_RAM_LIST}
)

set(PUBLIC_HEADER
    ${BTC_HEADER_LIST}
    ${CMAKE_CURRENT_SOURCE_DIR}/chip/ws53/ram/comm
)

set(PRIVATE_HEADER
    ${GMSSL_HEADER_LIST}
)

set(LIBRARY_OUTPUT_PATH ${BIN_DIR}/${CHIP}/libs/bluetooth/btc/${TARGET_COMMAND})
build_component()

# rom组件，编译BTC_ROM_LIST
set(COMPONENT_NAME "bgtp_rom")

set(SOURCES
    ${BTC_ROM_LIST}
)

set(PUBLIC_HEADER
    ${BTC_HEADER_LIST}
    ${CMAKE_CURRENT_SOURCE_DIR}/chip/ws53/ram/comm
)

if("DEVICE_ONLY" IN_LIST DEFINES)
    set(PRIVATE_DEFINES
        HCC_NOT_ADAPTION  # HCC适配前先用宏括起来
    )
else()

endif()

set(PUBLIC_DEFINES
    "BTC_SYS_PART=100"
)

# use this when you want to add ccflags like -include xxx
set(COMPONENT_PUBLIC_CCFLAGS
)

set(COMPONENT_CCFLAGS
    -Wundef
)

set(WHOLE_LINK
    true
)

set(MAIN_COMPONENT
    false
)

set(LOG_DEF
    ${CMAKE_CURRENT_SOURCE_DIR}/chip/ws53/ram/comm/log_def_btc.h
)

set(PRIVATE_HEADER
    ${GMSSL_HEADER_LIST}
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${BIN_DIR}/${CHIP}/libs/bluetooth/btc/${TARGET_COMMAND})
build_component()