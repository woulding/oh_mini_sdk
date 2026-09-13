#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved.
#===============================================================================

set(WIFI_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build/${CHIP})
if(USE_WS53_ROM_REPO IN_LIST DEFINES)
    set(WIFI_DEVICE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rom_code/${CHIP})
    message("Build wifi device with rom repo!")
else()
    set(WIFI_DEVICE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
endif()
include(${WIFI_BUILD_DIR}/wifi_alg_ws53.cmake)
if(wifi_dev_rom IN_LIST TARGET_COMPONENT)
    add_subdirectory(${WIFI_DEVICE_DIR}/source/alg wifi_alg_device)
    include(${WIFI_BUILD_DIR}/wifi_device.cmake)
    #include(${WIFI_DEVICE_BUILD_DIR}/wifi_alg_device.cmake)
elseif(wifi_drv_ws53 IN_LIST TARGET_COMPONENT)
    install_sdk(${WIFI_DIR}/com_code/alg "CMakeLists.txt")
    install_sdk(${WIFI_DIR}/com_code/alg/iot_alg/ "*")
    add_subdirectory(${WIFI_DIR}/com_code/alg wifi_alg_host)
    include(${WIFI_BUILD_DIR}/wifi_host.cmake)
    #include(${WIFI_BUILD_DIR}/wifi_alg_host.cmake)
endif()