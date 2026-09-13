#===============================================================================
# @brief    cmake file
# Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
#===============================================================================
if(DEFINED CONFIG_SAMPLE_SUPPORT_STA_SAMPLE)
    add_subdirectory_if_exist(sta_sample)
endif()

if(DEFINED CONFIG_SAMPLE_SUPPORT_SOFTAP_SAMPLE)
    add_subdirectory_if_exist(softap_sample)
endif()

if(DEFINED CONFIG_SAMPLE_SUPPORT_BLE_WIFI_CFG_SAMPLE)
    add_subdirectory_if_exist(ble_wifi_cfg_sample)
endif()

if(DEFINED CONFIG_SAMPLE_SUPPORT_SYSCHANNEL_DEV)
    add_subdirectory_if_exist(syschannel_dev)
endif()

if(DEFINED CONFIG_SUPPORT_HILINK)
    add_subdirectory_if_exist(ohos_connect)
endif()

if (DEFINES MATCHES "CONFIG_SUPPORT_HILINK_INDIE_UPGRADE")
    add_subdirectory_if_exist(hilink_indie_upgrade)
endif()

if(DEFINED CONFIG_SUPPORT_UAPI)
    add_subdirectory_if_exist(uhapi)
endif()

if(DEFINED CONFIG_SUPPORT_TCP_CLIENT_SAMPLE OR CONFIG_SUPPORT_TCP_SERVER_SAMPLE)
    add_subdirectory_if_exist(tcp_sample)
endif()

if(DEFINED CONFIG_SAMPLE_SUPPORT_MQTT)
    add_subdirectory_if_exist(mqtt_sample)
    set(PUBLIC_HEADER "${PUBLIC_HEADER}" "${CMAKE_CURRENT_SOURCE_DIR}/mqtt_sample/" PARENT_SCOPE)
endif()

set(SOURCES "${SOURCES}" PARENT_SCOPE)
if(syschannel_host_ko IN_LIST TARGET_COMPONENT)
install_sdk(${CMAKE_CURRENT_SOURCE_DIR}/syschannel_dev "*")
install_sdk(${CMAKE_CURRENT_SOURCE_DIR}/syschannel_host "*")
endif()