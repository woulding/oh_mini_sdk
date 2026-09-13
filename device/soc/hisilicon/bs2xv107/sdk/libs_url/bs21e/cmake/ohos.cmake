#===============================================================================
# @brief    cmake file - link OHOS lite component libs into the BS21E SDK image
# Copyright (c) 2026 Hihope Open Source Organization.
#===============================================================================
# Included automatically by protocol/CMakeLists.txt when this file exists
# (same hook mechanism as the ws63/ws53 integration layers).
#
# TARGET_COMMAND equals the string passed to `build.py -c`, i.e.
# `standard-bs21e-1100e` (hyphens, unlike ws53's underscore target keys).
# hm_build.sh copies the GN-produced libs into
# interim_binary/bs21e/libs/ohos/${TARGET_COMMAND}/ with the same naming.
#
# bs21e is a BT/NFC/SLP chip (no Wi-Fi), so wifiservice is not in the list.

if(NOT EXISTS ${BIN_DIR}/${CHIP}/libs/ohos/${TARGET_COMMAND})
    return()
endif()

if(${TARGET_COMMAND} MATCHES "standard-bs21e-1100e")
    set(OHOS_COMPONENT_LIST
            "begetutil"   "hilog_lite_static" "samgr_adapter" "bootstrap" "hilog_static" "inithook"   "samgr_source"
            "broadcast" "init_log"  "udidcomm"
            "cjson_static" "hal_sys_param" "init_utils"  "param_client_lite"
            "hiview_lite_static" "hal_sysparam" "hievent_lite_static" "samgr" "hal_iothardware"
            "ble_lite"  "sle_lite" "product" "bs21e_demo")
endif()

# Attach the OHOS lite libs to the firmware executable. whole-archive keeps
# the samgr/bootstrap service-registration sections that --gc-sections would
# otherwise drop. Components whose lib is not produced by the current product
# (e.g. the vestigial "product" entry) are skipped; the truly required libs
# are enforced by hm_build.sh REQUIRED_LIBS before cmake runs.
set(OHOS_LIB_DIR ${BIN_DIR}/${CHIP}/libs/ohos/${TARGET_COMMAND})
foreach(COMPONENT ${OHOS_COMPONENT_LIST})
    if(EXISTS ${OHOS_LIB_DIR}/lib${COMPONENT}.a)
        list(APPEND OHOS_LINK_LIBS ${OHOS_LIB_DIR}/lib${COMPONENT}.a)
    else()
        message(STATUS "ohos.cmake: lib${COMPONENT}.a not present, skipped")
    endif()
endforeach()

if(OHOS_LINK_LIBS)
    target_link_libraries(${TARGET_NAME} PRIVATE
        -Wl,--whole-archive ${OHOS_LINK_LIBS} -Wl,--no-whole-archive)
endif()
