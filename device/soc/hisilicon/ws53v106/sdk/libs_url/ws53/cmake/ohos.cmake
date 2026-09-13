#===============================================================================
# @brief    cmake file - link OHOS lite component libs into the WS53 SDK image
# Copyright (c) 2026 Hihope Open Source Organization.
#===============================================================================
# Included automatically by protocol/CMakeLists.txt when this file exists
# (same hook mechanism as the ws63 integration layer).
#
# Differences from the ws63 integration layer:
#   1. Target names use underscores (ws53_liteos_app / ws53_liteos_xts),
#      matching the ws53 SDK target keys; TARGET_COMMAND equals the string
#      passed to `build.py -c`, and hm_build.sh copies GN-produced libs into
#      interim_binary/ws53/libs/ohos/${TARGET_COMMAND}/ with the same naming.
#   2. The OHOS component names are NOT added to ram_component in config.py
#      (adding them makes every SDK component's TARGETS_INTERFACES reference
#      undefined *_interface targets and breaks standalone builds). Instead
#      the libs are attached directly to the firmware executable target,
#      which keeps `build.py -c` usable standalone (L1) and inside the OHOS
#      tree (L2/L3, where hm_build.sh has populated interim_binary/.../libs/
#      ohos before cmake runs).
#   3. No mbedtls_ohos switch block: the ws53 SDK uses mbedtls v3.6.0 whose
#      harden layout differs from ws63's v3.1.0; 7.0's third_party/mbedtls
#      (3.6.5) + huks works without the source-switch mechanism.

# Guard: standalone SDK build without the OHOS tree -> nothing to link.
if(NOT EXISTS ${BIN_DIR}/${CHIP}/libs/ohos/${TARGET_COMMAND})
    return()
endif()

if(${TARGET_COMMAND} MATCHES "ws53_liteos_xts")
    set(OHOS_COMPONENT_LIST "begetutil" "devattest_sdk" "hal_token_static" "hilog_lite_static" "huks_test_common" "module_ActsBootstrapTest" "module_ActsSamgrTest" "samgr_adapter" "bootstrap" "hal_update_static" "hilog_static" "inithook" "module_ActsDeviceAttestTest" "module_ActsUpdaterFuncTest" "samgr_source"
            "hal_file_static" "hctest" "hiview_lite_static" "init_log" "module_ActsDfxFuncTest" "native_file" "udidcomm"
            "cjson_static" "hal_sys_param" "hota" "init_utils" "module_ActsHieventLiteTest" "param_client_lite"
            "devattest_core" "hal_sysparam" "hievent_lite_static" "module_ActsHuksHalFunctionTest" "samgr"
            "product" "module_ActsParameterTest")
elseif(${TARGET_COMMAND} MATCHES "ws53_liteos_app")
    set(OHOS_COMPONENT_LIST
            "begetutil"   "hilog_lite_static" "samgr_adapter" "bootstrap" "hal_update_static" "hilog_static" "inithook"   "samgr_source"
            "broadcast" "hal_file_static"   "init_log"  "native_file" "udidcomm"
            "cjson_static" "hal_sys_param" "hichainsdk" "hota" "init_utils"  "param_client_lite"
            "hiview_lite_static" "hal_sysparam" "hievent_lite_static" "huks_3.0_sdk"   "samgr" "blackbox_lite" "hal_iothardware" "wifiservice"
            "hidumper_mini" "ble_lite"  "sle_lite" "product" "ws53_demo")
endif()

# Attach the OHOS lite libs to the firmware executable. whole-archive keeps
# the samgr/bootstrap service-registration sections that --gc-sections would
# otherwise drop. Components whose lib is not produced by the current product
# (e.g. the vestigial "product" entry, present in the ws63 list too) are
# skipped; the truly required libs are enforced by hm_build.sh REQUIRED_LIBS
# before cmake runs.
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
