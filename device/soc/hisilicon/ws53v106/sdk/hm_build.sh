#!/bin/bash
set -e
product_out_dir="$1"
build_ws53_sdk_open="$2"
# XTS overlay isolation: turn the GN-forwarded env vars (XTS_OVERLAY_ARG /
# HCTEST_RODATA_OPT_ARG) into the link-script preprocessor defines consumed by
# build_linker.cmake. Exported so the python3 build.py / cmake subprocess
# inherits them.
if [ "$XTS_OVERLAY_ARG" = "true" ]; then
    export XTS_OVERLAY_ENABLE=true
fi
if [ "$XTS_OVERLAY_ARG" = "true" ] || [ "$HCTEST_RODATA_OPT_ARG" = "true" ]; then
    export HCTEST_NEW_RUNNER=true
fi
# prebuild #
CROOT=$(pwd)

OUTPUT_SRC_DIR=$CROOT/output/ws53/fwpkg
OUTPUT_DST_DIR=$1

OHOS_LIBS_DIR=$CROOT/interim_binary/ws53/libs/ohos/ws53_liteos_app
OHOS_LIBS_XTS_DIR=$CROOT/interim_binary/ws53/libs/ohos/ws53_liteos_xts

rm $OHOS_LIBS_DIR -rf
rm $OHOS_LIBS_XTS_DIR -rf

mkdir -p $OHOS_LIBS_DIR
mkdir -p $OHOS_LIBS_XTS_DIR

find $OUTPUT_DST_DIR/libs/ -name '*.a' -exec cp "{}" $OHOS_LIBS_XTS_DIR  \;
find $OUTPUT_DST_DIR/libs/ -name '*.a' -exec cp "{}" $OHOS_LIBS_DIR  \;

# Sanity check: every lib required by the SDK cmake COMPONENT_LIST
# (libs_url/ws53/cmake/ohos.cmake) must have been copied; a missing lib here
# means the GN side did not finish archiving it (dependency race) and the
# cmake link would fail with "No rule to make target".
REQUIRED_LIBS="begetutil bootstrap hal_file_static hal_sys_param hal_sysparam hal_update_static hichainsdk hilog_lite_static hilog_static hiview_lite_static hievent_lite_static huks_3.0_sdk init_log init_utils inithook samgr samgr_adapter samgr_source cjson_static blackbox_lite hidumper_mini ble_lite sle_lite wifiservice native_file udidcomm param_client_lite hota hal_iothardware ws53_demo"
MISSING_LIBS=""
for lib in $REQUIRED_LIBS; do
    if [ ! -f "$OHOS_LIBS_DIR/lib${lib}.a" ]; then
        MISSING_LIBS="$MISSING_LIBS lib${lib}.a"
    fi
done
if [ -n "$MISSING_LIBS" ]; then
    echo "[ERROR] hm_build.sh: missing OHOS libs in $OHOS_LIBS_DIR:$MISSING_LIBS"
    echo "[ERROR] GN archiving ran concurrently with the SDK copy step (dependency race)."
    echo "[ERROR] Re-run the build; if it reproduces, check run_sdk_build deps in device/soc/hisilicon/ws53v106/sdk/BUILD.gn."
    exit 1
fi

# build #
echo "build ws53 sdk = $build_ws53_sdk_open"
if [ "$build_ws53_sdk_open" = "true" ]; then
    export build_ws53_sdk_open=true
    echo "export build_ws53_sdk_open=true "
fi

if [[ "$product_out_dir" == *xts* ]]; then
    python3 build.py -c ws53_liteos_xts
else
    python3 build.py -c ws53_liteos_app
fi

#
# after build #
if [ ! -d $OUTPUT_DST_DIR ]; then
   mkdir $OUTPUT_DST_DIR
fi
cp $OUTPUT_SRC_DIR/* $OUTPUT_DST_DIR/ -rf
