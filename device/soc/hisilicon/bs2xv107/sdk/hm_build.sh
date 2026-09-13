#!/bin/bash
set -e
product_out_dir="$1"
build_bs21e_sdk_open="$2"
# XTS overlay isolation: turn the GN-forwarded env vars into link-script
# preprocessor defines consumed by the SDK cmake. Exported so the python3
# build.py / cmake subprocess inherits them.
if [ "$XTS_OVERLAY_ARG" = "true" ]; then
    export XTS_OVERLAY_ENABLE=true
fi
if [ "$XTS_OVERLAY_ARG" = "true" ] || [ "$HCTEST_RODATA_OPT_ARG" = "true" ]; then
    export HCTEST_NEW_RUNNER=true
fi

# prebuild #
CROOT=$(pwd)

TARGET=standard-bs21e-1100e
OUTPUT_SRC_DIR=$CROOT/output/bs21e/fwpkg
OUTPUT_DST_DIR=$1

OHOS_LIBS_DIR=$CROOT/interim_binary/bs21e/libs/ohos/${TARGET}

rm -rf $OHOS_LIBS_DIR
mkdir -p $OHOS_LIBS_DIR

find $OUTPUT_DST_DIR/libs/ -name '*.a' -exec cp "{}" $OHOS_LIBS_DIR \;

# Sanity check: every lib required by the SDK cmake COMPONENT_LIST
# (libs_url/bs21e/cmake/ohos.cmake) must have been copied; a missing lib here
# means the GN side did not finish archiving it (dependency race) and the
# cmake link would fail with "No rule to make target".
REQUIRED_LIBS="begetutil bootstrap hal_sys_param hal_sysparam hilog_lite_static hilog_static hiview_lite_static hievent_lite_static init_log init_utils inithook samgr samgr_adapter samgr_source cjson_static ble_lite sle_lite udidcomm param_client_lite hal_iothardware bs21e_demo"
MISSING_LIBS=""
for lib in $REQUIRED_LIBS; do
    if [ ! -f "$OHOS_LIBS_DIR/lib${lib}.a" ]; then
        MISSING_LIBS="$MISSING_LIBS lib${lib}.a"
    fi
done
if [ -n "$MISSING_LIBS" ]; then
    echo "[ERROR] hm_build.sh: missing OHOS libs in $OHOS_LIBS_DIR:$MISSING_LIBS"
    echo "[ERROR] GN archiving ran concurrently with the SDK copy step (dependency race)."
    echo "[ERROR] Re-run the build; if it reproduces, check run_sdk_build deps in device/soc/hisilicon/bs2xv107/sdk/BUILD.gn."
    exit 1
fi

# build #
echo "build bs21e sdk = $build_bs21e_sdk_open"
if [ "$build_bs21e_sdk_open" = "true" ]; then
    export build_bs21e_sdk_open=true
    echo "export build_bs21e_sdk_open=true "
fi

python3 build.py -c ${TARGET}

#
# after build #
if [ ! -d $OUTPUT_DST_DIR ]; then
   mkdir $OUTPUT_DST_DIR
fi
cp $OUTPUT_SRC_DIR/* $OUTPUT_DST_DIR/ -rf
